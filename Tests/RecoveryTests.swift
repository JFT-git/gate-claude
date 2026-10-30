import Foundation
import Network
import Darwin

/// Exercises the real model with controlled IP replies, never launching Claude.
@main struct RecoveryTests {
    // Read and mutated only on the listener's dedicated serial queue.
    private final class ListenerState: @unchecked Sendable { var finished = false }
    @MainActor static var failures = 0
    @MainActor static func expect(_ value: Bool, _ label: String) {
        print("\(value ? "PASS" : "FAIL") \(label)")
        if !value { failures += 1 }
    }
    @MainActor static func wait(_ seconds: Double = 4, until condition: () -> Bool) async -> Bool {
        let end = Date().addingTimeInterval(seconds)
        while Date() < end {
            if condition() { return true }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return condition()
    }
    static func rejectedApplicationRequest(_ port: UInt16) async -> Bool {
        await withCheckedContinuation { continuation in
            let connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            let queue = DispatchQueue(label: "recovery.request")
            var finished = false
            let finish: (Bool) -> Void = { value in
                guard !finished else { return }; finished = true
                connection.cancel(); continuation.resume(returning: value)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: Data("CONNECT forbidden.invalid:443 HTTP/1.1\r\n\r\n".utf8), completion: .contentProcessed { _ in
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, done, error in
                            finish(data.map { String(decoding: $0, as: UTF8.self).contains("403") } ?? (done || error != nil))
                        }
                    })
                case .failed, .waiting: finish(true)
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 2) { finish(false) }
        }
    }

    static func localHTTPRequest(relay: UInt16, target: UInt16) async -> (Int32, String) {
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                let child = Process(); child.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                child.arguments = ["-q", "--silent", "--fail", "--max-time", "3", "--noproxy", "",
                                   "--proxy", "http://127.0.0.1:\(relay)", "--proxytunnel", "http://127.0.0.1:\(target)/"]
                let output = Pipe(); child.standardOutput = output; child.standardError = FileHandle.nullDevice
                do {
                    try child.run(); let data = output.fileHandleForReading.readDataToEndOfFile(); child.waitUntilExit()
                    continuation.resume(returning: (child.terminationStatus, String(decoding: data, as: UTF8.self)))
                } catch { continuation.resume(returning: (-1, "")) }
            }
        }
    }

    @MainActor static func verifyCurrentNetworkTransport() async {
        do {
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
            let listener = try NWListener(using: parameters, on: .any)
            let queue = DispatchQueue(label: "recovery.http-fixture")
            listener.newConnectionHandler = { connection in
                connection.stateUpdateHandler = { state in
                    if case .ready = state {
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { _, _, _, _ in
                            connection.send(content: Data("HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\ncurrent-route-ok".utf8), completion: .contentProcessed { _ in connection.cancel() })
                        }
                    }
                }
                connection.start(queue: queue)
            }
            let target: UInt16 = await withCheckedContinuation { continuation in
                let readiness = ListenerState()
                listener.stateUpdateHandler = { state in
                    guard !readiness.finished else { return }
                    if case .ready = state, let port = listener.port?.rawValue { readiness.finished = true; continuation.resume(returning: port) }
                    else if case .failed = state { readiness.finished = true; continuation.resume(returning: 0) }
                }
                listener.start(queue: queue)
            }
            defer { listener.cancel() }
            guard target != 0 else { expect(false, "local current-network fixture starts"); return }
            let relay = SOCKSRelay(currentNetwork: true); let gate = try await relay.start()
            defer { relay.stop() }
            let blocked = await localHTTPRequest(relay: gate, target: target)
            expect(blocked.0 != 0, "current-network gate rejects destination before verification")
            expect(relay.unlock(), "current-network gate unlocks explicitly")
            let forwarded = await localHTTPRequest(relay: gate, target: target)
            expect(forwarded.0 == 0 && forwarded.1 == "current-route-ok", "current-network CONNECT forwards through the selected local gate")
            relay.pause()
            let paused = await localHTTPRequest(relay: gate, target: target)
            expect(paused.0 != 0, "paused current-network gate rejects destination without direct fallback")
        } catch { expect(false, "current-network transport setup: \(error.localizedDescription)") }
    }

    @MainActor static func verifyPersistentIP(root: URL) async {
        let file = root.appendingPathComponent("persistent-ip/ip-memory.json")
        let memory = IPMemory(url: file)
        func saved() -> String? {
            do { return try memory.load() }
            catch { expect(false, "expected readable IP memory"); return "[unreadable]" }
        }
        func model(_ address: String) -> GuardModel {
            let value = GuardModel(diagnosticsURL: root.appendingPathComponent(UUID().uuidString + ".jsonl"), ipMemoryURL: file)
            value.e2eRuntimeRoot = root; value.useProxy = false; value.interval = 30
            value.e2eSystemProxyCapture = { try SystemProxy.parse("<dictionary> {\n}") }
            value.e2eCapturedPin = SOCKSRelay.LocalPin(v4: "192.0.2.10", v6: nil)
            value.timezone = "Europe/Amsterdam"; value.language = "en-US"
            value.e2eInitialCheck = { _ in IPReport(ip: address, countryCode: "NL", country: "NL", date: Date()) }
            value.e2ePublicCheck = { _ in address }
            return value
        }
        let first = model("203.0.113.7")
        first.check(andLaunch: false)
        expect(await wait { first.allowed }, "first fully checked session is admitted")
        expect(saved() == "203.0.113.7", "first checked IP is saved before traffic is allowed")
        expect(!first.canResetIP, "reset is unavailable during an active session")
        first.resetIP(); expect(saved() == "203.0.113.7", "active reset cannot delete the saved pin")
        first.stop(); expect(first.canResetIP, "reset becomes available after stop")
        expect(saved() == "203.0.113.7", "manual stop preserves the saved IP")
        let same = model("203.0.113.7"); same.check(andLaunch: false)
        expect(await wait { same.allowed }, "new model accepts the same saved IP"); same.stop()
        let changed = model("203.0.113.8"); changed.check(andLaunch: false)
        expect(await wait { changed.requiresRestart }, "new model rejects another foreign IP across restarts")
        expect(!changed.allowed && changed.e2eRelayPort == nil, "mismatch closes the relay before any launch")
        expect(saved() == "203.0.113.7", "rejected IP cannot overwrite stored memory")
        changed.resetIP(); expect(saved() == nil && changed.requiresRestart, "explicit reset clears memory but cannot reopen a latched session")
        let reset = model("203.0.113.8"); reset.check(andLaunch: false)
        expect(await wait { reset.allowed }, "a fresh session may pin another IP after explicit reset"); reset.stop()
        try? memory.reset()
        let split = model("203.0.113.7")
        split.e2eDestinationCheck = { _ in ("203.0.113.9", "NL") }
        split.check(andLaunch: false)
        expect(await wait { split.requiresRestart }, "a different destination exit blocks the session")
        expect(saved() == nil, "split route cannot save a first pin")
        try? Data("{broken".utf8).write(to: file)
        let corrupt = model("203.0.113.7"); var checked = false
        corrupt.e2eInitialCheck = { _ in checked = true; throw GuardError.message("unexpected probe") }
        corrupt.check(andLaunch: false)
        expect(await wait { !corrupt.busy } && !checked && !corrupt.allowed, "invalid memory blocks before a network probe")
        corrupt.resetIP(); expect(saved() == nil, "explicit reset recovers a damaged memory file")
        for value in [first, same, changed, reset, split, corrupt] { value.shutdown() }
    }

    @MainActor static func main() async {
        signal(SIGPIPE, SIG_IGN)
        await verifyCurrentNetworkTransport()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("Guard-recovery-" + UUID().uuidString)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        await verifyPersistentIP(root: root)
        let model = GuardModel(diagnosticsURL: root.appendingPathComponent("diagnostics.jsonl"))
        model.e2eRuntimeRoot = root // Prevent writing actual preferences.
        model.e2eSystemProxyCapture = { try SystemProxy.parse("<dictionary> {\n}") }
        model.useProxy = false; model.interval = 30; model.watchPublicIP = true
        model.e2eCapturedPin = SOCKSRelay.LocalPin(v4: "192.0.2.10", v6: nil)
        model.timezone = "Europe/Amsterdam"; model.language = "en-US"
        model.e2eInitialCheck = { _ in IPReport(ip: "203.0.113.7", countryCode: "NL", country: "NL", date: Date()) }
        var failProbe = false
        var observedIP = "203.0.113.7"
        var holdProbe = false
        var pending: CheckedContinuation<String, Error>?
        var checks = 0
        model.e2ePublicCheck = { _ in
            checks += 1
            if holdProbe { return try await withCheckedThrowingContinuation { pending = $0 } }
            if failProbe { throw GuardError.message("Controlled transient IP-service failure") }
            return observedIP
        }
        defer { model.shutdown() }
        model.check(andLaunch: false)
        expect(await wait { model.allowed && model.monitoring }, "current-network model establishes a foreign pinned IP through its relay")
        guard let port = model.e2eRelayPort else { exit(1) }

        failProbe = true
        model.e2eVerifyNow()
        expect(await wait { model.e2eSuspended && !model.allowed }, "transient service error alone suspends application traffic")
        expect(!model.requiresRestart && model.monitoring, "transient failure preserves the session without a permanent lock")
        expect(await rejectedApplicationRequest(port), "application CONNECT is rejected while verification is unavailable")
        failProbe = false
        expect(await wait { model.allowed && !model.e2eSuspended }, "successful retry of unchanged IP resumes the same session")
        expect(model.e2eRelayPort == port && !model.requiresRestart, "recovery retains the relay and has no false IP-change latch")
        model.e2eNetworkChanged()
        expect(model.e2eSuspended && !model.allowed, "local route event immediately suspends traffic before checking IP")
        expect(await wait { model.allowed && !model.e2eSuspended }, "same IP after a route event resumes without closing the session")

        model.e2ePowerChanged(sleeping: true)
        let beforeSleep = checks
        try? await Task.sleep(nanoseconds: 150_000_000)
        expect(model.e2eSuspended && !model.allowed && checks == beforeSleep, "sleep closes the gate without probing or killing the session")
        model.e2ePowerChanged(sleeping: false)
        expect(await wait { model.allowed && !model.e2eSuspended }, "wake resumes only after the unchanged IP is verified")

        holdProbe = true
        model.e2eNetworkChanged()
        expect(await wait { pending != nil }, "route verification can be held in flight")
        model.stop()
        holdProbe = false
        pending?.resume(returning: "203.0.113.7"); pending = nil
        try? await Task.sleep(nanoseconds: 150_000_000)
        expect(!model.allowed && !model.monitoring && model.e2eRelayPort == nil, "late successful reply cannot reopen a stopped session")

        model.check(andLaunch: false)
        expect(await wait { model.allowed }, "fresh manually stopped session establishes normally")
        holdProbe = true
        model.e2eNetworkChanged()
        expect(await wait { pending != nil }, "first route response is delayed for revision test")
        model.e2eNetworkChanged()
        holdProbe = false; observedIP = "203.0.113.8"
        pending?.resume(returning: "203.0.113.7"); pending = nil
        expect(await wait { model.requiresRestart }, "stale response cannot reopen the gate after a newer route event; changed IP latches")
        expect(!model.allowed && !model.monitoring && model.e2eRelayPort == nil, "confirmed changed IP closes the relay and requires restart")
        model.stop(); model.check(andLaunch: false)
        expect(model.requiresRestart && !model.allowed, "manual stop cannot clear the confirmed IP-change lock")
        let proxyModel = GuardModel(diagnosticsURL: root.appendingPathComponent("proxy-diagnostics.jsonl"))
        proxyModel.e2eRuntimeRoot = root; proxyModel.useProxy = false
        proxyModel.watchPublicIP = true
        proxyModel.e2eInitialCheck = { _ in IPReport(ip: "203.0.113.7", countryCode: "NL", country: "NL", date: Date()) }
        proxyModel.e2ePublicCheck = { _ in "203.0.113.7" }
        var proxyHost = "first.example"
        var proxyReadFails = false
        proxyModel.e2eSystemProxyCapture = {
            if proxyReadFails { throw GuardError.message("Тестовая ошибка чтения прокси") }
            return try SystemProxy.parse("<dictionary> {\nSOCKSEnable : 1\nSOCKSProxy : \(proxyHost)\nSOCKSPort : 1080\n}")
        }
        defer { proxyModel.shutdown() }
        proxyModel.check(andLaunch: false)
        expect(await wait { proxyModel.allowed }, "static system proxy is pinned at session start")
        proxyReadFails = true; proxyModel.e2eVerifyNow()
        expect(await wait { proxyModel.e2eSuspended && !proxyModel.allowed }, "proxy read failure pauses traffic for revalidation")
        expect(!proxyModel.requiresRestart, "proxy read failure does not latch a confirmed change")
        proxyReadFails = false
        expect(await wait { proxyModel.allowed }, "unchanged proxy after read recovery resumes traffic")
        proxyHost = "second.example"; proxyModel.e2eVerifyNow()
        expect(await wait { proxyModel.requiresRestart }, "changed pinned proxy fingerprint requires restart")
        expect(!proxyModel.allowed && !proxyModel.monitoring && proxyModel.e2eRelayPort == nil, "confirmed proxy change closes the session relay")
        proxyModel.stop(); proxyModel.check(andLaunch: false)
        expect(proxyModel.requiresRestart && !proxyModel.allowed, "manual stop cannot clear the proxy-change latch")

        // PG-01: without an active packet-filter barrier the session must fail closed.
        let barrierModel = GuardModel(diagnosticsURL: root.appendingPathComponent("barrier-diagnostics.jsonl"))
        barrierModel.e2eRuntimeRoot = root; barrierModel.useProxy = false
        barrierModel.e2eSystemProxyCapture = { try SystemProxy.parse("<dictionary> {\n}") }
        barrierModel.e2eInitialCheck = { _ in IPReport(ip: "203.0.113.7", countryCode: "NL", country: "NL", date: Date()) }
        barrierModel.e2ePublicCheck = { _ in "203.0.113.7" }
        barrierModel.e2eCapturedPin = SOCKSRelay.LocalPin(v4: "192.0.2.10", v6: nil)
        barrierModel.e2eBarrierProbe = .missing
        defer { barrierModel.shutdown() }
        barrierModel.check(andLaunch: false)
        expect(await wait { !barrierModel.busy }, "barrier gate finishes without hanging")
        expect(!barrierModel.allowed && !barrierModel.monitoring && barrierModel.e2eRelayPort == nil,
               "missing network barrier blocks the session before any relay opens")
        expect(barrierModel.detail.contains("Сетевой барьер не активен"), "barrier refusal explains the missing installation")
        barrierModel.e2eBarrierProbe = .active
        barrierModel.check(andLaunch: false)
        expect(await wait { barrierModel.allowed && barrierModel.barrierArmed }, "active barrier admits the session and arms the launch chain")
        barrierModel.e2eBarrierProbe = .broken("тестовое отключение")
        barrierModel.e2eVerifyNow()
        expect(await wait { !barrierModel.allowed && barrierModel.e2eSuspended },
               "losing the barrier mid-session suspends traffic like a route change")
        print("RECOVERY TESTS: \(failures) failures")
        exit(failures == 0 ? 0 : 1)
    }
}
