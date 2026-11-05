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
        let initialTransient = model("203.0.113.7")
        initialTransient.e2ePublicCheck = { _ in throw GuardError.message("controlled initial probe failure") }
        initialTransient.check(andLaunch: false)
        expect(await wait { !initialTransient.busy } && !initialTransient.monitoring && initialTransient.e2eRelayPort == nil,
               "initial pin failure blocks immediately without entering freeze recovery")
        try? Data("{broken".utf8).write(to: file)
        let corrupt = model("203.0.113.7"); var checked = false
        corrupt.e2eInitialCheck = { _ in checked = true; throw GuardError.message("unexpected probe") }
        corrupt.check(andLaunch: false)
        expect(await wait { !corrupt.busy } && !checked && !corrupt.allowed, "invalid memory blocks before a network probe")
        corrupt.resetIP(); expect(saved() == nil, "explicit reset recovers a damaged memory file")
        for value in [first, same, changed, reset, split, initialTransient, corrupt] { value.shutdown() }
    }

    final class FrozenFixture {
        var now: TimeInterval = 100
        var signals: [Int32] = []
        var failSignal: Int32?
        var ip = "203.0.113.7"
        var failProbe = false
        var holdProbe = false
        var pending: CheckedContinuation<String, Error>?
        var sample: RuntimeProcessSample?

        func identity() -> RuntimeIdentity {
            RuntimeIdentity(ownerPID: 50, ownerUID: 501, pid: 400, pgid: 400, startTime: 1234,
                            path: "/tmp/guard-model/Claude.app", frozen: false)
        }

        func system() -> ProcessSystem {
            sample = RuntimeProcessSample(uid: 501, pgid: 400, startTime: 1234,
                                          path: "/tmp/guard-model/Claude.app/Contents/MacOS/Claude")
            var system = ProcessSystem()
            system.currentPID = { 50 }
            system.currentUID = { 501 }
            system.currentPGID = { 100 }
            system.barrierGID = { 380 }
            system.sample = { [weak self] _ in self?.sample }
            system.members = { [weak self] _ in self?.sample == nil ? [] : [400] }
            system.send = { [weak self] pid, signal in
                guard let self else { return false }
                self.signals.append(signal)
                return self.failSignal != signal && pid == -400
            }
            system.exists = { _ in false }
            return system
        }
    }

    @MainActor static func frozenModel(root: URL, fixture: FrozenFixture, name: String) async -> GuardModel {
        let model = GuardModel(diagnosticsURL: root.appendingPathComponent(name + ".jsonl"),
                               processSystem: fixture.system(),
                               crashStoreURL: root.appendingPathComponent(name + "-crash.json"),
                               monotonicNow: { fixture.now })
        model.e2eRuntimeRoot = root; model.useProxy = false; model.interval = 30
        model.e2eSystemProxyCapture = { try SystemProxy.parse("<dictionary> {\n}") }
        model.e2eCapturedPin = SOCKSRelay.LocalPin(v4: "192.0.2.10", v6: nil)
        model.e2eInitialCheck = { _ in IPReport(ip: "203.0.113.7", countryCode: "NL", country: "NL", date: Date()) }
        model.e2ePublicCheck = { _ in
            if fixture.holdProbe { return try await withCheckedThrowingContinuation { fixture.pending = $0 } }
            if fixture.failProbe { throw GuardError.message("controlled transient failure") }
            return fixture.ip
        }
        model.check(andLaunch: false)
        expect(await wait { model.allowed }, name + " starts a verified session")
        do { try model.e2eInstallRuntime(fixture.identity()) }
        catch { expect(false, name + " installs test runtime identity") }
        model.lastVerifiedProfile = VerifiedProfile(sessionID: "fixture", timezone: "Europe/Amsterdam",
                                                    language: "en-US", url: "https://claude.ai/", locale: "en-US")
        return model
    }

    @MainActor static func verifyProcessFreezing(root: URL) async {
        let earlyFixture = FrozenFixture()
        let early = await frozenModel(root: root, fixture: earlyFixture, name: "freeze-unverified")
        early.lastVerifiedProfile = nil
        earlyFixture.ip = "203.0.113.8"
        early.e2eVerifyNow()
        expect(await wait { early.requiresRestart }, "an unverified runtime IP mismatch remains an immediate block")
        expect(earlyFixture.signals == [SIGKILL] && early.processState == .stopped,
               "an unverified runtime is never frozen or allowed to resume")
        early.shutdown()

        let fixture = FrozenFixture()
        let model = await frozenModel(root: root, fixture: fixture, name: "freeze")
        fixture.failProbe = true
        model.e2eVerifyNow()
        expect(await wait { model.processState == .frozen }, "transient failure pauses relay then stops captured Claude group")
        expect(fixture.signals == [SIGSTOP] && model.e2eFreezeDeadline == 120 && model.freezeRemaining == 20,
               "freeze starts with one STOP and a fixed twenty-second deadline")
        fixture.now = 101
        model.e2eFreezeTick()
        expect(model.freezeRemaining == 19, "freeze countdown reports nineteen seconds after one second")
        model.e2eNetworkChanged()
        expect(model.e2eFreezeDeadline == 120 && fixture.signals == [SIGSTOP],
               "repeated failures neither extend deadline nor repeat STOP")
        fixture.failProbe = false
        expect(await wait { model.allowed && model.processState == .running },
               "full validation unlocks relay then resumes Claude")
        expect(fixture.signals == [SIGSTOP, SIGCONT] && model.freezeRemaining == nil,
               "successful validation sends identity-checked CONT and clears freeze state")

        fixture.failProbe = true
        model.e2eVerifyNow()
        expect(await wait { model.processState == .frozen }, "second transient failure freezes the same runtime")
        fixture.failProbe = false; fixture.holdProbe = true
        expect(await wait { fixture.pending != nil }, "late-response fixture holds revalidation in flight")
        model.stop()
        let stoppedSignals = fixture.signals
        fixture.holdProbe = false
        fixture.pending?.resume(returning: fixture.ip); fixture.pending = nil
        try? await Task.sleep(nanoseconds: 150_000_000)
        expect(!model.allowed && !model.monitoring && fixture.signals == stoppedSignals,
               "stop invalidates generation and a late response cannot revive Claude")
        expect(stoppedSignals.last == SIGKILL && model.processState == .stopped,
               "manual stop kills a stopped security-session runtime without unverified continuation")
        model.shutdown()

        let timeoutFixture = FrozenFixture()
        let timeout = await frozenModel(root: root, fixture: timeoutFixture, name: "freeze-timeout")
        timeoutFixture.failProbe = true
        timeout.e2eVerifyNow()
        _ = await wait { timeout.processState == .frozen }
        timeoutFixture.now = 119
        timeout.e2eFreezeTick()
        expect(timeout.freezeRemaining == 1 && !timeoutFixture.signals.contains(SIGTERM),
               "nineteen seconds leaves one second without premature termination")
        timeoutFixture.failProbe = false; timeoutFixture.holdProbe = true
        _ = await wait { timeoutFixture.pending != nil }
        timeoutFixture.now = 120
        timeout.e2eFreezeTick()
        expect(timeoutFixture.signals == [SIGSTOP, SIGTERM, SIGCONT] && timeout.processState == .draining,
               "freeze timeout sends TERM then CONT and enters bounded graceful drain")
        timeoutFixture.holdProbe = false
        timeoutFixture.pending?.resume(returning: timeoutFixture.ip); timeoutFixture.pending = nil
        try? await Task.sleep(nanoseconds: 150_000_000)
        expect(!timeout.allowed && !timeout.monitoring && !timeout.claudeRunning,
               "late validation after timeout cannot reopen relay or runtime")
        timeout.shutdown()
        expect(timeoutFixture.signals.last == SIGKILL && timeout.processState == .stopped,
               "shutdown finishes freeze drain with SIGKILL and normal cleanup")

        let gracefulFixture = FrozenFixture()
        let graceful = await frozenModel(root: root, fixture: gracefulFixture, name: "freeze-stop")
        graceful.e2eBarrierProbe = .active
        graceful.barrierArmed = true
        gracefulFixture.failProbe = true
        graceful.e2eVerifyNow()
        _ = await wait { graceful.processState == .frozen }
        graceful.stop()
        expect(gracefulFixture.signals == [SIGSTOP, SIGCONT, SIGTERM],
               "graceful stop continues a verified frozen group before TERM")
        gracefulFixture.sample = nil
        graceful.shutdown()
        expect(graceful.processState == .stopped, "shutdown completes stopped-process drain state")

        let mismatchFixture = FrozenFixture()
        let mismatch = await frozenModel(root: root, fixture: mismatchFixture, name: "freeze-mismatch")
        mismatchFixture.ip = "203.0.113.8"
        mismatch.e2eVerifyNow()
        expect(await wait { mismatch.processState == .frozen }, "post-verification IP mismatch enters the fixed freeze window")
        expect(mismatchFixture.signals == [SIGSTOP] && !mismatch.requiresRestart,
               "IP mismatch pauses and stops without an immediate permanent latch")
        mismatchFixture.ip = "203.0.113.7"
        expect(await wait { mismatch.allowed && mismatch.processState == .running },
               "returning to the pinned IP during the window resumes the same runtime")
        expect(mismatchFixture.signals == [SIGSTOP, SIGCONT], "IP mismatch recovery unlocks then continues once")
        mismatch.shutdown()

        let ruFixture = FrozenFixture()
        let ru = await frozenModel(root: root, fixture: ruFixture, name: "freeze-ru")
        ru.e2eDestinationCheck = { _ in ("203.0.113.7", "RU") }
        ru.e2eVerifyNow()
        expect(await wait { ru.requiresRestart }, "RU route remains an immediate block")
        expect(ruFixture.signals == [SIGKILL] && ru.processState == .stopped,
               "RU route kills immediately without freeze recovery")

        let barrierFixture = FrozenFixture()
        let barrier = await frozenModel(root: root, fixture: barrierFixture, name: "freeze-barrier")
        barrier.e2eBarrierProbe = .active
        barrier.barrierArmed = true
        barrier.e2eBarrierProbe = .broken("controlled barrier loss")
        barrier.e2eVerifyNow()
        expect(await wait { barrier.requiresRestart }, "barrier loss remains an immediate block")
        expect(barrierFixture.signals == [SIGKILL] && barrier.processState == .stopped,
               "barrier loss kills stopped or running runtime without freeze delay")

        let signalFixture = FrozenFixture()
        let signalFailure = await frozenModel(root: root, fixture: signalFixture, name: "freeze-signal")
        signalFixture.failProbe = true
        signalFixture.failSignal = SIGSTOP
        signalFailure.e2eVerifyNow()
        expect(await wait { signalFailure.requiresRestart }, "STOP signal failure blocks the session")
        expect(signalFailure.processState == .stopped && !signalFailure.allowed,
               "signal failure cannot leave an apparently frozen active session")
    }

    @MainActor static func main() async {
        signal(SIGPIPE, SIG_IGN)
        await verifyCurrentNetworkTransport()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("Guard-recovery-" + UUID().uuidString)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        await verifyPersistentIP(root: root)
        await verifyProcessFreezing(root: root)
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
        expect(await wait { proxyModel.requiresRestart && !proxyModel.allowed }, "proxy read failure immediately closes the verified session")
        expect(!proxyModel.monitoring && proxyModel.e2eRelayPort == nil, "proxy channel failure closes the relay without freeze recovery")
        proxyReadFails = false
        proxyModel.e2eVerifyNow()
        expect(!proxyModel.allowed && proxyModel.requiresRestart, "proxy failure cannot be revived by a later successful read")

        let proxyChange = GuardModel(diagnosticsURL: root.appendingPathComponent("proxy-change-diagnostics.jsonl"))
        proxyChange.e2eRuntimeRoot = root; proxyChange.useProxy = false
        proxyChange.e2eInitialCheck = { _ in IPReport(ip: "203.0.113.7", countryCode: "NL", country: "NL", date: Date()) }
        proxyChange.e2ePublicCheck = { _ in "203.0.113.7" }
        proxyHost = "first.example"
        proxyChange.e2eSystemProxyCapture = {
            try SystemProxy.parse("<dictionary> {\nSOCKSEnable : 1\nSOCKSProxy : \(proxyHost)\nSOCKSPort : 1080\n}")
        }
        defer { proxyChange.shutdown() }
        proxyChange.check(andLaunch: false)
        expect(await wait { proxyChange.allowed }, "second static proxy session starts for mismatch coverage")
        proxyHost = "second.example"; proxyChange.e2eVerifyNow()
        expect(await wait { proxyChange.requiresRestart }, "changed pinned proxy fingerprint requires restart")
        expect(!proxyChange.allowed && !proxyChange.monitoring && proxyChange.e2eRelayPort == nil, "confirmed proxy change closes the session relay")
        proxyChange.stop(); proxyChange.check(andLaunch: false)
        expect(proxyChange.requiresRestart && !proxyChange.allowed, "manual stop cannot clear the proxy-change latch")

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
