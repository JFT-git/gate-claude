import Foundation
import Network

@main struct RelayTests {
    static var failures = 0
    static func expect(_ value: @autoclosure () -> Bool, _ label: String) {
        if value() { print("PASS \(label)") } else { print("FAIL \(label)"); failures += 1 }
    }
    static func rejected(_ label: String, _ body: () throws -> Void) {
        do { try body(); expect(false, label) } catch { expect(true, label) }
    }
    static func request(_ port: UInt16, host: String, destinationPort: UInt16 = 443, token: String? = nil) async -> (Int32, String) {
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                p.arguments = ["-q", "--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "",
                               "--proxy", "http://127.0.0.1:\(port)", "--proxytunnel", "http://\(host):\(destinationPort)/"]
                if let token { p.arguments! += ["--proxy-header", "Proxy-Authorization: Bearer \(token)"] }
                let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
                do {
                    try p.run(); let data = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
                    continuation.resume(returning: (p.terminationStatus, String(decoding: data, as: UTF8.self)))
                } catch { continuation.resume(returning: (-1, "")) }
            }
        }
    }
    static func main() async {
        let json = { (code: String, ip: String) in Data("{\"success\":true,\"ip\":\"\(ip)\",\"country_code\":\"\(code)\"}".utf8) }
        do {
            let good = try IPReport.parse(json("DE", "203.0.113.7")); try good.requireForeign()
            expect(good.countryCode == "DE", "foreign country accepted")
        } catch { expect(false, "foreign country accepted") }
        rejected("RU blocked") { try IPReport.parse(json("RU", "203.0.113.7")).requireForeign() }
        rejected("unknown country blocked") { _ = try IPReport.parse(json("ZZ", "203.0.113.7")) }
        rejected("invalid IP blocked") { _ = try IPReport.parse(json("DE", "garbage")) }
        rejected("API error blocked") { _ = try IPReport.parse(Data("{\"success\":false}".utf8)) }
        rejected("missing country blocked") { _ = try IPReport.parse(Data("{\"success\":true,\"ip\":\"8.8.8.8\"}".utf8)) }
        rejected("malformed JSON blocked") { _ = try IPReport.parse(Data("<html>error</html>".utf8)) }
        do { _ = try IPReport.parse(json("NL", "2001:db8::7")); expect(true, "IPv6 report supported") }
        catch { expect(false, "IPv6 report supported") }
        expect(IPChecker.publicIPURL(for: "203.0.113.7").contains("api.ipify.org"), "IPv4 session uses the dedicated IPv4 probe")
        expect(IPChecker.publicIPURL(for: "2001:db8::7").contains("api6.ipify.org"), "IPv6 session keeps its family instead of alternating dual-stack probes")
        rejected("URL as proxy host rejected") { _ = try ProxySettings.validated(host: "socks5://host", port: "1080", username: "", password: "") }
        rejected("zero proxy port rejected") { _ = try ProxySettings.validated(host: "host", port: "0", username: "", password: "") }
        rejected("oversized password rejected") { _ = try ProxySettings.validated(host: "host", port: "1080", username: "user", password: String(repeating: "x", count: 256)) }
        rejected("password without login rejected") { _ = try ProxySettings.validated(host: "host", port: "1080", username: "", password: "secret") }
        do {
            let report = try IPReport.parse(json("NL", "203.0.113.7"))
            var policy = SessionPolicy(); try policy.establish(report); try policy.verify("203.0.113.7")
            expect(!policy.requiresRestart, "identical pinned IP stays open")
            policy.suspend()
            expect(policy.suspended && !policy.requiresRestart, "temporary uncertainty pauses without permanent IP lock")
            try policy.verify("203.0.113.7")
            expect(!policy.suspended && !policy.requiresRestart, "same verified IP resumes a paused session")
            rejected("any new IP blocked, including another foreign IP") { try policy.verify("203.0.113.8") }
            expect(policy.requiresRestart, "IP change latches until app restart")
            policy.manualStop()
            rejected("manual stop cannot reset the security latch") { try policy.establish(report) }
            var fresh = SessionPolicy(); try fresh.establish(report)
            expect(!fresh.requiresRestart, "new app session can establish a new baseline")
            var local = SessionPolicy(); try local.establish(report); local.latch("Local address changed")
            rejected("explicit permanent security lock requires restart") { try local.verify(report.ip) }
            let equivalent = try IPIdentity.canonical("2001:db8:0:0::7") == IPIdentity.canonical("2001:db8::7")
            expect(equivalent, "equivalent IPv6 strings do not cause false change")
            let profile = LaunchProfile(timezone: "Europe/Amsterdam", language: "en-US")
            try profile.validate()
            expect(profile.environment(["TZ": "Europe/Moscow"])["TZ"] == "Europe/Amsterdam", "process timezone override replaces Moscow")
            expect(profile.arguments.contains("--lang=en-US") && profile.arguments.contains("(en-US)"), "Chromium and native language launch arguments present")
        } catch { expect(false, "session policy setup") }
        let trace = "h=claude.ai\nip=203.0.113.7\nloc=DE\n"
        do {
            let result = try IPChecker.parseDestinationTrace(Data(trace.utf8), hostname: "claude.ai", family: 4)
            expect(result.ip == "203.0.113.7" && result.countryCode == "DE", "valid destination trace")
            var policy = SessionPolicy()
            try policy.establish(IPReport.parse(json("DE", "203.0.113.1")))
            try policy.verifyDestination(hostname: "claude.ai", ip: result.ip, countryCode: result.countryCode)
            rejected("destination IP change rejected") { try policy.verifyDestination(hostname: "claude.ai", ip: "203.0.113.8", countryCode: "DE") }
            expect(policy.requiresRestart, "destination change latches like main IP")
        } catch { expect(false, "destination policy setup") }
        for (label, body) in [("bad h", trace.replacingOccurrences(of: "h=claude.ai", with: "h=example.com")),
                              ("mapped IP", trace.replacingOccurrences(of: "203.0.113.7", with: "::ffff:203.0.113.7")),
                              ("duplicate key", trace + "ip=203.0.113.7\n"), ("non ASCII", trace + "x=я\n"), ("invalid line", trace + "invalid\n")] {
            rejected("trace rejects \(label)") { _ = try IPChecker.parseDestinationTrace(Data(body.utf8), hostname: "claude.ai", family: 4) }
        }
        guard CommandLine.arguments.count > 1, let upstreamPort = UInt16(CommandLine.arguments[1]) else { exit(2) }
        do {
            // A direct HTTP fixture, separate from run.py's authenticated SOCKS server.
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
            let fixture = try NWListener(using: parameters, on: .any)
            let fixtureQueue = DispatchQueue(label: "tests.direct-fixture")
            fixture.newConnectionHandler = { connection in
                connection.start(queue: fixtureQueue)
                connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                    connection.send(content: Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".utf8),
                                    completion: .contentProcessed { _ in connection.cancel() })
                }
            }
            let fixturePort: UInt16 = try await withCheckedThrowingContinuation { continuation in
                fixture.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        fixture.stateUpdateHandler = nil
                        continuation.resume(returning: fixture.port!.rawValue)
                    case .failed(let error):
                        fixture.stateUpdateHandler = nil
                        continuation.resume(throwing: error)
                    default: break
                    }
                }
                fixture.start(queue: fixtureQueue)
            }
            defer { fixture.cancel() }
            let direct = SOCKSRelay(currentNetwork: true)
            let directPort = try await direct.start()
            direct.setPinnedFamily(.v4)
            expect(direct.unlock(), "current-network bridge unlocks with pinned IPv4")
            let directV4 = await request(directPort, host: "127.0.0.1", destinationPort: fixturePort)
            expect(directV4.0 == 0 && directV4.1 == "ok", "pinned IPv4 permits literal 127.0.0.1")
            let deniedV6 = await request(directPort, host: "[::1]", destinationPort: fixturePort)
            expect(deniedV6.0 != 0, "pinned IPv4 refuses literal ::1")
            direct.setPinnedFamily(.v6)
            let deniedV4 = await request(directPort, host: "127.0.0.1", destinationPort: fixturePort)
            expect(deniedV4.0 != 0, "pinned IPv6 refuses literal 127.0.0.1")
            direct.stop()

            let relay = SOCKSRelay(settings: ProxySettings(host: "127.0.0.1", port: upstreamPort, username: "user", password: "secret"))
            let port = try await relay.start()
            let denied = await request(port, host: "destination.test")
            expect(denied.0 != 0, "arbitrary destination blocked before verification")
            let probe = await request(port, host: "ipwho.is", token: relay.checkToken)
            expect(probe.0 == 0 && probe.1 == "ok:ipwho.is", "probe uses authenticated SOCKS and remote hostname")
            expect(relay.unlock(), "verified bridge unlocks")
            let allowed = await request(port, host: "destination.test")
            expect(allowed.0 == 0 && allowed.1 == "ok:destination.test", "HTTPS CONNECT bytes forwarded after unlock")

            // Hold an established tunnel open, then prove stop disconnects it.
            let client = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            let queue = DispatchQueue(label: "tests.client")
            let connected: Bool = await withCheckedContinuation { continuation in
                var resumed = false
                let finish: (Bool) -> Void = { value in if !resumed { resumed = true; continuation.resume(returning: value) } }
                client.stateUpdateHandler = { state in
                    if case .ready = state {
                        client.send(content: Data("CONNECT hold.test:443 HTTP/1.1\r\nHost: hold.test\r\n\r\n".utf8), completion: .contentProcessed { _ in
                            client.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, _, _ in
                                finish(data.map { String(decoding: $0, as: UTF8.self).contains("200") } ?? false)
                            }
                        })
                    } else if case .failed = state { finish(false) }
                }
                client.start(queue: queue)
                queue.asyncAfter(deadline: .now() + 5) { finish(false) }
            }
            expect(connected, "long-lived tunnel established")
            let control = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            let controlReady: Bool = await withCheckedContinuation { continuation in
                control.stateUpdateHandler = { state in
                    if case .ready = state {
                        control.send(content: Data("CONNECT claude.ai:443 HTTP/1.1\r\nProxy-Authorization: Bearer \(relay.checkToken)\r\n\r\n".utf8), completion: .contentProcessed { _ in
                            control.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                                continuation.resume(returning: data.map { String(decoding: $0, as: UTF8.self).contains("200") } ?? false)
                            }
                        })
                    }
                }
                control.start(queue: queue)
            }
            expect(controlReady, "authenticated control tunnel established")
            relay.pause()
            let controlSurvived: Bool = await withCheckedContinuation { continuation in
                control.send(content: Data("GET /cdn-cgi/trace HTTP/1.1\r\nHost: claude.ai\r\n\r\n".utf8), completion: .contentProcessed { _ in
                    control.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                        continuation.resume(returning: data.map { String(decoding: $0, as: UTF8.self).contains("h=claude.ai") } ?? false)
                    }
                })
            }
            expect(controlSurvived, "control tunnel survives pause and receives destination trace")
            control.cancel()
            let disconnected: Bool = await withCheckedContinuation { continuation in
                client.receive(minimumIncompleteLength: 1, maximumLength: 1024) { _, _, done, error in continuation.resume(returning: done || error != nil) }
            }
            expect(disconnected, "pause closes already established tunnels")
            client.cancel()
            let duringPause = await request(port, host: "blocked-during-pause.test")
            expect(duringPause.0 != 0, "paused bridge blocks application destinations")
            let unauthenticated = await request(port, host: "ipwho.is")
            expect(unauthenticated.0 != 0, "paused relay refuses unauthenticated probe")
            let pausedProbe = await request(port, host: "ipwho.is", token: relay.checkToken)
            expect(pausedProbe.0 == 0, "paused bridge still permits IP-control probes")
            expect(relay.unlock(), "paused bridge can resume after successful IP verification")
            let resumed = await request(port, host: "resumed.test")
            expect(resumed.0 == 0 && resumed.1 == "ok:resumed.test", "resumed bridge forwards fresh application requests")
            relay.stop()
            let afterStop = await request(port, host: "destination.test")
            expect(afterStop.0 != 0, "stopped bridge refuses new connections")
            expect(!relay.unlock(), "stopped bridge cannot reopen without new check")

            let resetRelay = SOCKSRelay(settings: ProxySettings(host: "127.0.0.1", port: upstreamPort, username: "user", password: "secret"))
            let resetPort = try await resetRelay.start()
            expect(resetRelay.unlock(), "reset scenario opens a verified bridge")
            let reset = await request(resetPort, host: "reset.test")
            expect(reset.0 != 0, "destination reset closes its own request")
            try await Task.sleep(nanoseconds: 200_000_000)
            let recovery = await request(resetPort, host: "recovery.test")
            expect(recovery.0 == 0 && recovery.1 == "ok:recovery.test", "destination reset does not kill unrelated proxy connections")
            let refused = await request(resetPort, host: "refused.test")
            expect(refused.0 != 0, "SOCKS destination refusal closes the rejected request")
            let afterRefusal = await request(resetPort, host: "after-refusal.test")
            expect(afterRefusal.0 == 0, "SOCKS destination refusal leaves other destinations usable")
            let interrupted = await request(resetPort, host: "aborted-before-reply.test")
            expect(interrupted.0 != 0, "interrupted SOCKS setup closes its own pending request")
            let suspended = await request(resetPort, host: "must-wait-for-probe.test")
            expect(suspended.0 != 0, "SOCKS transport failure pauses new application requests")
            let healthyProbe = await request(resetPort, host: "ipwho.is", token: resetRelay.checkToken)
            expect(healthyProbe.0 == 0 && resetRelay.unlock(), "successful control probe can recover the paused SOCKS transport")
            let afterTransportRecovery = await request(resetPort, host: "after-transport-recovery.test")
            expect(afterTransportRecovery.0 == 0, "recovered SOCKS transport accepts fresh application streams")
            resetRelay.stop()

            let wrong = SOCKSRelay(settings: ProxySettings(host: "127.0.0.1", port: upstreamPort, username: "user", password: "wrong"))
            let wrongPort = try await wrong.start()
            let invalidAuth = await request(wrongPort, host: "ipwho.is", token: wrong.checkToken)
            expect(invalidAuth.0 != 0, "wrong SOCKS password fails closed")
            expect(!wrong.unlock(), "authentication fault cannot unlock bridge")
            wrong.stop()

            let dead = SOCKSRelay(settings: ProxySettings(host: "127.0.0.1", port: 1, username: "", password: ""))
            let deadPort = try await dead.start()
            let unavailable = await request(deadPort, host: "ipwho.is", token: dead.checkToken)
            expect(unavailable.0 != 0 && !dead.unlock(), "unreachable SOCKS never falls back to direct")
            dead.stop()
        } catch { print("Unexpected error: \(error)"); failures += 1 }
        print("\(failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED") · \(failures) failures")
        exit(failures == 0 ? 0 : 1)
    }
}
