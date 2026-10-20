import Foundation
import AppKit
import Network
import Darwin

@main struct InstalledE2E {
    static func command(_ inspector: ClaudeInspector, _ method: String, _ params: [String: Any] = [:], session: String? = nil) async throws -> [String: Any] {
        try await withCheckedThrowingContinuation { continuation in
            inspector.testCommand(method, params, session: session) { continuation.resume(with: $0) }
        }
    }
    @MainActor static func wait(_ seconds: Double, until predicate: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if predicate() { return true }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        return predicate()
    }
    static func refusesConnection(_ port: UInt16) async -> Bool {
        await withCheckedContinuation { continuation in
            let connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            let queue = DispatchQueue(label: "e2e.refusal")
            var finished = false
            let finish: (Bool) -> Void = { value in
                guard !finished else { return }; finished = true; connection.cancel(); continuation.resume(returning: value)
            }
            connection.stateUpdateHandler = { state in
                switch state { case .ready: finish(false); case .waiting, .failed: finish(true); default: break }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 2) { finish(true) }
        }
    }
    @MainActor static func main() async {
        signal(SIGPIPE, SIG_IGN)
        let args = CommandLine.arguments
        if args.count == 4, args[1] == "--restarted", args[2] == "--proof" {
            let fresh = SessionPolicy()
            let proof: [String: Any] = ["pid": getpid(), "freshPolicy": !fresh.requiresRestart && fresh.pinnedIP == nil,
                                        "passwordAbsent": !ProcessInfo.processInfo.environment.values.contains("restart-memory-secret")]
            try? JSONSerialization.data(withJSONObject: proof).write(to: URL(fileURLWithPath: args[3]), options: .atomic)
            return
        }
        _ = NSApplication.shared
        guard args.count == 7, let socksPort = UInt16(args[2]) else { exit(2) }
        let root = URL(fileURLWithPath: args[1])
        let model = GuardModel(diagnosticsURL: root.appendingPathComponent("guard-diagnostics.jsonl"))
        var observedIP = "203.0.113.7"
        model.useProxy = true; model.host = "127.0.0.1"; model.port = String(socksPort)
        model.username = ""; model.password = ""; model.interval = 2; model.watchPublicIP = true
        model.timezone = "Europe/Amsterdam"; model.language = "en-US"; model.captureBodies = true
        model.e2eInitialCheck = { _ in IPReport(ip: "203.0.113.7", countryCode: "NL", country: "Нидерланды", date: Date()) }
        model.e2ePublicCheck = { _ in observedIP }
        model.e2eRuntimeRoot = root.appendingPathComponent("Cache")
        model.e2eBootstrapURL = URL(fileURLWithPath: args[3])
        model.e2eSandboxURL = URL(fileURLWithPath: args[4])
        model.e2eStderrURL = root.appendingPathComponent("claude.stderr.log")
        model.e2eHelperURL = URL(fileURLWithPath: args[5])
        model.e2eExtraArguments = ["--use-mock-keychain", "--no-sandbox", "--disable-gpu", "--site-per-process"]
        var verifiedProfiles: [String: VerifiedProfile] = [:]
        model.e2eOnVerified = { verifiedProfiles[$0.sessionID] = $0 }
        var proof: [String: Any] = ["source": "/Applications/Claude.app", "test": "real installed runtime, isolated profile, local TLS fixture",
                                    "keychain": "mock cookie keychain; securityd and user Keychains denied by sandbox",
                                    "internet": "denied; loopback only", "observedIPSource": "controlled test-only provider; no physical WAN change"]
        let started = Date()
        defer { model.shutdown() }
        do {
            model.check(andLaunch: true)
            let ready = await wait(60) { model.lastVerifiedProfile?.url.hasPrefix("https://claude.ai/") == true || model.requiresRestart || (!model.busy && !model.monitoring) }
            guard ready, let initial = model.lastVerifiedProfile, let inspector = model.e2eInspector,
                  let relayPort = model.e2eRelayPort, let processID = model.e2eProcessID else {
                throw GuardError.message("Startup failed: \(model.phase): \(model.detail); \(model.profileStatus)")
            }
            print("PASS actual Claude renderer: \(initial.timezone), \(initial.language)")
            let shared = try await command(inspector, "ProxyGuard.testSharedLocale", ["targetSession": initial.sessionID])
            guard let inheritedSession = shared["secondSession"] as? String else { throw GuardError.message("Native shared-locale test returned no session") }
            let inheritedVerified = await wait(6) { verifiedProfiles[inheritedSession] != nil || model.requiresRestart }
            guard inheritedVerified, model.claudeRunning, !model.requiresRestart,
                  let inherited = verifiedProfiles[inheritedSession], inherited.locale == "en-US", inherited.language == "en-US", inherited.timezone == "Europe/Amsterdam",
                  shared["inherited"] as? Bool == true else { throw GuardError.message("Inherited locale not verified: \(model.detail)") }
            proof["sharedLocale"] = shared
            print("PASS native Chromium locale ownership conflict reproduced; bootstrap and another CDP agent verify inherited en-US")
            let churn = """
            (()=>{window.guardFixtureProfiles=[];window.guardFixtureDone=false;
            addEventListener('message',e=>{if(e.origin==='https://challenges.cloudflare.com'&&e.data.guardFixture)guardFixtureProfiles.push(e.data)});
            let i=0;function next(){if(i++===8){guardFixtureDone=true;return}const f=document.createElement('iframe');
            f.src='https://challenges.cloudflare.com/__guard_test__/frame?iteration='+i;
            f.onload=()=>setTimeout(()=>{f.remove();setTimeout(next,15)},30);document.body.append(f)}next();return true})()
            """
            _ = try await command(inspector, "Runtime.evaluate", ["expression": churn, "returnByValue": true], session: initial.sessionID)
            try await Task.sleep(nanoseconds: 2_000_000_000)
            guard model.claudeRunning, !model.requiresRestart else { throw GuardError.message("Iframe lifecycle stopped Claude: \(model.detail)") }
            let frames = try await command(inspector, "Runtime.evaluate", ["expression": "({done:window.guardFixtureDone,profiles:window.guardFixtureProfiles})", "returnByValue": true], session: initial.sessionID)
            guard let frameResult = frames["result"] as? [String: Any], let frameValue = frameResult["value"] as? [String: Any],
                  frameValue["done"] as? Bool == true, let profiles = frameValue["profiles"] as? [[String: Any]], profiles.count == 8,
                  profiles.allSatisfy({ $0["timezone"] as? String == "Europe/Amsterdam" && $0["language"] as? String == "en-US" && $0["locale"] as? String == "en-US" }) else {
                throw GuardError.message("Iframe profiles or lifecycle incomplete: \(frames)")
            }
            proof["iframeLifecycle"] = frameValue
            print("PASS eight cross-origin iframe replacements retain the profile and keep Claude running")
            _ = try await command(inspector, "ProxyGuard.testWindowLifecycle")
            try await Task.sleep(nanoseconds: 500_000_000)
            guard model.claudeRunning, !model.requiresRestart else { throw GuardError.message("Window lifecycle stopped Claude: \(model.detail)") }
            let windows = try await command(inspector, "ProxyGuard.testWindowStatus")
            guard windows["completed"] as? Int == 2 else { throw GuardError.message("Window lifecycle incomplete") }
            proof["auxiliaryWindowsClosed"] = 2
            print("PASS closing auxiliary windows does not terminate Claude")
            let expression = """
            (async()=>{const p={timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,locale:Intl.DateTimeFormat().resolvedOptions().locale};const r=await fetch('/__guard_test__/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});return {profile:p,response:await r.json()};})()
            """
            let result = try await command(inspector, "Runtime.evaluate", ["expression": expression, "awaitPromise": true, "returnByValue": true], session: initial.sessionID)
            guard let runtime = result["result"] as? [String: Any], let value = runtime["value"] as? [String: Any],
                  let profile = value["profile"] as? [String: Any], profile["timezone"] as? String == "Europe/Amsterdam",
                  profile["language"] as? String == "en-US", profile["locale"] as? String == "en-US" else {
                throw GuardError.message("Unexpected renderer result: \(result)")
            }
            proof["rendererProfile"] = value
            func capturedProfile(_ text: String) -> Bool {
                guard let data = text.data(using: .utf8), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
                return object["timezone"] as? String == "Europe/Amsterdam" && object["language"] as? String == "en-US"
            }
            let captured = await wait(8) {
                model.traffic.contains { $0.url == "https://claude.ai/__guard_test__/capture" && capturedProfile($0.sent) && $0.received.contains("guard-response-ok") }
            }
            guard captured, let record = model.traffic.first(where: { $0.url == "https://claude.ai/__guard_test__/capture" && $0.received.contains("guard-response-ok") }) else {
                throw GuardError.message("The HTTP body was not captured in Guard")
            }
            proof["capturedHTTP"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(record))
            print("PASS real HTTPS request and response captured through CONNECT -> SOCKS5 -> local TLS")
            let stream = try await command(inspector, "Runtime.evaluate", ["expression": "(async()=>{const r=await fetch('/__guard_test__/stream');globalThis.guardStreamReader=r.body.getReader();const b=await guardStreamReader.read();return {open:!b.done,bytes:b.value.length};})()", "awaitPromise": true, "returnByValue": true], session: initial.sessionID)
            guard let streamResult = stream["result"] as? [String: Any], let streamValue = streamResult["value"] as? [String: Any],
                  streamValue["open"] as? Bool == true, (streamValue["bytes"] as? Int ?? 0) > 0 else {
                throw GuardError.message("HTTPS stream did not stay open: \(stream)")
            }
            print("PASS long-lived HTTPS stream opened in Claude renderer")
            let changed = Date(); observedIP = "203.0.113.8"
            let blocked = await wait(6) { model.requiresRestart && !model.claudeRunning && !model.monitoring && !model.allowed }
            let elapsed = Int(Date().timeIntervalSince(changed) * 1000)
            let processGone = await wait(2) { kill(processID, 0) != 0 && errno == ESRCH }
            let portClosed = await refusesConnection(relayPort)
            guard blocked, processGone, portClosed else {
                throw GuardError.message("Kill switch failed: blocked=\(blocked), processGone=\(processGone), portClosed=\(portClosed)")
            }
            model.stop(); model.check(andLaunch: true)
            guard model.requiresRestart, !model.claudeRunning else { throw GuardError.message("Restart latch was bypassed") }
            proof["killSwitch"] = ["from": "203.0.113.7", "to": observedIP, "blockedUntilRestart": true,
                                   "processGone": processGone, "relayRefusesNewConnections": portClosed, "milliseconds": elapsed]
            let restartProof = root.appendingPathComponent("restart-proof.json")
            var restartChild: Process?
            var restartCount = 0
            model.password = "restart-memory-secret"
            model.onRestart = {
                restartCount += 1
                model.shutdown()
                restartChild = try? GuardRelauncher.launch(executable: URL(fileURLWithPath: args[0]), arguments: ["--restarted", "--proof", restartProof.path])
            }
            model.restart(); model.restart()
            let restarted = await wait(5) { FileManager.default.fileExists(atPath: restartProof.path) && restartChild?.isRunning == false }
            guard restarted, restartCount == 1, let data = try? Data(contentsOf: restartProof),
                  let restart = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  restart["freshPolicy"] as? Bool == true, restart["passwordAbsent"] as? Bool == true,
                  restart["pid"] as? Int != Int(getpid()), model.requiresRestart else {
                throw GuardError.message("Restart did not create a fresh process safely")
            }
            proof["restart"] = restart
            print("PASS restart action launches one new process without the proxy password; old latch retained")
            let exitLog = root.appendingPathComponent("unexpected-exit.jsonl")
            let exitModel = GuardModel(diagnosticsURL: exitLog)
            exitModel.useProxy = true; exitModel.host = "127.0.0.1"; exitModel.port = String(socksPort)
            exitModel.username = ""; exitModel.password = ""; exitModel.watchPublicIP = true; exitModel.interval = 2
            exitModel.timezone = "Europe/Amsterdam"; exitModel.language = "en-US"
            exitModel.e2eInitialCheck = model.e2eInitialCheck
            exitModel.e2ePublicCheck = { _ in "203.0.113.7" }
            exitModel.e2eRuntimeRoot = model.e2eRuntimeRoot; exitModel.e2eBootstrapURL = model.e2eBootstrapURL
            exitModel.e2eSandboxURL = model.e2eSandboxURL; exitModel.e2eHelperURL = model.e2eHelperURL
            exitModel.e2eStderrURL = root.appendingPathComponent("unexpected-exit.stderr.log")
            exitModel.e2eExtraArguments = model.e2eExtraArguments
            defer { exitModel.shutdown() }
            exitModel.check(andLaunch: true)
            let exitReady = await wait(20) { exitModel.lastVerifiedProfile?.url.hasPrefix("https://claude.ai/") == true || exitModel.requiresRestart || (!exitModel.busy && !exitModel.monitoring) }
            guard exitReady, exitModel.claudeRunning, let exitInspector = exitModel.e2eInspector else { throw GuardError.message("Exit scenario startup failed: \(exitModel.detail)") }
            _ = try await command(exitInspector, "ProxyGuard.testExit")
            let reported = await wait(5) { exitModel.requiresRestart && !exitModel.claudeRunning }
            let restored = GuardDiagnostics(url: exitLog).previousFailure()
            guard reported, let restored, !restored.contains("остановлена пользователем") else { throw GuardError.message("Unexpected exit lost its reason: \(exitModel.detail)") }
            proof["unexpectedExitRecorded"] = restored
            print("PASS unexpected runtime exit persists its actual failure instead of a manual-stop message")
            proof["result"] = "PASS"; proof["durationSeconds"] = Date().timeIntervalSince(started)
            proof["completedAt"] = ISO8601DateFormatter().string(from: Date())
            try JSONSerialization.data(withJSONObject: proof, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: args[6]), options: .atomic)
            print("PASS IP change closed relay and Claude in \(elapsed) ms; restart latch preserved")
        } catch {
            proof["result"] = "FAIL"; proof["error"] = error.localizedDescription; proof["log"] = model.log
            proof["traffic"] = try? JSONSerialization.jsonObject(with: JSONEncoder().encode(model.traffic))
            try? JSONSerialization.data(withJSONObject: proof, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: args[6]), options: .atomic)
            print("E2E FAILED: \(error.localizedDescription)")
            model.shutdown(); exit(1)
        }
    }
}
