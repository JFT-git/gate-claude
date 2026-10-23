import Foundation
import Darwin

@main struct InspectorTests {
    @MainActor static func scenario(helper: String, fixture: String, mode: String, capture: Bool) async -> Bool {
        let child = Process(); child.executableURL = URL(fileURLWithPath: helper); child.arguments = [fixture]
        var environment = ProcessInfo.processInfo.environment; environment["MOCK_MODE"] = mode; child.environment = environment
        let commands = Pipe(), events = Pipe(); child.standardInput = commands; child.standardOutput = events
        child.standardError = FileHandle.nullDevice
        let inspector = ClaudeInspector(input: commands.fileHandleForWriting, output: events.fileHandleForReading,
                                        profile: LaunchProfile(timezone: "Europe/Amsterdam", language: "en-US"), captureBodies: capture)
        var verified = false
        var record: TrafficRecord?
        var finished = false
        let shouldSucceed = ["normal", "closing-target", "duplicate-target", "replaced-context", "shared-locale"].contains(mode)
        let ok: Bool = await withCheckedContinuation { continuation in
            let finish: (Bool) -> Void = { result in
                guard !finished else { return }; finished = true; continuation.resume(returning: result)
            }
            let check: () -> Void = {
                guard shouldSucceed, verified, let record, record.status == 200 else { return }
                let serialized = String(data: try! JSONEncoder().encode(record), encoding: .utf8)!
                let noSecrets = !["query-secret", "auth-secret", "cookie-secret", "request-secret", "response-secret", "response-cookie"].contains { serialized.contains($0) }
                if capture {
                    if record.received.contains("hello response") {
                        finish(noSecrets && record.sent.contains("hello request") && !record.warnings.isEmpty)
                    }
                } else { finish(noSecrets && record.sent == "[содержимое отключено]" && record.received.isEmpty) }
            }
            inspector.onRecord = { value in record = value; check() }
            inspector.onStatus = { value in if value.hasPrefix("Проверено") { verified = true }; check() }
            inspector.onFatal = { reason in
                if ["shared-locale-wrong", "shared-locale-language-wrong"].contains(mode) { finish(reason.contains("Профиль страницы не применён")) }
                else if mode == "shared-locale-unverified" { finish(reason.contains("Не удалось проверить")) }
                else { finish(!shouldSucceed) }
            }
            do { try child.run(); inspector.start() }
            catch { finish(false) }
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) { finish(false) }
        }
        inspector.stop()
        if child.isRunning { child.terminate() }
        child.waitUntilExit()
        return ok
    }
    @MainActor static func main() async {
        signal(SIGPIPE, SIG_IGN)
        guard CommandLine.arguments.count == 3 else { exit(2) }
        var failures = 0
        for (mode, capture, label) in [("normal", true, "pipe profile verification and two-way HTTP capture with redaction"),
                                       ("normal", false, "body capture can be disabled"),
                                       ("unsupported", true, "unsupported locale override fails closed"),
                                       ("wrong-profile", true, "Moscow observed in runtime fails closed"),
                                       ("closing-target", true, "closed iframe does not kill the main page"),
                                       ("duplicate-target", true, "duplicate attachment is configured once"),
                                       ("replaced-context", true, "stale response from destroyed context is ignored"),
                                       ("wrong-profile-child", true, "wrong profile in a live iframe still fails closed"),
                                       ("shared-locale", true, "inherited renderer locale is accepted only after runtime verification"),
                                       ("shared-locale-wrong", true, "conflicting inherited Intl locale fails closed"),
                                       ("shared-locale-language-wrong", true, "inherited locale cannot hide a wrong navigator language"),
                                       ("shared-locale-unverified", true, "missing inherited locale verification fails closed")] {
            let ok = await scenario(helper: CommandLine.arguments[1], fixture: CommandLine.arguments[2], mode: mode, capture: capture)
            print("\(ok ? "PASS" : "FAIL") \(label)"); if !ok { failures += 1 }
        }
        let fragment = TrafficSanitizer.body("data: {\"access_token\":\"stream-secret\"}\nBearer abc.def.ghi")
        let safe = !fragment.contains("stream-secret") && !fragment.contains("abc.def.ghi")
        print("\(safe ? "PASS" : "FAIL") streamed text masks known secrets"); if !safe { failures += 1 }
        let formSafe = TrafficSanitizer.body("password=x&access_token=y") == "password=[скрыто]&access_token=[скрыто]" &&
            TrafficSanitizer.body("client%5Fsecret=x&api-key=y&message=hello") == "client%5Fsecret=[скрыто]&api-key=[скрыто]&message=hello"
        let jsonSafe = !TrafficSanitizer.body(#"{"client_secret":"secret-g","api_key":"secret-h"}"#).contains("secret-")
        let keysSafe = ["client-secret", "APIKEY", "api_key", "account-password", "db_passwd", "nested_secret", "sessionkey", "legacytoken"].allSatisfy { key in
            TrafficSanitizer.secretKey(key) && !TrafficSanitizer.body("data: {\"\(key)\":\"secret-fragment\"}").contains("secret-fragment")
        }
        let headersSafe = ["Referer", "Origin", "Location", "From"].allSatisfy { key in
            TrafficSanitizer.headers([key: "https://user:pass@example.test/path?token=secret#private"]) == key + ": https://example.test/path"
        }
        let sanitizerSafe = formSafe && jsonSafe && keysSafe && headersSafe
        print("\(sanitizerSafe ? "PASS" : "FAIL") form, JSON, fragment secrets and URL headers are sanitized")
        if !sanitizerSafe { failures += 1 }
        let audit = TrafficSanitizer.audit(headers: [:], body: "{\"message\":\"I live in Europe/Moscow\"}")
        if audit.isEmpty { print("PASS chat text is not mistaken for timezone metadata") } else { failures += 1 }
        let logURL = FileManager.default.temporaryDirectory.appendingPathComponent("Guard-diagnostics-" + UUID().uuidString + ".jsonl")
        let diagnostics = GuardDiagnostics(url: logURL)
        diagnostics.record("blocked", "IP 203.0.113.7 -> 2001:db8::7; https://example.test/?token=query-secret Bearer bearer-secret")
        let stored = (try? String(contentsOf: logURL, encoding: .utf8)) ?? ""
        let restored = GuardDiagnostics(url: logURL).previousFailure()
        let safeLog = restored != nil && !["203.0.113.7", "2001:db8::7", "query-secret", "bearer-secret"].contains { stored.contains($0) }
        print("\(safeLog ? "PASS" : "FAIL") failure survives restart without IP addresses or URL/bearer secrets")
        if !safeLog { failures += 1 }
        try? FileManager.default.removeItem(at: logURL)
        print("CDP TESTS: \(failures) failures")
        exit(failures == 0 ? 0 : 1)
    }
}
