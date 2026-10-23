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
        let proxyFixture = """
        <dictionary> {
          HTTPEnable : 1
          HTTPProxy : PROXY.Example
          HTTPPort : 8080
          HTTPSEnable : 1
          HTTPSProxy : 192.0.2.1
          HTTPSPort : 443
          SOCKSEnable : 1
          SOCKSProxy : 2001:db8::1
          SOCKSPort : 1080
          ExceptionsList : <array> {
            0 : *.local
          }
        }
        """
        func proxyTest(_ label: String, _ test: () throws -> Bool) {
            let ok = (try? test()) == true
            print("\(ok ? "PASS" : "FAIL") \(label)")
            if !ok { failures += 1 }
        }
        func rejects(_ fixture: String) -> Bool {
            do { _ = try SystemProxy.parse(fixture); return false } catch { return true }
        }
        proxyTest("static system proxy parses all three protocols") {
            let snapshot = try SystemProxy.parse(proxyFixture)
            return snapshot.http == SystemProxy.Endpoint(host: "proxy.example", port: 8080) &&
                snapshot.https == SystemProxy.Endpoint(host: "192.0.2.1", port: 443) &&
                snapshot.socks == SystemProxy.Endpoint(host: "2001:db8::1", port: 1080) && snapshot.fingerprint.count == 64
        }
        proxyTest("PAC fails closed") { rejects(proxyFixture.replacingOccurrences(of: "HTTPEnable : 1", with: "ProxyAutoConfigEnable : 1\nHTTPEnable : 1")) }
        proxyTest("PAC URL fails closed even when disabled") { rejects(proxyFixture.replacingOccurrences(of: "HTTPEnable : 1", with: "ProxyAutoConfigURLString : https://pac.example/script\nHTTPEnable : 1")) }
        proxyTest("enabled protocol without port fails closed") { rejects(proxyFixture.replacingOccurrences(of: "HTTPPort : 8080", with: "")) }
        for value in ["0", "65536", "-1", "8x"] {
            proxyTest("invalid system proxy port \(value) fails closed") { rejects(proxyFixture.replacingOccurrences(of: "8080", with: value)) }
        }
        for value in ["user@proxy.example", "bad host", "127.1", "bad..example", "2001:invalid::1"] {
            proxyTest("invalid system proxy host \(value) fails closed") { rejects(proxyFixture.replacingOccurrences(of: "PROXY.Example", with: value)) }
        }
        proxyTest("duplicate keys fail closed") { rejects(proxyFixture.replacingOccurrences(of: "HTTPEnable : 1", with: "HTTPEnable : 1\nhttpenable : 1")) }
        proxyTest("fingerprint and equality ignore key order and host case") {
            let changed = proxyFixture.replacingOccurrences(of: "HTTPEnable : 1\n  HTTPProxy : PROXY.Example", with: "HTTPProxy : proxy.example\n  HTTPEnable : 1")
            let a = try SystemProxy.parse(proxyFixture), b = try SystemProxy.parse(changed)
            return a == b && a.fingerprint == b.fingerprint
        }
        proxyTest("SOCKS host change changes fingerprint") {
            try SystemProxy.parse(proxyFixture).fingerprint != SystemProxy.parse(proxyFixture.replacingOccurrences(of: "2001:db8::1", with: "2001:db8::2")).fingerprint
        }
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
        let headerCases: [([String: Any], [String], String)] = [
            (["Accept-Language": "en-US,en;q=0.9"], [], "expected language and primary fallback"),
            (["Accept-Language": "ru-RU"], ["transport.Accept-Language.mismatch"], "different language"),
            (["Accept-Language": "fr;q=0"], ["transport.Accept-Language.mismatch"], "q=0 still discloses a language"),
            (["Accept-Language": "en-US;q=1.1"], ["transport.Accept-Language.invalid"], "malformed entry"),
            ([:], [], "missing header"),
            (["accept-language": "EN-us;Q=0.,en;q=1.000"], [], "case insensitive tags and q grammar"),
            (["Accept-Language": 42], ["transport.Accept-Language.invalid"], "non-string header"),
            (["Accept-Language": ""], ["transport.Accept-Language.invalid"], "empty header"),
            (["Accept-Language": "en-US\r\n"], ["transport.Accept-Language.invalid"], "CRLF header"),
            (["Accept-Language": "en-US,"], ["transport.Accept-Language.invalid"], "empty comma entry"),
            (["X-Language": "ru-RU"], [], "unrelated header ignored")
        ]
        for (headers, expected, label) in headerCases {
            let ok = TrafficSanitizer.auditRequestHeaders(headers, language: "en-US") == expected
            print("\(ok ? "PASS" : "FAIL") Accept-Language: \(label)")
            if !ok { failures += 1 }
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
