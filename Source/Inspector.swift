import Foundation
import Darwin

struct TrafficRecord: Identifiable, Codable {
    let id: String
    var date = Date()
    var method = ""
    var url = ""
    var kind = ""
    var status: Int?
    var requestHeaders = ""
    var responseHeaders = ""
    var sent = ""
    var received = ""
    var note = ""
    var warnings: [String] = []
}

struct VerifiedProfile: Codable {
    let sessionID: String
    let timezone: String
    let language: String
    let url: String
    let locale: String
}

enum TrafficSanitizer {
    static let limit = 32_768
    static func secretKey(_ key: String) -> Bool {
        key.range(of: #"(?i)^(authorization|proxy[_-]authorization|cookie|set[_-]cookie|x[_-]api[_-]key|api[_-]?key|client[_-]secret|session[_-]?key)$|token$|(?:^|[_-])(?:secret|password|passwd)$"#,
                  options: .regularExpression) != nil
    }
    static func bounded(_ text: String) -> String {
        String(text.prefix(limit)) + (text.count > limit ? "\n[обрезано: лимит 32 768 символов]" : "")
    }
    static func safeURL(_ text: String) -> String {
        guard var parts = URLComponents(string: text) else { return "[некорректный URL]" }
        parts.user = nil; parts.password = nil; parts.query = nil; parts.fragment = nil
        return bounded(parts.string ?? "[URL]")
    }
    static func headers(_ headers: [String: Any]) -> String {
        bounded(headers.keys.sorted().map { key in
            let value = String(describing: headers[key]!)
            let cleaned = secretKey(key) ? "[скрыто]" :
                (["referer", "origin", "location", "from"].contains(key.lowercased()) ? safeURL(value) : value)
            return "\(key): \(cleaned)"
        }.joined(separator: "\n"))
    }
    static func body(_ text: String) -> String {
        func redact(_ object: Any) -> Any {
            if let dictionary = object as? [String: Any] {
                return dictionary.reduce(into: [String: Any]()) { result, pair in
                    result[pair.key] = secretKey(pair.key) ? "[скрыто]" : redact(pair.value)
                }
            }
            if let array = object as? [Any] { return array.map(redact) }
            return object
        }
        if let data = text.data(using: .utf8), let json = try? JSONSerialization.jsonObject(with: data),
           let cleaned = try? JSONSerialization.data(withJSONObject: redact(json), options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]),
           let string = String(data: cleaned, encoding: .utf8) { return bounded(string) }
        if text.range(of: #"^[^\s&=]+=[^\s&]*(?:&[^\s&=]+=[^\s&]*)*$"#, options: .regularExpression) != nil {
            return bounded(text.components(separatedBy: "&").map { pair in
                let index = pair.firstIndex(of: "=")!
                let key = String(pair[..<index])
                let decoded = key.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? key
                return secretKey(decoded) ? key + "=[скрыто]" : pair
            }.joined(separator: "&"))
        }
        var result = text
        // Also mask common JSON fragments and bearer strings in SSE/text chunks.
        let patterns = [
            #"(?i)("(?:[^"\r\n]*token|authorization|proxy[_-]authorization|cookie|set[_-]cookie|x[_-]api[_-]key|api[_-]?key|client[_-]secret|(?:[^"\r\n]*[_-])?(?:password|passwd|secret)|session[_-]?key)"\s*:\s*")[^"\r\n]*(")"#,
            #"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+"#
        ]
        for (index, pattern) in patterns.enumerated() {
            if let regex = try? NSRegularExpression(pattern: pattern) {
                result = regex.stringByReplacingMatches(in: result, range: NSRange(result.startIndex..., in: result),
                                                        withTemplate: index == 0 ? "$1[скрыто]$2" : "$1[скрыто]")
            }
        }
        return bounded(result)
    }
    static func auditRequestHeaders(_ headers: [String: Any], language: String) -> [String] {
        let expected = language.lowercased()
        let primary = String(expected.split(separator: "-", omittingEmptySubsequences: false)[0])
        let grammar = try! NSRegularExpression(pattern: #"^[ \t]*([a-z]{1,8}(?:-[a-z0-9]{1,8})*)[ \t]*(?:;[ \t]*q=(?:0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?))?[ \t]*$"#, options: .caseInsensitive)
        var flags: [String] = []
        func flag(_ value: String) { if !flags.contains(value) { flags.append(value) } }
        for (key, value) in headers where key.lowercased() == "accept-language" {
            guard let value = value as? String, !value.isEmpty,
                  !value.contains("\r"), !value.contains("\n") else {
                flag("transport.Accept-Language.invalid"); continue
            }
            for part in value.components(separatedBy: ",") {
                let range = NSRange(part.startIndex..., in: part)
                guard let match = grammar.firstMatch(in: part, range: range), match.range == range,
                      let tagRange = Range(match.range(at: 1), in: part) else {
                    flag("transport.Accept-Language.invalid"); continue
                }
                let tag = part[tagRange].lowercased()
                if tag != expected && tag != primary { flag("transport.Accept-Language.mismatch") }
            }
        }
        return flags
    }
    static func audit(headers: [String: Any], body: String) -> [String] {
        var flags = Set<String>()
        func inspect(key: String, value: String) {
            let k = key.lowercased(), v = value.lowercased()
            if (k.contains("timezone") || k.contains("time_zone") || k == "tz"),
               v.contains("moscow") || v.contains("moskow") { flags.insert("В метаданных обнаружена Europe/Moscow") }
            if (k.contains("language") || k == "locale"), v.hasPrefix("ru") {
                flags.insert("В метаданных обнаружен русский язык")
            }
        }
        func walk(_ object: Any) {
            if let dict = object as? [String: Any] {
                for (key, value) in dict {
                    if let value = value as? String { inspect(key: key, value: value) }
                    else { walk(value) }
                }
            } else if let list = object as? [Any] { list.forEach(walk) }
        }
        for (key, value) in headers { inspect(key: key, value: String(describing: value)) }
        if let data = body.data(using: .utf8), let json = try? JSONSerialization.jsonObject(with: data) { walk(json) }
        return flags.sorted()
    }
}

/// CDP over inherited file descriptors only. No HTTP/WebSocket debug server is opened.
final class ClaudeInspector: @unchecked Sendable {
    private let queue = DispatchQueue(label: "local.proxyguard.cdp")
    private let input: FileHandle
    private let output: FileHandle
    private var reader: DispatchSourceRead?
    private var readerManaged = false
    private let profile: LaunchProfile
    private let captureBodies: Bool
    private var buffer = Data()
    private var nextID = 0
    private var pending: [Int: (Result<[String: Any], Error>) -> Void] = [:]
    private var running = true
    private var userAgent = ""
    private var records: [String: TrafficRecord] = [:]
    private var earlyRequestHeaders: [String: [String: Any]] = [:]
    private var order: [String] = []
    private var sessions: [String: UUID] = [:]
    private var contexts: [String: Set<Int>] = [:]
    private var verificationDeadlines: [String: DispatchWorkItem] = [:]
    private var verifiedSessions = Set<String>()
    private var sessionDeadline: DispatchWorkItem?
    var onRecord: ((TrafficRecord) -> Void)?
    var onStatus: ((String) -> Void)?
    var onNotice: ((String) -> Void)?
    var onFatal: ((String) -> Void)?
    var onVerified: ((VerifiedProfile) -> Void)?

    init(input: FileHandle, output: FileHandle, profile: LaunchProfile, captureBodies: Bool) {
        self.input = input; self.output = output; self.profile = profile; self.captureBodies = captureBodies
    }

    func start() {
        queue.async { [self] in
            guard running else { return }
            let descriptor = output.fileDescriptor
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
                fatal("Не удалось открыть чтение диагностического канала."); return
            }
            let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
            reader = source; readerManaged = true
            source.setEventHandler { [weak self] in self?.readAvailable(descriptor) }
            let handle = output
            source.setCancelHandler { try? handle.close() }
            source.resume()
            command("Browser.getVersion") { [weak self] result in
                guard let self else { return }
                guard case .success(let version) = result, let agent = version["userAgent"] as? String else {
                    self.fatal("Claude не открыл диагностический канал. Язык, таймзона и перехват не подтверждены.")
                    return
                }
                self.userAgent = agent
                self.command("Target.setAutoAttach", self.attachParameters) { [weak self] result in
                    guard let self else { return }
                    guard case .success = result else { self.fatal("Не удалось подключить диагностику страниц Claude."); return }
                    self.emitStatus("Диагностика подключена; ожидаем страницу Claude")
                    let deadline = DispatchWorkItem { [weak self] in
                        guard let self, self.verifiedSessions.isEmpty else { return }
                        self.fatal("За 25 секунд не удалось проверить язык и таймзону веб-страницы Claude.")
                    }
                    self.sessionDeadline = deadline
                    self.queue.asyncAfter(deadline: .now() + 25, execute: deadline)
                }
            }
        }
    }

    private var attachParameters: [String: Any] {
        ["autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
         "filter": [["type": "page"], ["type": "iframe"], ["exclude": true]]]
    }

    func stop() {
        queue.sync {
            running = false; sessionDeadline?.cancel()
            closeReader()
            for deadline in verificationDeadlines.values { deadline.cancel() }
            verificationDeadlines.removeAll()
            failPending("Диагностика остановлена.")
            records.removeAll(); order.removeAll(); earlyRequestHeaders.removeAll()
            try? input.close()
        }
    }

    private func closeReader() {
        if let reader { reader.cancel(); self.reader = nil }
        else if !readerManaged { try? output.close(); readerManaged = true }
    }
    private func readAvailable(_ descriptor: Int32) {
        var bytes = [UInt8](repeating: 0, count: 65_536)
        for _ in 0..<32 {
            guard running else { return }
            let count = Darwin.read(descriptor, &bytes, bytes.count)
            if count > 0 { consume(Data(bytes.prefix(count))) }
            else if count == 0 { fatal("Диагностический канал Claude закрыт."); return }
            else if errno == EINTR { continue }
            else if errno == EAGAIN || errno == EWOULDBLOCK { return }
            else { fatal("Ошибка чтения диагностического канала Claude."); return }
        }
    }

    private func consume(_ data: Data) {
        guard running else { return }
        guard !data.isEmpty else { fatal("Диагностический канал Claude закрыт."); return }
        buffer.append(data)
        guard buffer.count <= 8 * 1024 * 1024 else { fatal("Диагностический буфер переполнен."); return }
        while running, let delimiter = buffer.firstIndex(of: 0) {
            let packet = Data(buffer[..<delimiter]); buffer.removeSubrange(...delimiter)
            guard let message = try? JSONSerialization.jsonObject(with: packet) as? [String: Any] else { continue }
            if let id = message["id"] as? Int, let callback = pending.removeValue(forKey: id) {
                if let error = message["error"] as? [String: Any] {
                    callback(.failure(GuardError.message(error["message"] as? String ?? "CDP method unavailable")))
                }
                else { callback(.success(message["result"] as? [String: Any] ?? [:])) }
            } else if let method = message["method"] as? String {
                event(method, message["params"] as? [String: Any] ?? [:], session: message["sessionId"] as? String ?? "")
            }
        }
    }

    private func command(_ method: String, _ parameters: [String: Any] = [:], session: String? = nil,
                         completion: @escaping (Result<[String: Any], Error>) -> Void = { _ in }) {
        guard running else { completion(.failure(GuardError.message("Диагностика остановлена."))); return }
        nextID += 1; let id = nextID
        var object: [String: Any] = ["id": id, "method": method, "params": parameters]
        if let session { object["sessionId"] = session }
        do {
            var data = try JSONSerialization.data(withJSONObject: object)
            data.append(0); pending[id] = completion
            try input.write(contentsOf: data)
            queue.asyncAfter(deadline: .now() + 6) { [weak self] in
                self?.pending.removeValue(forKey: id)?(.failure(GuardError.message("CDP timeout")))
            }
        } catch {
            pending.removeValue(forKey: id)
            completion(.failure(error)); fatal("Не удалось передать команду диагностики Claude.")
        }
    }

    private func configure(session: String) {
        guard sessions[session] == nil else { return }
        let generation = UUID()
        sessions[session] = generation; contexts[session] = []
        verifyBeforeDeadline(session, generation: generation)
        let locale = profile.language.replacingOccurrences(of: "-", with: "_")
        let tasks: [(String, [String: Any])] = [
            ("Emulation.setTimezoneOverride", ["timezoneId": profile.timezone]),
            ("Emulation.setLocaleOverride", ["locale": locale]),
            ("Network.enable", ["maxTotalBufferSize": 2_097_152, "maxResourceBufferSize": 131_072,
                                "maxPostDataSize": captureBodies ? 32_768 : 0]),
            ("Network.setUserAgentOverride", ["userAgent": userAgent, "acceptLanguage": profile.language]),
            ("Network.setExtraHTTPHeaders", ["headers": ["Accept-Language": profile.language]]),
            ("Runtime.enable", [:]),
            ("Target.setAutoAttach", attachParameters)
        ]
        func run(_ index: Int) {
            guard running, sessions[session] == generation else { return }
            if index == tasks.count {
                command("Runtime.runIfWaitingForDebugger", session: session) { [weak self] result in
                    guard let self, self.running, self.sessions[session] == generation else { return }
                    if case .failure(let error) = result {
                        if self.targetClosed(error) { self.retire(session); return }
                        self.fatal("Не удалось продолжить запуск страницы Claude.")
                    }
                }
                return
            }
            command(tasks[index].0, tasks[index].1, session: session) { [weak self] result in
                guard let self, self.running, self.sessions[session] == generation else { return }
                if case .failure(let error) = result {
                    if self.targetClosed(error) { self.retire(session); return }
                    if tasks[index].0 == "Emulation.setLocaleOverride",
                       error.localizedDescription.contains("Another locale override is already in effect") {
                        self.emitNotice("Локаль общего renderer уже задана; ожидаем проверку Intl и языка.")
                        run(index + 1)
                        return
                    }
                    self.fatal("Ошибка настройки \(tasks[index].0): \(error.localizedDescription). Запуск остановлен.")
                    return
                }
                run(index + 1)
            }
        }
        run(0)
    }

    private func targetClosed(_ error: Error) -> Bool {
        let message = error.localizedDescription.lowercased()
        return ["target closed", "session closed", "session with given id not found", "no session with given id",
                "no target with given id", "inspected target navigated or closed", "object has been destroyed"].contains { message.contains($0) }
    }
    private func retire(_ session: String) {
        sessions.removeValue(forKey: session); contexts.removeValue(forKey: session); verifiedSessions.remove(session)
        verificationDeadlines.removeValue(forKey: session)?.cancel()
    }
    private func verifyBeforeDeadline(_ session: String, generation: UUID) {
        verificationDeadlines.removeValue(forKey: session)?.cancel()
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, self.running, self.sessions[session] == generation, !self.verifiedSessions.contains(session) else { return }
            self.fatal("За 25 секунд не удалось подтвердить профиль активной страницы Claude.")
        }
        verificationDeadlines[session] = deadline
        queue.asyncAfter(deadline: .now() + 25, execute: deadline)
    }
    private func failPending(_ message: String) {
        let callbacks = Array(pending.values); pending.removeAll()
        for callback in callbacks { callback(.failure(GuardError.message(message))) }
    }

    private func event(_ method: String, _ p: [String: Any], session: String) {
        if method == "ProxyGuard.notice", let message = p["message"] as? String {
            emitNotice(message); return
        }
        if method == "ProxyGuard.error" {
            fatal("Ошибка локального адаптера: \(p["message"] as? String ?? "неизвестная ошибка")")
            return
        }
        if method == "Target.attachedToTarget", let id = p["sessionId"] as? String {
            configure(session: id); return
        }
        if method == "Target.detachedFromTarget", let id = p["sessionId"] as? String {
            retire(id); return
        }
        guard let generation = sessions[session] else { return }
        if method == "Runtime.executionContextDestroyed", let id = p["executionContextId"] as? Int {
            contexts[session]?.remove(id); return
        }
        if method == "Runtime.executionContextsCleared" {
            contexts[session] = []; verifiedSessions.remove(session)
            verifyBeforeDeadline(session, generation: generation); return
        }
        if method == "Runtime.executionContextCreated", let context = p["context"] as? [String: Any],
           let aux = context["auxData"] as? [String: Any], aux["isDefault"] as? Bool == true,
           let id = context["id"] as? Int {
            contexts[session, default: []].insert(id)
            command("Runtime.evaluate", ["expression": "({timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,locale:Intl.DateTimeFormat().resolvedOptions().locale,url:location.href})",
                                         "contextId": id, "returnByValue": true], session: session) { [weak self] result in
                guard let self, self.running, self.sessions[session] == generation, self.contexts[session]?.contains(id) == true else { return }
                if case .failure(let error) = result,
                   error.localizedDescription.lowercased().contains("context") || self.targetClosed(error) { return }
                guard case .success(let response) = result,
                      let result = response["result"] as? [String: Any], let value = result["value"] as? [String: Any],
                      let tz = value["timezone"] as? String, let lang = value["language"] as? String,
                      let locale = value["locale"] as? String, !locale.isEmpty else {
                    self.fatal("Не удалось проверить часовой пояс, язык и локаль страницы Claude."); return
                }
                let validTZ = tz == self.profile.timezone || (self.profile.timezone == "Etc/UTC" && tz == "UTC")
                let validLocale = locale.replacingOccurrences(of: "_", with: "-").lowercased() == self.profile.language.lowercased()
                guard validTZ, lang.lowercased() == self.profile.language.lowercased(), validLocale else {
                    self.fatal("Профиль страницы не применён: \(tz), язык \(lang), локаль \(locale). Claude остановлен."); return
                }
                self.verifiedSessions.insert(session); self.sessionDeadline?.cancel()
                self.verificationDeadlines.removeValue(forKey: session)?.cancel()
                self.emitStatus("Проверено в странице: \(tz) · \(lang)")
                let verified = VerifiedProfile(sessionID: session, timezone: tz, language: lang,
                                               url: TrafficSanitizer.safeURL(value["url"] as? String ?? ""),
                                               locale: locale)
                let callback = self.onVerified
                DispatchQueue.main.async { callback?(verified) }
            }
            return
        }
        guard let requestID = p["requestId"] as? String else { return }
        let key = session + ":" + requestID
        switch method {
        case "Network.requestWillBeSentExtraInfo":
            let headers = p["headers"] as? [String: Any] ?? [:]
            if var record = records[key] {
                record.requestHeaders = TrafficSanitizer.headers(headers)
                record.warnings = Array(Set(record.warnings + TrafficSanitizer.audit(headers: headers, body: "") + TrafficSanitizer.auditRequestHeaders(headers, language: profile.language))).sorted()
                save(record)
            } else {
                let warnings = TrafficSanitizer.auditRequestHeaders(headers, language: profile.language)
                if !warnings.isEmpty {
                    fatal("Проверка профиля не пройдена: " + warnings.joined(separator: ", ") + ".")
                    return
                }
                if earlyRequestHeaders.count >= 200 { earlyRequestHeaders.removeAll() }
                earlyRequestHeaders[key] = headers
            }
        case "Network.responseReceivedExtraInfo":
            if var record = records[key] {
                record.responseHeaders = TrafficSanitizer.headers(p["headers"] as? [String: Any] ?? [:])
                record.status = p["statusCode"] as? Int ?? record.status
                save(record)
            }
        case "Network.requestWillBeSent":
            guard let request = p["request"] as? [String: Any] else { return }
            var record = TrafficRecord(id: key)
            record.method = request["method"] as? String ?? "?"
            record.url = TrafficSanitizer.safeURL(request["url"] as? String ?? "")
            record.kind = p["type"] as? String ?? "HTTP"
            let headers = earlyRequestHeaders.removeValue(forKey: key) ?? (request["headers"] as? [String: Any] ?? [:])
            let body = request["postData"] as? String ?? ""
            record.requestHeaders = TrafficSanitizer.headers(headers)
            record.warnings = Array(Set(TrafficSanitizer.audit(headers: headers, body: body) + TrafficSanitizer.auditRequestHeaders(headers, language: profile.language))).sorted()
            record.sent = captureBodies ? TrafficSanitizer.body(body) : "[содержимое отключено]"
            save(record)
        case "Network.responseReceived":
            guard var record = records[key], let response = p["response"] as? [String: Any] else { return }
            record.status = response["status"] as? Int
            record.responseHeaders = TrafficSanitizer.headers(response["headers"] as? [String: Any] ?? [:])
            let mime = response["mimeType"] as? String ?? ""
            record.note = mime
            save(record)
            if captureBodies, mime.contains("event-stream") {
                command("Network.streamResourceContent", ["requestId": requestID], session: session) { [weak self] result in
                    guard let self, case .success(let r) = result, let data = r["bufferedData"] as? String else { return }
                    self.appendResponse(key, base64: data)
                }
            }
        case "Network.dataReceived":
            if captureBodies, let data = p["data"] as? String { appendResponse(key, base64: data) }
        case "Network.eventSourceMessageReceived":
            if captureBodies, var record = records[key], let data = p["data"] as? String {
                record.received = TrafficSanitizer.bounded(record.received + "\n" + TrafficSanitizer.body(data)); save(record)
            }
        case "Network.loadingFinished":
            guard captureBodies, let record = records[key] else { return }
            let mime = record.note.lowercased()
            guard mime.contains("json") || mime.contains("text") || mime.contains("javascript") || mime.contains("xml") else { return }
            command("Network.getResponseBody", ["requestId": requestID], session: session) { [weak self] result in
                guard let self, var record = self.records[key] else { return }
                if case .success(let response) = result, let body = response["body"] as? String {
                    if response["base64Encoded"] as? Bool == true {
                        record.received = Data(base64Encoded: body).flatMap { String(data: $0, encoding: .utf8) }.map(TrafficSanitizer.body) ?? "[бинарные данные]"
                    } else { record.received = TrafficSanitizer.body(body) }
                } else if record.received.isEmpty { record.received = "[тело недоступно в диагностическом буфере]" }
                self.save(record)
            }
        case "Network.loadingFailed":
            if var record = records[key] { record.note = p["errorText"] as? String ?? "Ошибка загрузки"; save(record) }
        case "Network.webSocketCreated":
            var record = TrafficRecord(id: key); record.method = "WS"; record.kind = "WebSocket"
            record.url = TrafficSanitizer.safeURL(p["url"] as? String ?? ""); save(record)
        case "Network.webSocketWillSendHandshakeRequest":
            if var record = records[key] {
                let request = p["request"] as? [String: Any] ?? [:]
                let headers = request["headers"] as? [String: Any] ?? [:]
                record.requestHeaders = TrafficSanitizer.headers(headers)
                record.warnings = Array(Set(record.warnings + TrafficSanitizer.audit(headers: headers, body: "") + TrafficSanitizer.auditRequestHeaders(headers, language: profile.language))).sorted()
                save(record)
            }
        case "Network.webSocketFrameSent", "Network.webSocketFrameReceived":
            guard captureBodies, var record = records[key], let response = p["response"] as? [String: Any] else { return }
            let text = (response["opcode"] as? Int == 1) ? TrafficSanitizer.body(response["payloadData"] as? String ?? "") : "[бинарный WebSocket-кадр]"
            if method.hasSuffix("Sent") { record.sent = TrafficSanitizer.bounded(record.sent + "\n" + text) }
            else { record.received = TrafficSanitizer.bounded(record.received + "\n" + text) }
            save(record)
        default: break
        }
    }

    private func appendResponse(_ key: String, base64: String) {
        guard var record = records[key], let data = Data(base64Encoded: base64), let text = String(data: data, encoding: .utf8) else { return }
        record.received = TrafficSanitizer.bounded(record.received + TrafficSanitizer.body(text)); save(record)
    }
    private func save(_ record: TrafficRecord) {
        if records[record.id] == nil {
            order.append(record.id)
            if order.count > 200 { records.removeValue(forKey: order.removeFirst()) }
        }
        records[record.id] = record
        let callback = onRecord
        DispatchQueue.main.async { callback?(record) }
    }
    private func emitStatus(_ text: String) { let callback = onStatus; DispatchQueue.main.async { callback?(text) } }
    private func emitNotice(_ text: String) { let callback = onNotice; DispatchQueue.main.async { callback?(text) } }
    private func fatal(_ text: String) {
        guard running else { return }
        running = false; sessionDeadline?.cancel()
        closeReader()
        for deadline in verificationDeadlines.values { deadline.cancel() }
        verificationDeadlines.removeAll(); failPending(text)
        let callback = onFatal
        DispatchQueue.main.async { callback?(text) }
    }
}

#if GUARD_E2E
extension ClaudeInspector {
    func testCommand(_ method: String, _ params: [String: Any] = [:], session: String? = nil,
                     completion: @escaping (Result<[String: Any], Error>) -> Void) {
        queue.async { self.command(method, params, session: session, completion: completion) }
    }
}
#endif
