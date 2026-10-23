import Foundation
import Network
import Darwin
import Security

enum GuardError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let text) = self { return text }; return nil }
}

struct ProxySettings: Equatable {
    let host: String
    let port: UInt16
    let username: String
    let password: String

    static func validated(host: String, port: String, username: String, password: String) throws -> ProxySettings {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, !host.contains("://"), !host.contains("/"),
              !host.contains("@"), !host.contains(where: { $0.isWhitespace }),
              let port = UInt16(port), port > 0 else {
            throw GuardError.message("Введите хост без socks5:// и порт от 1 до 65535.")
        }
        // Multicast DNS names resolve outside any pinned route and reveal the proxy
        // name on the local network; literal addresses or ordinary DNS names only.
        let lowered = host.lowercased()
        guard !lowered.hasSuffix(".local"), !lowered.hasSuffix(".local."),
              !lowered.hasSuffix(".lan"), !lowered.hasSuffix(".internal") else {
            throw GuardError.message("Имя прокси в зоне .local/.lan/.internal не поддерживается: оно разрешается через mDNS мимо закреплённого маршрута. Укажите числовой адрес или обычное DNS-имя.")
        }
        guard username.utf8.count <= 255, password.utf8.count <= 255 else {
            throw GuardError.message("Логин и пароль SOCKS5 должны быть не длиннее 255 байт.")
        }
        guard password.isEmpty || !username.isEmpty else {
            throw GuardError.message("Для пароля SOCKS5 нужен логин.")
        }
        return ProxySettings(host: host, port: port, username: username, password: password)
    }
}

struct IPReport: Equatable {
    let ip: String
    let countryCode: String
    let country: String
    let date: Date

    static func parse(_ data: Data) throws -> IPReport {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              json["success"] as? Bool == true,
              let ip = json["ip"] as? String,
              let code = json["country_code"] as? String else {
            throw GuardError.message("Сервис проверки не вернул достоверный IP и страну. Доступ закрыт.")
        }
        var v4 = in_addr(); var v6 = in6_addr()
        guard inet_pton(AF_INET, ip, &v4) == 1 || inet_pton(AF_INET6, ip, &v6) == 1,
              code.count == 2, code.unicodeScalars.allSatisfy({ (65...90).contains($0.value) }) else {
            throw GuardError.message("Некорректный ответ сервиса проверки. Доступ закрыт.")
        }
        // Unknown and special geographic assignments must never unlock launch.
        let isoCodes = Set(Locale.Region.isoRegions.map(\.identifier).filter { $0.count == 2 })
        guard isoCodes.contains(code), !["ZZ", "XX", "EU", "UN"].contains(code) else {
            throw GuardError.message("Страна IP не определена. Доступ закрыт.")
        }
        return IPReport(ip: ip, countryCode: code,
                        country: Locale(identifier: "ru_RU").localizedString(forRegionCode: code) ?? code,
                        date: Date())
    }

    func requireForeign() throws {
        if countryCode == "RU" { throw GuardError.message("Обнаружен российский IP (\(ip)). Доступ закрыт.") }
    }
}

enum IPChecker {
    // curl is bundled with macOS. -q must be the first argument: ignore ~/.curlrc.
    // Clear proxy environment variables so the only route is the explicitly selected one.
    static func check(relayPort: UInt16?, token: String) async throws -> IPReport {
        try IPReport.parse(await fetch(url: "https://ipwho.is/?fields=success,ip,country_code", relayPort: relayPort, token: token, timeout: 12))
    }

    static func publicIPURL(for pinnedIP: String?) -> String {
        // A dual-stack probe may alternate between the same network's IPv4 and IPv6.
        // Keep the family selected during the country check for every later probe.
        let host = pinnedIP.map { $0.contains(":") ? "api6.ipify.org" : "api.ipify.org" } ?? "api64.ipify.org"
        return "https://\(host)?format=json"
    }

    static func publicIP(relayPort: UInt16?, token: String, pinnedIP: String? = nil) async throws -> String {
        let data = try await fetch(url: publicIPURL(for: pinnedIP), relayPort: relayPort, token: token, timeout: 4)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ip = json["ip"] as? String else { throw GuardError.message("Не удалось определить внешний IP.") }
        return try IPIdentity.canonical(ip)
    }

    static let destinationHosts = ["claude.ai", "api.anthropic.com"]

    static func parseDestinationTrace(_ data: Data, hostname: String, family: Int) throws -> (ip: String, countryCode: String) {
        func invalid() -> GuardError { .message("Не удалось проверить маршрут Claude. Соединение закрыто.") }
        guard destinationHosts.contains(hostname), [4, 6].contains(family), data.count <= 16384,
              data.allSatisfy({ (32...126).contains($0) || $0 == 10 || $0 == 13 }),
              let body = String(data: data, encoding: .ascii),
              body.range(of: "\\r(?!\\n)", options: .regularExpression) == nil else { throw invalid() }
        var fields: [String: String] = [:]
        for line in body.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n") where !line.isEmpty {
            guard let split = line.firstIndex(of: "=") else { throw invalid() }
            let key = String(line[..<split]), value = String(line[line.index(after: split)...])
            guard key.range(of: "^[a-z_]+$", options: .regularExpression) != nil else { throw invalid() }
            if ["h", "ip", "loc"].contains(key) {
                guard fields[key] == nil else { throw invalid() }
                fields[key] = value
            }
        }
        guard fields["h"] == hostname, let ip = fields["ip"], !ip.contains("%"),
              let code = fields["loc"], code.range(of: "^[A-Z]{2}$", options: .regularExpression) != nil else { throw invalid() }
        let canonical = try IPIdentity.canonical(ip)
        guard !canonical.lowercased().hasPrefix("::ffff:") else { throw invalid() }
        return (canonical, code)
    }

    static func destinationTrace(relayPort: UInt16, token: String, hostname: String, family: Int) async throws -> (ip: String, countryCode: String) {
        guard destinationHosts.contains(hostname), [4, 6].contains(family) else { throw GuardError.message("Неверное назначение проверки Claude.") }
        return try parseDestinationTrace(await fetch(url: "https://\(hostname)/cdn-cgi/trace", relayPort: relayPort, token: token, timeout: 4, limit: 16384), hostname: hostname, family: family)
    }

    private static func fetch(url: String, relayPort: UInt16?, token: String, timeout: Int, limit: Int = 65536) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let process = Process()
                    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                    var args = ["-q", "--silent", "--show-error", "--fail", "--connect-timeout", "3",
                                "--max-time", String(timeout), "--max-filesize", String(limit), "--proto", "=https",
                                "--max-redirs", "0", "--header", "Cache-Control: no-cache"]
                    if let port = relayPort {
                        guard token.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw GuardError.message("Неверный токен проверки.") }
                        args += ["--proxy", "http://127.0.0.1:\(port)", "--noproxy", "", "--proxy-header", "Proxy-Authorization: Bearer \(token)"]
                    } else {
                        args += ["--proxy", "", "--noproxy", "*"]
                    }
                    args += [url]
                    process.arguments = args
                    process.environment = ProcessInfo.processInfo.environment.filter {
                        !["http_proxy", "https_proxy", "all_proxy", "no_proxy"].contains($0.key.lowercased())
                    }
                    let output = Pipe()
                    process.standardOutput = output; process.standardError = FileHandle.nullDevice
                    try process.run()
                    var data = Data()
                    while let chunk = try output.fileHandleForReading.read(upToCount: 4096), !chunk.isEmpty {
                        if data.count + chunk.count > limit { process.terminate(); process.waitUntilExit(); throw GuardError.message("Слишком большой ответ проверки IP.") }
                        data.append(chunk)
                    }
                    process.waitUntilExit()
                    guard process.terminationStatus == 0 else {
                        throw GuardError.message("Ошибка проверки IP (сеть, прокси или сервис). Доступ закрыт.")
                    }
                    continuation.resume(returning: data)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}

/// A local CONNECT bridge. SOCKS mode never falls back to a direct destination.
/// Current-network mode is an explicit choice and still passes through this gate.
final class SOCKSRelay: @unchecked Sendable {
    let checkToken: String = {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { fatalError("Не удалось создать токен шлюза.") }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }()
    enum Mode { case probeOnly, open, blocked }
    enum PinFamily { case v4, v6 }
    /// Kill switch for current-network sessions: upstream sockets are bound to the
    /// pinned local address of the approved egress interface. When the interface or
    /// VPN disappears, the address is gone and new connections fail before any packet
    /// leaves. A missing address for a required family refuses that family.
    struct LocalPin: Equatable { let v4: String?; let v6: String? }
    private let queue = DispatchQueue(label: "local.proxyguard.relay")
    private let settings: ProxySettings?
    private var listener: NWListener?
    private var tunnels: [UUID: RelayTunnel] = [:]
    private var mode: Mode = .probeOnly
    private var pinnedFamily: PinFamily?
    private var pinnedLocal: LocalPin?
    private var startup: CheckedContinuation<UInt16, Error>?
    private var alive = true
    private var faultReported = false
    var onFault: (() -> Void)?
    var onTunnelEvent: ((String, UInt16, Int, Int, Bool) -> Void)?

    init(settings: ProxySettings) { self.settings = settings }
    init(currentNetwork: Bool) { precondition(currentNetwork); self.settings = nil }

    func start() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                self.startup = continuation
                do {
                    let parameters = NWParameters.tcp
                    parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
                    let listener = try NWListener(using: parameters, on: .any)
                    self.listener = listener
                    listener.stateUpdateHandler = { [weak self] state in
                        guard let self else { return }
                        switch state {
                        case .ready:
                            if let port = listener.port?.rawValue {
                                self.startup?.resume(returning: port); self.startup = nil
                            }
                        case .failed:
                            self.startup?.resume(throwing: GuardError.message("Не удалось открыть локальный шлюз."))
                            self.startup = nil
                            self.upstreamFailed()
                        case .cancelled:
                            self.startup?.resume(throwing: GuardError.message("Шлюз остановлен.")); self.startup = nil
                        default: break
                        }
                    }
                    listener.newConnectionHandler = { [weak self] connection in
                        guard let self, self.alive, self.mode != .blocked, self.tunnels.count < 128 else {
                            connection.cancel(); return
                        }
                        let id = UUID()
                        let tunnel = RelayTunnel(client: connection, settings: self.settings, queue: self.queue, pinnedFamily: self.pinnedFamily, pinnedLocal: self.pinnedLocal, checkToken: self.checkToken)
                        tunnel.isAllowed = { [weak self] host, port, control in
                            guard let self, self.alive else { return false }
                            switch self.mode {
                            case .open: return true
                            case .probeOnly: return control
                            case .blocked: return false
                            }
                        }
                        tunnel.onClose = { [weak self] in self?.tunnels.removeValue(forKey: id) }
                        tunnel.onEvent = { [weak self] host, port, sent, received, finished in
                            let callback = self?.onTunnelEvent
                            DispatchQueue.main.async { callback?(host, port, sent, received, finished) }
                        }
                        tunnel.onUpstreamFault = { [weak self] in self?.upstreamFailed() }
                        tunnel.onProbeConnected = { [weak self] in self?.faultReported = false }
                        self.tunnels[id] = tunnel
                        tunnel.start()
                    }
                    listener.start(queue: self.queue)
                    self.queue.asyncAfter(deadline: .now() + 10) { [weak self] in
                        guard let self, let startup = self.startup else { return }
                        self.startup = nil
                        startup.resume(throwing: GuardError.message("Истекло время запуска локального шлюза."))
                        self.listener?.cancel()
                    }
                } catch {
                    self.startup?.resume(throwing: error); self.startup = nil
                }
            }
        }
    }

    /// nil leaves destination address selection unconstrained.
    func setPinnedFamily(_ family: PinFamily?) {
        queue.sync { pinnedFamily = family }
    }

    /// nil disables the egress kill switch (SOCKS sessions manage their own upstream).
    func setPinnedLocalAddresses(_ pin: LocalPin?) {
        queue.sync { pinnedLocal = pin }
    }

    func unlock() -> Bool {
        queue.sync {
            guard alive, mode == .probeOnly, !faultReported else { return false }
            mode = .open
            return true
        }
    }

    /// Pause application streams while preserving authenticated control checks.
    func pause() {
        queue.sync {
            guard alive else { return }
            mode = .probeOnly
            for tunnel in Array(tunnels.values) where !tunnel.isControl { tunnel.close() }
        }
    }

    func stop() {
        queue.sync {
            alive = false; mode = .blocked; pinnedFamily = nil; pinnedLocal = nil
            for tunnel in Array(tunnels.values) { tunnel.close() }
            listener?.cancel(); listener = nil
        }
    }

    private func upstreamFailed() {
        guard alive, !faultReported else { return }
        faultReported = true; mode = .probeOnly
        for tunnel in Array(tunnels.values) where !tunnel.isControl { tunnel.close() }
        let callback = onFault
        DispatchQueue.main.async { callback?() }
    }
}

private final class RelayTunnel {
    private let checkToken: String
    private(set) var isControl = false
    private let client: NWConnection
    private var upstream: NWConnection?
    private let settings: ProxySettings?
    private let queue: DispatchQueue
    var pinnedFamily: SOCKSRelay.PinFamily?
    private let pinnedLocal: SOCKSRelay.LocalPin?
    private var closed = false
    private var established = false
    private var header = Data()
    private var pending = Data()
    private var destination = ""
    private var port: UInt16 = 0
    private var sentBytes = 0
    private var receivedBytes = 0
    var onEvent: ((String, UInt16, Int, Int, Bool) -> Void)?
    var isAllowed: ((String, UInt16, Bool) -> Bool)?
    var onClose: (() -> Void)?
    var onUpstreamFault: (() -> Void)?
    var onProbeConnected: (() -> Void)?

    init(client: NWConnection, settings: ProxySettings?, queue: DispatchQueue, pinnedFamily: SOCKSRelay.PinFamily?, pinnedLocal: SOCKSRelay.LocalPin?, checkToken: String) {
        self.checkToken = checkToken
        self.client = client; self.settings = settings; self.queue = queue
        self.pinnedFamily = pinnedFamily; self.pinnedLocal = pinnedLocal
    }

    /// IPv4-mapped IPv6 must never open an unmonitored IPv4 connection.
    static func isMappedIPv4(_ host: String) -> Bool {
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, host, &v6) == 1 else { return false }
        return withUnsafeBytes(of: &v6) { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            return bytes[0..<10].allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
        }
    }

    func start() {
        client.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.receiveHeader()
            case .failed, .cancelled: self.close()
            default: break
            }
        }
        client.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self, !self.closed, !self.established else { return }
            // A client that never sent a header is just discarded.
            if self.upstream != nil, self.settings != nil { self.failUpstream() } else { self.close() }
        }
    }

    func close() {
        guard !closed else { return }
        closed = true
        client.stateUpdateHandler = nil; upstream?.stateUpdateHandler = nil
        client.cancel(); upstream?.cancel()
        if established { onEvent?(destination, port, sentBytes, receivedBytes, true) }
        onClose?(); onClose = nil
    }

    private func receiveHeader() {
        guard !closed else { return }
        client.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            if let data { self.header.append(data) }
            guard self.header.count <= 16384, error == nil else { self.close(); return }
            if let range = self.header.range(of: Data("\r\n\r\n".utf8)) {
                self.pending = Data(self.header[range.upperBound...])
                let text = String(decoding: self.header[..<range.lowerBound], as: UTF8.self)
                let words = text.components(separatedBy: "\r\n")[0].split(separator: " ")
                guard words.count == 3, words[0] == "CONNECT",
                      words[2] == "HTTP/1.1" || words[2] == "HTTP/1.0" else {
                    self.reject(); return
                }
                let credentials = text.components(separatedBy: "\r\n").dropFirst().compactMap { line -> String? in
                    guard let colon = line.firstIndex(of: ":"), line[..<colon].lowercased() == "proxy-authorization" else { return nil }
                    return line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                }
                var validToken = false
                if credentials.count == 1, credentials[0].range(of: "^Bearer [a-f0-9]{64}$", options: [.regularExpression, .caseInsensitive]) != nil {
                    let supplied = Array(credentials[0].dropFirst(7).utf8), expected = Array(self.checkToken.utf8)
                    var difference: UInt8 = 0
                    for i in 0..<64 { difference |= supplied[i] ^ expected[i] }
                    validToken = difference == 0
                }
                let authority = String(words[1])
                guard let split = authority.lastIndex(of: ":"),
                      let port = UInt16(authority[authority.index(after: split)...]), port > 0 else {
                    self.reject(); return
                }
                let host = String(authority[..<split]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                self.isControl = validToken && port == 443 && (["ipwho.is", "api.ipify.org", "api6.ipify.org", "api64.ipify.org"] + IPChecker.destinationHosts).contains(host.lowercased())
                guard !host.isEmpty, host.utf8.count <= 255,
                      !host.contains(where: { $0.isWhitespace }), !host.contains("@"),
                      self.isAllowed?(host, port, self.isControl) == true else {
                    self.reject(); return
                }
                self.destination = host; self.port = port
                if self.settings == nil { self.connectCurrentNetwork() } else { self.connectSOCKS() }
            } else if done { self.close() } else { self.receiveHeader() }
        }
    }

    private func reject() {
        client.send(content: Data("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".utf8),
                    completion: .contentProcessed { [weak self] _ in self?.close() })
    }

    private func connectSOCKS() {
        guard let settings else { close(); return }
        let upstream = NWConnection(host: NWEndpoint.Host(settings.host),
                                    port: NWEndpoint.Port(rawValue: settings.port)!, using: .tcp)
        self.upstream = upstream
        upstream.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready: self.negotiate()
            case .failed:
                if self.established { self.close() } else { self.failUpstream() }
            case .waiting: self.failUpstream()
            default: break
            }
        }
        upstream.start(queue: queue)
    }

    private func connectCurrentNetwork() {
        var host = destination
        if let pinnedFamily {
            let family = pinnedFamily == .v4 ? AF_INET : AF_INET6
            var v4 = in_addr(); var v6 = in6_addr()
            if inet_pton(AF_INET, destination, &v4) == 1 {
                guard family == AF_INET else { close(); return }
            } else if inet_pton(AF_INET6, destination, &v6) == 1 {
                guard family == AF_INET6, !Self.isMappedIPv4(destination) else { close(); return }
            } else {
                var hints = addrinfo()
                hints.ai_family = family
                hints.ai_socktype = SOCK_STREAM
                var results: UnsafeMutablePointer<addrinfo>?
                let status = getaddrinfo(destination, nil, &hints, &results)
                defer { if let results { freeaddrinfo(results) } }
                guard status == 0, let first = results,
                      first.pointee.ai_family == family, let address = first.pointee.ai_addr else {
                    close(); return
                }
                var literal = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                guard getnameinfo(address, first.pointee.ai_addrlen, &literal,
                                  socklen_t(literal.count), nil, 0, NI_NUMERICHOST) == 0 else {
                    close(); return
                }
                host = String(cString: literal)
                guard !Self.isMappedIPv4(host) else { close(); return }
            }
        }
        let parameters = NWParameters.tcp
        if let pin = pinnedLocal {
            // Kill switch: bind the upstream socket to the pinned address of the
            // approved egress interface. If that interface or VPN is gone, the bind
            // fails and no packet can leave through a fallback route.
            var v4check = in_addr()
            let isV4 = inet_pton(AF_INET, host, &v4check) == 1
            var parsedV4 = in_addr(); var parsedV6 = in6_addr()
            guard let local = isV4 ? pin.v4 : pin.v6,
                  (isV4 ? inet_pton(AF_INET, local, &parsedV4) : inet_pton(AF_INET6, local, &parsedV6)) == 1,
                  isV4 || !Self.isMappedIPv4(local) else { close(); return }
            parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(local), port: .any)
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: parameters)
        upstream = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready: self.connected()
            // A single destination failing is not evidence of a changed exit IP.
            case .failed, .waiting: self.close()
            default: break
            }
        }
        connection.start(queue: queue)
    }

    private func sendUpstream(_ data: Data, next: @escaping () -> Void) {
        guard !closed else { return }
        upstream?.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self, !self.closed else { return }
            if error != nil {
                if self.established { self.close() } else { self.failUpstream() }
            } else { next() }
        })
    }

    private func readExactly(_ count: Int, next: @escaping (Data) -> Void) {
        guard !closed else { return }
        upstream?.receive(minimumIncompleteLength: count, maximumLength: count) { [weak self] data, _, _, error in
            guard let self, !self.closed else { return }
            guard error == nil, let data, data.count == count else { self.failUpstream(); return }
            next(data)
        }
    }

    private func negotiate() {
        guard let settings else { close(); return }
        let method: UInt8 = settings.username.isEmpty ? 0 : 2
        sendUpstream(Data([5, 1, method])) { [weak self] in
            self?.readExactly(2) { [weak self] data in
                guard let self else { return }
                guard data[0] == 5, data[1] == method else { self.failUpstream(); return }
                if method == 2 { self.authenticate() } else { self.requestDestination() }
            }
        }
    }

    private func authenticate() {
        guard let settings else { close(); return }
        let user = Data(settings.username.utf8), password = Data(settings.password.utf8)
        var packet = Data([1, UInt8(user.count)]); packet.append(user)
        packet.append(UInt8(password.count)); packet.append(password)
        sendUpstream(packet) { [weak self] in
            self?.readExactly(2) { [weak self] data in
                guard let self else { return }
                guard data[0] == 1, data[1] == 0 else { self.failUpstream(); return }
                self.requestDestination()
            }
        }
    }

    private func requestDestination() {
        let host = Data(destination.utf8)
        var packet = Data([5, 1, 0, 3, UInt8(host.count)])
        packet.append(host); packet.append(UInt8(port >> 8)); packet.append(UInt8(port & 255))
        sendUpstream(packet) { [weak self] in
            self?.readExactly(4) { [weak self] data in
                guard let self else { return }
                // Destination-specific refusal closes only that tunnel. SOCKS errors
                // such as authentication failure or transport loss close the entire bridge.
                guard data[0] == 5, data[2] == 0 else { self.failUpstream(); return }
                guard data[1] == 0 else { self.close(); return }
                switch data[3] {
                case 1: self.readExactly(6) { [weak self] _ in self?.connected() }
                case 4: self.readExactly(18) { [weak self] _ in self?.connected() }
                case 3:
                    self.readExactly(1) { [weak self] length in
                        self?.readExactly(Int(length[0]) + 2) { [weak self] _ in self?.connected() }
                    }
                default: self.failUpstream()
                }
            }
        }
    }

    private func connected() {
        guard !closed, isAllowed?(destination, port, isControl) == true else { close(); return }
        if ["ipwho.is", "api.ipify.org", "api6.ipify.org", "api64.ipify.org"].contains(destination.lowercased()), port == 443 { onProbeConnected?() }
        established = true
        onEvent?(destination, port, 0, 0, false)
        client.send(content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8),
                    completion: .contentProcessed { [weak self] error in
            guard let self, !self.closed, let upstream = self.upstream else { return }
            guard error == nil else { self.close(); return }
            if !self.pending.isEmpty {
                self.sentBytes += self.pending.count
                self.sendUpstream(self.pending) { [weak self] in
                    guard let self else { return }
                    self.pump(from: self.client, to: upstream, upstreamRead: false)
                }
            } else { self.pump(from: self.client, to: upstream, upstreamRead: false) }
            self.pump(from: upstream, to: self.client, upstreamRead: true)
        })
    }

    private func pump(from source: NWConnection, to target: NWConnection, upstreamRead: Bool) {
        guard !closed else { return }
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            if error != nil {
                // An established SOCKS stream can reset when its destination closes.
                // It proves nothing about the proxy's other streams or its exit IP.
                self.close(); return
            }
            if let data, !data.isEmpty {
                if upstreamRead { self.receivedBytes += data.count } else { self.sentBytes += data.count }
                target.send(content: data, completion: .contentProcessed { [weak self] error in
                    guard let self, !self.closed else { return }
                    if error != nil { self.close() }
                    else if done { self.close() }
                    else { self.pump(from: source, to: target, upstreamRead: upstreamRead) }
                })
            } else if done { self.close() }
            else { self.pump(from: source, to: target, upstreamRead: upstreamRead) }
        }
    }

    private func failUpstream() { guard !closed else { return }; close(); onUpstreamFault?() }
}

/// Resolves the local addresses of the interface that owns the default route.
/// Current-network sessions pin upstream sockets to these addresses so a lost
/// interface or VPN makes new connections fail before any packet leaves.
enum EgressPin {
    static func current() throws -> SOCKSRelay.LocalPin {
        let snapshot = NetworkSnapshot.current()
        func pick(_ interface: String, family: Int32) -> String? {
            for entry in snapshot {
                let split = entry.split(separator: "|", maxSplits: 1)
                guard split.count == 2, split[0] == interface else { continue }
                let address = String(split[1])
                if family == AF_INET {
                    var v4 = in_addr()
                    guard inet_pton(AF_INET, address, &v4) == 1, !address.hasPrefix("169.254.") else { continue }
                    return address
                }
                var v6 = in6_addr()
                guard inet_pton(AF_INET6, address, &v6) == 1,
                      !address.lowercased().hasPrefix("fe80"),
                      !RelayTunnel.isMappedIPv4(address) else { continue }
                return address
            }
            return nil
        }
        let v4Interface = try defaultInterface(inet6: false)
        guard let v4 = pick(v4Interface, family: AF_INET) else {
            throw GuardError.message("Не удалось закрепить локальный адрес исходящего интерфейса. Доступ закрыт.")
        }
        // An absent IPv6 default route is not an error: the family stays refused.
        let v6 = (try? defaultInterface(inet6: true)).flatMap { pick($0, family: AF_INET6) }
        return SOCKSRelay.LocalPin(v4: v4, v6: v6)
    }

    private static func defaultInterface(inet6: Bool) throws -> String {
        var arguments = ["-n", "get"]
        if inet6 { arguments.append("-inet6") }
        arguments.append("default")
        let output = try run("/sbin/route", arguments)
        for line in output.components(separatedBy: .newlines) {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, parts[0] == "interface", !parts[1].isEmpty, parts[1].count <= 32,
               parts[1].range(of: "^[a-z0-9]+$", options: .regularExpression) != nil { return parts[1] }
        }
        throw GuardError.message("Маршрут по умолчанию не содержит интерфейса. Доступ закрыт.")
    }

    private static func run(_ path: String, _ arguments: [String]) throws -> String {
        let failure = GuardError.message("Не удалось определить маршрут по умолчанию. Доступ закрыт.")
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        do { try process.run() } catch { throw failure }
        pipe.fileHandleForWriting.closeFile()
        let fd = pipe.fileHandleForReading.fileDescriptor
        defer { pipe.fileHandleForReading.closeFile() }
        guard fcntl(fd, F_SETFL, O_NONBLOCK) != -1 else {
            kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw failure
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        var output = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count > 0 {
                guard output.count + count <= 16384 else {
                    kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw failure
                }
                output.append(contentsOf: buffer.prefix(count))
            } else if count == 0 { break }
            else if errno != EAGAIN && errno != EINTR {
                kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw failure
            }
            if DispatchTime.now().uptimeNanoseconds >= deadline {
                kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw failure
            }
            if count < 0 { usleep(5_000) }
        }
        while process.isRunning {
            if DispatchTime.now().uptimeNanoseconds >= deadline {
                kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw failure
            }
            usleep(5_000)
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0, let text = String(data: output, encoding: .utf8),
              !text.contains("\0") else { throw failure }
        return text
    }
}
