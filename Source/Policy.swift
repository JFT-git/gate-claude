import Foundation
import Darwin

enum IPIdentity {
    static func canonical(_ ip: String) throws -> String {
        var v4 = in_addr(); var v6 = in6_addr()
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if inet_pton(AF_INET, ip, &v4) == 1 {
            inet_ntop(AF_INET, &v4, &buffer, socklen_t(buffer.count))
        } else if inet_pton(AF_INET6, ip, &v6) == 1 {
            inet_ntop(AF_INET6, &v6, &buffer, socklen_t(buffer.count))
        } else { throw GuardError.message("Сервис вернул некорректный IP.") }
        return String(cString: buffer)
    }
}

/// Separate from the browser profile: stopping, upgrading or restarting Guard
/// never authorizes another exit. Only the confirmed UI reset writes nil.
struct IPMemory {
    static let mismatch = "Внешний IP не совпадает с сохранённым. Верните закреплённый IP. Перезапуск Guard не разрешает другой адрес; смена возможна только после сброса с подтверждением."
    static let unavailable = "Не удалось прочитать или сохранить закреплённый IP. Доступ закрыт. Проверьте файл памяти IP или сбросьте закрепление в интерфейсе."
    let url: URL
    static var defaultURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ClaudeProxyGuard/ip-memory.json")
    }
    private struct Document: Codable { let version: Int; let pinnedIP: String? }
    func load() throws -> String? {
        var before = stat()
        guard lstat(url.path, &before) == 0 else {
            if errno == ENOENT { return nil }
            throw GuardError.message(Self.unavailable)
        }
        guard before.st_mode & S_IFMT == S_IFREG, before.st_nlink == 1, before.st_size <= 4096 else { throw GuardError.message(Self.unavailable) }
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw GuardError.message(Self.unavailable) }
        defer { close(fd) }
        var after = stat()
        guard fstat(fd, &after) == 0, after.st_mode & S_IFMT == S_IFREG, after.st_nlink == 1,
              after.st_size <= 4096, before.st_ino == after.st_ino, before.st_dev == after.st_dev else { throw GuardError.message(Self.unavailable) }
        var buffer = [UInt8](repeating: 0, count: 4097)
        let count = read(fd, &buffer, buffer.count)
        guard count > 0, count <= 4096 else { throw GuardError.message(Self.unavailable) }
        do {
            let data = Data(buffer.prefix(count))
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(object.keys) == Set(["version", "pinnedIP"]) else { throw GuardError.message(Self.unavailable) }
            let document = try JSONDecoder().decode(Document.self, from: data)
            guard document.version == 1 else { throw GuardError.message(Self.unavailable) }
            guard let ip = document.pinnedIP else { return nil }
            guard !ip.contains("%") else { throw GuardError.message(Self.unavailable) }
            return try IPIdentity.canonical(ip)
        } catch { throw GuardError.message(Self.unavailable) }
    }
    @discardableResult func check(_ ip: String) throws -> String? {
        let saved = try load()
        if let saved, saved != (try IPIdentity.canonical(ip)) { throw GuardError.message(Self.mismatch) }
        return saved
    }
    @discardableResult func commit(_ ip: String) throws -> String {
        let canonical = try IPIdentity.canonical(ip)
        if try check(canonical) == nil { try write(canonical) }
        guard try load() == canonical else { throw GuardError.message(Self.unavailable) }
        return canonical
    }
    func reset() throws {
        try write(nil)
        guard try load() == nil else { throw GuardError.message(Self.unavailable) }
    }
    private func write(_ ip: String?) throws {
        let fm = FileManager.default, directory = url.deletingLastPathComponent()
        let temporary = directory.appendingPathComponent(".ip-memory-" + UUID().uuidString + ".tmp")
        defer { try? fm.removeItem(at: temporary) }
        do {
            try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            var parent = stat(), old = stat()
            guard lstat(directory.path, &parent) == 0, parent.st_mode & S_IFMT == S_IFDIR else { throw GuardError.message(Self.unavailable) }
            let exists = lstat(url.path, &old) == 0
            guard exists ? old.st_mode & S_IFMT == S_IFREG && old.st_nlink == 1 : errno == ENOENT else { throw GuardError.message(Self.unavailable) }
            let data = try JSONSerialization.data(withJSONObject: ["version": 1, "pinnedIP": ip.map { $0 as Any } ?? NSNull()], options: [.sortedKeys])
            let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw GuardError.message(Self.unavailable) }
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            try handle.write(contentsOf: data); try handle.synchronize(); try handle.close()
            guard rename(temporary.path, url.path) == 0 else { throw GuardError.message(Self.unavailable) }
        } catch { throw GuardError.message(Self.unavailable) }
    }
}

struct SessionPolicy {
    private(set) var destinationPins: [String: String] = [:]
    private(set) var pinnedIP: String?
    private(set) var lockedReason: String?
    private(set) var suspended = false
    var requiresRestart: Bool { lockedReason != nil }

    mutating func establish(_ report: IPReport) throws {
        guard !requiresRestart else { throw GuardError.message("Перезапустите Guard для новой сессии.") }
        try report.requireForeign()
        let ip = try IPIdentity.canonical(report.ip)
        if pinnedIP != nil { try verify(ip) } else { pinnedIP = ip; suspended = false }
    }

    mutating func verify(_ ip: String) throws {
        guard !requiresRestart else { throw GuardError.message("Перезапустите Guard для новой сессии.") }
        let canonical = try IPIdentity.canonical(ip)
        guard let baseline = pinnedIP else { throw GuardError.message("Исходный IP не подтверждён.") }
        if canonical != baseline {
            let reason = "Внешний IP изменился: \(baseline) → \(canonical). Перезапустите Guard."
            latch(reason)
            throw GuardError.message(reason)
        }
        suspended = false
    }

    mutating func verifyDestination(hostname: String, ip: String, countryCode: String) throws {
        guard !requiresRestart, pinnedIP != nil, IPChecker.destinationHosts.contains(hostname) else { throw GuardError.message("Исходный маршрут не подтверждён.") }
        let canonical = try IPIdentity.canonical(ip)
        guard countryCode.range(of: "^[A-Z]{2}$", options: .regularExpression) != nil else { throw GuardError.message("Страна маршрута Claude не определена.") }
        if countryCode == "RU" {
            let reason = "Маршрут Claude вышел через RU. Перезапустите Guard."
            latch(reason); throw GuardError.message(reason)
        }
        guard canonical == pinnedIP else {
            latch(IPMemory.mismatch); throw GuardError.message(IPMemory.mismatch)
        }
        if let baseline = destinationPins[hostname], baseline != canonical {
            let reason = "Внешний IP маршрута Claude изменился: \(baseline) → \(canonical). Перезапустите Guard."
            latch(reason); throw GuardError.message(reason)
        }
        destinationPins[hostname] = canonical
    }

    mutating func suspend() { if !requiresRestart, pinnedIP != nil { suspended = true } }
    mutating func latch(_ reason: String) { if lockedReason == nil { lockedReason = reason }; suspended = true }
    mutating func manualStop() { if !requiresRestart { pinnedIP = nil; destinationPins = [:]; suspended = false } }
}

struct LaunchProfile {
    let timezone: String
    let language: String
    static let timezones = ["Europe/Amsterdam", "Europe/London", "Europe/Berlin", "America/New_York", "Etc/UTC"]
    static let languages = ["en-US", "en-GB", "nl-NL", "de-DE", "fr-FR"]

    func validate() throws {
        guard Self.timezones.contains(timezone), TimeZone(identifier: timezone) != nil,
              Self.languages.contains(language) else { throw GuardError.message("Выберите язык и часовой пояс из списка.") }
    }
    var arguments: [String] {
        ["--lang=\(language)", "-AppleLanguages", "(\(language))", "-AppleLocale", language.replacingOccurrences(of: "-", with: "_")]
    }
    func environment(_ base: [String: String]) -> [String: String] {
        var result = base
        let locale = language.replacingOccurrences(of: "-", with: "_") + ".UTF-8"
        result["TZ"] = timezone; result["LANG"] = locale; result["LC_ALL"] = locale
        result["LC_MESSAGES"] = locale; result["LANGUAGE"] = language
        result.removeValue(forKey: "TZDIR")
        return result
    }
}

enum NetworkSnapshot {
    static func current() -> Set<String> {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return ["snapshot-error"] }
        defer { freeifaddrs(head) }
        var result = Set<String>()
        var pointer = head
        while let item = pointer {
            defer { pointer = item.pointee.ifa_next }
            let info = item.pointee
            guard let address = info.ifa_addr,
                  info.ifa_flags & UInt32(IFF_UP) != 0,
                  info.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host,
                              socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            result.insert("\(String(cString: info.ifa_name))|\(String(cString: host))")
        }
        return result
    }
}

/// The callback runs off the UI thread, so the relay can be closed even during a modal dialog.
final class LocalNetworkWatcher: @unchecked Sendable {
    private let queue = DispatchQueue(label: "local.proxyguard.addresses")
    private var timer: DispatchSourceTimer?
    private var previous = Set<String>()
    func start(baseline: Set<String>, onChange: @escaping () -> Void) {
        queue.sync {
            previous = baseline
            let source = DispatchSource.makeTimerSource(queue: queue)
            timer = source
            source.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(100))
            source.setEventHandler { [weak self] in
                guard let self else { return }
                let current = NetworkSnapshot.current()
                guard current != self.previous else { return }
                self.previous = current
                onChange()
            }
            source.resume()
        }
    }
    func stop() { queue.sync { timer?.cancel(); timer = nil } }
}
