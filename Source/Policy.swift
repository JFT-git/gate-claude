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

struct SessionPolicy {
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

    mutating func suspend() { if !requiresRestart, pinnedIP != nil { suspended = true } }
    mutating func latch(_ reason: String) { if lockedReason == nil { lockedReason = reason }; suspended = true }
    mutating func manualStop() { if !requiresRestart { pinnedIP = nil; suspended = false } }
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
