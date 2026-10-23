import Foundation

enum DeepLink {
    static func validateClaudeDeepLink(_ value: String) -> String? {
        let bytes = Array(value.utf8)
        guard bytes.count <= 8192, value.lowercased().hasPrefix("claude://"),
              bytes.allSatisfy({ (0x21...0x7e).contains($0) && ![34, 60, 62, 92].contains($0) }) else { return nil }
        func hex(_ byte: UInt8) -> Int? {
            switch byte {
            case 48...57: return Int(byte - 48)
            case 65...70: return Int(byte - 65 + 10)
            case 97...102: return Int(byte - 97 + 10)
            default: return nil
            }
        }
        for i in bytes.indices where bytes[i] == 37 {
            guard i + 2 < bytes.count, let high = hex(bytes[i + 1]), let low = hex(bytes[i + 2]),
                  high * 16 + low > 31, high * 16 + low != 127 else { return nil }
        }
        guard let url = URLComponents(string: value), url.scheme?.lowercased() == "claude",
              url.percentEncodedHost == "claude.ai", url.percentEncodedPath == "/magic-link",
              url.port == nil, (url.user ?? "").isEmpty, (url.password ?? "").isEmpty,
              let fragment = url.percentEncodedFragment else { return nil }
        let parts = fragment.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, parts.allSatisfy({ !$0.isEmpty }) else { return nil }
        return value
    }
}

// Main-thread confined; Foundation only so the inbox can also be tested without AppKit.
@MainActor
final class DeepLinkInbox {
    static let refused = "Ссылка входа отклонена: запустите Claude через Guard и повторите вход."
    static let queued = "Ссылка входа ожидает готовности защищённой сессии."
    static let delivered = "Ссылка входа передана в работающий Claude."
    static let failed = "Не удалось передать ссылку входа. Повторите вход в Claude."
    static let expired = "Время ожидания ссылки входа истекло. Повторите вход в Claude."
    private let active: () -> Bool
    private let ready: () -> Bool
    private let deliver: (String) throws -> Void
    private let notice: (String) -> Void
    private let now: () -> TimeInterval
    private let ttl: TimeInterval
    // AppKit delivery completes asynchronously; the default injected delivery stays synchronous.
    var deliverAsync: ((String, @escaping (Bool) -> Void) -> Void)?
    private var entry: (id: UUID, url: String, expires: TimeInterval)?
    private var timer: Timer?
    private var generation = 0
    private var flight = false

    init(active: @escaping () -> Bool = { true }, ready: @escaping () -> Bool,
         deliver: @escaping (String) throws -> Void, notice: @escaping (String) -> Void,
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }, ttl: TimeInterval = 30) {
        precondition(ttl > 0 && ttl <= 60, "Invalid link lifetime")
        self.active = active; self.ready = ready; self.deliver = deliver
        self.notice = notice; self.now = now; self.ttl = ttl
    }

    func clear() {
        generation += 1; timer?.invalidate(); timer = nil; entry = nil; flight = false
    }

    @discardableResult func accept(_ raw: String) -> Bool {
        guard let url = DeepLink.validateClaudeDeepLink(raw), active(), entry == nil, !flight else {
            notice(Self.refused); return false
        }
        let id = UUID()
        entry = (id, url, now() + ttl)
        let expected = generation
        timer = Timer.scheduledTimer(withTimeInterval: ttl, repeats: false) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.generation == expected, self.entry?.id == id else { return }
                self.entry = nil; self.timer = nil; self.notice(Self.expired)
            }
        }
        if ready() { flush() } else { notice(Self.queued) }
        return true
    }

    func flush() {
        guard let entry, !flight else { return }
        guard active(), now() < entry.expires else {
            self.entry = nil; timer?.invalidate(); timer = nil; notice(Self.expired); return
        }
        guard ready() else { return }
        self.entry = nil; timer?.invalidate(); timer = nil; flight = true
        let expected = generation
        let finish: (Bool) -> Void = { [weak self] success in
            guard let self, self.generation == expected, self.flight else { return }
            self.flight = false; self.notice(success && self.active() ? Self.delivered : Self.failed)
        }
        if let deliverAsync { deliverAsync(entry.url, finish) }
        else {
            do { try deliver(entry.url); finish(true) }
            catch { finish(false) }
        }
    }
}
