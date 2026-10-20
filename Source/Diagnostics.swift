import Foundation

/// Bounded operational diagnostics. Never receives traffic records, headers or bodies.
final class GuardDiagnostics {
    struct Entry: Codable {
        let date: String
        let kind: String
        let message: String
    }
    let url: URL
    private let queue = DispatchQueue(label: "local.proxyguard.diagnostics")
    init(url: URL? = nil) {
        self.url = url ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ClaudeProxyGuard/Diagnostics/events.jsonl")
    }
    static func sanitize(_ text: String) -> String {
        var value = TrafficSanitizer.body(text)
        let urls = try? NSRegularExpression(pattern: #"https?://[^\s\"'<>]+"#)
        for match in (urls?.matches(in: value, range: NSRange(value.startIndex..., in: value)) ?? []).reversed() {
            if let range = Range(match.range, in: value) { value.replaceSubrange(range, with: TrafficSanitizer.safeURL(String(value[range]))) }
        }
        let addresses = try? NSRegularExpression(pattern: #"(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![\w])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.%]+"#)
        if let addresses {
            value = addresses.stringByReplacingMatches(in: value, range: NSRange(value.startIndex..., in: value), withTemplate: "[IP скрыт]")
        }
        return String(value.prefix(1024))
    }
    private func read() -> [Entry] {
        guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 262_144,
              let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").suffix(100).compactMap { try? JSONDecoder().decode(Entry.self, from: Data($0.utf8)) }
    }
    func previousFailure() -> String? {
        queue.sync { read().last(where: { ["blocked", "unexpected_exit"].contains($0.kind) })?.message }
    }
    func record(_ kind: String, _ message: String) {
        queue.sync {
            let entry = Entry(date: ISO8601DateFormatter().string(from: Date()), kind: kind, message: Self.sanitize(message))
            var entries = Array(read().suffix(79)); entries.append(entry)
            do {
                let directory = url.deletingLastPathComponent()
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                let encoder = JSONEncoder()
                let output = try entries.reduce(into: Data()) { data, item in data.append(try encoder.encode(item)); data.append(10) }
                try output.write(to: url, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            } catch { /* A logging failure must not terminate the guard. */ }
        }
    }
}

enum GuardRelauncher {
    /// A fresh process creates a fresh IP policy. No password is passed or saved.
    static func launch(executable: URL, arguments: [String] = ["--restarted"]) throws -> Process {
        let process = Process()
        process.executableURL = executable; process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run()
        return process
    }
}
