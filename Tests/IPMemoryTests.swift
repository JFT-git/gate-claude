import Foundation
import Darwin

@main struct IPMemoryTests {
    static var failures = 0
    static func expect(_ value: Bool, _ label: String) { print("\(value ? "PASS" : "FAIL") \(label)"); if !value { failures += 1 } }
    static func rejected(_ label: String, _ work: () throws -> Void) {
        do { try work(); expect(false, label) } catch { expect(true, label) }
    }
    static func main() throws {
        let fm = FileManager.default, root = fm.temporaryDirectory.appendingPathComponent("guard-ip-store-" + UUID().uuidString)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }
        let memory = IPMemory(url: root.appendingPathComponent("ip-memory.json"))
        expect(try memory.load() == nil, "first run has no saved IP")
        try memory.commit("203.0.113.7")
        let original = try Data(contentsOf: memory.url)
        let reopened = IPMemory(url: memory.url)
        expect(try reopened.load() == "203.0.113.7", "new store instance reads the previous IP")
        try reopened.check("203.0.113.7")
        rejected("another foreign IP cannot replace a stored pin") { try reopened.commit("203.0.113.8") }
        expect(try Data(contentsOf: memory.url) == original, "mismatch preserves exact stored data")
        let mode = (try fm.attributesOfItem(atPath: memory.url.path)[.posixPermissions] as? NSNumber)?.intValue
        expect(mode == 0o600, "IP memory has private permissions")
        try memory.reset(); expect(try memory.load() == nil, "explicit reset writes an unpinned record")
        try memory.commit("2001:db8:0:0::7")
        expect(try memory.check("2001:db8::7") == "2001:db8::7", "equivalent IPv6 remains the same pin")
        rejected("IPv4 cannot replace a pinned IPv6") { try memory.commit("203.0.113.7") }
        for invalid in ["", "{bad", "{\"version\":2,\"pinnedIP\":null}", "{\"version\":1}", "{\"version\":1,\"pinnedIP\":\"bad\"}", "{\"version\":1,\"pinnedIP\":null,\"extra\":true}", String(repeating: "x", count: 4097)] {
            try Data(invalid.utf8).write(to: memory.url)
            rejected("invalid memory blocks reading") { _ = try memory.load() }
            rejected("invalid memory cannot be silently replaced") { try memory.commit("203.0.113.7") }
            expect(try String(contentsOf: memory.url, encoding: .utf8) == invalid, "failed read preserves invalid memory for explicit reset")
            try memory.reset()
        }
        try fm.removeItem(at: memory.url)
        let target = root.appendingPathComponent("target.json")
        try original.write(to: target)
        try fm.createSymbolicLink(at: memory.url, withDestinationURL: target)
        rejected("symlink memory is rejected") { _ = try memory.load() }
        rejected("reset cannot follow a symlink") { try memory.reset() }
        expect(try Data(contentsOf: target) == original, "linked target remains unchanged")
        try fm.removeItem(at: memory.url)
        try fm.linkItem(at: target, to: memory.url)
        rejected("hard-linked memory is rejected") { _ = try memory.load() }
        rejected("reset cannot alter hard-linked memory") { try memory.reset() }
        try fm.removeItem(at: memory.url)
        try fm.createDirectory(at: memory.url, withIntermediateDirectories: false)
        rejected("directory cannot be used as IP memory") { try memory.commit("203.0.113.7") }
        print("IP MEMORY TESTS: \(failures) failures")
        exit(failures == 0 ? 0 : 1)
    }
}
