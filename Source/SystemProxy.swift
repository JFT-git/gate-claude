import Foundation
import CryptoKit
import Darwin

/// Validates static system settings; does not alter the relay's transport.
enum SystemProxy {
    struct Endpoint: Equatable {
        let host: String
        let port: Int
    }
    struct Snapshot: Equatable {
        let http: Endpoint?
        let https: Endpoint?
        let socks: Endpoint?
        var fingerprint: String {
            let route = [http, https, socks].map { endpoint in
                endpoint.map { "\($0.host):\($0.port)" } ?? "direct"
            }.joined(separator: "\n")
            return SHA256.hash(data: Data(route.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        var hasStaticProxy: Bool { http != nil || https != nil || socks != nil }
    }
    private static var failure: GuardError {
        .message("Не удалось безопасно определить прокси macOS. Выберите явный SOCKS5-прокси в Guard.")
    }

    static func capture() throws -> Snapshot {
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        process.arguments = ["--proxy"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        do { try process.run() } catch { throw failure }
        pipe.fileHandleForWriting.closeFile()
        let fd = pipe.fileHandleForReading.fileDescriptor
        defer { pipe.fileHandleForReading.closeFile() }
        guard fcntl(fd, F_SETFL, O_NONBLOCK) != -1 else {
            kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw failure
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
        var output = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count > 0 {
                guard output.count + count <= 65536 else {
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
            if count < 0 { usleep(10_000) }
        }
        // EOF alone does not prove that the command has exited.
        while process.isRunning {
            if DispatchTime.now().uptimeNanoseconds >= deadline {
                kill(process.processIdentifier, SIGKILL); process.waitUntilExit(); throw failure
            }
            usleep(10_000)
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0, let text = String(data: output, encoding: .utf8) else { throw failure }
        return try parse(text)
    }

    static func parse(_ text: String) throws -> Snapshot {
        guard text.utf8.count <= 65536, !text.contains("\0") else { throw failure }
        let lines = text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard lines.first == "<dictionary> {" else { throw failure }
        var scopes: [Set<String>] = [[]], values: [String: String] = [:]
        for line in lines.dropFirst() {
            guard !scopes.isEmpty else { throw failure }
            if line == "}" { scopes.removeLast(); continue }
            guard let separator = line.range(of: " :") else { throw failure }
            let key = String(line[..<separator.lowerBound]).lowercased()
            let suffix = String(line[separator.upperBound...])
            guard suffix.isEmpty || suffix.hasPrefix(" ") else { throw failure }
            let value = suffix.isEmpty ? "" : String(suffix.dropFirst())
            guard !key.isEmpty, scopes[scopes.count - 1].insert(key).inserted else { throw failure }
            if value == "<dictionary> {" || value == "<array> {" {
                // Effective protocol controls must be scalar values.
                if scopes.count == 1 && controlKeys.contains(key) { throw failure }
                scopes.append([])
            } else {
                guard !value.contains("{"), !value.contains("}"), !value.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { throw failure }
                if scopes.count == 1 { values[key] = value }
            }
        }
        guard scopes.isEmpty else { throw failure }
        func enabled(_ key: String) throws -> Bool {
            guard let value = values[key] else { return false }
            guard value == "0" || value == "1" else { throw failure }
            return value == "1"
        }
        guard try !enabled("proxyautoconfigenable"), (values["proxyautoconfigurlstring"] ?? "").isEmpty else { throw failure }
        func endpoint(_ prefix: String) throws -> Endpoint? {
            guard try enabled(prefix + "enable") else { return nil }
            guard let host = values[prefix + "proxy"], let rawPort = values[prefix + "port"],
                  !rawPort.isEmpty, rawPort.utf8.allSatisfy({ (48...57).contains($0) }),
                  let port = Int(rawPort), (1...65535).contains(port) else { throw failure }
            return Endpoint(host: try normalizedHost(host), port: port)
        }
        return try Snapshot(http: endpoint("http"), https: endpoint("https"), socks: endpoint("socks"))
    }
    private static let controlKeys: Set<String> = ["httpenable", "httpproxy", "httpport", "httpsenable", "httpsproxy", "httpsport", "socksenable", "socksproxy", "socksport", "proxyautoconfigenable", "proxyautoconfigurlstring"]
    private static func normalizedHost(_ raw: String) throws -> String {
        guard !raw.isEmpty, raw.utf8.count <= 253,
              raw.range(of: "^[A-Za-z0-9.:-]+$", options: .regularExpression) != nil else { throw failure }
        if let ip = try? IPIdentity.canonical(raw) { return ip }
        let host = raw.lowercased()
        guard !host.contains(":"), host.range(of: "^[0-9.]+$", options: .regularExpression) == nil,
              host.range(of: "^0x[0-9a-f]+$", options: .regularExpression) == nil else { throw failure }
        let dns = host.hasSuffix(".") ? String(host.dropLast()) : host
        guard dns.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({
            !$0.isEmpty && $0.count <= 63 && $0.range(of: "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", options: .regularExpression) != nil
        }) else { throw failure }
        return dns
    }
}
