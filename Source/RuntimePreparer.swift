import Foundation
import CryptoKit

struct PreparedRuntime {
    let bundleURL: URL
    let profileURL: URL
    let sourceVersion: String
    let sourceSignatureValid: Bool
}

/// Builds a private local runtime from the user's installed app. Vendor files are never shipped.
enum RuntimePreparer {
    static let identifier = "local.proxyguard.claude.runtime"

    static func prepare(source: URL, bootstrapURL: URL, cacheRoot: URL? = nil) async throws -> PreparedRuntime {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do { continuation.resume(returning: try prepareSync(source: source, bootstrapURL: bootstrapURL, cacheRoot: cacheRoot)) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    private static func run(_ executable: String, _ arguments: [String]) throws -> Int32 {
        let task = Process(); task.executableURL = URL(fileURLWithPath: executable); task.arguments = arguments
        task.standardOutput = FileHandle.nullDevice; task.standardError = FileHandle.nullDevice
        try task.run(); task.waitUntilExit(); return task.terminationStatus
    }

    static func prepareSync(source: URL, bootstrapURL: URL, cacheRoot: URL?) throws -> PreparedRuntime {
        let fm = FileManager.default
        guard let sourceBundle = Bundle(url: source), sourceBundle.bundleIdentifier == "com.anthropic.claudefordesktop",
              let sourceExecutable = sourceBundle.executableURL else { throw GuardError.message("Выберите установленный Claude.app.") }
        let boot = try Data(contentsOf: bootstrapURL)
        let archive = source.appendingPathComponent("Contents/Resources/app.asar")
        let original = try Data(contentsOf: archive, options: .mappedIfSafe)
        let header = try ASARArchive(data: original)
        let version = sourceBundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        var fingerprint = Data(header.rawHeader)
        fingerprint.append(boot); fingerprint.append(try Data(contentsOf: sourceExecutable))
        fingerprint.append(Data("guard-runtime-v3".utf8))
        let digest = ASARArchive.hash(fingerprint)
        let root = cacheRoot ?? fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ClaudeProxyGuard", isDirectory: true)
        let directory = root.appendingPathComponent("Runtime-" + String(digest.prefix(16)), isDirectory: true)
        let destination = directory.appendingPathComponent("Claude.app", isDirectory: true)
        let profile = root.appendingPathComponent("Profile", isDirectory: true)
        let sourceVerified = try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", source.path]) == 0
        if fm.fileExists(atPath: destination.path),
           (try? run("/usr/bin/codesign", ["--verify", "--deep", "--strict", destination.path])) == 0 {
            return PreparedRuntime(bundleURL: destination, profileURL: profile, sourceVersion: version, sourceSignatureValid: sourceVerified)
        }
        try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try fm.createDirectory(at: profile, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let staging = root.appendingPathComponent("Preparing-" + UUID().uuidString, isDirectory: true)
        try fm.createDirectory(at: staging, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: staging) }
        let copy = staging.appendingPathComponent("Claude.app", isDirectory: true)
        if try run("/bin/cp", ["-cR", source.path, copy.path]) != 0 {
            if fm.fileExists(atPath: copy.path) { try fm.removeItem(at: copy) }
            try fm.copyItem(at: source, to: copy)
        }
        let result = try header.addBootstrap(boot)
        try result.archive.write(to: copy.appendingPathComponent("Contents/Resources/app.asar"), options: .atomic)
        let infoURL = copy.appendingPathComponent("Contents/Info.plist")
        guard var info = try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as? [String: Any],
              var integrity = info["ElectronAsarIntegrity"] as? [String: Any] else {
            throw GuardError.message("Неизвестный формат метаданных Claude. Исходник не изменён.")
        }
        integrity["Resources/app.asar"] = ["algorithm": "SHA256", "hash": result.headerHash]
        info["ElectronAsarIntegrity"] = integrity
        info["CFBundleIdentifier"] = identifier
        // Keep the original bundle filename/name so Electron can locate its helper executables.
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL, options: .atomic)
        guard try run("/usr/bin/codesign", ["--force", "--deep", "--sign", "-", "--options", "0", copy.path]) == 0,
              try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", copy.path]) == 0 else {
            throw GuardError.message("Не удалось подписать локальную копию Claude. Исходник не изменён.")
        }
        if fm.fileExists(atPath: directory.path) { try fm.removeItem(at: directory) }
        try fm.moveItem(at: staging, to: directory)
        return PreparedRuntime(bundleURL: destination, profileURL: profile, sourceVersion: version, sourceSignatureValid: sourceVerified)
    }
}

struct ASARArchive {
    let original: Data
    let rawHeader: Data
    let payloadStart: Int
    let json: [String: Any]
    init(data: Data) throws {
        func u32(_ offset: Int) -> Int {
            (0..<4).reduce(0) { $0 | (Int(data[offset + $1]) << ($1 * 8)) }
        }
        guard data.count > 16 else { throw GuardError.message("Архив Claude повреждён.") }
        let headerSize = u32(4), stringSize = u32(12)
        guard headerSize >= stringSize + 8, headerSize < data.count - 8, stringSize > 0, 16 + stringSize <= data.count,
              let decoded = try JSONSerialization.jsonObject(with: data.subdata(in: 16..<16 + stringSize)) as? [String: Any] else {
            throw GuardError.message("Неизвестный формат ASAR Claude.")
        }
        original = data; rawHeader = data.subdata(in: 16..<16 + stringSize); payloadStart = 8 + headerSize; json = decoded
    }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private func item(_ components: ArraySlice<String>, in node: [String: Any]) throws -> [String: Any] {
        guard let name = components.first, let files = node["files"] as? [String: Any], let child = files[name] as? [String: Any] else {
            throw GuardError.message("Файл входа Claude не найден в ASAR.")
        }
        return components.count == 1 ? child : try item(components.dropFirst(), in: child)
    }
    private func content(_ item: [String: Any]) throws -> Data {
        guard let offset = item["offset"] as? String, let number = Int(offset), number >= 0,
              let count = item["size"] as? Int, count >= 0, number + count <= original.count - payloadStart else {
            throw GuardError.message("Некорректная запись ASAR.")
        }
        return original.subdata(in: payloadStart + number..<payloadStart + number + count)
    }
    private func replacing(_ components: ArraySlice<String>, value: [String: Any], in node: [String: Any]) throws -> [String: Any] {
        guard let name = components.first, var files = node["files"] as? [String: Any] else { throw GuardError.message("Некорректная структура ASAR.") }
        var changed = node
        if components.count == 1 { files[name] = value }
        else {
            guard let child = files[name] as? [String: Any] else { throw GuardError.message("Каталог ASAR не найден.") }
            files[name] = try replacing(components.dropFirst(), value: value, in: child)
        }
        changed["files"] = files; return changed
    }
    func addBootstrap(_ bootstrap: Data) throws -> (archive: Data, headerHash: String) {
        let package = try content(item(["package.json"][...], in: json))
        guard let metadata = try JSONSerialization.jsonObject(with: package) as? [String: Any],
              let main = metadata["main"] as? String else { throw GuardError.message("Не найден входной модуль Claude.") }
        let components = main.split(separator: "/").map(String.init).filter { $0 != "." }
        guard !main.hasPrefix("/"), !components.contains(".."), main.hasSuffix(".js"), !components.isEmpty else {
            throw GuardError.message("Неизвестный тип входного модуля Claude.")
        }
        let entry = try content(item(components[...], in: json))
        let marker = Data("\"use strict\";require(\"./proxy-guard-boot.cjs\");\n".utf8)
        let modified = marker + entry
        var body = original.subdata(in: payloadStart..<original.count)
        func file(_ data: Data, offset: Int) -> [String: Any] {
            let blockSize = 4_194_304
            let hashes = stride(from: 0, to: data.count, by: blockSize).map { ASARArchive.hash(data.subdata(in: $0..<min($0 + blockSize, data.count))) }
            return ["size": data.count, "offset": String(offset),
                    "integrity": ["algorithm": "SHA256", "hash": Self.hash(data), "blockSize": blockSize, "blocks": hashes]]
        }
        var changed = try replacing(components[...], value: file(modified, offset: body.count), in: json)
        body.append(modified)
        var bootstrapPath = Array(components.dropLast()); bootstrapPath.append("proxy-guard-boot.cjs")
        changed = try replacing(bootstrapPath[...], value: file(bootstrap, offset: body.count), in: changed)
        body.append(bootstrap)
        let raw = try JSONSerialization.data(withJSONObject: changed, options: [.sortedKeys, .withoutEscapingSlashes])
        func u32(_ value: Int) -> Data { var number = UInt32(value).littleEndian; return withUnsafeBytes(of: &number) { Data($0) } }
        var payload = u32(raw.count) + raw
        payload.append(Data(repeating: 0, count: (4 - raw.count % 4) % 4))
        let header = u32(payload.count) + payload
        return (u32(4) + u32(header.count) + header + body, Self.hash(raw))
    }
}
