import Foundation
import Darwin

struct RuntimeIdentity: Codable, Equatable {
    let ownerPID: Int32
    let ownerUID: UInt32
    let pid: Int32
    let pgid: Int32
    let startTime: UInt64
    let path: String
    var frozen: Bool
}

struct RuntimeProcessSample: Equatable {
    let uid: UInt32
    let pgid: Int32
    var startTime: UInt64
    let path: String
}

struct ProcessSystem {
    var currentPID: () -> Int32 = { getpid() }
    var currentUID: () -> UInt32 = { getuid() }
    var currentPGID: () -> Int32 = { getpgrp() }
    var barrierGID: () -> UInt32? = {
        guard let group = getgrnam("_cpguard") else { return nil }
        return UInt32(group.pointee.gr_gid)
    }
    var sample: (Int32) -> RuntimeProcessSample? = { pid in
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0,
              size >= MemoryLayout<kinfo_proc>.stride else { return nil }
        let started = info.kp_proc.p_starttime
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return RuntimeProcessSample(uid: UInt32(info.kp_eproc.e_ucred.cr_uid),
                                    pgid: info.kp_eproc.e_pgid,
                                    startTime: UInt64(started.tv_sec) * 1_000_000 + UInt64(started.tv_usec),
                                    path: String(cString: buffer))
    }
    var children: (Int32) -> [Int32] = { pgrep(["-P", String($0)]) }
    var members: (Int32) -> [Int32] = { pgrep(["-g", String($0)]) }
    var send: (Int32, Int32) -> Bool = { kill($0, $1) == 0 }
    var exists: (Int32) -> Bool = { kill($0, 0) == 0 || errno == EPERM }

    private static func pgrep(_ arguments: [String]) -> [Int32] {
        let task = Process(), output = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        task.arguments = arguments
        task.standardOutput = output
        task.standardError = FileHandle.nullDevice
        do { try task.run() } catch { return [] }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        guard task.terminationStatus == 0 else { return [] }
        return String(decoding: data, as: UTF8.self).split(separator: "\n").compactMap { Int32($0) }
    }

    static let live = ProcessSystem()
}

enum ProcessSignalError: LocalizedError {
    case unsafeGroup
    case identityChanged
    case signalFailed(Int32)

    var errorDescription: String? {
        switch self {
        case .unsafeGroup: return "Безопасная группа процессов Claude не подтверждена."
        case .identityChanged: return "Идентичность процесса Claude изменилась; сигнал не отправлен."
        case .signalFailed(let signal): return "Не удалось отправить Claude сигнал \(signal)."
        }
    }
}

struct ProcessSignaler {
    let system: ProcessSystem

    func safeGroup(_ pgid: Int32) -> Bool {
        pgid > 1 && pgid != system.currentPGID() && pgid != Int32(bitPattern: system.barrierGID() ?? UInt32.max)
    }

    func matches(_ identity: RuntimeIdentity, sample: RuntimeProcessSample) -> Bool {
        identity.ownerUID == sample.uid && identity.pid > 1 && identity.pgid == sample.pgid &&
        identity.startTime == sample.startTime && Self.path(sample.path, belongsTo: identity.path)
    }

    func matchesLeader(_ identity: RuntimeIdentity) -> Bool {
        guard safeGroup(identity.pgid), let sample = system.sample(identity.pid) else { return false }
        return matches(identity, sample: sample)
    }

    func signal(_ identity: RuntimeIdentity, _ signal: Int32, allowOrphanedLeader: Bool = false) throws {
        guard safeGroup(identity.pgid) else { throw ProcessSignalError.unsafeGroup }
        if let leader = system.sample(identity.pid) {
            guard matches(identity, sample: leader) else { throw ProcessSignalError.identityChanged }
        } else {
            guard allowOrphanedLeader else { throw ProcessSignalError.identityChanged }
            let members = system.members(identity.pgid)
            if members.isEmpty { return }
            for pid in members {
                guard pid != system.currentPID(), let sample = system.sample(pid),
                      sample.uid == identity.ownerUID, sample.pgid == identity.pgid,
                      Self.path(sample.path, belongsTo: identity.path) else { throw ProcessSignalError.identityChanged }
            }
        }
        guard system.send(-identity.pgid, signal) else { throw ProcessSignalError.signalFailed(signal) }
    }

    func stop(_ identity: RuntimeIdentity) throws { try signal(identity, SIGSTOP) }
    func resume(_ identity: RuntimeIdentity, allowOrphanedLeader: Bool = false) throws {
        try signal(identity, SIGCONT, allowOrphanedLeader: allowOrphanedLeader)
    }
    func terminate(_ identity: RuntimeIdentity, allowOrphanedLeader: Bool = false) throws {
        try signal(identity, SIGTERM, allowOrphanedLeader: allowOrphanedLeader)
    }
    func kill(_ identity: RuntimeIdentity, allowOrphanedLeader: Bool = true) throws {
        try signal(identity, SIGKILL, allowOrphanedLeader: allowOrphanedLeader)
    }

    func terminateFrozen(_ identity: RuntimeIdentity) throws {
        try terminate(identity)
        try resume(identity)
    }

    static func path(_ candidate: String, belongsTo runtime: String) -> Bool {
        let root = URL(fileURLWithPath: runtime).standardizedFileURL.resolvingSymlinksInPath().path
        let path = URL(fileURLWithPath: candidate).standardizedFileURL.resolvingSymlinksInPath().path
        return root != "/" && path.hasPrefix(root + "/")
    }

    static func capture(visiblePID: Int32, barrierLaunched: Bool, path: String,
                        system: ProcessSystem = .live, timeout: TimeInterval = 2) throws -> RuntimeIdentity {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            let candidates = barrierLaunched ? system.children(visiblePID) : [visiblePID]
            let valid = candidates.filter { pid in
                guard pid > 1, let sample = system.sample(pid), sample.pgid == pid,
                      sample.uid == system.currentUID(), Self.path(sample.path, belongsTo: path) else { return false }
                return ProcessSignaler(system: system).safeGroup(sample.pgid)
            }
            if valid.count == 1, let sample = system.sample(valid[0]) {
                return RuntimeIdentity(ownerPID: system.currentPID(), ownerUID: system.currentUID(),
                                       pid: valid[0], pgid: sample.pgid, startTime: sample.startTime,
                                       path: path, frozen: false)
            }
            if valid.count > 1 { throw ProcessSignalError.unsafeGroup }
            Thread.sleep(forTimeInterval: 0.02)
        } while Date() < deadline
        throw ProcessSignalError.unsafeGroup
    }
}

struct RuntimeCrashStore {
    let url: URL

    static var defaultURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ClaudeProxyGuard/runtime-crash.json")
    }

    func write(_ identity: RuntimeIdentity) throws {
        let manager = FileManager.default
        let directory = url.deletingLastPathComponent()
        try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let temporary = directory.appendingPathComponent(".runtime-crash-" + UUID().uuidString + ".tmp")
        defer { try? manager.removeItem(at: temporary) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(identity)
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw GuardError.message("Не удалось записать состояние процесса Claude.") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try handle.close()
        guard rename(temporary.path, url.path) == 0 else { throw GuardError.message("Не удалось сохранить состояние процесса Claude.") }
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY)
        if directoryFD >= 0 {
            fsync(directoryFD)
            close(directoryFD)
        }
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    func load() -> RuntimeIdentity? {
        var metadata = stat()
        guard lstat(url.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_nlink == 1, metadata.st_size > 0, metadata.st_size <= 16_384 else { return nil }
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        let data = FileHandle(fileDescriptor: fd, closeOnDealloc: false).readDataToEndOfFile()
        guard let identity = try? JSONDecoder().decode(RuntimeIdentity.self, from: data),
              identity.ownerPID > 0, identity.pid > 1, identity.pgid > 1,
              identity.path.hasPrefix("/"), !identity.path.contains("\n") else { return nil }
        return identity
    }

    func remove(matching identity: RuntimeIdentity? = nil) {
        if let identity, let current = load() {
            guard current.ownerPID == identity.ownerPID, current.pid == identity.pid,
                  current.pgid == identity.pgid, current.startTime == identity.startTime,
                  current.path == identity.path else { return }
        }
        try? FileManager.default.removeItem(at: url)
        let directoryFD = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY)
        if directoryFD >= 0 { fsync(directoryFD); close(directoryFD) }
    }
}

enum RuntimeCrashRecovery {
    @discardableResult
    static func clean(store: RuntimeCrashStore, system: ProcessSystem = .live) -> Bool {
        guard let identity = store.load() else {
            if FileManager.default.fileExists(atPath: store.url.path) { store.remove() }
            return true
        }
        guard identity.ownerPID != system.currentPID(), !system.exists(identity.ownerPID) else { return true }
        let signaler = ProcessSignaler(system: system)
        do {
            if identity.frozen { try signaler.resume(identity, allowOrphanedLeader: true) }
            try signaler.terminate(identity, allowOrphanedLeader: true)
            try signaler.kill(identity)
            store.remove(matching: identity)
            return true
        } catch ProcessSignalError.identityChanged {
            if system.sample(identity.pid) != nil { store.remove(matching: identity); return true }
            return false
        } catch { return false }
    }
}

enum FreezeWindow {
    static let duration: TimeInterval = 20
    static let retry: TimeInterval = 1
    static let drain: TimeInterval = 5

    static func remaining(at now: TimeInterval, deadline: TimeInterval) -> Int {
        max(0, Int(ceil(deadline - now)))
    }

    static func retryDelay(at now: TimeInterval, deadline: TimeInterval) -> TimeInterval {
        max(0, min(retry, deadline - now))
    }
}

struct FreezeSession {
    let id = UUID()
    let deadline: TimeInterval
    let identity: RuntimeIdentity
}

enum GuardProcessState: String {
    case stopped
    case running
    case frozen
    case draining

    var title: String {
        switch self {
        case .stopped: return "Остановлен"
        case .running: return "Запущен"
        case .frozen: return "Заморожен"
        case .draining: return "Завершается"
        }
    }
}
