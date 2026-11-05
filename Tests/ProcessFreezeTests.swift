import Foundation
import Darwin

@main struct ProcessFreezeTests {
    final class Fixture {
        var samples: [Int32: RuntimeProcessSample] = [:]
        var children: [Int32: [Int32]] = [:]
        var signals: [(pid: Int32, signal: Int32)] = []
        var ownerExists = false
        var groupExists = true
        var failSignals = false
        var failKill = false

        func system(currentPGID: Int32 = 100, barrierGID: UInt32 = 380) -> ProcessSystem {
            var system = ProcessSystem()
            system.currentPID = { 50 }
            system.currentUID = { 501 }
            system.currentPGID = { currentPGID }
            system.barrierGID = { barrierGID }
            system.sample = { [weak self] in self?.samples[$0] }
            system.children = { [weak self] in self?.children[$0] ?? [] }
            system.members = { [weak self] group in
                self?.samples.filter { $0.value.pgid == group }.map(\.key) ?? []
            }
            system.send = { [weak self] pid, signal in
                guard let self, !self.failSignals else { return false }
                self.signals.append((pid, signal))
                return !(self.failKill && signal == SIGKILL)
            }
            system.exists = { [weak self] pid in
                guard let self else { return false }
                if pid < 0 { return self.groupExists && self.samples.values.contains { $0.pgid == -pid } }
                return self.ownerExists
            }
            return system
        }

        func identity(pgid: Int32 = 400, start: UInt64 = 1234, frozen: Bool = false) -> RuntimeIdentity {
            RuntimeIdentity(ownerPID: 50, ownerUID: 501, pid: 400, pgid: pgid, startTime: start,
                            path: "/tmp/guard-test/Claude.app", frozen: frozen)
        }

        func install(_ identity: RuntimeIdentity) {
            samples[identity.pid] = RuntimeProcessSample(uid: identity.ownerUID, pgid: identity.pgid,
                startTime: identity.startTime, path: identity.path + "/Contents/MacOS/Claude")
        }
    }

    static var failures = 0
    static func expect(_ value: Bool, _ label: String) {
        print("\(value ? "PASS" : "FAIL") \(label)")
        if !value { failures += 1 }
    }

    static func native(host: String, fixture: String) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("guard-freeze-native-" + UUID().uuidString)
        let executable = root.appendingPathComponent("Claude.app/Contents/MacOS/Claude")
        try FileManager.default.createDirectory(at: executable.deletingLastPathComponent(), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.copyItem(at: URL(fileURLWithPath: fixture), to: executable)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: host)
        process.arguments = [executable.path, "30"]
        try process.run()
        defer { if process.isRunning { kill(process.processIdentifier, SIGKILL) } }
        let identity = try ProcessSignaler.capture(visiblePID: process.processIdentifier, barrierLaunched: false,
                                                  path: root.appendingPathComponent("Claude.app").path, timeout: 2)
        let signaler = ProcessSignaler(system: .live)
        expect(identity.pid == process.processIdentifier && identity.pgid == identity.pid && identity.pgid != getpgrp(),
               "native GuardHost establishes independent launch-time process group")
        try signaler.stop(identity)
        Thread.sleep(forTimeInterval: 0.1)
        let status = Process()
        let output = Pipe()
        status.executableURL = URL(fileURLWithPath: "/bin/ps")
        status.arguments = ["-o", "stat=", "-p", String(identity.pid)]
        status.standardOutput = output
        try status.run()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        status.waitUntilExit()
        expect(text.contains("T"), "native SIGSTOP freezes the entire runtime leader")
        try signaler.resume(identity)
        Thread.sleep(forTimeInterval: 0.1)
        let continued = Process()
        let continuedOutput = Pipe()
        continued.executableURL = URL(fileURLWithPath: "/bin/ps")
        continued.arguments = ["-o", "stat=", "-p", String(identity.pid)]
        continued.standardOutput = continuedOutput
        try continued.run()
        let continuedText = String(decoding: continuedOutput.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        continued.waitUntilExit()
        expect(!continuedText.contains("T"), "native identity-checked SIGCONT resumes the runtime")
        try signaler.kill(identity, allowOrphanedLeader: false)
        process.waitUntilExit()
        expect(!process.isRunning, "native runtime cleanup kills the captured process group")
    }

    static func main() throws {
        setbuf(stdout, nil)
        signal(SIGPIPE, SIG_IGN)
        let fixture = Fixture()
        let identity = fixture.identity()
        fixture.install(identity)
        let signaler = ProcessSignaler(system: fixture.system())
        try signaler.stop(identity)
        try signaler.resume(identity)
        expect(fixture.signals.map(\.signal) == [SIGSTOP, SIGCONT] && fixture.signals.allSatisfy { $0.pid == -400 },
               "pause and resume signal only the captured safe process group")

        fixture.signals = []
        var reused = fixture.samples[400]!
        reused.startTime += 1
        fixture.samples[400] = reused
        do {
            try signaler.resume(identity)
            expect(false, "PID reuse refuses identity-mismatched signals")
        } catch { expect(fixture.signals.isEmpty, "PID reuse refuses identity-mismatched signals") }

        fixture.install(identity)
        let ownGroup = ProcessSignaler(system: fixture.system(currentPGID: 400))
        do {
            try ownGroup.stop(identity)
            expect(false, "Guard process group is never signalled")
        } catch { expect(fixture.signals.isEmpty, "Guard process group is never signalled") }
        let barrierGroup = ProcessSignaler(system: fixture.system(barrierGID: 400))
        do {
            try barrierGroup.stop(identity)
            expect(false, "_cpguard GID is never accepted as PGID")
        } catch { expect(fixture.signals.isEmpty, "_cpguard GID is never accepted as PGID") }

        fixture.failSignals = true
        do {
            try signaler.stop(identity)
            expect(false, "signal failures are surfaced")
        } catch { expect(true, "signal failures are surfaced") }
        fixture.failSignals = false

        let captured = try ProcessSignaler.capture(visiblePID: 400, barrierLaunched: false,
                                                  path: identity.path, system: fixture.system(), timeout: 0)
        expect(captured.pid == 400 && captured.pgid == 400 && captured.startTime == 1234 && captured.path == identity.path,
               "launch capture records PID PGID start time and runtime path")
        fixture.children[99] = [400]
        let barrierCapture = try ProcessSignaler.capture(visiblePID: 99, barrierLaunched: true,
                                                        path: identity.path, system: fixture.system(), timeout: 0)
        expect(barrierCapture.pid == 400 && barrierCapture.pgid == 400, "barrier launch captures GuardHost child through pgrep")
        fixture.children[99] = []
        do {
            _ = try ProcessSignaler.capture(visiblePID: 99, barrierLaunched: true, path: identity.path,
                                            system: fixture.system(), timeout: 0)
            expect(false, "launch aborts when a safe group cannot be established")
        } catch { expect(true, "launch aborts when a safe group cannot be established") }

        expect(FreezeWindow.remaining(at: 0, deadline: 20) == 20 && FreezeWindow.remaining(at: 1, deadline: 20) == 19,
               "freeze countdown is 20 seconds and 19 after one second")
        expect(FreezeWindow.retryDelay(at: 1, deadline: 20) == 1 && FreezeWindow.retryDelay(at: 19.5, deadline: 20) == 0.5,
               "validation retries about one second without passing the deadline")
        let deadline = FreezeWindow.duration
        _ = FreezeWindow.retryDelay(at: 5, deadline: deadline)
        expect(deadline == 20 && FreezeWindow.remaining(at: 20, deadline: deadline) == 0 && FreezeWindow.drain == 5,
               "freeze deadline never extends and graceful drain is bounded to five seconds")

        let root = FileManager.default.temporaryDirectory.appendingPathComponent("guard-freeze-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let store = RuntimeCrashStore(url: root.appendingPathComponent("crash.json"))
        let stale = RuntimeIdentity(ownerPID: 60, ownerUID: 501, pid: 400, pgid: 400, startTime: 1234,
                                    path: "/tmp/guard-test/Claude.app", frozen: true)
        try store.write(stale)
        let stored = store.load()
        let mode = try FileManager.default.attributesOfItem(atPath: store.url.path)[.posixPermissions] as? NSNumber
        expect(stored == stale && mode?.intValue == 0o600,
               "crash record atomically persists owner PID PGID start path and frozen state")
        fixture.signals = []
        fixture.ownerExists = false
        let cleaned = RuntimeCrashRecovery.clean(store: store, system: fixture.system())
        expect(cleaned && fixture.signals.map(\.signal) == [SIGCONT, SIGTERM, SIGKILL] && store.load() == nil,
               "stale-owner crash cleanup performs identity-checked CONT TERM KILL")
        try store.write(stale)
        fixture.signals = []
        fixture.ownerExists = true
        _ = RuntimeCrashRecovery.clean(store: store, system: fixture.system())
        expect(fixture.signals.isEmpty && store.load() != nil, "live-owner crash record receives no recovery signals")
        fixture.ownerExists = false
        reused.startTime += 10
        fixture.samples[400] = reused
        _ = RuntimeCrashRecovery.clean(store: store, system: fixture.system())
        expect(fixture.signals.isEmpty && store.load() == nil, "stale or reused runtime record is removed without continuation")

        try store.write(stale)
        fixture.samples.removeValue(forKey: 400)
        fixture.samples[401] = RuntimeProcessSample(uid: 501, pgid: 400, startTime: 1235,
                                                    path: stale.path + "/Contents/Frameworks/Claude Helper")
        fixture.signals = []
        let orphanCleaned = RuntimeCrashRecovery.clean(store: store, system: fixture.system())
        expect(orphanCleaned && fixture.signals.map(\.signal) == [SIGCONT, SIGTERM, SIGKILL] && store.load() == nil,
               "crash cleanup thaws and terminates a verified orphaned runtime group")

        try store.write(stale)
        fixture.signals = []
        fixture.failKill = true
        fixture.groupExists = false
        let vanishedCleaned = RuntimeCrashRecovery.clean(store: store, system: fixture.system())
        expect(vanishedCleaned && fixture.signals.map(\.signal) == [SIGCONT, SIGTERM, SIGKILL] && store.load() == nil,
               "crash cleanup removes the record when the runtime group exits before SIGKILL: cleaned=\(vanishedCleaned), signals=\(fixture.signals), record=\(store.load() != nil)")

        if CommandLine.arguments.count == 3 { try native(host: CommandLine.arguments[1], fixture: CommandLine.arguments[2]) }
        print("PROCESS FREEZE TESTS: \(failures) failures")
        exit(failures == 0 ? 0 : 1)
    }
}
