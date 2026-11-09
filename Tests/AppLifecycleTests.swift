import AppKit
import Darwin
import Foundation

@MainActor
final class AppLifecycleProbe: NSObject {
    private let application: NSApplication
    private let delegate: AppDelegate
    private let outputURL: URL?
    private var observer: NSObjectProtocol?
    private var checks: [String: Bool] = [:]
    private var artifacts: [String: String] = [:]
    private var failures: [String] = []
    private var finished = false
    private var finalized = false

    init(application: NSApplication, delegate: AppDelegate, outputURL: URL?) {
        self.application = application
        self.delegate = delegate
        self.outputURL = outputURL
        super.init()
    }

    func run() -> Int32 {
        application.setActivationPolicy(.accessory)
        observer = NotificationCenter.default.addObserver(forName: NSApplication.didFinishLaunchingNotification,
                                                          object: application, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.verifyLifecycle() }
        }
        NotificationCenter.default.addObserver(self, selector: #selector(applicationWillTerminate(_:)),
                                               name: NSApplication.willTerminateNotification, object: application)
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            Task { @MainActor in
                guard let self, !self.finished else { return }
                self.expect(false, "application launch completed")
                self.finished = true
                self.application.terminate(nil)
            }
        }
        application.run()
        if let observer { NotificationCenter.default.removeObserver(observer) }
        NotificationCenter.default.removeObserver(self, name: NSApplication.willTerminateNotification, object: application)
        return finishTermination()
    }

    @objc private func applicationWillTerminate(_ notification: Notification) {
        exit(finishTermination())
    }

    private func finishTermination() -> Int32 {
        guard !finalized else { return failures.isEmpty ? 0 : 1 }
        finalized = true
        expect(delegate.model.phase == "Остановлено" && !delegate.model.monitoring && !delegate.model.allowed,
               "explicit quit uses existing shutdown")
        writeProof()
        return failures.isEmpty ? 0 : 1
    }

    private func expect(_ condition: Bool, _ name: String) {
        checks[name] = condition
        if !condition { failures.append(name) }
        print("\(condition ? "PASS" : "FAIL") \(name)")
    }

    private func pump(_ interval: TimeInterval = 0.2) {
        RunLoop.main.run(until: Date().addingTimeInterval(interval))
    }

    private func snapshot(_ view: NSView, name: String) {
        guard let directory = outputURL?.deletingLastPathComponent() else { return }
        view.layoutSubtreeIfNeeded()
        view.displayIfNeeded()
        guard view.bounds.width > 0, view.bounds.height > 0,
              let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            expect(false, name + " snapshot")
            return
        }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]), !png.isEmpty else {
            expect(false, name + " snapshot")
            return
        }
        let url = directory.appendingPathComponent(name + ".png")
        do {
            try png.write(to: url)
            artifacts[name] = url.path
        } catch {
            expect(false, name + " snapshot")
        }
    }

    private func snapshot(_ image: NSImage, name: String) {
        guard let directory = outputURL?.deletingLastPathComponent() else { return }
        guard let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
              let png = bitmap.representation(using: .png, properties: [:]), !png.isEmpty else {
            expect(false, name + " snapshot")
            return
        }
        let url = directory.appendingPathComponent(name + ".png")
        do {
            try png.write(to: url)
            artifacts[name] = url.path
        } catch {
            expect(false, name + " snapshot")
        }
    }

    private func verifyLifecycle() {
        guard !finished else { return }
        finished = true
        pump()
        expect(application.activationPolicy() == .accessory, "ordinary launch is accessory")
        expect(delegate.window != nil && delegate.window?.isVisible == false,
               "ordinary launch does not show main window")
        guard let statusItem = delegate.statusItem else {
            expect(false, "status item exists")
            application.terminate(nil)
            return
        }
        expect(statusItem.isVisible, "status item is visible")
        expect(statusItem.button?.image?.isTemplate == true, "status item uses template icon")
        expect(statusItem.button?.image?.accessibilityDescription == "Claude Proxy Guard",
               "status item has accessibility description")
        if let image = statusItem.button?.image { snapshot(image, name: "macos-status-item") }

        guard let menu = statusItem.menu else {
            expect(false, "status menu exists")
            application.terminate(nil)
            return
        }
        let open = menu.item(withTitle: "Открыть Claude Proxy Guard")
        let updateRoot = menu.item(withTitle: "Обновления")
        let updates = updateRoot?.submenu?.item(withTitle: "Проверить обновления…")
        let quit = menu.item(withTitle: "Выход")
        let session = menu.items.first { $0.title.hasPrefix("Сессия:") }
        expect(open?.action == #selector(AppDelegate.showWindow), "open menu action opens main window")
        expect(updates?.action == #selector(AppDelegate.checkUpdates), "updates menu uses existing update action")
        expect(updateRoot?.submenu?.items.count == 2 && updateRoot?.submenu?.item(at: 1)?.isEnabled == false,
               "updates submenu exposes status without closing the app")
        expect(quit?.action == #selector(NSApplication.terminate(_:)), "quit menu uses NSApplication termination")
        expect(session?.isEnabled == false, "session state is informational")

        delegate.model.phase = "Постоянный IP подтверждён"
        delegate.model.detail = "Тестовая защищённая сессия; Claude и сеть не запускаются."
        delegate.model.processState = .running
        delegate.model.claudeRunning = true
        delegate.model.monitoring = true
        delegate.model.allowed = true
        delegate.menuWillOpen(menu)
        expect(session?.title == "Сессия: Постоянный IP подтверждён · Claude: \(GuardProcessState.running.title)",
               "session menu reflects live model state")

        if let open, let action = open.action {
            expect(application.sendAction(action, to: open.target, from: open), "tray open action is dispatchable")
        }
        if let updates, let action = updates.action {
            expect(application.sendAction(action, to: updates.target, from: updates), "updates menu action is dispatchable")
        }
        pump()
        expect(application.activationPolicy() == .accessory && delegate.window?.isVisible == true,
               "updates menu presents panel without leaving status-bar mode")
        expect(application.activationPolicy() == .accessory && delegate.window?.isVisible == true,
               "tray opens visible window without leaving accessory mode")
        if let contentView = delegate.window?.contentView { snapshot(contentView, name: "macos-lifecycle-window") }

        delegate.window?.close()
        pump()
        expect(delegate.window?.isVisible == false && application.activationPolicy() == .accessory,
               "closing main window returns to accessory")
        expect(statusItem.isVisible && delegate.model.claudeRunning && delegate.model.monitoring &&
               delegate.model.allowed && delegate.model.processState == .running,
               "closing window preserves protected session and tray")
        expect(!delegate.applicationShouldTerminateAfterLastWindowClosed(application),
               "last window close does not terminate application")

        expect(delegate.applicationShouldHandleReopen(application, hasVisibleWindows: false), "reopen is handled")
        pump()
        expect(delegate.window?.isVisible == true && application.activationPolicy() == .accessory,
               "reopen restores main window")
        delegate.applicationDidHide(Notification(name: NSApplication.didHideNotification))
        pump()
        expect(application.activationPolicy() == .accessory, "hide notification returns to accessory")
        _ = delegate.applicationShouldHandleReopen(application, hasVisibleWindows: false)
        pump()
        expect(delegate.window?.isVisible == true && application.activationPolicy() == .accessory,
               "reopen after hide restores window and activation")
        delegate.window?.close()
        pump()

        let url = URL(string: "claude://claude.ai/magic-link#lifecycle:proof")!
        delegate.application(application, open: [url])
        pump()
        expect(delegate.window?.isVisible == true && application.activationPolicy() == .accessory,
               "deep link opens main window")
        delegate.window?.close()
        pump()
        expect(statusItem.isVisible && application.activationPolicy() == .accessory,
               "deep link window can return to tray")

        NSStatusBar.system.removeStatusItem(statusItem)
        application.terminate(nil)
    }

    private func writeProof() {
        guard let outputURL else { return }
        let proof: [String: Any] = [
            "result": failures.isEmpty ? "PASS" : "FAIL",
            "bundleIdentifier": Bundle.main.bundleIdentifier ?? "",
            "checks": checks,
            "failures": failures,
            "artifacts": artifacts,
            "networkActions": "not run",
            "updater": "disabled for isolated lifecycle probe"
        ]
        do {
            let data = try JSONSerialization.data(withJSONObject: proof, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: outputURL, options: .atomic)
            print("Lifecycle proof: \(outputURL.path)")
        } catch {
            failures.append("write proof")
            print("FAIL write proof: \(error.localizedDescription)")
        }
    }
}

@main
struct AppLifecycleTests {
    @MainActor static func main() {
        signal(SIGPIPE, SIG_IGN)
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("guard-lifecycle-model-" + UUID().uuidString)
        try? FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        let model = GuardModel(diagnosticsURL: temporary.appendingPathComponent("diagnostics.jsonl"),
                               ipMemoryURL: temporary.appendingPathComponent("ip-memory.json"),
                               crashStoreURL: temporary.appendingPathComponent("runtime-crash.json"))
        model.previousStop = nil
        let application = NSApplication.shared
        let delegate = AppDelegate(model: model, startUpdater: false)
        application.delegate = delegate
        let outputURL = CommandLine.arguments.count > 1 ? URL(fileURLWithPath: CommandLine.arguments[1]) : nil
        let probe = AppLifecycleProbe(application: application, delegate: delegate, outputURL: outputURL)
        let result = probe.run()
        try? FileManager.default.removeItem(at: temporary)
        withExtendedLifetime(delegate) {}
        exit(result)
    }
}
