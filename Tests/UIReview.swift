import SwiftUI
import AppKit

/// Test-only view render; no start/stop, network or installed Claude interaction.
@main struct UIReview {
    @MainActor static func main() throws {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("guard-ui-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let model = GuardModel(diagnosticsURL: temporary.appendingPathComponent("diagnostics.jsonl"))
        model.host = "127.0.0.1"; model.port = "1080"; model.username = ""; model.password = ""
        model.claudePath = "/Applications/Claude.app"; model.previousStop = nil
        model.phase = "Тест интерфейса: ожидание"; model.detail = "Тестовый профиль. Claude и сеть не запускаются."
        let view = NSHostingView(rootView: GuardView(model: model))
        view.frame = NSRect(x: 0, y: 0, width: 720, height: 900)
        let window = NSWindow(contentRect: view.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = view
        window.orderFront(nil)
        RunLoop.current.run(until: Date().addingTimeInterval(0.4))
        view.layoutSubtreeIfNeeded()
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { fatalError("No bitmap") }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
        let output = CommandLine.arguments.count > 1 ? URL(fileURLWithPath: CommandLine.arguments[1]) : temporary.appendingPathComponent("macos-ui.png")
        try png.write(to: output)
        print("PASS SwiftUI view rendered with test-only model; network actions NOT RUN")
        window.orderOut(nil)
    }
}
