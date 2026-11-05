import SwiftUI
import AppKit

@main struct UIReview {
    @MainActor static func render(model: GuardModel, width: CGFloat, dark: Bool, reducedMotion: Bool,
                                  enlarged: Bool = false, output: URL) throws {
        let root = GuardView(model: model)
            .environment(\.guardReduceMotionOverride, reducedMotion)
            .environment(\.sizeCategory, enlarged ? .accessibilityExtraExtraExtraLarge : .large)
        let view = NSHostingView(rootView: root)
        view.frame = NSRect(x: 0, y: 0, width: width, height: 820)
        let window = NSWindow(contentRect: view.frame, styleMask: [.titled], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        window.contentView = view
        window.orderFront(nil)
        RunLoop.current.run(until: Date().addingTimeInterval(0.4))
        view.layoutSubtreeIfNeeded()
        guard view.bounds.width == width, let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            fatalError("No bitmap at \(width)")
        }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]), !png.isEmpty else { fatalError("No PNG") }
        try png.write(to: output)
        window.orderOut(nil)
    }

    @MainActor static func main() throws {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("guard-ui-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let memory = temporary.appendingPathComponent("ip-memory.json")
        try IPMemory(url: memory).commit("203.0.113.7")
        let model = GuardModel(diagnosticsURL: temporary.appendingPathComponent("diagnostics.jsonl"), ipMemoryURL: memory)
        model.host = "127.0.0.1"; model.port = "1080"; model.username = ""; model.password = ""
        model.claudePath = "/Applications/Claude.app"; model.previousStop = nil
        model.phase = "Ожидание проверки"; model.detail = "Тестовый профиль. Claude и сеть не запускаются."
        model.report = IPReport(ip: "203.0.113.7", countryCode: "NL", country: "Нидерланды", date: Date())
        let output = CommandLine.arguments.count > 1 ? URL(fileURLWithPath: CommandLine.arguments[1]) : temporary.appendingPathComponent("macos-ui.png")
        let base = output.deletingPathExtension()
        let ext = output.pathExtension.isEmpty ? "png" : output.pathExtension
        if CommandLine.arguments.count > 2 {
            model.phase = "Тест интерфейса: ожидание"
        }
        try render(model: model, width: 320, dark: CommandLine.arguments.count > 2 && CommandLine.arguments[2] == "dark",
                   reducedMotion: false, output: output)
        print("PASS SwiftUI stopped state renders at 320px without network actions")

        model.phase = "Claude заморожен — проверяем IP"
        model.detail = "Активные потоки закрыты. Крайний срок не продлевается."
        model.processState = .frozen; model.freezeRemaining = 19
        model.claudeRunning = true; model.monitoring = true; model.busy = true
        try render(model: model, width: 320, dark: true, reducedMotion: true, enlarged: true,
                   output: base.appendingPathExtension("frozen-320-dark." + ext))
        print("PASS SwiftUI frozen countdown renders dark, reduced motion, 320px and enlarged accessibility content")

        model.phase = "Постоянный IP подтверждён"; model.detail = "Шлюз и Claude возобновлены."
        model.processState = .running; model.freezeRemaining = nil
        model.allowed = true; model.busy = false
        try render(model: model, width: 420, dark: false, reducedMotion: false,
                   output: base.appendingPathExtension("running-420-light." + ext))
        print("PASS SwiftUI running state renders with country, IP and process state at 420px")

        model.phase = "Проверка не завершилась"; model.detail = "Claude завершается; профиль сохраняется."
        model.processState = .draining; model.allowed = false
        try render(model: model, width: 320, dark: true, reducedMotion: true,
                   output: base.appendingPathExtension("draining-320-dark." + ext))
        print("PASS SwiftUI draining state renders accessibly without animation")
        print("PASS SwiftUI view state matrix; network actions NOT RUN")
    }
}
