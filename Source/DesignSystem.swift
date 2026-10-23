import SwiftUI
import AppKit

/// Semantic colors resolved against the current system appearance.
enum GuardPalette {
    private static func adaptive(_ dark: UInt32, _ light: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil, dynamicProvider: { appearance in
            let hex = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
                           green: CGFloat((hex >> 8) & 255) / 255,
                           blue: CGFloat(hex & 255) / 255, alpha: 1)
        }))
    }
    static let background = adaptive(0x0f1817, 0xf4f7f5)
    static let surface = adaptive(0x142120, 0xffffff)
    static let raised = adaptive(0x1a2a27, 0xeef3f0)
    static let border = adaptive(0x354b42, 0xc3d2c9)
    static let text = adaptive(0xe3ede9, 0x12211a)
    static let secondary = adaptive(0xb9cbc3, 0x33473e)
    static let muted = adaptive(0x9bb3a8, 0x4d635a)
    static let accent = adaptive(0x9fe3bb, 0x1f7a4d)
    static let onAccent = adaptive(0x0f2a1c, 0xffffff)
    static let warning = adaptive(0xe6c46f, 0x8a6d1f)
    static let danger = adaptive(0xf0a084, 0xb3261e)
}


/// Presentation only. The engine, model and privilege boundary are unchanged.
struct GuardActionStyle: ButtonStyle {
    let primary: Bool
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .frame(maxWidth: .infinity, minHeight: 44)
            .foregroundColor(enabled ? (primary ? GuardPalette.onAccent : GuardPalette.text) : GuardPalette.muted)
            .background(enabled && primary ? GuardPalette.accent : (configuration.isPressed ? GuardPalette.border : GuardPalette.raised))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(enabled && primary ? Color.clear : GuardPalette.border))
            .contentShape(RoundedRectangle(cornerRadius: 8))
    }
}

/// View-local feedback; does not change GuardModel or controller behavior.
final class GuardPresentation: ObservableObject {
    @Published var lastAction = "Действий ещё не было"
}
