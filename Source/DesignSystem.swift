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
    static let background = adaptive(0x131715, 0xf4f5f2)
    static let surface = adaptive(0x1b201d, 0xffffff)
    static let raised = adaptive(0x212723, 0xf7f8f5)
    static let border = adaptive(0x333b36, 0xd9dcd5)
    static let text = adaptive(0xe8ece9, 0x1d2420)
    static let secondary = adaptive(0xa2ada6, 0x59635d)
    static let muted = adaptive(0x8f9b94, 0x59635d)
    static let accent = adaptive(0x5cc4a6, 0x1f6f5c)
    static let onAccent = adaptive(0x0d1a15, 0xffffff)
    static let warning = adaptive(0xe6bd6a, 0x86570a)
    static let danger = adaptive(0xf0988f, 0xa1342b)
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

private struct GuardReduceMotionKey: EnvironmentKey {
    static let defaultValue: Bool? = nil
}

extension EnvironmentValues {
    var guardReduceMotionOverride: Bool? {
        get { self[GuardReduceMotionKey.self] }
        set { self[GuardReduceMotionKey.self] = newValue }
    }
}

/// View-local feedback; does not change GuardModel or controller behavior.
final class GuardPresentation: ObservableObject {
    @Published var lastAction = "Действий ещё не было"
}
