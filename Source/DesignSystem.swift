import SwiftUI

/// Presentation only. The engine, model and privilege boundary are unchanged.
struct GuardActionStyle: ButtonStyle {
    let primary: Bool
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .frame(maxWidth: .infinity, minHeight: 44)
            .foregroundColor(enabled ? (primary ? Color(red: 0.06, green: 0.16, blue: 0.11) : Color(red: 0.89, green: 0.94, blue: 0.91)) : Color(red: 0.57, green: 0.66, blue: 0.61))
            .background(enabled && primary ? Color(red: 0.62, green: 0.89, blue: 0.73) : Color.white.opacity(configuration.isPressed ? 0.12 : 0.055))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(enabled && primary ? Color.clear : Color.white.opacity(0.18)))
            .contentShape(RoundedRectangle(cornerRadius: 8))
    }
}

/// View-local feedback; does not change GuardModel or controller behavior.
final class GuardPresentation: ObservableObject {
    @Published var lastAction = "Действий ещё не было"
}
