import AppKit
import Sparkle

@MainActor
final class GuardUpdateController: NSObject, SPUUpdaterDelegate {
    private let model: GuardModel
    private lazy var controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: nil)
    private var pendingInstallation: (() -> Void)?
    private var installConfirmed = false
    private var shutdownComplete = false

    init(model: GuardModel) {
        self.model = model
        super.init()
        controller.updater.automaticallyChecksForUpdates = true
        controller.updater.updateCheckInterval = 86_400
        controller.updater.automaticallyDownloadsUpdates = true
        controller.updater.sendsSystemProfile = false
        do {
            try controller.updater.start()
            controller.updater.checkForUpdatesInBackground()
        } catch {
            report(error)
        }
    }

    var canRestartGuard: Bool {
        !controller.updater.sessionInProgress && pendingInstallation == nil && !installConfirmed
    }

    func checkForUpdates() {
        guard !model.restarting, !installConfirmed else { return }
        model.updateError = nil
        controller.checkForUpdates(nil)
    }

    func prepareForTermination() -> Bool {
        if installConfirmed {
            shutdownOnce()
            return true
        }
        if let pendingInstallation {
            guard !model.restarting else { return false }
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.messageText = "Установить обновление перед выходом?"
            alert.informativeText = "Claude и локальный шлюз будут остановлены, Guard обновится и перезапустится. Claude автоматически не запустится, пароль прокси не сохранится. Профиль, Runtime, память IP и диагностика останутся. Без подтверждения выход отменён, чтобы обновление не установилось автоматически."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Остановить, установить и перезапустить")
            alert.addButton(withTitle: "Отмена").keyEquivalent = "\u{1b}"
            guard alert.runModal() == .alertFirstButtonReturn else {
                model.updateStatus = "Обновление загружено; выход отменён до явного решения об установке."
                return false
            }
            installConfirmed = true
            self.pendingInstallation = nil
            shutdownOnce()
            pendingInstallation()
            return false
        }
        guard !controller.updater.sessionInProgress else {
            model.updateStatus = "Дождитесь завершения проверки или загрузки обновления перед выходом."
            return false
        }
        return true
    }

    private func shutdownOnce() {
        guard !shutdownComplete else { return }
        model.shutdown()
        shutdownComplete = true
        #if GUARD_UPDATE_TEST
        GuardUpdateTest.writeMarker(environmentKey: "GUARD_UPDATE_TEST_SHUTDOWN")
        #endif
    }

    private func report(_ error: Error) {
        let nsError = error as NSError
        var detail = nsError.localizedDescription
        if let suggestion = nsError.localizedRecoverySuggestion, !suggestion.isEmpty, suggestion != detail {
            detail += " " + suggestion
        }
        switch nsError.code {
        case 1005:
            detail = "Guard запущен из транслоицированного расположения. Переместите приложение в /Applications и запустите его заново. " + detail
        case 1003:
            detail = "Guard запущен с DMG. Скопируйте приложение в /Applications перед обновлением. " + detail
        case 4000, 4012:
            detail = "Каталог установки доступен только для чтения или не позволяет записать обновление. Проверьте владельца и права приложения. " + detail
        default:
            break
        }
        model.updateError = detail
        model.updateStatus = "Обновление: ошибка — \(detail)"
    }

    func feedURLString(for updater: SPUUpdater) -> String? {
        #if GUARD_UPDATE_TEST
        if let feed = GuardUpdateTest.values["GUARD_UPDATE_TEST_FEED"] { return feed }
        #endif
        return nil
    }

    func updater(_ updater: SPUUpdater, mayPerform updateCheck: SPUUpdateCheck) throws {
        guard !model.restarting, !installConfirmed else {
            throw NSError(domain: "local.proxyguard.claude.update", code: 1, userInfo: [NSLocalizedDescriptionKey: "Проверка обновлений недоступна во время перезапуска или установки."])
        }
    }

    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        model.updateError = nil
        model.updateStatus = "Найдено обновление \(item.displayVersionString); загрузка в фоне."
    }

    func updaterDidNotFindUpdate(_ updater: SPUUpdater, error: Error) {
        model.updateError = nil
        model.updateStatus = "Установлена последняя версия Guard."
        #if GUARD_UPDATE_TEST
        GuardUpdateTest.finishIfNegative(outcome: "no_update", error: nil)
        #endif
    }

    func updater(_ updater: SPUUpdater, didDownloadUpdate item: SUAppcastItem) {
        model.updateStatus = "Обновление загружено. Установка только после подтверждения и остановки Claude."
    }

    func updater(_ updater: SPUUpdater, userDidMake choice: SPUUserUpdateChoice, forUpdate updateItem: SUAppcastItem, state: SPUUserUpdateState) {
        if choice == .install {
            installConfirmed = true
            model.updateStatus = "Установка подтверждена; Claude останавливается перед обновлением Guard."
        }
    }

    func updater(_ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem, immediateInstallationBlock immediateInstallHandler: @escaping () -> Void) -> Bool {
        pendingInstallation = immediateInstallHandler
        model.updateStatus = "Обновление готово. Подтвердите остановку Claude, установку и перезапуск Guard."
        #if GUARD_UPDATE_TEST
        if GuardUpdateTest.values["GUARD_UPDATE_TEST_AUTOINSTALL"] == "1" {
            DispatchQueue.main.async { [weak self] in
                guard let self, let pendingInstallation = self.pendingInstallation else { return }
                self.installConfirmed = true
                self.pendingInstallation = nil
                self.shutdownOnce()
                pendingInstallation()
            }
        }
        #endif
        return true
    }

    func updaterShouldRelaunchApplication(_ updater: SPUUpdater) -> Bool {
        installConfirmed && shutdownComplete
    }

    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {
        report(error)
    }

    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: Error?) {
        if let error {
            report(error)
            #if GUARD_UPDATE_TEST
            GuardUpdateTest.finishIfNegative(outcome: "error", error: error)
            #endif
        }
    }
}

#if GUARD_UPDATE_TEST
@MainActor
enum GuardUpdateTest {
    static var values: [String: String] {
        var values: [String: String] = [:]
        if let url = Bundle.main.url(forResource: "UpdateTest", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let configuration = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
            values = configuration
        }
        for (key, value) in ProcessInfo.processInfo.environment where key.hasPrefix("GUARD_UPDATE_TEST_") {
            values[key] = value
        }
        return values
    }

    static func prepareProcessEnvironment() {
        for (key, variable) in [("GUARD_UPDATE_TEST_HOME", "HOME"), ("GUARD_UPDATE_TEST_HOME", "CFFIXED_USER_HOME"), ("GUARD_UPDATE_TEST_TMPDIR", "TMPDIR")] {
            if let value = values[key] { setenv(variable, value, 1) }
        }
    }

    static func writeMarker(environmentKey: String) {
        guard let path = GuardUpdateTest.values[environmentKey] else { return }
        try? Data("shutdown-complete\n".utf8).write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    static func finishIfNegative(outcome: String, error: Error?) {
        let environment = GuardUpdateTest.values
        guard environment["GUARD_UPDATE_TEST_EXPECT_FAILURE"] == "1",
              let result = environment["GUARD_UPDATE_TEST_RESULT"] else { return }
        var object: [String: Any] = ["outcome": outcome, "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""]
        if let error {
            let nsError = error as NSError
            object["domain"] = nsError.domain
            object["code"] = nsError.code
            object["description"] = nsError.localizedDescription
        }
        try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: result), options: .atomic)
        exit(0)
    }

    static func finishInstalledProbeIfRequested() -> Bool {
        let environment = GuardUpdateTest.values
        guard let expected = environment["GUARD_UPDATE_TEST_EXPECT_VERSION"],
              let result = environment["GUARD_UPDATE_TEST_RESULT"] else { return false }
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
        guard version == expected else {
            UserDefaults.standard.set("preserved", forKey: "GuardUpdateTestSentinel")
            UserDefaults.standard.synchronize()
            return false
        }
        let home = environment["GUARD_UPDATE_TEST_HOME"] ?? ""
        let sentinels = [
            "Library/Application Support/Claude Proxy Guard/Profile/sentinel.txt",
            "Library/Application Support/Claude Proxy Guard/Runtime/sentinel.txt",
            "Library/Application Support/Claude Proxy Guard/ip-memory/sentinel.txt",
            "Library/Application Support/Claude Proxy Guard/diagnostics/sentinel.txt"
        ]
        let preserved = sentinels.allSatisfy {
            (try? String(contentsOf: URL(fileURLWithPath: home).appendingPathComponent($0), encoding: .utf8)) == "preserve-me\n"
        }
        let defaultsPreserved = UserDefaults.standard.string(forKey: "GuardUpdateTestSentinel") == "preserved"
        let object: [String: Any] = ["outcome": "installed", "version": version, "dataPreserved": preserved, "defaultsPreserved": defaultsPreserved]
        try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: result), options: .atomic)
        exit(preserved && defaultsPreserved ? 0 : 1)
    }
}
#endif
