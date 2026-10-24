import SwiftUI
import AppKit
import Network
import Darwin

@MainActor
final class GuardModel: ObservableObject {
    @Published var useProxy = true
    @Published var host = "127.0.0.1"
    @Published var port = "1080"
    @Published var username = ""
    @Published var password = ""
    @Published var claudePath = "/Applications/Claude.app"
    @Published var interval = 5
    @Published var watchPublicIP = true
    @Published var networkBarrier = true
    @Published var barrierActive = false
    @Published var barrierSummary = "Состояние барьера ещё не проверено"
    var barrierArmed = false
    private var barrierEnvURL: URL?
    private var barrierLaunched = false
    private var sessionNetworkMode = false
    @Published var timezone = "Europe/Amsterdam"
    @Published var language = "en-US"
    @Published var inspectPages = true
    @Published var runtimeStatus = "Используется отдельная локальная копия установленного Claude"
    @Published var lastVerifiedProfile: VerifiedProfile?
    @Published var captureBodies = false
    @Published var profileStatus = "Профиль страницы ещё не проверен"
    @Published var phase = "Ожидание проверки"
    @Published var detail = "Выберите маршрут и проверьте внешний IP перед запуском."
    @Published var report: IPReport?
    @Published var busy = false
    @Published var monitoring = false
    @Published var allowed = false
    @Published var requiresRestart = false
    @Published var claudeRunning = false
    @Published var restarting = false
    @Published var operationFailure: String?
    @Published var previousStop: String?
    @Published var nextCheck: Date?
    @Published var log: [String] = []
    @Published var showLog = false
    @Published var traffic: [TrafficRecord] = []
    @Published var selectedTrafficID: String?
    private var relay: SOCKSRelay?
    private var relayPort: UInt16?
    private var process: Process?
    private var timer: Timer?
    private var inspector: ClaudeInspector?
    private var networkWatcher: LocalNetworkWatcher?
    private var operation = UUID()
    private var activePath: String?
    private var powerObservers: [NSObjectProtocol] = []
    private var pathMonitor: NWPathMonitor?
    private var localBaseline = Set<String>()
    private var policy = SessionPolicy()
    private var systemProxy: SystemProxy.Snapshot?
    private var revalidationTask: Task<Void, Never>?
    private var launchPending = false
    private var launchAfterValidation = false
    private var networkRevision = 0
    private var sleeping = false
    private var trafficWindow: NSWindow?
    private let diagnostics: GuardDiagnostics
    private var childBundleURL: URL?
    private var deepLinkReady: Bool {
        allowed && !policy.suspended && !sleeping && !restarting && !requiresRestart &&
        claudeRunning && process?.isRunning == true && lastVerifiedProfile != nil && childBundleURL != nil
    }
    lazy var deepLinkInbox: DeepLinkInbox = {
        let inbox = DeepLinkInbox(
            active: { [weak self] in
                guard let self else { return false }
                return !self.requiresRestart && !self.restarting && (self.busy || self.monitoring || self.claudeRunning)
            },
            ready: { [weak self] in self?.deepLinkReady == true },
            deliver: { _ in throw GuardError.message(DeepLinkInbox.failed) },
            notice: { [weak self] text in self?.appendLog(text) })
        inbox.deliverAsync = { [weak self] raw, finish in
            guard let self, self.deepLinkReady, let childBundleURL = self.childBundleURL,
                  let url = URL(string: raw),
                  NSWorkspace.shared.runningApplications.contains(where: {
                      $0.bundleURL?.standardizedFileURL == childBundleURL.standardizedFileURL && !$0.isTerminated
                  }) else { finish(false); return }
            let configuration = NSWorkspace.OpenConfiguration()
            configuration.createsNewApplicationInstance = false
            let token = self.operation
            NSWorkspace.shared.open([url], withApplicationAt: childBundleURL, configuration: configuration) { [weak self] app, error in
                Task { @MainActor in
                    finish(error == nil && app != nil && self?.operation == token && self?.deepLinkReady == true)
                }
            }
        }
        return inbox
    }()
    var onRestart: (() -> Void)?

    #if GUARD_E2E
    var e2eSystemProxyCapture: (() throws -> SystemProxy.Snapshot)?
    var e2eDestinationCheck: ((String) async throws -> (ip: String, countryCode: String))?
    var e2eInitialCheck: ((UInt16?) async throws -> IPReport)?
    var e2ePublicCheck: ((UInt16?) async throws -> String)?
    var e2eRuntimeRoot: URL?
    var e2eBootstrapURL: URL?
    var e2eHelperURL: URL?
    var e2eSandboxURL: URL?
    var e2eStderrURL: URL?
    var e2eExtraArguments: [String] = []
    var e2eBarrierProbe: NetworkBarrier.Probe?
    var e2eCapturedPin: SOCKSRelay.LocalPin?
    var e2eOnVerified: ((VerifiedProfile) -> Void)?
    var e2eInspector: ClaudeInspector? { inspector }
    var e2eRelayPort: UInt16? { relayPort }
    var e2eProcessID: Int32? { process?.processIdentifier }
    var e2eSuspended: Bool { policy.suspended }
    func e2eVerifyNow() { verifyPinnedIP(andLaunch: false) }
    func e2eNetworkChanged() { networkChanged("Изменение тестовой сети") }
    func e2ePowerChanged(sleeping: Bool) { powerChanged(sleeping: sleeping) }
    #endif

    /// Tests never enter the privileged chain unless they explicitly pin a probe.
    private var barrierRequired: Bool {
        #if GUARD_E2E
        if e2eRuntimeRoot != nil && e2eBarrierProbe == nil { return false }
        #endif
        return networkBarrier
    }
    func currentBarrierProbe() -> NetworkBarrier.Probe {
        #if GUARD_E2E
        if let e2eBarrierProbe { return e2eBarrierProbe }
        return .broken("тестовый режим без барьера")
        #else
        return NetworkBarrier.probe()
        #endif
    }
    func refreshBarrierStatus() {
        let probe = currentBarrierProbe()
        barrierActive = probe.active
        if !networkBarrier {
            barrierSummary = "Барьер выключен. Native и MCP-компоненты Claude смогут обходить шлюз."
        } else {
            barrierSummary = probe.summary
        }
    }
    func installBarrier() {
        guard !busy, !monitoring else { return }
        appendLog("Запрошена установка системного сетевого барьера…")
        Task {
            do {
                try await Task.detached { try NetworkBarrier.install() }.value
                self.appendLog("Системный сетевой барьер установлен и активен.")
            } catch {
                self.appendLog("Установка барьера не удалась: \(error.localizedDescription)")
            }
            self.refreshBarrierStatus()
        }
    }
    /// One-time offer during session start. Refusal fails the session closed.
    private func offerBarrierInstall(_ probe: NetworkBarrier.Probe) async -> Bool {
        #if GUARD_E2E
        if e2eRuntimeRoot != nil { return false }
        #endif
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Установить системный сетевой барьер?"
        alert.informativeText = "Без барьера нативные компоненты Claude (MCP, Cowork, расширения) могут отправлять запросы мимо шлюза. Установка добавляет правило packet filter и одноразово требует пароль администратора. " + probe.summary
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Установить и продолжить")
        alert.addButton(withTitle: "Отмена").keyEquivalent = "\u{1b}"
        guard alert.runModal() == .alertFirstButtonReturn else { return false }
        do {
            try await Task.detached { try NetworkBarrier.install() }.value
            appendLog("Системный сетевой барьер установлен и активен.")
            return true
        } catch {
            appendLog("Установка барьера не удалась: \(error.localizedDescription)")
            return false
        }
    }


    init(diagnosticsURL: URL? = nil) {
        diagnostics = GuardDiagnostics(url: diagnosticsURL)
        previousStop = diagnostics.previousFailure()
        let d = UserDefaults.standard
        if d.object(forKey: "useProxy") != nil { useProxy = d.bool(forKey: "useProxy") }
        host = d.string(forKey: "proxyHost") ?? host; port = d.string(forKey: "proxyPort") ?? port
        username = d.string(forKey: "proxyUsername") ?? username; claudePath = d.string(forKey: "claudePath") ?? claudePath
        let saved = d.integer(forKey: "checkIntervalV2")
        if [2, 5, 10, 30].contains(saved) { interval = saved }
        // Periodic IP control is mandatory: a session without it cannot detect a
        // silently changed exit. Ignore any previously stored opt-out.
        watchPublicIP = true
        if d.object(forKey: "networkBarrierV1") != nil { networkBarrier = d.bool(forKey: "networkBarrierV1") }
        if let value = d.string(forKey: "profileTimezone"), LaunchProfile.timezones.contains(value) { timezone = value }
        if let value = d.string(forKey: "profileLanguage"), LaunchProfile.languages.contains(value) { language = value }

        if d.object(forKey: "captureBodies") != nil { captureBodies = d.bool(forKey: "captureBodies") }
        let center = NSWorkspace.shared.notificationCenter
        for event in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification] {
            powerObservers.append(center.addObserver(forName: event, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in
                    guard let self else { return }
                    self.powerChanged(sleeping: event == NSWorkspace.willSleepNotification)
                }
            })
        }
        refreshBarrierStatus()
    }

    func saveSettings() {
        #if GUARD_E2E
        if e2eRuntimeRoot != nil { return }
        #endif
        let d = UserDefaults.standard
        d.set(useProxy, forKey: "useProxy"); d.set(host, forKey: "proxyHost"); d.set(port, forKey: "proxyPort")
        d.set(username, forKey: "proxyUsername"); d.set(claudePath, forKey: "claudePath")
        d.set(interval, forKey: "checkIntervalV2"); d.set(watchPublicIP, forKey: "watchPublicIP")
        d.set(networkBarrier, forKey: "networkBarrierV1")
        d.set(timezone, forKey: "profileTimezone"); d.set(language, forKey: "profileLanguage")
        d.set(inspectPages, forKey: "inspectPages"); d.set(captureBodies, forKey: "captureBodies")
    }
    func selectClaude() {
        let panel = NSOpenPanel(); panel.title = "Выберите Claude.app"
        panel.canChooseDirectories = false; panel.canChooseFiles = true; panel.allowedContentTypes = [.applicationBundle]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        if panel.runModal() == .OK, let url = panel.url { claudePath = url.path; saveSettings() }
    }

    func check(andLaunch launch: Bool) {
        guard !busy, !requiresRestart, !(launch && claudeRunning) else { return }
        operationFailure = nil
        saveSettings()
        if monitoring { verifyPinnedIP(andLaunch: launch); return }
        report = nil; traffic.removeAll(); lastVerifiedProfile = nil; profileStatus = "Профиль страницы ещё не проверен"
        let token = UUID(); operation = token
        allowed = false; busy = true; phase = "Проверяем исходный IP…"
        detail = "Подтверждаем иностранный IP и фиксируем адрес для этой сессии."
        localBaseline = NetworkSnapshot.current()
        Task { [self] in
            defer { if launch { password = "" } }
            do {
                try LaunchProfile(timezone: timezone, language: language).validate()
                // PG-01: without the packet-filter barrier native Claude components
                // (MCP, Cowork, helpers) could bypass the relay entirely. A session
                // starts only with the barrier active or explicitly switched off.
                barrierArmed = false
                if barrierRequired {
                    var probe = currentBarrierProbe()
                    barrierActive = probe.active; barrierSummary = probe.summary
                    if !probe.active, await offerBarrierInstall(probe) {
                        guard operation == token else { return }
                        probe = currentBarrierProbe()
                        barrierActive = probe.active; barrierSummary = probe.summary
                    }
                    guard probe.active else {
                        throw GuardError.message("Сетевой барьер не активен, запуск отменён. Установите барьер или осознанно выключите его в настройках.")
                    }
                    barrierArmed = true
                    appendLog("Сетевой барьер подтверждён: процессы Claude ограничены локальным шлюзом.")
                }
                let networkMode = !useProxy
                let snapshot = networkMode ? try await captureSystemProxy() : nil
                guard operation == token else { return }
                systemProxy = snapshot
                if snapshot?.hasStaticProxy == true { appendLog("Статический системный прокси закреплён за сессией.") }
                let relay: SOCKSRelay
                if !networkMode {
                    let config = try ProxySettings.validated(host: host, port: port, username: username, password: password)
                    relay = SOCKSRelay(settings: config)
                } else if let socks = snapshot?.socks {
                    // A pinned system SOCKS proxy becomes the session upstream; without
                    // this the traffic would bypass the very proxy the system advertises.
                    appendLog("Используем системный SOCKS-прокси \(socks.host):\(socks.port).")
                    relay = SOCKSRelay(settings: ProxySettings(host: socks.host, port: UInt16(socks.port), username: "", password: ""))
                } else if snapshot?.http != nil || snapshot?.https != nil {
                    throw GuardError.message("Системный HTTP-прокси нельзя применить в режиме «Текущая сеть»: запросы ушли бы мимо него. Выберите SOCKS5-прокси в Guard или задайте системный SOCKS-прокси.")
                } else { relay = SOCKSRelay(currentNetwork: true) }
                relay.onFault = { [weak self] in
                    guard let self, self.operation == token else { return }
                    self.networkChanged("Шлюз временно потерял соединение с прокси")
                }
                relay.onTunnelEvent = { [weak self] host, port, sent, received, finished in
                    guard let self, self.operation == token else { return }
                    var record = TrafficRecord(id: UUID().uuidString)
                    record.method = "CONNECT"; record.kind = "TLS-шлюз"; record.url = "\(host):\(port)"
                    record.note = finished ? "Закрыто: ↑ \(sent) байт, ↓ \(received) байт" : "Туннель открыт"
                    record.sent = "TLS зашифрован. Содержимое веб-запросов смотрите в записях CDP."
                    self.addTraffic(record)
                }
                self.relay = relay
                sessionNetworkMode = networkMode && relay.isDirect
                let localPort = try await relay.start()
                guard operation == token else { relay.stop(); return }
                relayPort = localPort
                guard operation == token else { return }
                startNetworkGuard(token: token)
                let result = try await initialIPCheck(relayPort)
                guard operation == token else { return }
                report = result
                try policy.establish(result)
                if watchPublicIP {
                    let actual = try await currentIPCheck(relayPort)
                    guard operation == token else { return }
                    try policy.verify(actual)
                }
                relay.setPinnedFamily(policy.pinnedIP.map { $0.contains(":") ? .v6 : .v4 })
                if relay.isDirect {
                    // Pin the addresses the control checks actually used rather than
                    // the default route owner: split-route VPNs (0/1+128/1) would
                    // otherwise pin the physical interface and bypass the tunnel.
                    var captured = relay.capturedLocalAddresses()
                    #if GUARD_E2E
                    if captured == nil { captured = e2eCapturedPin }
                    #endif
                    guard let captured else {
                        throw GuardError.message("Не удалось закрепить локальный адрес выхода. Доступ закрыт.")
                    }
                    relay.setPinnedLocalAddresses(captured)
                }
                try await verifyDestinations(operation: token)
                guard operation == token else { return }
                try await confirmSystemProxy(operation: token)
                guard operation == token else { return }
                localBaseline = NetworkSnapshot.current()
                if sleeping {
                    monitoring = true; busy = false; launchAfterValidation = launch
                    suspendTraffic("Mac находится в режиме сна")
                    return
                }
                relay.setPinnedFamily(policy.pinnedIP.map { $0.contains(":") ? .v6 : .v4 })
                if !relay.unlock() { throw GuardError.message("Локальный шлюз уже закрыт.") }
                allowed = true; monitoring = true; busy = false
                phase = "IP закреплён за сессией"
                detail = watchPublicIP ? "Внешний IP: каждые \(interval) с. Изменение сети приостанавливает шлюз до повторной проверки IP." : "Изменение локальной сети приостанавливает шлюз для проверки IP. Периодические проверки отключены."
                appendLog("Исходный IP закреплён: \(result.ip) · \(result.countryCode)")
                scheduleCheck()
                if launch { attemptLaunch() }
            } catch {
                guard operation == token else { return }
                if policy.pinnedIP != nil, !policy.requiresRestart {
                    monitoring = true
                    verifyPinnedIP(andLaunch: launch, pauseReason: error.localizedDescription)
                } else { block(error.localizedDescription, latch: policy.requiresRestart) }
            }
        }
    }

    private func verifyPinnedIP(andLaunch launch: Bool, pauseReason: String? = nil) {
        guard !requiresRestart, policy.pinnedIP != nil else { return }
        launchAfterValidation = launchAfterValidation || launch
        if let pauseReason { suspendTraffic(pauseReason) }
        guard revalidationTask == nil, !sleeping else { return }
        busy = true; let token = operation
        revalidationTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled, self.operation == token, !self.sleeping {
                let revision = self.networkRevision
                do {
                    let wasSuspended = self.policy.suspended
                    // A removed packet-filter barrier reopens direct egress for the
                    // whole Claude tree; treat it like a route change.
                    if self.barrierArmed, !self.currentBarrierProbe().active {
                        throw GuardError.message("Сетевой барьер отключён во время сессии.")
                    }
                    // While the gate is paused, control probes rebind freely; app
                    // traffic stays closed until the fresh proven pin is installed.
                    if self.sessionNetworkMode { self.relay?.resetLocalPinning() }
                    let actual = try await self.currentIPCheck(self.relayPort)
                    guard !Task.isCancelled, self.operation == token, !self.sleeping else { return }
                    // A response started before the most recent route event cannot reopen the gate.
                    guard revision == self.networkRevision else { continue }
                    try self.policy.verify(actual)
                    if wasSuspended { self.policy.suspend() }
                    try await self.verifyDestinations(operation: token)
                    guard !Task.isCancelled, self.operation == token, !self.sleeping else { return }
                    guard revision == self.networkRevision else { continue }
                    try await self.confirmSystemProxy(operation: token)
                    guard !Task.isCancelled, self.operation == token, !self.sleeping else { return }
                    guard revision == self.networkRevision else { continue }
                    try self.policy.verify(actual)
                    self.relay?.setPinnedFamily(self.policy.pinnedIP.map { $0.contains(":") ? .v6 : .v4 })
                    if self.sessionNetworkMode, let relay = self.relay {
                        // Re-pin from the addresses these very probes used, then open.
                        var captured = relay.capturedLocalAddresses()
                        #if GUARD_E2E
                        if captured == nil { captured = self.e2eCapturedPin }
                        #endif
                        guard let captured else {
                            throw GuardError.message("Не удалось закрепить локальный адрес выхода после изменения сети.")
                        }
                        relay.setPinnedLocalAddresses(captured)
                    }
                    if wasSuspended, let relay = self.relay, !relay.unlock() {
                        throw GuardError.message("Шлюз ожидает успешного контрольного подключения.")
                    }
                    self.localBaseline = NetworkSnapshot.current()
                    if let last = self.report { self.report = IPReport(ip: actual, countryCode: last.countryCode, country: last.country, date: Date()) }
                    self.allowed = true; self.monitoring = true; self.busy = self.launchPending
                    self.phase = "IP закреплён за сессией"
                    if wasSuspended {
                        self.detail = "Прежний внешний IP подтверждён. Шлюз возобновлён."
                        self.appendLog("Повторная проверка подтвердила прежний IP; шлюз возобновлён.")
                    }
                    self.revalidationTask = nil
                    let shouldLaunch = self.launchAfterValidation; self.launchAfterValidation = false
                    self.scheduleCheck()
                    self.deepLinkInbox.flush()
                    if shouldLaunch, !self.launchPending, !self.claudeRunning { self.attemptLaunch() }
                    return
                } catch {
                    guard !Task.isCancelled, self.operation == token else { return }
                    // Close the gate before any further awaiting: a failing probe must
                    // never leave the relay open while settings are being inspected.
                    self.relay?.pause()
                    if self.policy.requiresRestart { self.block(error.localizedDescription, latch: true); return }
                    // A failed IP/destination probe must not hide a confirmed proxy change.
                    do { try await self.confirmSystemProxy(operation: token) }
                    catch {
                        guard !Task.isCancelled, self.operation == token else { return }
                        if self.policy.requiresRestart { self.block(error.localizedDescription, latch: true); return }
                    }
                    guard !Task.isCancelled, self.operation == token else { return }
                    self.suspendTraffic(error.localizedDescription)
                    do { try await Task.sleep(nanoseconds: 2_000_000_000) } catch { return }
                }
            }
        }
    }

    private func suspendTraffic(_ reason: String) {
        let firstPause = !policy.suspended
        policy.suspend(); relay?.pause()
        allowed = false; phase = "Шлюз приостановлен — проверяем IP"
        detail = "\(reason). Новые запросы Claude закрыты до подтверждения прежнего IP."
        timer?.invalidate(); timer = nil; nextCheck = nil
        if firstPause { appendLog("Шлюз приостановлен для повторной проверки IP: \(reason)") }
    }

    private func networkChanged(_ reason: String) {
        networkRevision += 1
        relay?.pause()
        guard policy.pinnedIP != nil, monitoring || claudeRunning else { return }
        verifyPinnedIP(andLaunch: false, pauseReason: reason)
    }

    private func powerChanged(sleeping: Bool) {
        self.sleeping = sleeping
        networkRevision += 1
        relay?.pause()
        guard policy.pinnedIP != nil else { return }
        suspendTraffic(sleeping ? "Mac переходит в режим сна" : "Mac вышел из режима сна")
        revalidationTask?.cancel(); revalidationTask = nil
        if !sleeping { verifyPinnedIP(andLaunch: false) }
    }

    private func scheduleCheck() {
        timer?.invalidate(); timer = nil; nextCheck = nil
        guard watchPublicIP else { return }
        nextCheck = Date().addingTimeInterval(TimeInterval(interval))
        timer = Timer(timeInterval: TimeInterval(interval), repeats: false) { [weak self] _ in
            Task { @MainActor in self?.verifyPinnedIP(andLaunch: false) }
        }
        if let timer { RunLoop.main.add(timer, forMode: .common) }
    }

    private func startNetworkGuard(token: UUID) {
        let currentRelay = relay
        let changed: () -> Void = { [weak self] in
            currentRelay?.pause()
            DispatchQueue.main.async {
                guard let self, self.operation == token else { return }
                self.networkChanged("Локальный адрес или маршрут изменился")
            }
        }
        let watcher = LocalNetworkWatcher(); networkWatcher = watcher
        watcher.start(baseline: localBaseline, onChange: changed)
        let monitor = NWPathMonitor(); pathMonitor = monitor
        // NWPathMonitor may repeat the same route; only a changed snapshot blocks it.
        let state = PathSnapshotState()
        monitor.pathUpdateHandler = { path in if state.changed(path) { changed() } }
        monitor.start(queue: DispatchQueue(label: "local.proxyguard.path"))
    }

    private func verifyDestinations(operation expected: UUID) async throws {
        guard let relay, let relayPort else { throw GuardError.message("Локальный шлюз закрыт.") }
        for host in IPChecker.destinationHosts {
            let result: (ip: String, countryCode: String)
            #if GUARD_E2E
            // Existing recovery fixtures replace the entire external route check.
            if let e2eDestinationCheck {
                result = try await e2eDestinationCheck(host)
            } else if e2eInitialCheck != nil, let report {
                result = (report.ip, report.countryCode)
            } else {
                result = try await IPChecker.destinationTrace(relayPort: relayPort, token: relay.checkToken, hostname: host, family: policy.pinnedIP?.contains(":") == true ? 6 : 4)
            }
            #else
            result = try await IPChecker.destinationTrace(relayPort: relayPort, token: relay.checkToken, hostname: host, family: policy.pinnedIP?.contains(":") == true ? 6 : 4)
            #endif
            guard operation == expected, !Task.isCancelled else { throw CancellationError() }
            try policy.verifyDestination(hostname: host, ip: result.ip, countryCode: result.countryCode)
        }
    }

    private func captureSystemProxy() async throws -> SystemProxy.Snapshot {
        #if GUARD_E2E
        if let e2eSystemProxyCapture { return try e2eSystemProxyCapture() }
        #endif
        return try await Task.detached { try SystemProxy.capture() }.value
    }

    private func confirmSystemProxy(operation expected: UUID) async throws {
        // The pinned mode belongs to the session, independently of editable UI settings.
        guard let pinned = systemProxy else { return }
        let current: SystemProxy.Snapshot
        do { current = try await captureSystemProxy() }
        catch {
            guard operation == expected, !Task.isCancelled else { throw CancellationError() }
            let reason = "Не удалось подтвердить настройки прокси macOS. Повторяем проверку."
            suspendTraffic(reason)
            throw GuardError.message(reason)
        }
        guard operation == expected, !Task.isCancelled else { throw CancellationError() }
        if current.fingerprint != pinned.fingerprint {
            let reason = "Настройки системного прокси изменились. Сессия закрыта до перезапуска Guard."
            policy.latch(reason)
            throw GuardError.message(reason)
        }
    }

    private func initialIPCheck(_ port: UInt16?) async throws -> IPReport {
        #if GUARD_E2E
        if let e2eInitialCheck { return try await e2eInitialCheck(port) }
        #endif
        return try await IPChecker.check(relayPort: port, token: relay?.checkToken ?? "")
    }
    private func currentIPCheck(_ port: UInt16?) async throws -> String {
        #if GUARD_E2E
        if let e2ePublicCheck { return try await e2ePublicCheck(port) }
        #endif
        return try await IPChecker.publicIP(relayPort: port, token: relay?.checkToken ?? "", pinnedIP: policy.pinnedIP)
    }
    private func attemptLaunch() {
        guard !busy, !requiresRestart else { return }
        busy = true; launchPending = true
        let token = operation
        runtimeStatus = "Подготавливаем отдельную локальную копию Claude…"
        Task {
            defer { password = ""; if operation == token { launchPending = false; busy = revalidationTask != nil } }
            var checkingRoute = false
            do {
                let source = URL(fileURLWithPath: claudePath).standardizedFileURL.resolvingSymlinksInPath()
                var bootstrap = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/RuntimeBootstrap.cjs")
                var cacheRoot: URL?
                #if GUARD_E2E
                bootstrap = e2eBootstrapURL ?? bootstrap; cacheRoot = e2eRuntimeRoot
                #endif
                let prepared = try await RuntimePreparer.prepare(source: source, bootstrapURL: bootstrap, cacheRoot: cacheRoot)
                guard operation == token else { return }
                checkingRoute = true
                if watchPublicIP { try policy.verify(await currentIPCheck(relayPort)) }
                if NetworkSnapshot.current() != localBaseline { networkChanged("Сеть изменилась во время подготовки Claude") }
                while policy.suspended, operation == token {
                    try await Task.sleep(nanoseconds: 100_000_000)
                }
                guard operation == token else { return }
                try await confirmSystemProxy(operation: token)
                guard operation == token else { return }
                checkingRoute = false
                runtimeStatus = "Локальная копия Claude \(prepared.sourceVersion), отдельный профиль"
                if !prepared.sourceSignatureValid {
                    runtimeStatus += ". Проверка подписи исходника не пройдена; копия подписана локально."
                    appendLog("Подпись установленного исходника не прошла проверку. Оригинал не изменён; локальная копия переподписана.")
                }
                try launchClaude(prepared)
                busy = false; scheduleCheck()
            } catch {
                guard operation == token else { return }
                if checkingRoute, !policy.requiresRestart {
                    launchAfterValidation = true
                    verifyPinnedIP(andLaunch: true, pauseReason: error.localizedDescription)
                } else { block(error.localizedDescription, latch: policy.requiresRestart) }
            }
        }
    }

    private func launchClaude(_ prepared: PreparedRuntime) throws {
        let bundleURL = prepared.bundleURL
        guard let bundle = Bundle(url: bundleURL), bundle.bundleIdentifier == RuntimePreparer.identifier,
              let executable = bundle.executableURL, FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw GuardError.message("Подготовленная копия Claude повреждена.")
        }
        guard NSRunningApplication.runningApplications(withBundleIdentifier: RuntimePreparer.identifier).isEmpty else {
            throw GuardError.message("Локальная копия Claude уже открыта. Завершите её и начните новую сессию Guard.")
        }
        let profile = LaunchProfile(timezone: timezone, language: language)
        try profile.validate()
        let child = Process()
        var environment = ProcessInfo.processInfo.environment.filter {
            !$0.key.hasPrefix("ELECTRON_") && !$0.key.hasPrefix("CLAUDE_") &&
            !["http_proxy", "https_proxy", "all_proxy", "no_proxy", "electron_run_as_node", "node_options", "claude_cdp_auth", "claude_user_data_dir"].contains($0.key.lowercased())
        }
        var config: [String: Any] = ["userData": prepared.profileURL.path, "timezone": timezone, "language": language]
        if let port = relayPort {
            let proxyURL = "http://127.0.0.1:\(port)"
            config["proxyURL"] = proxyURL
            for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] { environment[key] = proxyURL }
            environment["NO_PROXY"] = ""; environment["no_proxy"] = ""
        }
        environment["PROXY_GUARD_CONFIG"] = String(data: try JSONSerialization.data(withJSONObject: config), encoding: .utf8)
        let fullEnvironment = profile.environment(environment)
        // PG-01: with the barrier armed the prepared environment travels through a
        // private 0600 file because sudo scrubs the inherited environment.
        var useBarrierChain = barrierArmed
        #if GUARD_E2E
        if e2eRuntimeRoot != nil { useBarrierChain = false }
        #endif
        if useBarrierChain {
            guard NetworkBarrier.probe().active else {
                throw GuardError.message("Сетевой барьер отключён перед запуском Claude. Запуск отменён.")
            }
            let envURL = prepared.profileURL.deletingLastPathComponent()
                .appendingPathComponent("guard-env-" + UUID().uuidString.lowercased())
            try writeBarrierEnvironment(fullEnvironment, to: envURL)
            barrierEnvURL = envURL
            // sudo env_reset strips inherited variables; the env file path travels
            // as a helper argument instead.
            child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
            barrierLaunched = true
        } else {
            child.environment = fullEnvironment
            barrierLaunched = false
        }
        child.standardError = FileHandle.nullDevice
        #if GUARD_E2E
        if let e2eStderrURL {
            FileManager.default.createFile(atPath: e2eStderrURL.path, contents: nil)
            child.standardError = try FileHandle(forWritingTo: e2eStderrURL)
        }
        #endif
        let token = operation
        var helper = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/GuardHost")
        var arguments = [executable.path] + profile.arguments
        #if GUARD_E2E
        helper = e2eHelperURL ?? helper; arguments += e2eExtraArguments
        #endif
        guard FileManager.default.isExecutableFile(atPath: helper.path) else { throw GuardError.message("В сборке отсутствует GuardHost.") }
        if useBarrierChain {
            guard let barrierEnvURL else { throw GuardError.message("Окружение сессии для барьера не подготовлено.") }
            child.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            child.arguments = ["-n", NetworkBarrier.helperPath, "--env-file", barrierEnvURL.path, helper.path] + arguments
        } else {
            child.executableURL = helper; child.arguments = arguments
        }
        #if GUARD_E2E
        if let e2eSandboxURL {
            child.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
            child.arguments = ["-f", e2eSandboxURL.path, helper.path] + arguments
        }
        #endif
        let commands = Pipe(), events = Pipe()
        child.standardInput = commands; child.standardOutput = events
        let inspector = ClaudeInspector(input: commands.fileHandleForWriting, output: events.fileHandleForReading,
                                        profile: profile, captureBodies: captureBodies)
        inspector.onRecord = { [weak self] record in
            guard let self, self.operation == token else { return }
            self.addTraffic(record)
        }
        inspector.onStatus = { [weak self] text in guard let self, self.operation == token else { return }; self.profileStatus = text }
        inspector.onNotice = { [weak self] text in guard let self, self.operation == token else { return }; self.appendLog(text) }
        inspector.onVerified = { [weak self] profile in
            guard let self, self.operation == token else { return }
            self.lastVerifiedProfile = profile
            self.deepLinkInbox.flush()
            #if GUARD_E2E
            self.e2eOnVerified?(profile)
            #endif
        }
        inspector.onFatal = { [weak self] reason in
            guard let self, self.operation == token else { return }
            if let process = self.process, !process.isRunning { self.claudeExited(process) }
            else { self.block(reason, latch: true) }
        }
        self.inspector = inspector
        profileStatus = "Подключаем локальный адаптер к страницам Claude…"
        child.terminationHandler = { [weak self] _ in
            Task { @MainActor in
                guard let self, self.operation == token else { return }
                self.claudeExited(child)
            }
        }
        try child.run()
        childBundleURL = bundleURL
        process = child; activePath = bundleURL.path; claudeRunning = true
        inspector.start()
        appendLog("Локальная копия Claude запущена: \(timezone) · \(language)")
    }

    private func writeBarrierEnvironment(_ environment: [String: String], to url: URL) throws {
        for (key, value) in environment {
            guard key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil,
                  !value.contains("\n"), !value.contains("\r") else {
                throw GuardError.message("Переменная окружения «\(key)» небезопасна для запуска через барьер.")
            }
        }
        let payload = environment.keys.sorted().map { "\($0)=\(environment[$0] ?? "")" }.joined(separator: "\n") + "\n"
        guard payload.utf8.count <= 65536 else { throw GuardError.message("Окружение сессии слишком велико для барьера.") }
        clearBarrierEnvironment()
        guard FileManager.default.createFile(atPath: url.path, contents: Data(payload.utf8),
                                             attributes: [.posixPermissions: 0o600]) else {
            throw GuardError.message("Не удалось записать окружение сессии для барьера.")
        }
    }
    private func clearBarrierEnvironment() {
        guard let url = barrierEnvURL else { return }
        barrierEnvURL = nil
        try? FileManager.default.removeItem(at: url)
    }

    private func claudeExited(_ child: Process) {
        clearBarrierEnvironment()
        let status = child.terminationStatus
        let signalled = child.terminationReason == .uncaughtSignal
        let reason = signalled ? "Claude завершился по сигналу \(status). Причина сохранена в журнале." : "Claude завершился с кодом \(status)."
        diagnostics.record("unexpected_exit", reason)
        block(reason, manual: status == 0 && !signalled, latch: status != 0 || signalled)
    }

    func stop() {
        operationFailure = nil
        block(requiresRestart ? (policy.lockedReason ?? "Перезапустите Guard.") : "Сессия остановлена пользователем.", manual: true)
    }
    func restart() {
        guard !restarting, let onRestart else { return }
        operationFailure = nil
        deepLinkInbox.clear()
        restarting = true
        onRestart()
    }
    func restartFailed(_ message: String) {
        restarting = false; detail = message; appendLog(message)
        operationFailure = "Перезапуск: не удалось — " + message
    }
    private func block(_ reason: String, manual: Bool = false, latch: Bool = false) {
        let failedLaunch = busy || launchPending || launchAfterValidation
        deepLinkInbox.clear()
        childBundleURL = nil
        password = ""
        clearBarrierEnvironment(); barrierArmed = false
        barrierLaunched = false; sessionNetworkMode = false
        if latch { policy.latch(reason) }
        requiresRestart = policy.requiresRestart
        operation = UUID()
        revalidationTask?.cancel(); revalidationTask = nil
        launchPending = false; launchAfterValidation = false
        relay?.stop(); relay = nil; relayPort = nil; systemProxy = nil
        inspector?.stop(); inspector = nil
        timer?.invalidate(); timer = nil; nextCheck = nil
        pathMonitor?.cancel(); pathMonitor = nil
        networkWatcher?.stop(); networkWatcher = nil
        stopOwnedClaude()
        monitoring = false; allowed = false; busy = false
        if !requiresRestart { policy.manualStop() }
        phase = requiresRestart ? "Заблокировано до перезапуска Guard" : (manual ? "Остановлено" : "Доступ закрыт")
        detail = reason
        if !manual {
            if failedLaunch { operationFailure = "Запуск: не удалось — " + reason }
            previousStop = GuardDiagnostics.sanitize(reason)
            diagnostics.record("blocked", reason)
        }
        appendLog(reason)
    }
    private func stopOwnedClaude() {
        guard let path = activePath else { return }
        process?.terminationHandler = nil
        if let process, process.isRunning {
            let pid = process.processIdentifier
            if barrierLaunched {
                // The visible child is sudo; the runtime execs through GuardDrop and
                // GuardHost into its own process group led by sudo's only child.
                // Signal THAT group so MCP and helper processes cannot linger.
                process.terminate()
                if let leader = childProcessGroup(of: pid) { kill(-leader, SIGKILL) }
            // GuardHost creates an independent process group; never signal our own group.
            } else if getpgid(pid) == pid { kill(-pid, SIGKILL) } else { process.terminate() }
        }
        for app in NSWorkspace.shared.runningApplications {
            if let url = app.executableURL, url.standardizedFileURL.resolvingSymlinksInPath().path.hasPrefix(path + "/") { app.forceTerminate() }
        }
        process = nil; activePath = nil; claudeRunning = false
    }
    /// Returns the process-group leader started under the given sudo process, or nil.
    private func childProcessGroup(of sudoPID: Int32) -> Int32? {
        let task = Process(), pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        task.arguments = ["-P", String(sudoPID)]
        task.standardOutput = pipe; task.standardError = FileHandle.nullDevice
        do { try task.run() } catch { return nil }
        task.waitUntilExit()
        guard task.terminationStatus == 0 else { return nil }
        let text = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard let line = text.split(separator: "\n").first, let child = Int32(line), child > 1,
              getpgid(child) == child else { return nil }
        return child
    }
    func appendLog(_ text: String) {
        diagnostics.record("event", text)
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss"
        log.insert("\(f.string(from: Date()))  \(text)", at: 0); log = Array(log.prefix(80))
    }
    func addTraffic(_ record: TrafficRecord) {
        if let index = traffic.firstIndex(where: { $0.id == record.id }) { traffic[index] = record }
        else { traffic.insert(record, at: 0); traffic = Array(traffic.prefix(200)) }
    }
    func showTraffic() {
        if trafficWindow == nil {
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1080, height: 740),
                                  styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            window.title = "Трафик Claude — локальный просмотр"
            window.isReleasedWhenClosed = false; window.contentView = NSHostingView(rootView: TrafficView(model: self))
            window.center(); trafficWindow = window
        }
        trafficWindow?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    func exportTraffic() {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = "Claude-traffic.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
            try encoder.encode(traffic).write(to: url, options: .atomic)
        } catch { appendLog("Не удалось экспортировать журнал: \(error.localizedDescription)") }
    }
    func shutdown() { stop() }
    func showDiagnostics() {
        diagnostics.record("event", "Журнал завершений открыт пользователем.")
        NSWorkspace.shared.activateFileViewerSelecting([diagnostics.url])
    }
}

private final class PathSnapshotState: @unchecked Sendable {
    private var previous: String?
    // Called only on NWPathMonitor's dedicated serial callback queue.
    func changed(_ path: NWPath) -> Bool {
        let interfaces = path.availableInterfaces.map { "\($0.index):\($0.name):\($0.type)" }.sorted().joined(separator: ",")
        let gateways = path.gateways.map { String(describing: $0) }.sorted().joined(separator: ",")
        let snapshot = "\(path.status)|\(interfaces)|\(gateways)|\(path.supportsIPv4)|\(path.supportsIPv6)|\(path.supportsDNS)|\(path.isExpensive)|\(path.isConstrained)"
        defer { previous = snapshot }
        return previous.map { $0 != snapshot } ?? false
    }
}

private struct Surface<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        content.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            .background(GuardPalette.surface)
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(GuardPalette.border))
    }
}

@MainActor
private func confirmRestartDialog() -> Bool {
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = "Перезапустить Guard?"
    alert.informativeText = "Текущая сессия Claude будет закрыта, а пароль прокси потребуется ввести снова."
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Перезапустить").hasDestructiveAction = true
    alert.addButton(withTitle: "Отмена").keyEquivalent = "\u{1b}"
    return alert.runModal() == .alertFirstButtonReturn
}

struct GuardView: View {
    @ObservedObject var model: GuardModel
    @StateObject private var presentation = GuardPresentation()
    private var statusColor: Color {
        if model.requiresRestart { return GuardPalette.danger }
        if model.allowed { return GuardPalette.accent }
        if model.busy || model.monitoring { return GuardPalette.warning }
        return GuardPalette.secondary
    }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 14) {
                    Image(systemName: "network.badge.shield.half.filled")
                        .font(.system(size: 32, weight: .medium)).foregroundStyle(GuardPalette.accent)
                        .frame(width: 58, height: 58).background(GuardPalette.accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 17))
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Claude Proxy Guard").font(.system(size: 25, weight: .semibold, design: .rounded))
                        Text("Проверка IP перед запуском Claude").font(.system(size: 13)).foregroundStyle(GuardPalette.secondary)
                    }
                    Spacer()
                    Text("v" + (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.3.5")).font(.system(size: 11, weight: .medium, design: .monospaced)).foregroundStyle(GuardPalette.secondary)
                }
                Surface {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 9) {
                            Circle().fill(statusColor).frame(width: 8, height: 8)
                            Text(model.phase).font(.system(size: 16, weight: .semibold))
                                .foregroundStyle(model.requiresRestart ? GuardPalette.danger : GuardPalette.text)
                                .accessibilityAddTraits(.updatesFrequently)
                            Spacer()
                            if model.busy { ProgressView().controlSize(.small) }
                        }
                        if let report = model.report {
                            HStack(alignment: .firstTextBaseline, spacing: 16) {
                                Text(report.ip).font(.system(size: 25, weight: .medium, design: .monospaced)).textSelection(.enabled)
                                Text("\(report.country) · \(report.countryCode)").font(.system(size: 13)).foregroundStyle(GuardPalette.secondary)
                            }
                        } else { Text("Внешний IP ещё не проверен").font(.system(size: 15, weight: .medium)).foregroundStyle(GuardPalette.secondary) }
                        Text(model.detail).font(.system(size: 12)).foregroundStyle(GuardPalette.secondary).fixedSize(horizontal: false, vertical: true)
                            .accessibilityAddTraits(.updatesFrequently)
                        if model.requiresRestart {
                            Label("Нажмите «Перезапустить Guard» — пароль прокси нужно будет ввести снова.", systemImage: "exclamationmark.triangle.fill")
                                .font(.system(size: 13, weight: .semibold)).foregroundStyle(GuardPalette.danger)
                                .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                                .background(GuardPalette.danger.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                        }
                        if let previous = model.previousStop, !model.monitoring {
                            Text("Последняя причина завершения: \(previous)").font(.system(size: 11)).foregroundStyle(GuardPalette.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                        if let next = model.nextCheck {
                            Text("Следующая проверка в \(next.formatted(date: .omitted, time: .standard))")
                                .font(.system(size: 11, design: .monospaced)).foregroundStyle(GuardPalette.secondary)
                        }
                        HStack(spacing: 8) {
                            Button { presentation.lastAction = "Запуск: запрос отправлен"; model.check(andLaunch: true) } label: {
                                Label("Запустить", systemImage: "play")
                            }.buttonStyle(GuardActionStyle(primary: !model.claudeRunning && !model.busy && !model.requiresRestart))
                                .disabled(model.busy || model.claudeRunning || model.requiresRestart || model.restarting)
                                .keyboardShortcut(.defaultAction)
                                .help("Проверить IP и запустить копию Claude")
                            Button { presentation.lastAction = "Остановка: команда отправлена"; model.stop() } label: {
                                Label("Остановить", systemImage: "stop")
                            }.buttonStyle(GuardActionStyle(primary: (model.claudeRunning || model.busy) && !model.requiresRestart))
                                .disabled((!model.monitoring && !model.busy && !model.claudeRunning) || model.restarting)
                                .keyboardShortcut(".", modifiers: .command)
                                .help("Закрыть шлюз и остановить собственную копию Claude")
                            Button { requestRestart() } label: {
                                Label("Перезапустить Guard", systemImage: "arrow.clockwise")
                            }.buttonStyle(GuardActionStyle(primary: model.requiresRestart))
                                .disabled(model.restarting)
                                .help("Заново открыть Guard и закрыть текущую сессию. Пароль прокси потребуется ввести снова.")
                        }
                        Text("Последнее действие: \(presentation.lastAction)").font(.system(size: 12))
                            .foregroundStyle(presentation.lastAction == model.operationFailure ? GuardPalette.danger : GuardPalette.secondary)
                            .accessibilityLabel("Последнее действие: \(presentation.lastAction)")
                            .accessibilityAddTraits(.updatesFrequently)
                        HStack {
                            Label("Системная служба не используется", systemImage: "info.circle").font(.system(size: 12)).foregroundStyle(GuardPalette.secondary)
                            Spacer()
                            Button("Показать файл журнала") { model.showLog = true; model.showDiagnostics() }.keyboardShortcut("l", modifiers: .command)
                        }
                    }
                }
                Surface {
                    VStack(alignment: .leading, spacing: 16) {
                        Text("Подключение").font(.system(size: 15, weight: .semibold))
                        Picker("Маршрут", selection: $model.useProxy) {
                            Text("SOCKS5-прокси").tag(true)
                            Text("Текущая сеть / VPN").tag(false)
                        }.pickerStyle(.segmented).labelsHidden()
                        if model.useProxy {
                            HStack(alignment: .top, spacing: 12) {
                                field("Хост", placeholder: "127.0.0.1", value: $model.host)
                                field("Порт", placeholder: "1080", value: $model.port).frame(width: 95)
                            }
                            HStack(alignment: .top, spacing: 12) {
                                field("Логин, если нужен", placeholder: "Необязательно", value: $model.username)
                                VStack(alignment: .leading, spacing: 6) {
                                    Text("Пароль").font(.system(size: 11)).foregroundStyle(GuardPalette.secondary)
                                    SecureField("Необязательно", text: $model.password).textFieldStyle(.roundedBorder).accessibilityLabel("Пароль")
                                }
                            }
                            Text("Пароль остаётся только в памяти и не сохраняется на диск.")
                                .font(.system(size: 11)).foregroundStyle(GuardPalette.secondary)
                        } else {
                            Text("Проверяем IP текущего маршрута. VPN нужно включить отдельно. Приложение не меняет системные настройки сети.")
                                .font(.system(size: 12)).foregroundStyle(GuardPalette.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                        HStack {
                            Text("Внешний IP").font(.system(size: 12))
                            Spacer()
                            Picker("Интервал", selection: $model.interval) {
                                Text("Каждые 2 с").tag(2); Text("Каждые 5 с").tag(5); Text("Каждые 10 с").tag(10); Text("Каждые 30 с").tag(30)
                            }.labelsHidden().frame(width: 150)
                        }
                        Text("Публичный IP проверяется через ipify постоянно: без периодического контроля смена выхода может остаться незамеченной.").font(.system(size: 12))
                        Text("Изменение сети или ошибка проверки приостанавливает шлюз. Прежний подтверждённый IP возобновляет сессию; другой IP блокирует её до перезапуска Guard.")
                            .font(.system(size: 11)).foregroundStyle(GuardPalette.secondary).fixedSize(horizontal: false, vertical: true)
                    }.disabled(model.monitoring || model.busy || model.requiresRestart)
                }
                Surface {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Text("Системный сетевой барьер").font(.system(size: 15, weight: .semibold))
                            Spacer()
                            Toggle("", isOn: $model.networkBarrier).labelsHidden().toggleStyle(.switch)
                                .accessibilityLabel("Системный сетевой барьер")
                        }
                        Text(model.barrierSummary).font(.system(size: 12))
                            .foregroundStyle(model.networkBarrier && model.barrierActive ? GuardPalette.accent : GuardPalette.warning)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 12) {
                            Button("Проверить состояние") { model.refreshBarrierStatus() }
                            if model.networkBarrier && !model.barrierActive {
                                Button("Установить или восстановить…") { model.installBarrier() }
                            }
                        }.font(.system(size: 12))
                        Text("Барьер packet filter пропускает процессы Claude только к локальному шлюзу: весь TCP/UDP-трафик группы процессов (native, MCP, Cowork), идущий наружу, блокируется ядром, включая момент смены IP. Установка одноразово требует пароль администратора; выключенный барьер оставляет обходной риск.")
                            .font(.system(size: 11)).foregroundStyle(GuardPalette.secondary).fixedSize(horizontal: false, vertical: true)
                    }.disabled(model.monitoring || model.busy || model.requiresRestart)
                }
                Surface {
                    VStack(alignment: .leading, spacing: 13) {
                        Text("Профиль Claude").font(.system(size: 15, weight: .semibold))
                        HStack {
                            Picker("Часовой пояс", selection: $model.timezone) {
                                ForEach(LaunchProfile.timezones, id: \.self) { Text($0).tag($0) }
                            }
                            Picker("Язык", selection: $model.language) {
                                ForEach(LaunchProfile.languages, id: \.self) { Text($0).tag($0) }
                            }.frame(width: 160)
                        }
                        Label("Проверка профиля страницы и перехват включены", systemImage: "checkmark.shield").font(.system(size: 12))
                        Toggle("Показывать содержимое запросов и ответов", isOn: $model.captureBodies)
                            .font(.system(size: 12)).disabled(!model.inspectPages)
                        Text("Применяется к Claude. Настройки macOS не меняются. Диагностика работает через закрытый pipe, без сертификатов и сетевого порта.")
                            .font(.system(size: 11)).foregroundStyle(GuardPalette.secondary).fixedSize(horizontal: false, vertical: true)
                    }.disabled(model.monitoring || model.busy || model.requiresRestart)
                    Text(model.profileStatus).font(.system(size: 11, design: .monospaced)).foregroundStyle(GuardPalette.secondary).padding(.top, 8)
                }
                Surface {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Text("Claude Desktop").font(.system(size: 15, weight: .semibold))
                            Spacer()
                            if model.claudeRunning { Label("Запущен", systemImage: "checkmark.circle.fill").foregroundStyle(GuardPalette.accent).font(.system(size: 11)) }
                        }
                        Text(model.runtimeStatus).font(.system(size: 11)).foregroundStyle(GuardPalette.secondary).fixedSize(horizontal: false, vertical: true)
                        HStack {
                            Text(model.claudePath).font(.system(size: 11, design: .monospaced)).foregroundStyle(GuardPalette.secondary).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Button("Выбрать…") { model.selectClaude() }.disabled(model.monitoring || model.busy || model.requiresRestart)
                        }
                        Button("Только проверка IP") { presentation.lastAction = "Проверка IP: запрос отправлен"; model.check(andLaunch: false) }
                            .disabled(model.busy || model.requiresRestart || model.restarting)
                        HStack {
                            Link("Скачать официальный Claude Desktop ↗", destination: URL(string: "https://claude.com/download")!)
                                .font(.system(size: 11)).tint(.secondary)
                            Spacer()
                            Button("Трафик: \(model.traffic.count)") { model.showTraffic() }
                        }

                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    Label(model.networkBarrier && model.barrierActive ? "Системный kill switch активен" : "Упрощённая защита — системный барьер не активен", systemImage: model.networkBarrier && model.barrierActive ? "checkmark.shield" : "info.circle")
                        .font(.system(size: 12, weight: .medium)).foregroundStyle(model.networkBarrier && model.barrierActive ? GuardPalette.accent : GuardPalette.warning)
                    Text("Начальная страна: ipwho.is; повторный IP: ipify. Подтверждённый новый IP завершает сессию. Ошибка проверки, смена маршрута или сон приостанавливают трафик; прежний подтверждённый IP восстанавливает доступ без перезапуска Claude. Публичный IP нельзя проверить локально за NAT. Активный барьер ограничивает весь процесс Claude локальным шлюзом; без него native, MCP и Cowork могут обходить прокси; CDP видит только доступные веб-контексты.")
                        .font(.system(size: 11)).foregroundStyle(GuardPalette.secondary).fixedSize(horizontal: false, vertical: true)
                    DisclosureGroup("Журнал проверок", isExpanded: $model.showLog) {
                        VStack(alignment: .leading, spacing: 6) {
                            if model.log.isEmpty { Text("Проверок пока нет") }
                            ForEach(Array(model.log.enumerated()), id: \.offset) { _, line in Text(line).textSelection(.enabled) }
                        }.font(.system(size: 10, design: .monospaced)).foregroundStyle(GuardPalette.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
                    }.font(.system(size: 11)).padding(.top, 5)
                }.padding(.horizontal, 4)
            }.padding(28)
        }
        .frame(minWidth: 620, idealWidth: 720, minHeight: 620, idealHeight: 900)
        .background(GuardPalette.background)
        .foregroundStyle(GuardPalette.text)
        .tint(GuardPalette.accent)
        .onChange(of: model.phase) { phase in presentation.lastAction = model.operationFailure ?? (phase + " · " + Date().formatted(date: .omitted, time: .standard)) }
        .onReceive(model.$operationFailure) { failure in
            if let failure { presentation.lastAction = failure; Self.announce(failure) }
        }
        .onChange(of: model.requiresRestart) { blocked in
            if blocked && model.operationFailure == nil { Self.announce("Сессия закрыта. \(model.phase). Требуется перезапуск Guard.") }
        }
    }

    private func requestRestart() {
        if model.monitoring || model.claudeRunning || model.busy {
            guard confirmRestartDialog() else { return }
        }
        presentation.lastAction = "Перезапуск: ожидаем новое окно"
        model.restart()
    }

    private static func announce(_ message: String) {
        guard let window = NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.windows.first else { return }
        NSAccessibility.post(element: window, notification: .announcementRequested,
                             userInfo: [NSAccessibility.NotificationUserInfoKey.announcement: message,
                                        NSAccessibility.NotificationUserInfoKey.priority: NSAccessibilityPriorityLevel.high.rawValue])
    }

    private func field(_ title: String, placeholder: String, value: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 11)).foregroundStyle(GuardPalette.secondary)
            TextField(placeholder, text: value).textFieldStyle(.roundedBorder).accessibilityLabel(title)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = GuardModel()
    var window: NSWindow!
    var statusItem: NSStatusItem!
    private var restartedProcess: Process?

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls { model.deepLinkInbox.accept(url.absoluteString) }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        model.onRestart = { [weak self] in self?.restartApplication() }
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 850),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Claude Proxy Guard"
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: GuardView(model: model))
        window.center(); showWindow()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem.button?.image = NSImage(systemSymbolName: "network.badge.shield.half.filled", accessibilityDescription: "Claude Proxy Guard")
        let menu = NSMenu()
        let open = NSMenuItem(title: "Открыть Claude Proxy Guard", action: #selector(showWindow), keyEquivalent: "")
        open.target = self; menu.addItem(open)
        let stop = NSMenuItem(title: "Остановить Claude и шлюз", action: #selector(stopGuard), keyEquivalent: "")
        stop.target = self; menu.addItem(stop)
        let restart = NSMenuItem(title: "Перезапустить Guard", action: #selector(restartGuard), keyEquivalent: "")
        restart.target = self; menu.addItem(restart)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Выйти", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        statusItem.menu = menu
        let appMenu = NSMenu()
        let root = NSMenuItem(); appMenu.addItem(root)
        let submenu = NSMenu(); root.submenu = submenu
        submenu.addItem(NSMenuItem(title: "О Claude Proxy Guard", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: ""))
        submenu.addItem(.separator())
        submenu.addItem(NSMenuItem(title: "Скрыть Claude Proxy Guard", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h"))
        let hideOthers = NSMenuItem(title: "Скрыть остальные", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        submenu.addItem(hideOthers)
        submenu.addItem(.separator())
        submenu.addItem(NSMenuItem(title: "Выйти из Claude Proxy Guard", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        let editRoot = NSMenuItem(); appMenu.addItem(editRoot)
        let edit = NSMenu(title: "Правка"); editRoot.submenu = edit
        for (title, selector, key) in [("Отменить", "undo:", "z"), ("Вырезать", "cut:", "x"), ("Копировать", "copy:", "c"), ("Вставить", "paste:", "v"), ("Выбрать всё", "selectAll:", "a")] {
            edit.addItem(NSMenuItem(title: title, action: Selector(selector), keyEquivalent: key))
        }
        let windowRoot = NSMenuItem(); appMenu.addItem(windowRoot)
        let windowMenu = NSMenu(title: "Окно"); windowRoot.submenu = windowMenu
        windowMenu.addItem(NSMenuItem(title: "Свернуть", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m"))
        windowMenu.addItem(NSMenuItem(title: "Увеличить", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: ""))
        windowMenu.addItem(.separator())
        windowMenu.addItem(NSMenuItem(title: "Закрыть", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w"))
        windowMenu.addItem(.separator())
        windowMenu.addItem(NSMenuItem(title: "Все окна — на передний план", action: #selector(NSApplication.arrangeInFront(_:)), keyEquivalent: ""))
        NSApplication.shared.windowsMenu = windowMenu
        NSApplication.shared.mainMenu = appMenu
    }

    @objc func showWindow() { window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
    @objc func stopGuard() { model.stop() }
    @objc func restartGuard() {
        guard !model.restarting else { return }
        if model.monitoring || model.claudeRunning || model.busy {
            guard confirmRestartDialog() else { return }
        }
        model.restart()
    }
    private func restartApplication() {
        model.shutdown()
        do {
            guard let executable = Bundle.main.executableURL else { throw GuardError.message("Не найдено приложение для перезапуска.") }
            restartedProcess = try GuardRelauncher.launch(executable: executable)
            NSApp.terminate(nil)
        } catch { model.restartFailed("Не удалось перезапустить Guard: \(error.localizedDescription)") }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool { showWindow(); return true }
    func applicationWillTerminate(_ notification: Notification) { model.shutdown() }
}

#if !PREVIEW
@main
struct Main {
    @MainActor static func main() {
        signal(SIGPIPE, SIG_IGN)
        let application = NSApplication.shared
        let delegate = AppDelegate()
        application.delegate = delegate
        application.setActivationPolicy(.regular)
        application.run()
        withExtendedLifetime(delegate) {}
    }
}
#endif
