'use strict';
const { app, BrowserWindow, ipcMain, dialog, powerMonitor, shell } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { GuardController } = require('./controller.cjs');
const { NetworkFence } = require('./fence.cjs');
const { discoverClaude } = require('./discovery.cjs');
const { prepareRuntime } = require('./runtime.cjs');
const { validateSettings } = require('./policy.cjs');
const { diagnostic } = require('./sanitize.cjs');
const { takeDeepLinkFromArgv, LINK_REFUSED } = require('./deep-link.cjs');
const { ensureGuardProtocolRegistration, SETTINGS_URL } = require('./protocol-registration.cjs');

app.setName('Claude Proxy Guard');
app.setAppUserModelId?.('local.proxyguard.gate-claude');
if (!app.requestSingleInstanceLock()) { app.quit(); }
else {
  let window, controller, protocolState, earlyLinkRefused = false;
  const receiveDeepLink = argv => {
    const link = takeDeepLinkFromArgv(argv);
    if (!link.hadLink) return;
    if (!controller) { earlyLinkRefused = true; return; }
    void controller.deliverDeepLink(link.url);
  };
  receiveDeepLink(process.argv);
  const traffic = new Map();
  const root = path.join(app.getPath('userData'), 'Guard');
  const resources = app.isPackaged ? process.resourcesPath : path.resolve(__dirname, '..', 'resources');
  const send = (type, data) => { if (window && !window.isDestroyed()) window.webContents.send('guard:event', { type, data }); };
  const safeError = error => diagnostic(error?.message || 'Не удалось выполнить действие.');
  function settings() {
    const defaults = { mode: 'network', host: '127.0.0.1', port: 1080, username: '', timezone: 'Europe/Amsterdam', language: 'en-US', interval: 2, captureBodies: false, claudePath: '', claudeSource: 'auto' };
    try {
      const stored = validateSettings({ ...JSON.parse(fs.readFileSync(path.join(root, 'settings.json'), 'utf8')), password: '' });
      delete stored.password; return { ...defaults, ...stored };
    } catch { return defaults; }
  }
  function handle(name, callback) {
    ipcMain.handle('guard:' + name, async (event, ...args) => {
      if (event.sender !== window?.webContents || event.senderFrame !== window.webContents.mainFrame) throw Error('Недопустимый источник команды.');
      try { return await callback(...args); } catch (error) { return { error: safeError(error) }; }
    });
  }
  app.whenReady().then(async () => {
    controller = new GuardController(root, resources, {
      ownerWindow: () => {
        if (!window || window.isDestroyed()) throw Error('Окно Guard недоступно для системного запроса Windows.');
        window.show(); window.focus();
        return window.getNativeWindowHandle();
      }
    });
    const checkProtocol = async () => {
      protocolState = await ensureGuardProtocolRegistration(app, { smokeTest: process.argv.includes('--smoke-test') });
      send('protocol', protocolState); return protocolState;
    };
    await checkProtocol();
    if (protocolState.selectionRequired) controller.log(protocolState.registered
      ? 'Для входа по ссылке выберите Claude Proxy Guard для протокола claude в приложениях Windows по умолчанию.'
      : 'Не удалось зарегистрировать обработчик входа Guard. Повторите проверку выбора приложения.', 'warning');
    if (earlyLinkRefused) { earlyLinkRefused = false; controller.log(LINK_REFUSED, 'warning'); }
    controller.on('state', value => send('state', value));
    controller.on('log', value => send('log', value));
    controller.on('record', value => {
      traffic.set(value.id, value); while (traffic.size > 200) traffic.delete(traffic.keys().next().value);
      send('record', value);
    });
    handle('init', async () => {
      const value = settings();
      return { version: app.getVersion(), settings: value, protocol: protocolState, state: controller.snapshot(), logs: controller.events, records: [...traffic.values()] };
    });
    let finding;
    const findClaude = () => {
      if (!finding) finding = discoverClaude().finally(() => { finding = null; });
      return finding;
    };
    handle('find', findClaude);
    handle('codeWorkspace', async () => {
      const workspace = path.join(root, 'CodeState', 'Workspace');
      for (const directory of [root, path.join(root, 'CodeState'), workspace]) {
        try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
        const info = fs.lstatSync(directory);
        if (!info.isDirectory() || info.isSymbolicLink() || fs.realpathSync(directory).toLowerCase() !== path.resolve(directory).toLowerCase()) throw Error('Рабочая папка Code не прошла проверку пути.');
      }
      const message = await shell.openPath(workspace);
      if (message) throw Error('Не удалось открыть рабочую папку Code.');
      return { opened: true };
    });
    handle('protocolCheck', checkProtocol);
    handle('protocolSettings', async () => {
      // This action accepts no URL or path from the renderer.
      await shell.openExternal(SETTINGS_URL); return { opened: true };
    });
    handle('choose', async () => {
      const result = await dialog.showOpenDialog(window, { title: 'Выберите установленный claude.exe', properties: ['openFile'], filters: [{ name: 'Claude Desktop', extensions: ['exe'] }] });
      return result.canceled ? '' : result.filePaths[0];
    });
    handle('start', async input => {
      const value = validateSettings(input);
      if (value.claudeSource === 'auto') {
        const found = await findClaude();
        if (found.status !== 'found') throw Error(found.message);
        value.claudePath = found.path; send('discovery', found);
      }
      const saved = { ...value }; delete saved.password;
      fs.mkdirSync(root, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(root, 'settings.json'), JSON.stringify(saved, null, 2), { mode: 0o600 });
      traffic.clear(); send('clear', null); await controller.start(value); return controller.snapshot();
    });
    handle('stop', () => { controller.stop(); return controller.snapshot(); });
    handle('restart', async () => {
      if (NetworkFence.approvalPending) throw Error('Сначала ответьте на системный запрос Windows. Для отмены запуска выберите «Нет», затем перезапустите Guard.');
      const host = controller.host; controller.stop();
      if (host && host.exitCode == null) await Promise.race([new Promise(resolve => host.once('exit', resolve)), new Promise(resolve => setTimeout(resolve, 1500))]);
      app.relaunch(); app.exit(0);
    });
    handle('export', async () => {
      const result = await dialog.showSaveDialog(window, { title: 'Экспорт перехваченного трафика', defaultPath: 'guard-traffic.json', filters: [{ name: 'JSON', extensions: ['json'] }] });
      if (!result.canceled && result.filePath) { fs.writeFileSync(result.filePath, JSON.stringify([...traffic.values()], null, 2), { mode: 0o600 }); return true; }
      return false;
    });
    window = new BrowserWindow({ width: 1140, height: 820, minWidth: 880, minHeight: 650, backgroundColor: '#101919', title: 'Claude Proxy Guard',
      autoHideMenuBar: true, webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, sandbox: true, nodeIntegration: false, webSecurity: true } });
    window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    window.webContents.on('will-navigate', event => event.preventDefault());
    window.webContents.session.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
    window.webContents.session.setPermissionCheckHandler(() => false);
    window.webContents.on('render-process-gone', () => { controller.block('Окно Guard аварийно завершилось.'); app.quit(); });
    await window.loadFile(path.join(__dirname, 'ui', 'index.html'));
    if (process.argv.includes('--smoke-test')) {
      const proof = await window.webContents.executeJavaScript(`new Promise(resolve => {
        const started = Date.now();
        const poll = () => {
          if (document.body.dataset.ready === 'true' && document.body.dataset.discoveryDone === 'true' || Date.now() - started > 25000)
            resolve({title:document.title,api:typeof window.guard?.start,ready:document.body.dataset.ready,discoveryDone:document.body.dataset.discoveryDone,
              claudeFound:document.body.dataset.claudeFound==='true',connectionModes:[...document.querySelectorAll('#mode option')].map(x=>x.value),
              selectedMode:document.getElementById('mode').value,claudeSource:document.getElementById('claudeSource').value,buttons:document.querySelectorAll('button').length});
          else setTimeout(poll, 50);
        }; poll();
      })`);
      const out = process.env.GATE_SMOKE_OUT;
      if (process.platform === 'win32') {
        proof.nativeRoutesVerified = false;
        try { await controller.routeFingerprint(); proof.nativeRoutesVerified = true; }
        catch { proof.routeErrorCode = controller.routeErrorCode; }
      }
      await window.webContents.executeJavaScript('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
      if (process.env.GATE_SMOKE_PNG) fs.writeFileSync(process.env.GATE_SMOKE_PNG, (await window.webContents.capturePage()).toPNG());
      if (process.env.GATE_SMOKE_PREPARE === '1') {
        proof.runtimePrepared = false;
        try {
          const found = await findClaude();
          if (found.status !== 'found') throw Error(found.message);
          const runtime = await prepareRuntime(found.path, path.join(root, 'Cache'), path.join(resources, 'RuntimeBootstrap.cjs'));
          proof.runtimePrepared = Boolean(runtime.executable);
          proof.sourceSignatureValid = runtime.signature === 'Valid';
        } catch (error) { proof.prepareError = safeError(error); }
      }
      const ok = proof.ready === 'true' && proof.api === 'function' && proof.discoveryDone === 'true' && proof.connectionModes.includes('network') && proof.connectionModes.includes('socks5') &&
        (process.platform !== 'win32' || proof.nativeRoutesVerified === true) &&
        (process.env.GATE_EXPECT_CLAUDE !== '1' || proof.claudeFound) &&
        (process.env.GATE_SMOKE_PREPARE !== '1' || proof.runtimePrepared && proof.sourceSignatureValid);
      if (out) fs.writeFileSync(out, JSON.stringify({ ...proof, platform: process.platform, version: app.getVersion(), result: ok ? 'PASS' : 'FAIL' }, null, 2));
      app.exit(ok ? 0 : 1);
    }
  }).catch(error => {
    dialog.showErrorBox('Claude Proxy Guard', safeError(error)); app.exit(1);
  });
  app.on('second-instance', (_event, argv) => { receiveDeepLink(argv); if (window) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); } });
  app.on('before-quit', () => controller?.stop());
  app.on('window-all-closed', () => app.quit());
  const powerBlock = () => { if (controller && !['idle', 'blocked'].includes(controller.state)) controller.revalidate('Сон или пробуждение компьютера. Проверяем прежний IP.'); };
  app.whenReady().then(() => { powerMonitor.on('suspend', powerBlock); powerMonitor.on('resume', powerBlock); });
  process.on('uncaughtException', () => { controller?.block('Внутренняя ошибка Guard. Сессия закрыта.'); app.exit(1); });
  process.on('unhandledRejection', () => { controller?.block('Внутренняя ошибка Guard. Сессия закрыта.'); app.exit(1); });
}
