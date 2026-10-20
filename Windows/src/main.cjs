'use strict';
const { app, BrowserWindow, ipcMain, dialog, powerMonitor } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { GuardController } = require('./controller.cjs');
const { discoverClaude } = require('./runtime.cjs');
const { validateSettings } = require('./policy.cjs');
const { diagnostic } = require('./sanitize.cjs');

app.setName('Claude Proxy Guard');
app.setAppUserModelId?.('local.proxyguard.gate-claude');
if (!app.requestSingleInstanceLock()) { app.quit(); }
else {
  let window, controller;
  const traffic = new Map();
  const root = path.join(app.getPath('userData'), 'Guard');
  const resources = app.isPackaged ? process.resourcesPath : path.resolve(__dirname, '..', 'resources');
  const send = (type, data) => { if (window && !window.isDestroyed()) window.webContents.send('guard:event', { type, data }); };
  const safeError = error => diagnostic(error?.message || 'Не удалось выполнить действие.');
  function settings() {
    const defaults = { host: '127.0.0.1', port: 1080, username: '', timezone: 'Europe/Amsterdam', language: 'en-US', interval: 5, captureBodies: false, claudePath: '' };
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
    controller = new GuardController(root, resources);
    controller.on('state', value => send('state', value));
    controller.on('log', value => send('log', value));
    controller.on('record', value => {
      traffic.set(value.id, value); while (traffic.size > 200) traffic.delete(traffic.keys().next().value);
      send('record', value);
    });
    handle('init', async () => {
      const value = settings(); if (!value.claudePath) value.claudePath = await discoverClaude();
      return { version: app.getVersion(), settings: value, state: controller.snapshot(), logs: controller.events, records: [...traffic.values()] };
    });
    handle('choose', async () => {
      const result = await dialog.showOpenDialog(window, { title: 'Выберите установленный claude.exe', properties: ['openFile'], filters: [{ name: 'Claude Desktop', extensions: ['exe'] }] });
      return result.canceled ? '' : result.filePaths[0];
    });
    handle('start', async input => {
      const value = validateSettings(input), saved = { ...value }; delete saved.password;
      fs.mkdirSync(root, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(root, 'settings.json'), JSON.stringify(saved, null, 2), { mode: 0o600 });
      traffic.clear(); send('clear', null); await controller.start(value); return controller.snapshot();
    });
    handle('stop', () => { controller.stop(); return controller.snapshot(); });
    handle('restart', async () => {
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
          if (document.body.dataset.ready === 'true' || Date.now() - started > 15000)
            resolve({title:document.title,api:typeof window.guard?.start,ready:document.body.dataset.ready,buttons:document.querySelectorAll('button').length});
          else setTimeout(poll, 50);
        }; poll();
      })`);
      const out = process.env.GATE_SMOKE_OUT;
      if (process.env.GATE_SMOKE_PNG) fs.writeFileSync(process.env.GATE_SMOKE_PNG, (await window.webContents.capturePage()).toPNG());
      if (out) fs.writeFileSync(out, JSON.stringify({ ...proof, platform: process.platform, version: app.getVersion(), result: proof.ready === 'true' && proof.api === 'function' ? 'PASS' : 'FAIL' }, null, 2));
      app.exit(proof.ready === 'true' && proof.api === 'function' ? 0 : 1);
    }
  }).catch(error => {
    dialog.showErrorBox('Claude Proxy Guard', safeError(error)); app.exit(1);
  });
  app.on('second-instance', () => { if (window) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); } });
  app.on('before-quit', () => controller?.stop());
  app.on('window-all-closed', () => app.quit());
  const powerBlock = () => { if (controller && !['idle', 'blocked'].includes(controller.state)) controller.block('Сон или пробуждение компьютера. Перезапустите Guard.'); };
  app.whenReady().then(() => { powerMonitor.on('suspend', powerBlock); powerMonitor.on('resume', powerBlock); });
  process.on('uncaughtException', () => { controller?.block('Внутренняя ошибка Guard. Сессия закрыта.'); app.exit(1); });
  process.on('unhandledRejection', () => { controller?.block('Внутренняя ошибка Guard. Сессия закрыта.'); app.exit(1); });
}
