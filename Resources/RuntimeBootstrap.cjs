'use strict';
const electron = require('electron');
const { app, webContents } = electron;
const fs = require('node:fs');
const path = require('node:path');
const cfg = JSON.parse(process.env.PROXY_GUARD_CONFIG || '{}');
if (!path.isAbsolute(cfg.userData || '')) throw Error('Guard: absolute userData required');
fs.mkdirSync(cfg.userData, { recursive: true, mode: 0o700 });
app.setName('Claude Proxy Guard Runtime');
app.setPath('userData', cfg.userData);
app.setPath('logs', path.join(cfg.userData, 'logs'));
if (cfg.proxyURL) {
  app.commandLine.appendSwitch('proxy-server', cfg.proxyURL);
  app.commandLine.appendSwitch('proxy-bypass-list', '<-loopback>');
}
app.commandLine.appendSwitch('lang', cfg.language || 'en-US');
try { electron.autoUpdater.checkForUpdates = function () { this.emit('update-not-available'); }; } catch {}
const reader = fs.createReadStream(null, { fd: 3, autoClose: false });
const writer = fs.createWriteStream(null, { fd: 4, autoClose: false });
const sessions = new Map();
const rootSessions = new Map();
let autoAttach = false;
let incoming = Buffer.alloc(0);
function emit(message) { writer.write(JSON.stringify(message) + '\0'); }
function fatal(error) { emit({ method: 'ProxyGuard.error', params: { message: String(error && error.message || error) } }); app.exit(1); }
function localeMatches(actual) {
  return typeof actual === 'string' && actual.replaceAll('_', '-').toLowerCase() === (cfg.language || 'en-US').toLowerCase();
}
async function ensureRendererLocale(wc) {
  let inherited = false;
  try {
    await wc.debugger.sendCommand('Emulation.setLocaleOverride', { locale: (cfg.language || 'en-US').replaceAll('-', '_') });
  } catch (error) {
    if (!String(error.message || error).includes('Another locale override is already in effect')) throw error;
    inherited = true;
  }
  // ICU locale belongs to the renderer process, while CDP ownership belongs to an agent.
  // Another agent may already own the correct locale. Verify it before navigation.
  const response = await wc.debugger.sendCommand('Runtime.evaluate', {
    expression: 'Intl.DateTimeFormat().resolvedOptions().locale', returnByValue: true
  });
  const actual = response.result && response.result.value;
  if (response.exceptionDetails || !localeMatches(actual)) throw Error('Renderer locale mismatch: ' + String(actual));
  if (inherited) emit({ method: 'ProxyGuard.notice', params: { message: 'Общая локаль renderer проверена: ' + actual } });
  return inherited;
}
function expose(wc) {
  const sid = rootSessions.get(wc.id);
  if (sid && autoAttach) emit({ method: 'Target.attachedToTarget', params: { sessionId: sid, waitingForDebugger: false,
    targetInfo: { targetId: String(wc.id), type: wc.getType() === 'webview' ? 'page' : 'page', title: '', url: wc.getURL() } } });
}
const sessionGates = new WeakMap();
function configureSession(s) {
  if (sessionGates.has(s)) return sessionGates.get(s);
  const gate = cfg.proxyURL ? s.setProxy({ mode: 'fixed_servers', proxyRules: cfg.proxyURL, proxyBypassRules: '<-loopback>' }) : Promise.resolve();
  sessionGates.set(s, gate); gate.catch(fatal); return gate;
}
app.on('session-created', configureSession);
function attach(wc) {
  if (rootSessions.has(wc.id)) { expose(wc); return; }
  const type = wc.getType();
  if (!['window', 'webview', 'browserView', 'offscreen'].includes(type)) return;
  const sid = 'guard-' + wc.id;
  let closed = false;
  const active = () => !closed && !wc.isDestroyed();
  const targetFailure = error => { if (active()) fatal(error); };
  function cleanup() {
    if (closed) return;
    closed = true;
    for (const [id, session] of sessions) if (session.wc === wc) sessions.delete(id);
    rootSessions.delete(wc.id);
    emit({ method: 'Target.detachedFromTarget', params: { sessionId: sid } });
  }
  wc.debugger.attach('1.3');
  rootSessions.set(wc.id, sid); sessions.set(sid, { wc });
  wc.debugger.on('message', (_event, method, params, childSessionId) => {
    if (!active()) return;
    if (method === 'Target.attachedToTarget' && params.sessionId) sessions.set(params.sessionId, { wc, child: params.sessionId });
    if (method === 'Target.detachedFromTarget' && params.sessionId) sessions.delete(params.sessionId);
    emit({ method, params, sessionId: childSessionId || sid });
  });
  wc.debugger.on('detach', (_e, reason) => {
    // Electron emits detach before destroyed during ordinary window teardown.
    // A live target losing its debugger still fails closed after the teardown turn.
    setImmediate(() => { if (!active()) cleanup(); else fatal(new Error('Debugger detached: ' + reason)); });
  });
  wc.once('destroyed', cleanup);
  const originalLoadURL = wc.loadURL.bind(wc);
  const ready = (async () => {
    // A blank renderer must exist before renderer-domain CDP commands can complete.
    await configureSession(wc.session);
    await Promise.resolve();
    await originalLoadURL('about:blank');
    await wc.debugger.sendCommand('Emulation.setTimezoneOverride', { timezoneId: cfg.timezone || 'Europe/Amsterdam' });
    await ensureRendererLocale(wc);
    await wc.debugger.sendCommand('Network.enable');
    await wc.debugger.sendCommand('Network.setUserAgentOverride', { userAgent: wc.getUserAgent(), acceptLanguage: cfg.language || 'en-US' });
    await wc.debugger.sendCommand('Network.setExtraHTTPHeaders', { headers: { 'Accept-Language': cfg.language || 'en-US' } });
  })();
  ready.catch(targetFailure);
  // Apply the profile before the application navigates its first web page.
  for (const name of ['loadURL', 'loadFile']) {
    const original = wc[name].bind(wc);
    wc[name] = (...args) => ready.then(() => active() ? original(...args) : undefined)
      .catch(error => { if (active()) throw error; });
  }
  expose(wc);
}
app.on('web-contents-created', (_event, wc) => { try { attach(wc); } catch (error) { fatal(error); } });
async function command(m) {
  let result;
  if (!m.sessionId) {
    if (m.method === 'Browser.getVersion') result = { userAgent: app.userAgentFallback, product: 'Chrome/' + process.versions.chrome, protocolVersion: '1.3' };
    else if (m.method === 'Target.setAutoAttach') { autoAttach = !!m.params.autoAttach; for (const wc of webContents.getAllWebContents()) attach(wc); result = {}; }
    else if (m.method === 'Target.getTargets') result = { targetInfos: [...rootSessions].map(([id]) => ({ targetId: String(id), type: 'page' })) };
    else throw Error('Unsupported root method: ' + m.method);
  } else {
    const session = sessions.get(m.sessionId);
    if (!session || session.wc.isDestroyed()) throw Error('Target closed');
    const params = { ...m.params };
    if (m.method === 'Network.setUserAgentOverride' && !session.child) params.userAgent = session.wc.getUserAgent();
    result = session.child ? await session.wc.debugger.sendCommand(m.method, params, session.child) : await session.wc.debugger.sendCommand(m.method, params);
  }
  emit({ id: m.id, result: result || {} });
}
reader.on('data', chunk => {
  incoming = Buffer.concat([incoming, chunk]);
  if (incoming.length > 8 * 1024 * 1024) { fatal(Error('Input buffer exceeded')); return; }
  let delimiter;
  while ((delimiter = incoming.indexOf(0)) >= 0) {
    const packet = incoming.subarray(0, delimiter); incoming = incoming.subarray(delimiter + 1);
    let message;
    try { message = JSON.parse(packet.toString()); } catch (error) { fatal(error); return; }
    command(message).catch(error => emit({ id: message.id, error: { message: String(error.message || error) } }));
  }
});
reader.on('end', () => app.exit(0)); reader.on('error', fatal); writer.on('error', () => app.exit(1));
