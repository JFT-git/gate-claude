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
// --- Native network hardening (PG-05/06) ---------------------------------
// The kernel packet filter (when armed) is the real boundary; these hooks add
// fail-closed depth inside the main process for QUIC/UDP/DNS and direct Node
// egress. Loopback stays available so local MCP/IPC keeps working.
function installNetworkHardening() {
  const net = require('node:net'), tls = require('node:tls'), dgram = require('node:dgram');
  const dns = require('node:dns'), http = require('node:http'), https = require('node:https'), http2 = require('node:http2');
  const denied = name => { const error = Error('Guard blocked network escape: ' + name); error.code = 'ERR_GUARD_NETWORK_DENIED'; return error; };
  const deny = name => function () { throw denied(name); };
  function hook(object, key, value) {
    if (!object || typeof object[key] !== 'function') return;
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor && !descriptor.configurable) {
      if (object[key] !== value) throw Error('Guard cannot protect ' + key);
      return;
    }
    Object.defineProperty(object, key, { enumerable: descriptor?.enumerable ?? true, configurable: false, get: () => value, set() {} });
  }
  function block(object, names, label) { for (const name of names) hook(object, name, deny(label + '.' + name)); }
  const literalLoopback = value => /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(value)) || String(value) === '::1';
  const originalConnect = net.Socket.prototype.connect;
  hook(net.Socket.prototype, 'connect', function (...args) {
    const target = args[0];
    if (typeof target === 'string') {
      if (target.startsWith('/')) return originalConnect.apply(this, args); // unix socket: local
      // Numeric-string port form: connect("443", "host").
      const host = typeof args[1] === 'string' ? args[1] : undefined;
      if (/^\d+$/.test(target) && (!host || literalLoopback(host))) return originalConnect.apply(this, args);
      throw denied('net.Socket.connect');
    }
    if (target && typeof target === 'object') {
      if (target.path) return originalConnect.apply(this, args); // unix socket: local
      if (!target.host || literalLoopback(target.host)) return originalConnect.apply(this, args);
      throw denied('net.Socket.connect');
    }
    const host = typeof args[1] === 'string' ? args[1] : undefined;
    if (!host || literalLoopback(host)) return originalConnect.apply(this, args);
    throw denied('net.Socket.connect');
  });
  const pipeConnection = function (...args) { return new net.Socket().connect(...args); };
  hook(net, 'connect', pipeConnection); hook(net, 'createConnection', pipeConnection);
  const originalListen = net.Server.prototype.listen;
  hook(net.Server.prototype, 'listen', function (...args) {
    const target = args[0];
    if (typeof target === 'string') return originalListen.apply(this, args); // unix socket: local
    if (target && typeof target === 'object') {
      if (target.path) return originalListen.apply(this, args);
      if (literalLoopback(target.host)) return originalListen.apply(this, args);
      throw denied('net.Server.listen');
    }
    // listen(port) without a host would bind every interface: require loopback.
    const host = typeof args[1] === 'string' ? args[1] : undefined;
    if (literalLoopback(host)) return originalListen.apply(this, args);
    throw denied('net.Server.listen');
  });
  const originalTls = tls.connect;
  hook(tls, 'connect', function (...args) {
    const target = args[0];
    if (target && typeof target === 'object' && target.socket) return originalTls.apply(this, args); // wraps a gated socket
    if (typeof target === 'string' && /^\d+$/.test(target)) {
      const host = typeof args[1] === 'string' ? args[1] : undefined;
      if (!host || literalLoopback(host)) return originalTls.apply(this, args);
      throw denied('tls.connect');
    }
    const host = target && typeof target === 'object' ? target.host : (typeof args[0] === 'number' ? args[1] : typeof target === 'string' ? target : undefined);
    if (!host || literalLoopback(host)) return originalTls.apply(this, args);
    throw denied('tls.connect');
  });
  block(dgram, ['createSocket'], 'dgram');
  block(dgram.Socket?.prototype, ['send', 'connect', 'bind', 'addMembership', 'addSourceSpecificMembership'], 'dgram.Socket');
  const dnsMethods = object => Object.getOwnPropertyNames(object || {}).filter(name => /^(?:resolve|reverse)/.test(name));
  for (const object of [dns, dns.promises, dns.Resolver?.prototype, dns.promises?.Resolver?.prototype]) block(object, dnsMethods(object), 'dns');
  block(dns.Resolver?.prototype, ['lookup'], 'dns'); block(dns.promises?.Resolver?.prototype, ['lookup'], 'dns');
  // Node resolves even literal listen/connect hosts through dns.lookup; loopback
  // literals make no network query, so only those may pass.
  const originalLookup = dns.lookup;
  hook(dns, 'lookup', function (name, ...rest) {
    if (literalLoopback(String(name))) return originalLookup.apply(this, [name, ...rest]);
    throw denied('dns.lookup');
  });
  if (dns.promises && typeof dns.promises.lookup === 'function') {
    const originalPromisesLookup = dns.promises.lookup;
    hook(dns.promises, 'lookup', function (name, ...rest) {
      if (literalLoopback(String(name))) return originalPromisesLookup.apply(this, [name, ...rest]);
      throw denied('dns.promises.lookup');
    });
  }
  const httpGuard = (original, label) => function (...args) {
    const target = args[0];
    let host;
    try {
      if (typeof target === 'string' || target instanceof URL) host = new URL(target).hostname;
      else host = target?.hostname ?? (typeof target?.host === 'string' ? target.host.split(':')[0] : undefined);
    } catch { throw denied(label); }
    if (host === undefined || literalLoopback(host)) return original.apply(this, args);
    throw denied(label);
  };
  hook(http, 'request', httpGuard(http.request, 'http.request')); hook(http, 'get', httpGuard(http.get, 'http.get'));
  hook(https, 'request', httpGuard(https.request, 'https.request')); hook(https, 'get', httpGuard(https.get, 'https.get'));
  const originalHttp2 = http2.connect;
  hook(http2, 'connect', function (authority) {
    let host;
    try { host = new URL(String(authority)).hostname; } catch { throw denied('http2.connect'); }
    if (literalLoopback(host)) return originalHttp2.apply(this, arguments);
    throw denied('http2.connect');
  });
  const originalFetch = globalThis.fetch;
  if (typeof originalFetch === 'function') {
    hook(globalThis, 'fetch', function (input) {
      let host;
      try { host = new URL(typeof input === 'string' ? input : input.url).hostname; } catch { return Promise.reject(denied('fetch')); }
      if (literalLoopback(host)) return originalFetch.apply(this, arguments);
      return Promise.reject(denied('fetch'));
    });
  }
  for (const name of ['WebSocket', 'EventSource']) {
    const original = globalThis[name];
    if (typeof original !== 'function') continue;
    hook(globalThis, name, function (url) {
      let host;
      try { host = new URL(String(url)).hostname; } catch { throw denied(name); }
      if (!literalLoopback(host)) throw denied(name);
      return Reflect.construct(original, arguments);
    });
  }
  const proxySettingsMatch = options => options && options.mode === 'fixed_servers' &&
    options.proxyRules === cfg.proxyURL && options.proxyBypassRules === '<-loopback>' && !options.pacScript;
  const protectedSessions = new WeakSet();
  function protectSession(s) {
    if (!s || protectedSessions.has(s)) return;
    protectedSessions.add(s);
    const setProxy = s.setProxy;
    hook(s, 'setProxy', function (options) {
      if (!cfg.proxyURL || !proxySettingsMatch(options)) return Promise.reject(denied('session.setProxy'));
      return setProxy.call(this, options);
    });
    block(s, ['resolveHost'], 'session');
  }
  app.on('session-created', protectSession);
  installNetworkHardening.protectSession = protectSession;
  const commandLine = app.commandLine;
  const switches = {
    'force-webrtc-ip-handling-policy': 'disable_non_proxied_udp', 'disable-quic': '', 'dns-prefetch-disable': '',
    // Destination names are resolved by the relay; Chromium only connects to its
    // literal loopback address. Speculative/background hostname lookups must fail.
    'host-resolver-rules': 'MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'
  };
  if (cfg.proxyURL) { switches['proxy-server'] = cfg.proxyURL; switches['proxy-bypass-list'] = '<-loopback>'; }
  const dangerousSwitches = new Set(['no-proxy-server', 'proxy-auto-detect', 'proxy-pac-url', 'enable-quic']);
  const appendSwitch = commandLine.appendSwitch;
  for (const [name, value] of Object.entries(switches)) appendSwitch.call(commandLine, name, value);
  hook(commandLine, 'appendSwitch', function (name, value = '') {
    const key = String(name).replace(/^--/, '').toLowerCase();
    if (dangerousSwitches.has(key) || (Object.hasOwn(switches, key) && String(value) !== switches[key])) throw denied('commandLine.appendSwitch');
    return appendSwitch.call(this, name, value);
  });
  const removeSwitch = commandLine.removeSwitch;
  hook(commandLine, 'removeSwitch', function (name) {
    if (Object.hasOwn(switches, String(name).replace(/^--/, '').toLowerCase())) throw denied('commandLine.removeSwitch');
    return removeSwitch.call(this, name);
  });
  const appendArgument = commandLine.appendArgument;
  hook(commandLine, 'appendArgument', function (argument) {
    if (String(argument).startsWith('--')) throw denied('commandLine.appendArgument');
    return appendArgument.call(this, argument);
  });
  try { block(electron.net, ['resolveHost'], 'electron.net'); } catch {}
  installNetworkHardening.lockWebRTC = wc => {
    if (typeof wc.setWebRTCIPHandlingPolicy !== 'function') return;
    const policy = wc.setWebRTCIPHandlingPolicy;
    policy.call(wc, 'disable_non_proxied_udp');
    hook(wc, 'setWebRTCIPHandlingPolicy', function (value) {
      if (value !== 'disable_non_proxied_udp') throw denied('webContents.setWebRTCIPHandlingPolicy');
      return policy.call(this, value);
    });
  };
}
installNetworkHardening();
function configureSession(s) {
  if (sessionGates.has(s)) return sessionGates.get(s);
  installNetworkHardening.protectSession?.(s);
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
app.on('web-contents-created', (_event, wc) => { try { installNetworkHardening.lockWebRTC?.(wc); attach(wc); } catch (error) { fatal(error); } });
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
