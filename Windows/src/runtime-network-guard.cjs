'use strict';

// Installed by the Windows bootstrap before the vendor entry point. This reduces
// native/Node escape paths; it is not a kernel firewall or a hostile-code sandbox.
let installed;
function installNetworkGuard(cfg) {
  const parsed = new URL(cfg?.proxyURL || '');
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || !parsed.port ||
      parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw Error('Guard requires one explicit loopback HTTP relay.');
  }
  const codeFingerprint = JSON.stringify(cfg.code || null);
  if (installed) {
    if (installed.codeFingerprint !== codeFingerprint) throw Error('Guard Code configuration is immutable.');
    if (installed.proxyURL !== cfg.proxyURL || installed.channelPipe !== (cfg.channelPipe || null)) throw Error('Guard network configuration is immutable.');
    return installed;
  }
  const electron = require('electron');
  const net = require('node:net'), tls = require('node:tls'), dgram = require('node:dgram');
  const dns = require('node:dns'), http = require('node:http'), https = require('node:https');
  const http2 = require('node:http2'), child = require('node:child_process'), workers = require('node:worker_threads');
  const ownPipe = typeof cfg.channelPipe === 'string' && /^\\\\\.\\pipe\\gate-claude-[a-f0-9]{32}$/.test(cfg.channelPipe) ? cfg.channelPipe : null;
  if (cfg.channelPipe && !ownPipe) throw Error('Guard requires its own authenticated diagnostic pipe.');
  const denied = name => {
    const error = Error('Guard blocked native network or external execution: ' + name);
    error.code = 'ERR_GUARD_NETWORK_DENIED'; return error;
  };
  const deny = name => function () { throw denied(name); };
  // Ignore attempts to replace a hook. Instrumentation often wraps these methods;
  // keeping the deny hook avoids both restoring the original and a startup throw.
  function hook(object, key, value) {
    if (!object || typeof object[key] !== 'function') return;
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor && !descriptor.configurable) {
      if (object[key] !== value) throw Error('Guard cannot protect ' + key); return;
    }
    Object.defineProperty(object, key, { enumerable: descriptor?.enumerable ?? true, configurable: false, get: () => value, set() {} });
  }
  function block(object, names, label) { for (const name of names) hook(object, name, deny(label + '.' + name)); }
  const originalConnect = net.Socket.prototype.connect;
  const isOwnPipe = args => {
    const target = args[0];
    return ownPipe && (target === ownPipe || (target && typeof target === 'object' && target.path === ownPipe &&
      target.port == null && target.host == null && target.fd == null));
  };
  hook(net.Socket.prototype, 'connect', function (...args) {
    if (!isOwnPipe(args)) throw denied('net.Socket.connect');
    return originalConnect.apply(this, args);
  });
  const pipeConnection = function (...args) {
    if (!isOwnPipe(args)) throw denied('net.connect');
    return new net.Socket().connect(...args);
  };
  hook(net, 'connect', pipeConnection); hook(net, 'createConnection', pipeConnection);
  block(net.Server?.prototype, ['listen'], 'net.Server');
  block(tls, ['connect'], 'tls');
  block(dgram, ['createSocket'], 'dgram');
  block(dgram.Socket?.prototype, ['send', 'connect', 'bind', 'addMembership', 'addSourceSpecificMembership'], 'dgram.Socket');
  const dnsMethods = object => Object.getOwnPropertyNames(object || {}).filter(name => /^(?:lookup|resolve|reverse)/.test(name));
  for (const object of [dns, dns.promises, dns.Resolver?.prototype, dns.promises?.Resolver?.prototype]) block(object, dnsMethods(object), 'dns');
  block(http, ['request', 'get'], 'http'); block(https, ['request', 'get'], 'https'); block(http2, ['connect'], 'http2');
  const nativeSpawn = child.spawn, nativePrototypeSpawn = child.ChildProcess.prototype.spawn;
  const codeHost = cfg.code?.hostPath;
  if (codeHost && (!/^[A-Za-z]:\\/.test(codeHost) || /[\x00-\x1f]/.test(codeHost) || require('node:path').win32.basename(codeHost) !== 'CodeHost.exe')) throw Error('Guard requires its fixed CodeHost.');
  let codeSpawnDepth = 0;
  hook(child.ChildProcess.prototype, 'spawn', function (options) {
    if (!codeSpawnDepth || !codeHost || options?.file !== codeHost || !Array.isArray(options.args) || options.args.length !== 2 || options.args[0] !== codeHost || options.args[1] !== '--managed') throw denied('ChildProcess.spawn');
    return nativePrototypeSpawn.call(this, options);
  });
  const spawnCodeBroker = function (executable, args, options) {
    if (!codeHost || executable !== codeHost || !Array.isArray(args) || args.length !== 1 || args[0] !== '--managed' || !options || options.shell || options.detached || options.argv0 || options.stdio?.join(',') !== 'pipe,pipe,pipe') throw denied('CodeHost.spawn');
    codeSpawnDepth++;
    try { return nativeSpawn(executable, args, options); }
    finally { codeSpawnDepth--; }
  };
  block(child, ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'], 'child_process');
  block(workers, ['Worker'], 'worker_threads');
  for (const name of ['node:inspector', 'node:inspector/promises']) {
    try { block(require(name), ['open'], 'inspector'); }
    catch (error) { if (error.code !== 'ERR_UNKNOWN_BUILTIN_MODULE') throw error; }
  }
  hook(globalThis, 'fetch', function () { return Promise.reject(denied('fetch')); });
  block(globalThis, ['WebSocket', 'EventSource'], 'global');
  block(electron.utilityProcess, ['fork'], 'utilityProcess');
  block(electron.shell, ['openExternal', 'openPath', 'showItemInFolder', 'trashItem'], 'shell');
  block(electron.app, ['relaunch', 'setLoginItemSettings'], 'app');
  hook(electron.app, 'setAsDefaultProtocolClient', () => false);
  block(electron.autoUpdater, ['quitAndInstall', 'setFeedURL'], 'autoUpdater');
  hook(electron.autoUpdater, 'checkForUpdates', function () { this.emit?.('update-not-available'); });
  block(electron.net, ['resolveHost'], 'electron.net');
  const proxySettingsMatch = options => options && options.mode === 'fixed_servers' &&
    options.proxyRules === cfg.proxyURL && options.proxyBypassRules === '<-loopback>' && !options.pacScript;
  const protectedSessions = new WeakSet();
  function protectSession(session) {
    if (!session || protectedSessions.has(session)) return;
    protectedSessions.add(session);
    const setProxy = session.setProxy;
    hook(session, 'setProxy', function (options) {
      if (!proxySettingsMatch(options)) return Promise.reject(denied('session.setProxy'));
      return setProxy.call(this, options);
    });
    block(session, ['resolveHost'], 'session');
  }
  electron.app.on('session-created', protectSession);
  // The default session getter is only valid after ready. The existing bootstrap
  // handles session-created before any vendor code can create a new partition.
  if (electron.app.isReady?.()) protectSession(electron.session?.defaultSession);
  electron.app.on('web-contents-created', (_event, contents) => {
    protectSession(contents.session);
    if (typeof contents.setWebRTCIPHandlingPolicy === 'function') {
      const policy = contents.setWebRTCIPHandlingPolicy;
      policy.call(contents, 'disable_non_proxied_udp');
      hook(contents, 'setWebRTCIPHandlingPolicy', function (value) {
        if (value !== 'disable_non_proxied_udp') throw denied('webContents.setWebRTCIPHandlingPolicy');
        return policy.call(this, value);
      });
    }
  });
  const commandLine = electron.app.commandLine;
  const switches = { 'proxy-server': cfg.proxyURL, 'proxy-bypass-list': '<-loopback>',
    'force-webrtc-ip-handling-policy': 'disable_non_proxied_udp', 'disable-quic': '', 'dns-prefetch-disable': '',
    // Destination names are resolved by the relay; Chromium only connects to its
    // literal loopback address. Speculative/background hostname lookups must fail.
    'host-resolver-rules': 'MAP * ~NOTFOUND, EXCLUDE 127.0.0.1' };
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
  // Block public low-level entry points too. Node internals and Electron's own
  // native bindings still require an OS policy for an adversarial-code guarantee.
  const binding = process.binding;
  const dangerousBindings = new Set(['tcp_wrap', 'udp_wrap', 'cares_wrap', 'process_wrap', 'spawn_sync', 'tls_wrap', 'pipe_wrap']);
  hook(process, 'binding', function (name) {
    if (dangerousBindings.has(String(name))) throw denied('process.binding');
    return binding.call(this, name);
  });
  block(process, ['dlopen'], 'process');
  installed = Object.freeze({ installed: true, proxyURL: cfg.proxyURL, channelPipe: cfg.channelPipe || null, codeFingerprint, spawnCodeBroker });
  return installed;
}
module.exports = { installNetworkGuard };
