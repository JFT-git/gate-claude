'use strict';
// Offline harness for Resources/RuntimeBootstrap.cjs: stubs the electron module,
// loads the bootstrap, and verifies the network hardening hooks (PG-05/06).
// The bootstrap talks over fixed fds 3/4, so the checks run in a child process
// with those descriptors mapped to /dev/null.
if (process.env.GUARD_BOOT_CHILD !== '1') {
  const { spawnSync } = require('node:child_process');
  const result = spawnSync(process.execPath, [__filename], {
    env: { ...process.env, GUARD_BOOT_CHILD: '1' },
    stdio: ['inherit', 'inherit', 'inherit', 'ignore', 'ignore']
  });
  process.exit(result.status ?? 1);
}
const Module = require('node:module');
const { EventEmitter } = require('node:events');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

let failures = 0;
const pending = [];
function check(name, fn) {
  try {
    const result = fn();
    if (result instanceof Promise) {
      pending.push(result.then(() => console.log('PASS ' + name), error => { failures++; console.log('FAIL ' + name + ' :: ' + (error && error.message)); }));
    } else { console.log('PASS ' + name); }
  } catch (error) { failures++; console.log('FAIL ' + name + ' :: ' + (error && error.message)); }
}

const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-boot-'));
const switches = {};
const commandLine = {
  appendSwitch(name, value = '') { switches[name] = String(value); },
  removeSwitch(name) { delete switches[name]; },
  appendArgument() {}
};
const appEvents = new EventEmitter();
class FakeSession {
  constructor() { this.calls = []; }
  setProxy(options) { this.calls.push(options); return Promise.resolve(); }
  resolveHost() { return Promise.resolve({ endpoints: [] }); }
}
const fakeApp = {
  exitCode: null,
  setName() {}, setPath() {},
  commandLine,
  on(event, fn) { appEvents.on(event, fn); },
  isReady() { return false; },
  exit(code) { this.exitCode = code; }
};
const fakeElectron = {
  app: fakeApp,
  webContents: { getAllWebContents: () => [] },
  autoUpdater: { checkForUpdates() {}, quitAndInstall() {}, setFeedURL() {} },
  net: { resolveHost() { return Promise.resolve({}); } }
};
const originalLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === 'electron') return fakeElectron;
  return originalLoad.call(this, request, ...rest);
};
process.env.PROXY_GUARD_CONFIG = JSON.stringify({
  userData, timezone: 'Europe/Amsterdam', language: 'en-US', proxyURL: 'http://127.0.0.1:8123'
});
require(path.join(__dirname, '..', 'Resources', 'RuntimeBootstrap.cjs'));

check('switch-disable-quic', () => assert.strictEqual(switches['disable-quic'], ''));
check('switch-webrtc', () => assert.strictEqual(switches['force-webrtc-ip-handling-policy'], 'disable_non_proxied_udp'));
check('switch-dns-prefetch', () => assert.strictEqual(switches['dns-prefetch-disable'], ''));
check('switch-host-resolver', () => assert.strictEqual(switches['host-resolver-rules'], 'MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'));
check('switch-proxy', () => assert.strictEqual(switches['proxy-server'], 'http://127.0.0.1:8123'));
check('switch-bypass', () => assert.strictEqual(switches['proxy-bypass-list'], '<-loopback>'));
check('appendSwitch-dangerous', () => assert.throws(() => commandLine.appendSwitch('enable-quic'), /ERR_GUARD_NETWORK_DENIED|Guard blocked/));
check('appendSwitch-proxy-tamper', () => assert.throws(() => commandLine.appendSwitch('proxy-server', 'http://169.254.0.1:1')));
check('appendSwitch-benign', () => { commandLine.appendSwitch('disable-features', 'X'); assert.strictEqual(switches['disable-features'], 'X'); });
check('removeSwitch-protected', () => assert.throws(() => commandLine.removeSwitch('disable-quic')));
check('removeSwitch-benign', () => { commandLine.appendSwitch('temp-x', '1'); commandLine.removeSwitch('temp-x'); });
check('appendArgument-flag', () => assert.throws(() => commandLine.appendArgument('--proxy-server=http://x')));

const net = require('node:net');
check('net-connect-external', () => assert.throws(() => net.connect(443, '203.0.113.9'), /Guard blocked/));
check('net-connect-options-external', () => assert.throws(() => net.connect({ host: '203.0.113.9', port: 443 }), /Guard blocked/));
check('net-connect-hostname-denied', () => assert.throws(() => net.connect(443, 'claude.ai'), /Guard blocked/));
check('net-connect-loopback-allowed', () => { const s = net.connect(9, '127.0.0.1'); s.destroy(); });
check('net-connect-unix-allowed', () => { const s = net.connect('/tmp/guard-nonexistent.sock'); s.destroy(); });
check('net-hook-sticky', () => { net.Socket.prototype.connect = () => {}; assert.throws(() => net.connect(443, '203.0.113.9')); });
check('net-connect-string-port-external', () => assert.throws(() => net.connect('443', '203.0.113.9'), /Guard blocked/));
check('net-connect-string-port-loopback', () => { const s = net.connect('9', '127.0.0.1'); s.destroy(); });
check('server-listen-external', () => assert.throws(() => net.createServer().listen({ host: '0.0.0.0', port: 0 }), /Guard blocked/));
check('server-listen-no-host', () => assert.throws(() => net.createServer().listen(0), /Guard blocked/));
check('server-listen-loopback', () => { const s = net.createServer(); s.listen(0, '127.0.0.1'); s.close(); });
// Numeric strings are ports to Node, not unix paths: listen("0") would bind
// every interface, and normalized-args arrays would skip the property checks.
check('server-listen-numeric-string-no-host', () => assert.throws(() => net.createServer().listen('0'), /Guard blocked/));
check('server-listen-numeric-string-loopback', () => { const s = net.createServer(); s.listen('0', '127.0.0.1'); s.close(); });
check('net-connect-normalized-array-external', () => assert.throws(() => net.connect(net._normalizeArgs([{ host: '203.0.113.9', port: 443 }])), /Guard blocked/));
check('net-connect-normalized-array-loopback', () => { const s = net.connect(net._normalizeArgs([{ host: '127.0.0.1', port: 9 }])); s.destroy(); });

const tls = require('node:tls');
check('tls-connect-external', () => assert.throws(() => tls.connect(443, '203.0.113.9'), /Guard blocked/));

const dgram = require('node:dgram');
check('dgram-denied', () => assert.throws(() => dgram.createSocket('udp4'), /Guard blocked/));

const dns = require('node:dns');
check('dns-lookup-denied', () => assert.throws(() => dns.lookup('claude.ai', () => {}), /Guard blocked/));
check('dns-lookup-loopback-literal', () => dns.lookup('127.0.0.1', (error, address) => { assert.ifError(error); assert.strictEqual(address, '127.0.0.1'); }));
check('dns-resolve-denied', () => assert.throws(() => dns.resolve4('claude.ai', () => {}), /Guard blocked/));
check('dns-promises-denied', () => assert.throws(() => dns.promises.lookup('claude.ai'), /Guard blocked/));
check('dns-resolver-denied', () => assert.throws(() => new dns.Resolver().resolve4('claude.ai', () => {}), /Guard blocked/));

const http = require('node:http'), https = require('node:https'), http2 = require('node:http2');
check('http-request-external', () => assert.throws(() => http.request('http://203.0.113.9/'), /Guard blocked/));
check('https-get-external', () => assert.throws(() => https.get('https://claude.ai/'), /Guard blocked/));
check('https-get-literal-ip', () => assert.throws(() => https.get('https://203.0.113.9/'), /Guard blocked/));
check('http2-external', () => assert.throws(() => http2.connect('https://claude.ai'), /Guard blocked/));

check('fetch-external-rejected', () => {
  const result = fetch('http://203.0.113.9/');
  assert.ok(result instanceof Promise);
  return result.then(() => { throw Error('fetch resolved'); }, error => assert.match(String(error && error.message || error), /Guard blocked/));
});
check('websocket-denied', () => { if (typeof WebSocket === 'function') assert.throws(() => new WebSocket('ws://203.0.113.9/'), /Guard blocked/); });

const session = new FakeSession();
appEvents.emit('session-created', session);
check('session-proxy-locked', () => {
  const wrong = session.setProxy({ mode: 'direct' });
  assert.ok(wrong instanceof Promise);
  return wrong.then(() => { throw Error('setProxy allowed'); }, () => {});
});
check('session-proxy-exact-allowed', () => session.setProxy({ mode: 'fixed_servers', proxyRules: 'http://127.0.0.1:8123', proxyBypassRules: '<-loopback>' }));
check('session-resolveHost-denied', () => assert.throws(() => session.resolveHost('claude.ai'), /Guard blocked/));

let policyValue = null;
const wc = {
  id: 777, session,
  setWebRTCIPHandlingPolicy(value) { policyValue = value; },
  getType: () => 'remote', getURL: () => 'about:blank'
};
appEvents.emit('web-contents-created', {}, wc);
check('webrtc-policy-applied', () => assert.strictEqual(policyValue, 'disable_non_proxied_udp'));
check('webrtc-policy-locked', () => assert.throws(() => wc.setWebRTCIPHandlingPolicy('default'), /Guard blocked/));
check('webrtc-policy-same-allowed', () => { wc.setWebRTCIPHandlingPolicy('disable_non_proxied_udp'); });

Promise.allSettled(pending).then(() => setTimeout(() => {
  fs.rmSync(userData, { recursive: true, force: true });
  process.exit(failures === 0 ? 0 : 1);
}, 300));
