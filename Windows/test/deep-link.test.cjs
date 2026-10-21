'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const D = require('../src/deep-link.cjs');
const link = 'claude://claude.ai/magic-link?anon_id=fixture-only#fixture-a:fixture-b';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('accepts the confirmed vendor magic-link route without changing opaque tokens', () => {
  assert.equal(D.validateClaudeDeepLink(link), link);
  assert.equal(D.validateClaudeDeepLink('claude://claude.ai/magic-link#fixture-a:fixture-b'), 'claude://claude.ai/magic-link#fixture-a:fixture-b');
  for (const value of ['https://claude.ai/magic-link#a:b', 'claude://login?token=fixture', 'claude://claude.ai/sso-callback#a:b', 'claude://claude.ai/magic-link', 'claude://claude.ai/magic-link#a:', 'claude://claude.ai/magic-link#a:b:c', 'claude://user@claude.ai/magic-link#a:b', 'claude://claude.ai:443/magic-link#a:b', 'claude://claude.ai.evil/magic-link#a:b', 'claude://claude.ai/magic-link/../new#a:b', link + '\n', link + '%00', link + '%zz', link + '"', link + '\\', 'claude://claude.ai/magic-link#' + 'a'.repeat(8192) + ':b', null, {}]) assert.equal(D.validateClaudeDeepLink(value), null, String(value).slice(0, 80));
});

test('extracts one URL, ignores arbitrary switches and scrubs received argv copies', () => {
  const argv = ['Guard.exe', '--user-data-dir=attacker', '--some-switch', link];
  assert.deepEqual(D.takeDeepLinkFromArgv(argv), { hadLink: true, url: link });
  assert.equal(argv.at(-1), '');
  assert.deepEqual(D.takeDeepLinkFromArgv(['Guard.exe']), { hadLink: false, url: null });
  const duplicate = [link, link]; assert.deepEqual(D.takeDeepLinkFromArgv(duplicate), { hadLink: true, url: null }); assert.deepEqual(duplicate, ['', '']);
  assert.equal(D.takeDeepLinkFromArgv(Array(65).fill('x')).url, null);
});

test('registers only the current Guard executable, never during smoke tests or on other platforms', () => {
  const calls = [], app = { isPackaged: true, setAsDefaultProtocolClient: (...args) => { calls.push(args); return true; }, isDefaultProtocolClient: () => true };
  assert.deepEqual(D.registerGuardProtocol(app, { platform: 'win32', execPath: 'C:\\Own Guard\\Guard.exe' }), { registered: true });
  assert.deepEqual(calls, [['claude', 'C:\\Own Guard\\Guard.exe', []]]);
  D.registerGuardProtocol(app, { platform: 'win32', smokeTest: true }); D.registerGuardProtocol(app, { platform: 'darwin' }); assert.equal(calls.length, 1);
  app.isPackaged = false; app.getAppPath = () => 'C:\\own-source'; D.registerGuardProtocol(app, { platform: 'win32', execPath: 'C:\\electron.exe' }); assert.deepEqual(calls.at(-1), ['claude', 'C:\\electron.exe', ['C:\\own-source']]);
  app.isDefaultProtocolClient = () => false; assert.equal(D.registerGuardProtocol(app, { platform: 'win32', execPath: 'C:\\Guard.exe' }).registered, false);
});

function inbox(overrides = {}) {
  let active = true, ready = true; const seen = [], notices = [];
  const box = new D.DeepLinkInbox({ active: () => active, ready: () => ready, deliver: async value => { seen.push(value); return { delivered: true }; }, notice: value => notices.push(value), ...overrides });
  return { box, seen, notices, active: value => { active = value; }, ready: value => { ready = value; } };
}

test('delivers only once and clears token memory before the attempt', async () => {
  const f = inbox(); assert.deepEqual(await f.box.accept(link), { accepted: true, delivered: true });
  assert.equal(f.box.entry, null); assert.equal(f.box.flight, null); assert.deepEqual(f.seen, [link]);
  await f.box.flush(); assert.equal(f.seen.length, 1); assert.deepEqual(f.notices, ['delivered']);
});

test('idle sessions refuse links without retaining or auto-starting', async () => {
  const f = inbox(); f.active(false); assert.deepEqual(await f.box.accept(link), { accepted: false });
  f.active(true); await f.box.flush(); assert.equal(f.seen.length, 0); assert.equal(f.box.entry, undefined);
});

test('startup queue is one item, expires monotonically and cannot replay after clear/epoch change', async () => {
  let clock = 100; const f = inbox({ now: () => clock, ttl: 20 }); f.ready(false);
  assert.deepEqual(await f.box.accept(link), { accepted: true, queued: true });
  assert.deepEqual(await f.box.accept(link), { accepted: false });
  clock = 121; f.ready(true); assert.deepEqual(await f.box.flush(), { accepted: false }); assert.equal(f.seen.length, 0);
  f.ready(false); clock = 200; await f.box.accept(link); f.box.clear(); f.ready(true); await f.box.flush(); assert.equal(f.seen.length, 0);
  f.ready(false); await f.box.accept(link); f.box.clear(); assert.equal(f.box.entry, null);
});

test('queue timer clears a token even when the runtime never becomes ready', async () => {
  const f = inbox({ ttl: 15 }); f.ready(false); await f.box.accept(link); await sleep(30);
  assert.equal(f.box.entry, null); assert.equal(f.seen.length, 0); assert.ok(f.notices.includes('expired'));
});

test('failed or cancelled attempted delivery is consumed and only generic notices escape', async () => {
  const f = inbox({ deliver: async () => { throw Error('fixture error includes ' + link); } });
  assert.deepEqual(await f.box.accept(link), { accepted: true, delivered: false }); await f.box.flush();
  assert.deepEqual(f.notices, ['failed']); assert.equal(f.box.entry, null);
  let finish; const g = inbox({ deliver: () => new Promise(resolve => { finish = resolve; }) }); const result = g.box.accept(link);
  g.box.clear(); finish({ delivered: true }); assert.deepEqual(await result, { accepted: true, delivered: false }); assert.deepEqual(g.notices, []);
});

test('runtime forwarding waits for profile readiness and emits only fixed own-profile argv', async () => {
  const app = new EventEmitter(), seen = []; let ready;
  app.on('second-instance', (...args) => seen.push(args));
  const promise = D.forwardRuntimeDeepLink(link, { app, profileReady: new Promise(resolve => { ready = resolve; }), userData: 'C:\\private\\Profile', executable: 'C:\\private\\Runtime\\claude.exe', cwd: 'C:\\private\\Runtime' });
  assert.equal(seen.length, 0); ready(); assert.deepEqual(await promise, { delivered: true });
  assert.deepEqual(seen[0][1], ['C:\\private\\Runtime\\claude.exe', '--user-data-dir=C:\\private\\Profile', link]);
  assert.equal(seen[0][2], 'C:\\private\\Runtime'); assert.deepEqual(seen[0][3], {}); assert.equal(typeof seen[0][0].preventDefault, 'function');
});

test('injected runtime source rejects malformed routes, missing listeners and handler exceptions without URL disclosure', async () => {
  let tick = 0;
  const context = { URL, performance: { now: () => (tick++) * 4000 }, setTimeout, Error };
  const forward = vm.runInNewContext(D.runtimeDeepLinkSource() + '\nguardForwardDeepLink;', context);
  const options = { app: new EventEmitter(), profileReady: Promise.resolve(), userData: 'C:\\private\\Profile', executable: 'C:\\private\\claude.exe', cwd: 'C:\\private' };
  await assert.rejects(forward(link, options), error => !error.message.includes('fixture'));
  await assert.rejects(forward('claude://login?token=fixture', options), error => !error.message.includes('fixture'));
  options.app.on('second-instance', () => { throw Error(link); });
  await assert.rejects(forward(link, options), error => !error.message.includes('fixture'));
});

test('Windows bootstrap embeds root-only authenticated forwarding and preserves the shared bootstrap', () => {
  const A = require('../src/asar.cjs'), file = path.resolve(__dirname, '../../Resources/RuntimeBootstrap.cjs');
  const base = fs.readFileSync(file, 'utf8'), generated = A.windowsBootstrap(base).toString();
  assert.ok(generated.includes("!m.sessionId && m.method === 'ProxyGuard.openDeepLink'"));
  assert.ok(generated.includes('guardForwardDeepLink(m.params?.url'));
  new vm.Script(generated); assert.equal(fs.readFileSync(file, 'utf8'), base); assert.ok(!base.includes('ProxyGuard.openDeepLink'));
});

test('controller refuses idle/blocked links and clears startup links on teardown without raw URL diagnostics', async t => {
  const { GuardController } = require('../src/controller.cjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-deep-link-controller-')); const c = new GuardController(root, root);
  t.after(() => { c.host = null; c.channel = null; c.stop(); fs.rmSync(root, { recursive: true, force: true }); });
  assert.deepEqual(await c.deliverDeepLink(link), { accepted: false });
  c.policy.pin({ country_code: 'NL', ip: '203.0.113.7' }); c.state = 'starting'; c.host = { exitCode: null, killed: false }; let deliveries = 0;
  c.channel = { closed: false, socket: {}, command: async (method, params) => { assert.equal(method, 'ProxyGuard.openDeepLink'); assert.equal(params.url, link); deliveries++; return { delivered: true }; } };
  assert.deepEqual(await c.deliverDeepLink(link), { accepted: true, queued: true });
  c.deepLinkReady = true; assert.deepEqual(await c.deepLinks.flush(), { accepted: true, delivered: true }); assert.equal(deliveries, 1);
  c.state = 'rechecking'; await c.deliverDeepLink(link); c.host = null; c.channel.close = () => {}; c.block('fixture block');
  assert.equal(c.deepLinks.entry, null); assert.deepEqual(await c.deliverDeepLink(link), { accepted: false }); assert.equal(deliveries, 1);
  const logs = fs.readFileSync(path.join(root, 'diagnostics.json'), 'utf8'); assert.ok(!logs.includes('fixture-a')); assert.ok(!logs.includes('fixture-b')); assert.ok(!logs.includes('anon_id'));
});
