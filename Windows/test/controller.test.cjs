'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
// Dependency substitution is confined to this test worker; the packaged app has no test providers.
const runtime = require('../src/runtime.cjs'), checker = require('../src/ip-check.cjs');
require('../src/fence.cjs').NetworkFence.prepare = async () => ({ on() {}, close: async () => {} });
runtime.prepareRuntime = async () => ({ executable: 'fixture-not-launched', profile: 'fixture-profile', signature: 'Valid' });
let initial, current;
checker.initialIP = () => initial(); checker.currentIP = () => current();
const { GuardController } = require('../src/controller.cjs');
const input = { host: '127.0.0.1', port: 1080, claudePath: 'fixture', interval: 2 };
const pause = () => new Promise(resolve => setTimeout(resolve, 10));
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-controller-'));
  const controller = new GuardController(root, root); controller.routeFingerprint = async () => ''; controller.localEgressAddresses = async () => ({ v4: '127.0.0.1', v6: null });
  const direct = Object.freeze({ kind: 'direct', host: '', port: 0, fingerprint: 'd'.repeat(64) });
  controller.networkProxy = direct; controller.networkProxyConfiguration = async () => direct;
  controller.requestDestinationIP = async (_epoch, hostname) => ({ hostname, ip: '203.0.113.7', country_code: 'NL' });
  t.after(async () => { controller.stop(); await fs.rm(root, { recursive: true, force: true }); });
  return controller;
}
test('initial RU, malformed IP, mismatch and service failures close relay and latch the controller', async t => {
  for (const connection of ['socks5', 'network']) for (const mode of ['RU', 'malformed', 'mismatch', 'service']) {
    const controller = await fixture(t);
    initial = async () => { if (mode === 'service') throw Error('fixture service failure'); return { success: true, country_code: mode === 'RU' ? 'RU' : 'NL', ip: mode === 'malformed' ? 'invalid' : '203.0.113.7' }; };
    current = async () => ({ ip: '203.0.113.8' });
    await controller.start({ ...input, mode: connection });
    assert.equal(controller.state, 'blocked', mode); assert.equal(controller.policy.blocked, true, mode);
    assert.equal(controller.relay, null, mode); assert.equal(controller.settings, null, mode);
    await assert.rejects(controller.start(input));
  }
});
test('current network session closes its live tunnel and latches on a new foreign IP', async t => {
  const net = require('node:net'), { once } = require('node:events');
  const { NetworkRelay, connectTunnel } = require('../src/relay.cjs');
  const controller = await fixture(t); let address = '203.0.113.7';
  current = async () => ({ ip: address }); controller.policy.pin({ country_code: 'NL', ip: address });
  const echo = net.createServer(socket => { socket.on('error', () => {}); socket.pipe(socket); }); echo.listen(0, '127.0.0.1'); await once(echo, 'listening'); t.after(() => echo.close());
  controller.relay = new NetworkRelay(); await controller.relay.start(); controller.relay.pinIPFamily(4); controller.relay.unlock();
  await controller.queryDestinations(controller.epoch, controller.relay.port, controller.relay.checkToken, true);
  controller.state = 'running'; controller.settings = { interval: 2 }; controller.route = '';
  const port = controller.relay.port, socket = await connectTunnel(port, '127.0.0.1', echo.address().port); socket.resume();
  const closed = once(socket, 'close'); address = '203.0.113.8'; await controller.poll(controller.epoch); await closed;
  assert.equal(controller.state, 'blocked'); assert.equal(controller.policy.blocked, true);
  await assert.rejects(connectTunnel(port, '127.0.0.1', echo.address().port));
  controller.stop(); await assert.rejects(controller.start({ mode: 'network' }));
});
test('a held proxy tunnel survives equivalent raw settings but real route changes close and latch without rerouting', { timeout: 10000 }, async t => {
  const net = require('node:net'), { once } = require('node:events');
  const { NetworkRelay, connectTunnel } = require('../src/relay.cjs');
  const { parseRegistryOutput } = require('../src/system-proxy.cjs');
  const settingsKey = 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
  const registry = (server, state = '0x1') => settingsKey + '\r\n    ProxyEnable    REG_DWORD    ' + state + '\r\n    ProxyServer    REG_SZ    ' + server + '\r\n';
  async function upstream() {
    const peers = new Set(), requests = []; let connections = 0;
    const server = net.createServer(socket => {
      connections++;
      peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket));
      let header = Buffer.alloc(0);
      const receive = chunk => {
        header = Buffer.concat([header, chunk]); const end = header.indexOf('\r\n\r\n');
        if (end < 0) return;
        socket.off('data', receive); requests.push(header.subarray(0, end).toString('latin1'));
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (header.length > end + 4) socket.write(header.subarray(end + 4));
        socket.pipe(socket);
      };
      socket.on('data', receive);
    });
    t.after(async () => { for (const socket of peers) socket.destroy(); if (server.listening) await new Promise(resolve => server.close(resolve)); });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    return { port: server.address().port, requests, get connections() { return connections; } };
  }
  for (const change of ['host', 'port']) {
    const controller = await fixture(t), first = await upstream(), unused = await upstream();
    let raw = registry('127.0.0.1:' + first.port);
    const captured = parseRegistryOutput(raw);
    controller.networkProxy = captured; controller.networkProxyConfiguration = async () => parseRegistryOutput(raw);
    current = async () => ({ ip: '203.0.113.7' }); controller.policy.pin({ country_code: 'NL', ip: '203.0.113.7' });
    const relay = new NetworkRelay({ upstream: captured }); controller.relay = relay;
    await relay.start(); relay.pinIPFamily(4); relay.unlock();
    controller.state = 'running'; controller.settings = { mode: 'network', interval: 30 }; controller.route = '';
    await controller.queryDestinations(controller.epoch, relay.port, relay.checkToken, true);
    const socket = await connectTunnel(relay.port, 'held.invalid', 443); socket.resume();
    t.after(() => socket.destroy());
    const echo = async text => { const answer = once(socket, 'data'); socket.write(text); assert.equal((await answer)[0].toString(), text); };
    await echo('before-equivalent-' + change);
    raw = registry('socks=unused.invalid:1080;HTTPS=127.0.0.1:' + first.port + '; http = 127.0.0.1:' + first.port, '0x00000001');
    await controller.poll(controller.epoch); clearTimeout(controller.pollTimer);
    assert.equal(controller.state, 'running'); assert.equal(controller.policy.blocked, false);
    assert.equal(socket.destroyed, false); assert.equal(relay.closed, false); assert.deepEqual(relay.upstream, captured);
    await echo('after-equivalent-' + change);
    const closed = once(socket, 'close');
    raw = registry(change === 'host' ? 'localhost:' + first.port : '127.0.0.1:' + unused.port);
    await controller.poll(controller.epoch); await closed;
    assert.equal(controller.state, 'blocked'); assert.equal(controller.policy.blocked, true); assert.equal(relay.closed, true);
    assert.equal(controller.relay, null); assert.deepEqual(relay.upstream, captured); assert.equal(Object.isFrozen(relay.upstream), true);
    assert.equal(first.connections, 1); assert.equal(first.requests.length, 1); assert.match(first.requests[0], /^CONNECT held\.invalid:443 HTTP\/1\.1\r\n/);
    assert.equal(unused.connections, 0); assert.equal(unused.requests.length, 0);
    await assert.rejects(connectTunnel(relay.port, 'held.invalid', 443));
    await assert.rejects(controller.start({ mode: 'network' }), /перезапуска/);
  }
});
test('stop during initial request cannot pin an IP or reopen resources after cancellation', async t => {
  const controller = await fixture(t); let resolve;
  initial = () => new Promise(done => { resolve = done; }); current = async () => ({ ip: '203.0.113.7' });
  const starting = controller.start(input);
  while (!resolve) await pause();
  controller.stop(); resolve({ success: true, country_code: 'NL', ip: '203.0.113.7' }); await starting;
  assert.equal(controller.state, 'blocked'); assert.equal(controller.policy.pinned, null); assert.equal(controller.policy.blocked, true);
  assert.equal(controller.relay, null); assert.equal(controller.host, null);
});

test('failed initial IP check never discovers or publishes a local pin', async t => {
  for (const mode of ['network', 'socks5']) {
    const controller = await fixture(t); let calls = 0;
    controller.localEgressAddresses = async () => { calls++; throw Error('fixture pin unavailable'); };
    initial = async () => { throw Error('fixture stops bootstrap'); };
    await controller.start({ ...input, mode });
    assert.equal(calls, 0);
  }
});
test('successful revalidation refreshes the local pin and stop resets it', async t => {
  const controller = await fixture(t); let calls = 0, resumed = 0;
  controller.settings = { mode: 'network', interval: 30 }; controller.state = 'rechecking'; controller.route = '';
  controller.policy.pin({ country_code: 'NL', ip: '203.0.113.7' });
  controller.relay = { port: 1234, pause() {}, resume() { resumed++; }, close() {} };
  controller.checkCurrentIP = async () => '203.0.113.7'; controller.queryDestinations = async () => true;
  controller.localEgressAddresses = async () => { calls++; return { v4: null, v6: '::1' }; };
  await controller.poll(controller.epoch);
  assert.equal(calls, 1); assert.equal(resumed, 1);
  const relay = require('../src/relay.cjs');
  await assert.rejects(relay.connectCurrentNetwork('127.0.0.1', 1, undefined, 4), /Локальный адрес/);
  controller.stop();
  // An unpinned dial must reach socket creation rather than fail at the pin gate.
  const net = require('node:net'), original = net.createConnection;
  net.createConnection = () => { throw Error('pin reset confirmed'); };
  try { await assert.rejects(relay.connectCurrentNetwork('127.0.0.1', 1, undefined, 4), /pin reset confirmed/); }
  finally { net.createConnection = original; }
});
test('interface watcher pauses synchronously before asynchronous revalidation', async t => {
  const controller = await fixture(t), original = global.setInterval; let watcher, release;
  global.setInterval = callback => { watcher = callback; return original(() => {}, 60000); };
  controller.routeFingerprint = () => new Promise(resolve => { release = resolve; });
  const starting = controller.start(input);
  while (!watcher) await pause();
  global.setInterval = original;
  const events = [];
  controller.relay = { pause() { events.push('pause'); }, close() {} };
  controller.fingerprint = 'changed';
  controller.revalidate = async () => { events.push('revalidate'); await new Promise(() => {}); };
  watcher(); assert.deepEqual(events, ['pause', 'revalidate']);
  controller.stop(); release(''); await starting;
});
async function capturedDial(address, inspect = () => {}) {
  const net = require('node:net'), { EventEmitter } = require('node:events');
  const original = net.createConnection;
  net.createConnection = options => {
    inspect(options);
    const socket = new EventEmitter();
    socket.localAddress = address;
    socket.setTimeout = socket.pause = socket.destroy = () => socket;
    queueMicrotask(() => socket.emit('connect'));
    return socket;
  };
  try { return require('../src/relay.cjs').connectCurrentNetwork('203.0.113.1', 443, undefined, 4); }
  finally { net.createConnection = original; }
}
test('local pin discovery reads captured control addresses and fails closed when empty', async t => {
  const controller = await fixture(t), relay = require('../src/relay.cjs');
  relay.beginEgressCapture();
  await assert.rejects(GuardController.prototype.localEgressAddresses.call(controller), /локальные адреса выхода Windows/);
  await capturedDial('10.8.0.2');
  assert.deepEqual(await GuardController.prototype.localEgressAddresses.call(controller), { v4: '10.8.0.2' });
  relay.setPinnedLocalAddresses(null);
  assert.deepEqual(relay.capturedEgressLocalAddresses(), { v4: '10.8.0.2' });
  const copy = relay.capturedEgressLocalAddresses(); copy.v4 = '192.0.2.1';
  assert.deepEqual(relay.capturedEgressLocalAddresses(), { v4: '10.8.0.2' });
  relay.beginEgressCapture();
  for (const address of ['127.0.0.1', '::1', '::ffff:10.8.0.2', 'invalid']) await capturedDial(address);
  assert.deepEqual(relay.capturedEgressLocalAddresses(), {});
});
test('revalidation removes stale binding before all probes and pins the new address before resume', async t => {
  const controller = await fixture(t), relay = require('../src/relay.cjs'), events = [];
  controller.settings = { mode: 'network', interval: 30 }; controller.state = 'rechecking'; controller.route = '';
  controller.policy.pin({ country_code: 'NL', ip: '203.0.113.7' });
  relay.setPinnedLocalAddresses({ v4: '192.0.2.99' });
  controller.relay = { port: 1234, pause() { events.push('pause'); }, resume() { events.push('resume'); }, close() {} };
  controller.checkCurrentIP = async () => {
    await capturedDial('10.8.0.3', options => { assert.equal(options.localAddress, undefined); events.push('unbound IP'); });
    return '203.0.113.7';
  };
  controller.queryDestinations = async () => {
    await capturedDial('10.8.0.3', options => { assert.equal(options.localAddress, undefined); events.push('unbound destinations'); });
    return true;
  };
  controller.localEgressAddresses = async () => { events.push('capture'); return relay.capturedEgressLocalAddresses(); };
  await controller.poll(controller.epoch);
  assert.deepEqual(events, ['pause', 'unbound IP', 'unbound destinations', 'capture', 'resume']);
  await capturedDial('10.8.0.3', options => assert.equal(options.localAddress, '10.8.0.3'));
});
test('a captured address changing while the new pin is read keeps traffic paused', async t => {
  const controller = await fixture(t), relay = require('../src/relay.cjs'); let resumed = 0;
  controller.settings = { mode: 'network', interval: 30 }; controller.state = 'rechecking'; controller.route = '';
  controller.policy.pin({ country_code: 'NL', ip: '203.0.113.7' });
  controller.relay = { port: 1234, pause() {}, resume() { resumed++; }, close() {} };
  controller.checkCurrentIP = async () => { await capturedDial('10.8.0.2'); return '203.0.113.7'; };
  controller.queryDestinations = async () => true;
  controller.localEgressAddresses = async () => {
    const pin = relay.capturedEgressLocalAddresses();
    await capturedDial('10.8.0.3');
    return pin;
  };
  await controller.poll(controller.epoch);
  assert.equal(resumed, 0); assert.equal(controller.state, 'rechecking');
});

test('a revalidation event during local pin read forbids resume', async t => {
  const controller = await fixture(t); let resumed = 0;
  controller.settings = { mode: 'network', interval: 30 }; controller.state = 'rechecking'; controller.route = '';
  controller.policy.pin({ country_code: 'NL', ip: '203.0.113.7' });
  controller.relay = { port: 1234, pause() {}, resume() { resumed++; }, close() {} };
  controller.checkCurrentIP = async () => '203.0.113.7'; controller.queryDestinations = async () => true;
  controller.localEgressAddresses = async () => {
    controller.pauseForRevalidation('fixture interface event');
    return { v4: '10.8.0.3' };
  };
  await controller.poll(controller.epoch);
  assert.equal(resumed, 0); assert.equal(controller.state, 'rechecking');
});
