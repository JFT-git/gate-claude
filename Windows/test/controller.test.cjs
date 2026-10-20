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
  const controller = new GuardController(root, root); controller.routeFingerprint = async () => '';
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
  controller.relay = new NetworkRelay(); await controller.relay.start(); controller.relay.unlock();
  controller.state = 'running'; controller.settings = { interval: 2 }; controller.route = '';
  const port = controller.relay.port, socket = await connectTunnel(port, '127.0.0.1', echo.address().port); socket.resume();
  const closed = once(socket, 'close'); address = '203.0.113.8'; await controller.poll(controller.epoch); await closed;
  assert.equal(controller.state, 'blocked'); assert.equal(controller.policy.blocked, true);
  await assert.rejects(connectTunnel(port, '127.0.0.1', echo.address().port));
  controller.stop(); await assert.rejects(controller.start({ mode: 'network' }));
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
