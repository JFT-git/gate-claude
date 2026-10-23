'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const runtime = require('../src/runtime.cjs');
const checker = require('../src/ip-check.cjs');
const relays = require('../src/relay.cjs');
const { NetworkFence } = require('../src/fence.cjs');
const child = require('node:child_process');
// These substitutions exist only in this isolated test worker. Production uses real WFP.
let prepare, initial, launches = 0, relayInstances;
runtime.prepareRuntime = async () => ({ executable: 'same-private-runtime', profile: 'fixture', signature: 'Valid' });
NetworkFence.prepare = (...args) => prepare(...args);
checker.initialIP = (...args) => initial(...args);
checker.currentIP = async () => ({ ip: '203.0.113.7' });
child.spawn = () => { launches++; throw Error('The cancelled runtime must not be launched'); };
class Relay extends EventEmitter {
  constructor() { super(); this.port = 12345; this.checkToken = 'fixture'; this.closed = false; this.unlocks = 0; relayInstances.push(this); }
  async start() { return this.port; }
  pinIPFamily(family) { this.ipFamily = family; }
  unlock() { this.unlocks++; }
  pause() {}
  close() { this.closed = true; }
}
relays.NetworkRelay = Relay;
const { GuardController } = require('../src/controller.cjs');
const input = { mode: 'network', claudePath: 'fixture', interval: 2 };
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function until(check) { for (let n = 0; n < 100; n++) { if (check()) return; await turn(); } throw Error('Fixture condition was not reached'); }
class Fence extends EventEmitter {
  constructor() { super(); this.installed = true; this.closes = 0; }
  async close() { this.closes++; this.installed = false; }
}
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-fence-startup-'));
  const controller = new GuardController(root, root); controller.routeFingerprint = async () => '';
  controller.networkProxyConfiguration = async () => Object.freeze({ kind: 'direct', host: '', port: 0, fingerprint: 'd'.repeat(64) });
  controller.requestDestinationIP = async (_epoch, hostname) => ({ hostname, ip: '203.0.113.7', country_code: 'NL' });
  relayInstances = []; launches = 0;
  t.after(async () => { controller.stop(); await fs.rm(root, { recursive: true, force: true }); });
  return controller;
}

test('stop during pending fence installation latches the session and prevents a second overlapping broker', async t => {
  const c = await fixture(t), pending = deferred(), fence = new Fence(); let prepares = 0, checks = 0;
  prepare = () => { prepares++; return pending.promise; };
  initial = async () => { checks++; return { country_code: 'NL', ip: '203.0.113.7' }; };
  const starting = c.start(input);
  t.after(async () => { pending.resolve(fence); await starting; });
  await until(() => prepares === 1);
  c.stop();
  assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true); assert.equal(c.policy.pinned, null);
  await assert.rejects(c.start(input), /перезапуска/);
  assert.equal(prepares, 1, 'a second fence installation must never start while the first broker is pending');
  pending.resolve(fence); await starting;
  assert.equal(fence.closes, 1, 'the late broker must remove its own unused installation');
  assert.equal(c.fencePending, false); assert.equal(c.state, 'blocked');
  assert.equal(checks, 0); assert.equal(launches, 0); assert.equal(relayInstances.length, 1);
  assert.equal(relayInstances[0].closed, true); assert.equal(relayInstances[0].unlocks, 0);
});

test('stop after fence installation but before IP pinning also prevents a new start', async t => {
  const c = await fixture(t), answer = deferred(), fence = new Fence(); let prepares = 0, checks = 0;
  prepare = async () => { prepares++; return fence; };
  initial = () => { checks++; return answer.promise; };
  const starting = c.start(input);
  t.after(async () => { answer.resolve({ country_code: 'NL', ip: '203.0.113.7' }); await starting; });
  await until(() => checks === 1);
  assert.equal(c.fence, fence); assert.equal(c.policy.pinned, null);
  c.stop();
  assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true);
  await assert.rejects(c.start(input), /перезапуска/);
  answer.resolve({ country_code: 'NL', ip: '203.0.113.7' }); await starting;
  assert.equal(prepares, 1); assert.equal(fence.closes, 1); assert.equal(c.policy.pinned, null);
  assert.equal(launches, 0); assert.equal(relayInstances[0].unlocks, 0); assert.equal(relayInstances[0].closed, true);
});

test('a late rejected fence installation cannot clear the cancellation latch or launch Claude', async t => {
  const c = await fixture(t), pending = deferred(); let prepares = 0;
  prepare = () => { prepares++; return pending.promise; };
  initial = async () => { throw Error('IP checks must not run after cancelled preparation'); };
  const starting = c.start(input);
  t.after(async () => { pending.reject(Error('cancelled UAC fixture')); await starting; });
  await until(() => prepares === 1); c.stop();
  pending.reject(Error('cancelled UAC fixture')); await starting;
  assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true); assert.equal(c.fencePending, false);
  await assert.rejects(c.start(input), /перезапуска/);
  assert.equal(prepares, 1); assert.equal(launches, 0); assert.equal(relayInstances[0].closed, true);
});

test('the trusted Guard window handle is forwarded to the fence and a missing owner stops before elevation', async t => {
  const c = await fixture(t), owner = Buffer.from('3412000000000000', 'hex'); let calls = 0;
  c.fenceOwnerWindow = () => owner;
  prepare = async (_runtime, _port, options) => { calls++; assert.equal(options.ownerWindow, owner); throw Error('fixture refuses consent'); };
  await c.start(input);
  assert.equal(calls, 1); assert.equal(c.state, 'blocked'); assert.equal(launches, 0);
  const other = await fixture(t);
  other.fenceOwnerWindow = () => { throw Error('Guard owner unavailable'); };
  await other.start(input);
  assert.equal(calls, 1); assert.equal(other.state, 'blocked'); assert.equal(other.fencePending, false); assert.equal(launches, 0);
});
