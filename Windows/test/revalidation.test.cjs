'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const child = require('node:child_process');
const runtime = require('../src/runtime.cjs'), checker = require('../src/ip-check.cjs');
require('../src/fence.cjs').NetworkFence.prepare = async () => ({ on() {}, close: async () => {} });
const { Channel } = require('../src/channel.cjs');
let provider, initialProvider, onSpawn, waitForChannel;
checker.currentIP = (...args) => provider(...args);
checker.initialIP = (...args) => initialProvider(...args);
runtime.prepareRuntime = async () => ({ executable: 'fixture', profile: 'fixture', signature: 'Valid' });
child.spawn = () => {
  const host = new EventEmitter(); host.stdin = new PassThrough(); host.stdout = new PassThrough();
  host.kill = () => host.emit('exit', 0); onSpawn?.(host); return host;
};
Channel.prototype.connected = function () { return waitForChannel(this); };
const { GuardController } = require('../src/controller.cjs');
const pinned = '203.0.113.7';
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function until(check) { for (let n = 0; n < 100; n++) { if (check()) return; await turn(); } throw Error('Fixture condition was not reached'); }
class Relay extends EventEmitter {
  constructor() { super(); this.port = 1; this.checkToken = 'fixture-control-token'; this.paused = false; this.resumes = 0; this.closed = false; }
  pause() { this.paused = true; }
  resume() { if (this.closed) throw Error('closed'); this.paused = false; this.resumes++; }
  close() { this.closed = true; this.paused = true; }
}
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-revalidation-'));
  const controller = new GuardController(root, root); controller.policy.pin({ country_code: 'NL', ip: pinned });
  controller.state = 'running'; controller.settings = { interval: 2 }; controller.route = 'route-A';
  controller.verified = { timezone: 'Europe/Amsterdam', language: 'en-US' };
  controller.relay = new Relay(); controller.routeFingerprint = async () => 'route-A';
  provider = async (_port, token) => { assert.equal(token, 'fixture-control-token'); return { ip: pinned }; };
  t.after(async () => { controller.stop(); await fs.rm(root, { recursive: true, force: true }); });
  return controller;
}
test('temporary IP service failure pauses traffic and resumes the same runtime after a valid unchanged IP', async t => {
  const c = await fixture(t), relay = c.relay;
  provider = async () => { throw Error('temporary timeout'); };
  await c.poll(c.epoch);
  assert.equal(c.state, 'rechecking'); assert.equal(c.policy.blocked, false); assert.equal(relay.paused, true); assert.equal(relay.resumes, 0);
  provider = async () => ({ ip: pinned }); await c.poll(c.epoch);
  assert.equal(c.state, 'running'); assert.equal(c.policy.blocked, false); assert.equal(c.relay, relay); assert.equal(relay.paused, false); assert.equal(relay.resumes, 1);
});
test('changing response family is not mistaken for a changed public address', async t => {
  const c = await fixture(t), relay = c.relay;
  provider = async (_port, token, family) => { assert.equal(family, 4); return { ip: '2001:db8::7' }; };
  await c.poll(c.epoch);
  assert.equal(c.state, 'rechecking'); assert.equal(c.policy.blocked, false); assert.equal(relay.paused, true);
  provider = async () => ({ ip: pinned }); await c.poll(c.epoch);
  assert.equal(c.state, 'running'); assert.equal(c.policy.pinned, pinned);
});
test('malformed and missing IP answers keep traffic paused without permanently blocking an unchanged address', async t => {
  const c = await fixture(t), relay = c.relay;
  for (const result of [null, {}, { ip: 'not-an-IP' }]) {
    provider = async () => result; await c.poll(c.epoch);
    assert.equal(c.state, 'rechecking'); assert.equal(c.policy.blocked, false); assert.equal(relay.paused, true); assert.equal(relay.resumes, 0);
  }
  provider = async () => ({ ip: pinned }); await c.poll(c.epoch); assert.equal(c.state, 'running'); assert.equal(relay.resumes, 1);
});
test('route changes pause immediately and require a fresh unchanged IP answer before resuming', async t => {
  const c = await fixture(t), relay = c.relay, first = deferred(); let checks = 0;
  c.routeFingerprint = async () => 'route-B';
  provider = () => { checks++; return checks === 1 ? first.promise : Promise.resolve({ ip: pinned }); };
  const pending = c.poll(c.epoch); await until(() => relay.paused);
  assert.equal(c.state, 'rechecking'); assert.equal(c.policy.blocked, false);
  first.resolve({ ip: pinned }); await pending; clearTimeout(c.pollTimer);
  assert.equal(relay.resumes, 0);
  await c.poll(c.epoch); assert.equal(checks, 2); assert.equal(c.state, 'running'); assert.equal(c.route, 'route-B'); assert.equal(relay.resumes, 1);
});
test('an event during an in-flight check discards that old result and never overlaps IP requests', async t => {
  const c = await fixture(t), relay = c.relay, first = deferred(), second = deferred(); let active = 0, max = 0, checks = 0;
  provider = async () => { const next = ++checks === 1 ? first : second; active++; max = Math.max(max, active); try { return await next.promise; } finally { active--; } };
  const pending = c.poll(c.epoch); await until(() => checks === 1);
  c.revalidate('Network changed'); assert.equal(relay.paused, true); assert.equal(c.state, 'rechecking');
  first.resolve({ ip: pinned }); await pending; clearTimeout(c.pollTimer);
  assert.equal(relay.resumes, 0);
  const refreshing = c.poll(c.epoch); await until(() => checks === 2); second.resolve({ ip: pinned }); await refreshing;
  assert.equal(max, 1); assert.equal(relay.resumes, 1); assert.equal(c.state, 'running');
});
test('a valid changed IP kills the session immediately even while the route query is still pending', async t => {
  const c = await fixture(t), relay = c.relay, route = deferred();
  c.routeFingerprint = () => route.promise; provider = async () => ({ ip: '203.0.113.8' });
  const pending = c.poll(c.epoch); await until(() => c.state === 'blocked');
  assert.equal(c.policy.blocked, true); assert.equal(relay.closed, true); assert.equal(c.relay, null);
  route.resolve('route-A'); await pending; assert.equal(relay.resumes, 0);
});
test('a temporary route-query failure keeps traffic paused until both the IP and route are confirmed', async t => {
  const c = await fixture(t), relay = c.relay;
  c.routeFingerprint = async () => { throw Error('temporary route service error'); }; await c.poll(c.epoch);
  assert.equal(c.state, 'rechecking'); assert.equal(c.policy.blocked, false); assert.equal(relay.paused, true);
  c.routeFingerprint = async () => 'route-A'; await c.poll(c.epoch); assert.equal(c.state, 'running'); assert.equal(relay.resumes, 1);
});
test('stopping during revalidation prevents a late valid answer from reopening the relay', async t => {
  const c = await fixture(t), relay = c.relay, answer = deferred();
  provider = () => answer.promise; const checking = c.revalidate('Wake from sleep'); await turn();
  c.stop(); answer.resolve({ ip: pinned }); await checking;
  assert.equal(c.state, 'blocked'); assert.equal(relay.closed, true); assert.equal(relay.resumes, 0); assert.equal(c.relay, null);
});
test('security failures still terminate the runtime during network revalidation', async t => {
  const c = await fixture(t), relay = c.relay, answer = deferred();
  provider = () => answer.promise; const checking = c.revalidate('Network changed'); await turn();
  c.block('Locale verification failed'); answer.resolve({ ip: pinned }); await checking;
  assert.equal(c.policy.blocked, true); assert.equal(c.state, 'blocked'); assert.equal(relay.closed, true); assert.equal(relay.resumes, 0);
});
test('IP monitoring starts before a slow runtime diagnostic connection and catches changes during startup', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-startup-monitor-'));
  const c = new GuardController(root, root), channel = deferred(); let host, checks = 0;
  c.routeFingerprint = async () => 'route-A'; initialProvider = async () => ({ country_code: 'NL', ip: pinned });
  provider = async () => ({ ip: ++checks === 1 ? pinned : '203.0.113.8' });
  onSpawn = value => { host = value; }; waitForChannel = () => channel.promise;
  t.after(async () => { c.stop(); channel.resolve(); host?.emit('exit', 0); onSpawn = null; await fs.rm(root, { recursive: true, force: true }); });
  const starting = c.start({ mode: 'network', claudePath: 'fixture', interval: 2 });
  await until(() => host);
  assert.equal(c.state, 'starting'); assert.ok(c.pollTimer, 'monitor must exist before channel connects');
  await c.poll(c.epoch); assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true); assert.equal(checks, 2);
  channel.resolve(); await starting;
});
