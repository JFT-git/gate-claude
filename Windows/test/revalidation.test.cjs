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
const policy = require('../src/policy.cjs');
const { RouteReadError } = require('../src/route-reader.cjs');
let interfaces = 'interfaces-A';
policy.networkFingerprint = () => interfaces;
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
function stubNetwork(controller) {
  const direct = Object.freeze({ kind: 'direct', host: '', port: 0, fingerprint: 'd'.repeat(64) });
  controller.networkProxy = direct; controller.networkProxyConfiguration = async () => direct;
  controller.requestDestinationIP = async (_epoch, hostname) => ({ hostname, ip: hostname === 'claude.ai' ? '203.0.113.20' : '203.0.113.21', country_code: 'NL' });
}
class Relay extends EventEmitter {
  constructor() { super(); this.port = 1; this.checkToken = 'fixture-control-token'; this.paused = false; this.resumes = 0; this.closed = false; }
  pause() { this.paused = true; }
  resume() { if (this.closed) throw Error('closed'); this.paused = false; this.resumes++; }
  close() { this.closed = true; this.paused = true; }
}
async function fixture(t) {
  interfaces = 'interfaces-A';
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-revalidation-'));
  const controller = new GuardController(root, root); controller.policy.pin({ country_code: 'NL', ip: pinned });
  controller.state = 'running'; controller.settings = { mode: 'network', interval: 2 }; controller.route = 'route-A';
  controller.verified = { timezone: 'Europe/Amsterdam', language: 'en-US' };
  controller.relay = new Relay(); controller.routeFingerprint = async () => 'route-A';
  stubNetwork(controller); await controller.queryDestinations(controller.epoch, 1, 'fixture-control-token', true);
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
test('rechecking rejects an old-route IP answer combined with a new-route fingerprint', async t => {
  const c = await fixture(t), relay = c.relay; let route = 'route-A', checks = 0;
  c.pauseForRevalidation('Recheck the existing pin');
  c.routeFingerprint = async () => route;
  provider = async () => { checks++; route = 'route-B'; return { ip: pinned }; };
  await c.poll(c.epoch); clearTimeout(c.pollTimer);
  assert.equal(c.state, 'rechecking'); assert.equal(c.policy.blocked, false); assert.equal(relay.paused, true); assert.equal(relay.resumes, 0);
  await c.poll(c.epoch);
  assert.equal(checks, 2); assert.equal(c.state, 'running'); assert.equal(c.route, 'route-B'); assert.equal(relay.resumes, 1);
});
test('a stable recheck brackets one external IP request with two native route reads', async t => {
  const c = await fixture(t), relay = c.relay, order = [];
  c.pauseForRevalidation('Recheck the existing pin');
  c.routeFingerprint = async () => { order.push('route'); return 'route-A'; };
  provider = async () => { order.push('ip'); return { ip: pinned }; };
  await c.poll(c.epoch);
  assert.deepEqual(order, ['route', 'ip', 'route']); assert.equal(relay.resumes, 1); assert.equal(c.state, 'running');
});
for (const failedRead of [1, 2]) {
  test(`a route error at recheck boundary ${failedRead} stays paused and a later stable check recovers`, async t => {
    const c = await fixture(t), relay = c.relay; let reads = 0, checks = 0;
    c.pauseForRevalidation('Recheck the existing pin');
    c.routeFingerprint = async () => { if (++reads === failedRead) throw new RouteReadError('TIMEOUT'); return 'route-A'; };
    provider = async () => { checks++; return { ip: pinned }; };
    await c.poll(c.epoch); clearTimeout(c.pollTimer);
    assert.equal(relay.paused, true); assert.equal(relay.resumes, 0); assert.equal(c.policy.blocked, false); assert.equal(checks, 1);
    await c.poll(c.epoch);
    assert.equal(checks, 2); assert.equal(relay.resumes, 1); assert.equal(c.state, 'running');
  });
}
test('an unavailable route read cannot hide a confirmed changed IP while rechecking', async t => {
  const c = await fixture(t), relay = c.relay; let checks = 0;
  c.pauseForRevalidation('Recheck the existing pin');
  c.routeFingerprint = async () => { throw new RouteReadError('TIMEOUT'); };
  provider = async () => { checks++; return { ip: '203.0.113.8' }; };
  await c.poll(c.epoch);
  assert.equal(checks, 1); assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true);
  assert.equal(relay.closed, true); assert.equal(relay.resumes, 0); assert.equal(c.relay, null);
});
test('repeated failed route reads still check unchanged IP and never reopen traffic', async t => {
  const c = await fixture(t), relay = c.relay; let checks = 0;
  c.pauseForRevalidation('Recheck the existing pin');
  c.routeFingerprint = async () => { throw new RouteReadError('TIMEOUT'); };
  provider = async () => { checks++; return { ip: pinned }; };
  for (let attempt = 0; attempt < 2; attempt++) { await c.poll(c.epoch); clearTimeout(c.pollTimer); }
  assert.equal(checks, 2); assert.equal(c.state, 'rechecking'); assert.equal(c.policy.blocked, false);
  assert.equal(relay.paused, true); assert.equal(relay.resumes, 0);
});
test('stable independent destination exits do not cause a false IP-change block', async t => {
  const c = await fixture(t), relay = c.relay;
  c.pauseForRevalidation('Recheck each destination'); await c.poll(c.epoch);
  assert.equal(c.policy.pinned, pinned); assert.equal(c.destinationPolicies.get('claude.ai').pinned, '203.0.113.20');
  assert.equal(c.destinationPolicies.get('api.anthropic.com').pinned, '203.0.113.21');
  assert.equal(c.state, 'running'); assert.equal(c.policy.blocked, false); assert.equal(relay.resumes, 1);
});
test('an unchanged ipify answer cannot hide a changed Claude destination while another probe is slow', async t => {
  const c = await fixture(t), relay = c.relay, slow = deferred(); let pendingHost;
  c.requestDestinationIP = async (_epoch, hostname) => {
    if (hostname === 'api.anthropic.com') { pendingHost = hostname; return slow.promise; }
    return { hostname, ip: '203.0.113.22', country_code: 'NL' };
  };
  const pending = c.poll(c.epoch); await until(() => c.state === 'blocked');
  assert.equal(pendingHost, 'api.anthropic.com'); assert.equal(relay.closed, true); assert.equal(relay.resumes, 0);
  slow.resolve({ hostname: pendingHost, ip: '203.0.113.21', country_code: 'NL' }); await pending;
  assert.equal(c.state, 'blocked'); assert.equal(c.relay, null);
});
test('a Claude destination switching IPv4 to IPv6 terminates even while ipify stays unchanged', async t => {
  const c = await fixture(t), relay = c.relay, normal = c.requestDestinationIP;
  c.requestDestinationIP = async (...args) => {
    const result = await normal(...args);
    return result.hostname === 'claude.ai' ? { ...result, ip: '2001:db8::20' } : result;
  };
  await c.poll(c.epoch);
  assert.equal(c.policy.pinned, pinned); assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true);
  assert.equal(relay.closed, true); assert.equal(relay.resumes, 0); assert.equal(c.relay, null);
});
test('destination failure pauses traffic and only a fresh stable same-exit bracket recovers', async t => {
  const c = await fixture(t), relay = c.relay, normal = c.requestDestinationIP;
  c.requestDestinationIP = async () => { throw Error('fixture unavailable'); };
  await c.poll(c.epoch); clearTimeout(c.pollTimer);
  assert.equal(c.state, 'rechecking'); assert.equal(relay.paused, true); assert.equal(c.policy.blocked, false);
  c.requestDestinationIP = normal; await c.poll(c.epoch);
  assert.equal(c.state, 'running'); assert.equal(relay.resumes, 1);
});
test('route failures still check destination exits and terminate on a confirmed change', async t => {
  const c = await fixture(t), relay = c.relay; let domains = 0;
  c.pauseForRevalidation('Recheck after a route transition');
  c.routeFingerprint = async () => { throw new RouteReadError('TIMEOUT'); };
  c.requestDestinationIP = async (_epoch, hostname) => { domains++; return { hostname, ip: hostname === 'claude.ai' ? '203.0.113.22' : '203.0.113.21', country_code: 'NL' }; };
  await c.poll(c.epoch);
  assert.equal(domains, 2); assert.equal(c.state, 'blocked'); assert.equal(relay.closed, true);
});
test('RU destination closes the session even if its IP and ipify remain unchanged', async t => {
  const c = await fixture(t), relay = c.relay, normal = c.requestDestinationIP;
  c.requestDestinationIP = async (...args) => ({ ...await normal(...args), country_code: 'RU' });
  await c.poll(c.epoch);
  assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true); assert.equal(relay.closed, true);
});
test('changing or removing the captured system proxy permanently blocks a paused session', async t => {
  for (const kind of ['http', 'direct']) {
    const c = await fixture(t), relay = c.relay;
    c.pauseForRevalidation('Recheck proxy configuration');
    c.networkProxyConfiguration = async () => ({ kind, host: kind === 'http' ? '127.0.0.1' : '', port: kind === 'http' ? 9697 : 0, fingerprint: 'e'.repeat(64) });
    await c.poll(c.epoch);
    assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true); assert.equal(relay.closed, true); assert.equal(relay.resumes, 0);
    await assert.rejects(c.start({ mode: 'network' }), /перезапуска/);
  }
});
test('a system-proxy read failure keeps an unchanged session paused until a fresh complete check', async t => {
  const c = await fixture(t), relay = c.relay, normal = c.networkProxyConfiguration;
  c.networkProxyConfiguration = async () => { throw Error('fixture registry timeout'); };
  await c.poll(c.epoch); clearTimeout(c.pollTimer);
  assert.equal(c.state, 'rechecking'); assert.equal(relay.paused, true); assert.equal(c.policy.blocked, false);
  c.networkProxyConfiguration = normal; await c.poll(c.epoch);
  assert.equal(c.state, 'running'); assert.equal(relay.resumes, 1);
});
test('a system-proxy change at the end of a successful recheck cannot reopen traffic', async t => {
  const c = await fixture(t), relay = c.relay, normal = c.networkProxy; let reads = 0;
  c.pauseForRevalidation('Recheck proxy configuration');
  c.networkProxyConfiguration = async () => ++reads === 1 ? normal : { ...normal, fingerprint: 'e'.repeat(64) };
  await c.poll(c.epoch);
  assert.equal(reads, 2); assert.equal(c.state, 'blocked'); assert.equal(relay.closed, true); assert.equal(relay.resumes, 0);
});
test('stop while destination probes are pending prevents late answers from reopening traffic', async t => {
  const c = await fixture(t), relay = c.relay, answer = deferred(); let domains = 0;
  c.pauseForRevalidation('Recheck destination exits');
  c.requestDestinationIP = async (_epoch, hostname) => { domains++; await answer.promise; return { hostname, ip: '203.0.113.20', country_code: 'NL' }; };
  const pending = c.poll(c.epoch); await until(() => domains === 2); c.stop(); const epoch = c.epoch;
  answer.resolve(); await pending;
  assert.equal(c.epoch, epoch); assert.equal(c.state, 'blocked'); assert.equal(relay.closed, true); assert.equal(relay.resumes, 0);
});
test('stopping after a failed route read cancels its pending IP result without reopening', async t => {
  const c = await fixture(t), relay = c.relay, answer = deferred(); let checks = 0;
  c.pauseForRevalidation('Recheck the existing pin');
  c.routeFingerprint = async () => { throw new RouteReadError('TIMEOUT'); };
  provider = () => { checks++; return answer.promise; };
  const pending = c.poll(c.epoch); await until(() => checks === 1);
  c.stop(); const stoppedEpoch = c.epoch; answer.resolve({ ip: pinned }); await pending;
  assert.equal(c.epoch, stoppedEpoch); assert.equal(c.state, 'blocked'); assert.equal(c.policy.blocked, true);
  assert.equal(relay.closed, true); assert.equal(relay.resumes, 0); assert.equal(c.relay, null);
  assert.equal(c.events.some(event => event.message.includes('Соединение возобновлено')), false);
});
test('an interface change during a recheck bracket requires another unchanged-IP sample', async t => {
  const c = await fixture(t), relay = c.relay; let checks = 0;
  c.pauseForRevalidation('Recheck the existing pin');
  provider = async () => { checks++; interfaces = 'interfaces-B'; return { ip: pinned }; };
  await c.poll(c.epoch); clearTimeout(c.pollTimer);
  assert.equal(relay.paused, true); assert.equal(relay.resumes, 0); assert.equal(c.policy.blocked, false);
  await c.poll(c.epoch);
  assert.equal(checks, 2); assert.equal(relay.resumes, 1); assert.equal(c.state, 'running');
});
test('a revision during the final recheck route read invalidates the bracket', async t => {
  const c = await fixture(t), relay = c.relay, finalRoute = deferred(); let reads = 0, checks = 0;
  c.pauseForRevalidation('Recheck the existing pin');
  c.routeFingerprint = () => ++reads === 2 ? finalRoute.promise : Promise.resolve('route-A');
  provider = async () => { checks++; return { ip: pinned }; };
  const pending = c.poll(c.epoch); await until(() => reads === 2);
  c.revalidate('New event while the final route read is pending');
  finalRoute.resolve('route-A'); await pending; clearTimeout(c.pollTimer);
  assert.equal(relay.paused, true); assert.equal(relay.resumes, 0); assert.equal(c.policy.blocked, false);
  await c.poll(c.epoch);
  assert.equal(checks, 2); assert.equal(relay.resumes, 1); assert.equal(c.state, 'running');
});
test('stopping during the final recheck route read prevents late reopening', async t => {
  const c = await fixture(t), relay = c.relay, finalRoute = deferred(); let reads = 0;
  c.pauseForRevalidation('Recheck the existing pin');
  c.routeFingerprint = () => ++reads === 2 ? finalRoute.promise : Promise.resolve('route-A');
  const pending = c.poll(c.epoch); await until(() => reads === 2);
  c.stop(); finalRoute.resolve('route-A'); await pending;
  assert.equal(relay.closed, true); assert.equal(relay.resumes, 0); assert.equal(c.state, 'blocked');
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
  stubNetwork(c);
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
