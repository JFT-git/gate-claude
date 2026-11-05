'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { GuardController } = require('../src/controller.cjs');

const pinned = '203.0.113.7';
const turn = () => new Promise(resolve => setImmediate(resolve));
async function until(check) {
  for (let n = 0; n < 100; n++) { if (check()) return; await turn(); }
  throw Error('Fixture condition was not reached');
}
class Relay {
  constructor() { this.port = 1; this.checkToken = 'fixture'; this.paused = false; this.resumes = 0; this.closed = false; }
  pause() { this.paused = true; }
  resume() { if (this.closed) throw Error('closed'); this.paused = false; this.resumes++; }
  close() { this.closed = true; this.paused = true; }
}
class Host extends EventEmitter {
  constructor() {
    super(); this.stdin = new PassThrough(); this.stdout = new PassThrough(); this.exitCode = null; this.signalCode = null;
    this.commands = []; this.autoAck = true; this.killed = false;
    this.stdin.on('data', chunk => {
      for (const line of chunk.toString().split('\n')) {
        if (!line || line === 'ping') continue;
        const [command, id] = line.split(' '); this.commands.push({ command, id: Number(id) });
        if (this.autoAck) queueMicrotask(() => this.ack(command, Number(id)));
      }
    });
  }
  ack(command, id, ok = true) {
    const key = command === 'freeze' ? 'freezeAck' : 'thawAck';
    this.stdout.write(JSON.stringify({ [key]: id, ok, count: ok ? 3 : 0 }) + '\n');
  }
  kill() { this.killed = true; this.exitCode = 1; this.emit('exit', 1); }
}
async function fixture(t, options = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-process-freeze-'));
  const c = new GuardController(root, root); c.policy.pin({ country_code: 'NL', ip: pinned });
  c.state = 'running'; c.settings = { mode: 'socks5', interval: 30 }; c.route = '';
  c.verified = { timezone: 'Europe/Amsterdam', language: 'en-US' }; c.relay = new Relay(); c.fixtureRelay = c.relay;
  c.host = new Host(); c.fixtureHost = c.host; c.runtimePID = 100;
  c.host.stdout.on('data', chunk => { for (const line of chunk.toString().split('\n')) if (line) c.resolveHostCommand(JSON.parse(line)); });
  c.provider = async () => ({ ip: pinned }); c.requestIP = async () => c.provider();
  c.queryDestinations = async () => true; c.routeFingerprint = async () => '';
  c.closeCalls = 0; c.channel = { closed: false, frozen: false, setFrozen(value) { this.frozen = value; }, close() { this.closed = true; }, command: async method => { assert.equal(method, 'Browser.close'); c.closeCalls++; return {}; } };
  if (options.timers) {
    t.mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: 0 });
    t.mock.method(performance, 'now', () => Date.now());
  }
  t.after(async () => { c.stop(); await fs.rm(root, { recursive: true, force: true }); });
  return c;
}
async function failInitialCheck(c) {
  c.provider = async () => { throw Error('fixture transient failure'); };
  const pending = c.revalidate('fixture transient failure');
  assert.equal(c.relay.paused, true); assert.equal(c.processFrozen, true);
  assert.deepEqual(c.host.commands.map(item => item.command), ['freeze']);
  await pending; await until(() => c.processState === 'frozen');
}
for (const seconds of [1, 19]) {
  test(`successful full validation thaws before relay resume at ${seconds}s with a fixed deadline`, { timeout: 10000 }, async t => {
    const c = await fixture(t, { timers: true }), deadlineAtStart = () => c.freezeDeadline;
    await failInitialCheck(c); const deadline = deadlineAtStart(); let checks = 0;
    c.provider = async () => { checks++; if (performance.now() < seconds * 1000) throw Error('still unavailable'); return { ip: pinned }; };
    for (let second = 1; second <= seconds; second++) { t.mock.timers.tick(1000); await until(() => checks >= second); }
    await until(() => c.state === 'running');
    assert.equal(c.processFrozen, false); assert.equal(c.snapshot().secondsRemaining, 0);
    assert.equal(c.fixtureRelay.resumes, 1); assert.equal(c.relay.paused, false);
    assert.deepEqual(c.host.commands.map(item => item.command), ['freeze', 'thaw']);
    assert.ok(checks >= seconds, '30-second polling changed to one-second retries');
    assert.equal(deadline, 20000);
  });
}
test('repeated failures never extend the deadline and timeout gets one bounded graceful close', { timeout: 10000 }, async t => {
  const c = await fixture(t, { timers: true }); await failInitialCheck(c);
  const deadline = c.freezeDeadline; let checks = 0; c.provider = async () => { checks++; throw Error('offline'); };
  for (let second = 1; second < 20; second++) {
    t.mock.timers.tick(1000); await until(() => checks >= second);
    assert.equal(c.freezeDeadline, deadline); assert.deepEqual(c.host.commands.map(item => item.command), ['freeze']);
    assert.equal(c.snapshot().secondsRemaining, 20 - second);
  }
  t.mock.timers.tick(1000); await until(() => c.processState === 'closing' && c.closeCalls === 1);
  const checksAtClose = checks;
  assert.equal(c.closeCalls, 1); assert.equal(c.state, 'rechecking'); assert.equal(c.fixtureRelay.resumes, 0);
  assert.equal(c.snapshot().secondsRemaining, 0); assert.equal(c.freezeDeadline, deadline);
  t.mock.timers.tick(4999); await turn(); assert.equal(c.state, 'rechecking'); assert.equal(checks, checksAtClose);
  t.mock.timers.tick(1); await until(() => c.state === 'blocked');
  assert.equal(c.fixtureRelay.closed, true); assert.equal(c.processFrozen, false); assert.equal(c.closeCalls, 1);
  t.mock.timers.tick(1000); await until(() => c.fixtureHost.killed);
});
test('an expected Browser.close exit is handled as timeout closure without a second failure', async t => {
  const c = await fixture(t, { timers: true }); await failInitialCheck(c);
  c.channel.command = async () => { c.closeCalls++; queueMicrotask(() => { c.host.exitCode = 0; c.host.emit('exit', 0); }); };
  t.mock.timers.tick(20000); await until(() => c.state === 'blocked');
  assert.equal(c.closeCalls, 1); assert.match(c.message, /20 секунд/); assert.equal(c.fixtureRelay.resumes, 0);
});
test('a late thaw acknowledgement after stop cannot resume or revive the session', async t => {
  const c = await fixture(t); await failInitialCheck(c); c.host.autoAck = false; c.provider = async () => ({ ip: pinned });
  const pending = c.poll(c.epoch); await until(() => c.host.commands.some(item => item.command === 'thaw'));
  const host = c.host, thaw = host.commands.find(item => item.command === 'thaw'); c.stop(); const epoch = c.epoch; host.ack('thaw', thaw.id);
  await pending; assert.equal(c.epoch, epoch); assert.equal(c.state, 'blocked');
  assert.equal(c.fixtureRelay.resumes, 0); assert.equal(c.processFrozen, false); assert.equal(c.host, null);
});
test('a new failure during thaw refreezes without extending the deadline or resuming the relay', async t => {
  const c = await fixture(t); await failInitialCheck(c); const deadline = c.freezeDeadline;
  c.host.autoAck = false; c.provider = async () => ({ ip: pinned });
  const pending = c.poll(c.epoch); await until(() => c.host.commands.some(item => item.command === 'thaw'));
  c.pauseForRevalidation('new failure during thaw', false);
  const host = c.host, thaw = host.commands.find(item => item.command === 'thaw'); host.autoAck = true; host.ack('thaw', thaw.id);
  await pending; await until(() => c.processState === 'frozen');
  assert.deepEqual(host.commands.map(item => item.command),['freeze','thaw','freeze']);
  assert.equal(c.fixtureRelay.resumes,0); assert.equal(c.freezeDeadline,deadline);
  await c.poll(c.epoch); assert.equal(c.state,'running'); assert.equal(c.fixtureRelay.resumes,1);
});
test('stop during native freeze invalidates its late acknowledgement', async t => {
  const c = await fixture(t); c.host.autoAck = false;
  const pending = c.revalidate('stop during freeze'); const host = c.host, command = host.commands[0];
  c.stop(); host.ack('freeze', command.id); await pending;
  assert.equal(c.state, 'blocked'); assert.equal(c.fixtureRelay.resumes, 0); assert.equal(c.processFrozen, false);
});
test('stop during timeout thaw prevents Browser.close and ignores the late acknowledgement', async t => {
  const c = await fixture(t, { timers: true }); await failInitialCheck(c); c.host.autoAck = false;
  t.mock.timers.tick(20000); await until(() => c.host.commands.some(item => item.command === 'thaw'));
  const host = c.host, thaw = host.commands.find(item => item.command === 'thaw'); c.stop(); host.ack('thaw', thaw.id); await turn();
  assert.equal(c.closeCalls, 0); assert.equal(c.state, 'blocked'); assert.equal(c.processFrozen, false);
});
test('a hosted IP mismatch freezes before retry and recovers only after the original IP validates', async t => {
  const c = await fixture(t); c.provider = async () => ({ ip: '203.0.113.8' });
  await c.poll(c.epoch); await until(() => c.processState === 'frozen');
  assert.equal(c.state, 'rechecking'); assert.equal(c.policy.blocked, false); assert.equal(c.fixtureRelay.resumes, 0);
  c.provider = async () => ({ ip: pinned }); await c.poll(c.epoch);
  assert.equal(c.state, 'running'); assert.equal(c.processFrozen, false); assert.equal(c.fixtureRelay.resumes, 1);
});
test('initial or unhosted IP mismatch and hosted proxy failures remain immediate blocks', async t => {
  const unhosted = await fixture(t); unhosted.host = null;
  unhosted.provider = async () => ({ ip: '203.0.113.8' }); await unhosted.poll(unhosted.epoch);
  assert.equal(unhosted.state, 'blocked'); assert.equal(unhosted.processFrozen, false);
  const hosted = await fixture(t); hosted.settings = { mode: 'network', interval: 30 };
  hosted.networkProxyConfiguration = async () => { throw Error('registry unavailable'); };
  assert.equal(await hosted.confirmNetworkProxy(hosted.epoch), false);
  assert.equal(hosted.state, 'blocked'); assert.equal(hosted.processFrozen, false); assert.equal(hosted.host, null);
});
test('native freeze rejection fails closed without relay resume', async t => {
  const c = await fixture(t); c.host.autoAck = false;
  const pending = c.revalidate('native failure'); const command = c.host.commands[0]; c.host.ack('freeze', command.id, false);
  await pending; assert.equal(c.state, 'blocked'); assert.equal(c.fixtureRelay.closed, true); assert.equal(c.fixtureRelay.resumes, 0);
});
