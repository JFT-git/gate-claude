'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { GuardController } = require('../src/controller.cjs');
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-probe-diagnostics-'));
  const c = new GuardController(root, root);
  c.state = 'running'; c.relay = { close() {} };
  t.after(async () => { c.stop(); await fs.rm(root, { recursive: true, force: true }); });
  return c;
}
test('untrusted network errors cannot inject addresses, credentials or invented diagnostic fields', async t => {
  const c = await fixture(t);
  const secret = 'Bearer diagnostic-private-value 203.0.113.20 2001:db8::20';
  const error = Object.assign(Error(secret), { code: 'TLS', phase: 'tls', service: secret, httpStatus: 403, cause: secret, headers: { Authorization: secret } });
  c.reportProbeFailure('claude.ai', error, 12.6);
  assert.equal(c.events.length, 1);
  assert.equal(c.events[0].message, 'Проверка сети: claude.ai · UNCONFIRMED · check · 13 мс.');
  assert.doesNotMatch(JSON.stringify(c.events), /private-value|203\.0|db8|Bearer|403|TLS/);
  c.reportProbeFailure(secret, error, 20);
  assert.equal(c.events.length, 1, 'Only fixed probe sources may enter diagnostics');
});
test('repeated identical probe failures do not replace useful state transitions with log spam', async t => {
  const c = await fixture(t);
  for (let n = 0; n < 100; n++) c.reportProbeFailure('public', Error('hidden'), n);
  assert.equal(c.events.length, 1);
  assert.equal(c.probeFailures.size, 1);
  c.probeFailures.set('public:UNCONFIRMED:check:', performance.now() - 30001);
  c.reportProbeFailure('public', Error('hidden'), 4);
  assert.equal(c.events.length, 2);
});
test('an unsuccessful IP request keeps its original rejection while adding only safe timing metadata', async t => {
  const c = await fixture(t), failure = Error('hidden response and token');
  await assert.rejects(c.requestIP(c.epoch, async () => { throw failure; }, 1, 'hidden-control-token'), error => error === failure);
  assert.equal(c.ipRequest, null);
  assert.equal(c.events.length, 1);
  assert.match(c.events[0].message, /^Проверка сети: public · UNCONFIRMED · check · \d+ мс\.$/);
  assert.doesNotMatch(JSON.stringify(c.events), /hidden|response|token/);
});
test('a cancelled probe cannot add a late error to the next session', async t => {
  const c = await fixture(t); let reject;
  const pending = c.requestIP(c.epoch, () => new Promise((_, no) => { reject = no; }), 1, 'hidden');
  await new Promise(resolve => setImmediate(resolve));
  c.stop(); const count = c.events.length;
  reject(Error('late hidden response'));
  await assert.rejects(pending);
  assert.equal(c.events.length, count);
  assert.equal(c.ipRequest, null);
});
test('preparation progress contains only known stages and never hides a network pause', async t => {
  const c = await fixture(t);
  c.preparationProgress({ toolId: 'git', stage: 'cache-verify', done: 1, total: 9606, elapsedMS: 123 });
  assert.match(c.message, /Git · 1 \/ 9606/);
  const count = c.events.length;
  c.preparationProgress({ toolId: 'git', stage: 'cache-verify', done: 2, total: 9606, elapsedMS: 250 });
  assert.equal(c.events.length, count, 'Counters update the UI without logging each file');
  c.state = 'rechecking'; c.status('Network verification pending');
  c.preparationProgress({ toolId: 'powershell', stage: 'cache-verify', done: 5, total: 662, elapsedMS: 300 });
  assert.equal(c.message, 'Network verification pending');
  const messages = JSON.stringify(c.events);
  c.preparationProgress({ toolId: 'hidden-file-token', stage: 'cache-verify', done: 0, total: 1, elapsedMS: 10 });
  c.preparationProgress({ toolId: 'git', stage: 'hidden-path', done: 0, total: 1, elapsedMS: 10 });
  c.preparationProgress({ toolId: 'git', stage: 'cache-verify', done: 11, total: 10, elapsedMS: 10 });
  assert.equal(JSON.stringify(c.events), messages);
});
test('typed probe failures expose only their fixed category, HTTP status and bounded duration', async t => {
  const { NetworkCheckError } = require('../src/ip-check.cjs');
  const c = await fixture(t);
  c.reportProbeFailure('api.anthropic.com', new NetworkCheckError({ code: 'HTTP_STATUS', service: 'api.anthropic.com', phase: 'headers', httpStatus: 429 }), 999999999);
  assert.equal(c.events.at(-1).message, 'Проверка сети: api.anthropic.com · HTTP_STATUS · headers · HTTP 429 · 600000 мс.');
});
