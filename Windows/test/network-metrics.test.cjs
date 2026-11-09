'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { GuardController } = require('../src/controller.cjs');
async function fixture(t, options) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-network-metrics-'));
  const controller = new GuardController(root, root, options);
  controller.state = 'running'; controller.relay = { close() {} };
  t.after(async () => { controller.stop(); await fs.rm(root, { recursive: true, force: true }); });
  return controller;
}

test('external DNS metrics are validated, deduplicated and emitted without blocking a session', async t => {
  let calls = 0, release;
  const controller = await fixture(t, { dnsProbe: () => { calls++; return new Promise(resolve => { release = resolve; }); } });
  const first = controller.refreshDNSMetrics(controller.epoch, 1, 'token');
  const second = controller.refreshDNSMetrics(controller.epoch, 1, 'token');
  assert.equal(calls, 1);
  release({ ip: '203.0.113.9', geo: 'Germany - Google LLC' });
  await Promise.all([first, second]);
  const metrics = controller.snapshot().metrics;
  assert.deepEqual(metrics.dns, { state: 'ready', ip: '203.0.113.9', organization: 'Germany - Google LLC' });
  assert.equal(metrics.webRTC, 'disable_non_proxied_udp');
  assert.equal(metrics.quic, 'disabled');
});

test('late and malformed DNS metrics cannot affect a stopped session or expose response data', async t => {
  const secret = 'private-response-value';
  let release;
  const controller = await fixture(t, { dnsProbe: () => new Promise(resolve => { release = resolve; }) });
  const pending = controller.refreshDNSMetrics(controller.epoch, 1, 'token');
  controller.stop(); release({ ip: '203.0.113.9', geo: secret }); await pending;
  assert.notEqual(controller.snapshot().metrics.dns.state, 'ready');
  assert.equal(JSON.stringify(controller.snapshot()).includes(secret), false);
  const malformed = await fixture(t, { dnsProbe: async () => ({ ip: secret, geo: secret }) });
  await malformed.refreshDNSMetrics(malformed.epoch, 1, 'token');
  assert.equal(malformed.snapshot().metrics.dns.state, 'unavailable');
  assert.equal(JSON.stringify(malformed.snapshot()).includes(secret), false);
});
