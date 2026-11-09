'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DiagnosticStore, createZip, safeText, sessionSnapshot } = require('../src/diagnostics.cjs');
const { parsePortableZip, inflateEntry } = require('../src/portable-zip.cjs');

function temporary(t) { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-diagnostics-')); t.after(() => fs.rmSync(root, { recursive: true, force: true })); return root; }
function unpack(bundle) {
  const parsed = parsePortableZip(bundle.bytes, bundle.files);
  return Object.fromEntries(parsed.entries.map(entry => [entry.path, inflateEntry(entry).toString('utf8')]));
}
function controller() {
  return {
    runtimePID: 4321, runtime: { version: '1.44121.2' }, relay: { closed: false, unlocked: true }, fence: { installed: true, closed: false },
    liveHost: () => true,
    snapshot: () => ({ state: 'rechecking', message: 'Проверка 203.0.113.9', blocked: false, processFrozen: true, processState: 'frozen', secondsRemaining: 12,
      windowsApprovalPending: false, savedIP: '203.0.113.9', exitIP: '203.0.113.9', ipMemoryError: '', country: 'NL',
      profile: { timezone: 'Europe/Amsterdam', language: 'en-US', locale: 'en-US' },
      metrics: { sources: ['ipwho.is'], organization: 'Example', asn: 'AS64500', destinations: { 'claude.ai': { state: 'ok', latencyMs: 120 } },
        dns: { state: 'ready', ip: '203.0.113.9', organization: 'Resolver' }, dnsProtection: 'pinned_egress', webRTC: 'disable_non_proxied_udp', quic: 'disabled' } })
  };
}

test('diagnostic bundle round-trips and excludes IPs, secrets, user paths and traffic data', async t => {
  const store = new DiagnosticStore(temporary(t));
  store.event('host_command_ack', { id: 7, command: 'freeze', ok: false, error: 'InvalidOperationException:0:ThreadSnapshot', elapsedMS: 1503.4 });
  store.error('ipc:start', Error('Bearer fixture-token at 203.0.113.9 in C:\\Users\\alice\\AppData\\Secret'));
  const bundle = await store.bundle({ manifest: { schema: 1, appVersion: '0.9.4' }, session: sessionSnapshot(controller()),
    service: { schema: 1, available: true, state: 'running', code: null, actions: ['stop'], sessionRoutingSupported: true } });
  const files = unpack(bundle), text = Object.values(files).join('\n');
  assert.ok(files['events.jsonl'].includes('ThreadSnapshot'));
  assert.ok(files['guard.log'].includes('ipc:start'));
  assert.equal(JSON.parse(files['session.json']).runtime.pid, 4321);
  assert.equal(JSON.parse(files['session.json']).savedIPPresent, true);
  assert.ok(!text.includes('203.0.113.9')); assert.ok(!text.includes('fixture-token')); assert.ok(!text.includes('alice'));
  assert.ok(!Object.hasOwn(files, 'settings.json')); assert.ok(!Object.hasOwn(files, 'ip-memory.json')); assert.ok(!Object.hasOwn(files, 'traffic.json'));
  assert.ok(!text.includes('requestHeaders')); assert.ok(!text.includes('fixture-cookie'));
  assert.ok(files['README.txt'].includes('settings.json'));
});

test('log rotation stays bounded and retains only the current and previous segments', async t => {
  const root = temporary(t), store = new DiagnosticStore(root, { maxFileBytes: 1200 });
  for (let index = 0; index < 40; index++) store.event('state', { epoch: index, state: 'rechecking', message: 'x'.repeat(80) });
  await store.flush();
  const names = fs.readdirSync(path.join(root, 'logs')).sort();
  assert.deepEqual(names, ['events.jsonl', 'events.previous.jsonl']);
  for (const name of names) assert.ok(fs.statSync(path.join(root, 'logs', name)).size <= 1200);
  const files = unpack(await store.bundle({ manifest: {}, session: {}, service: {} }));
  assert.ok(files['events.jsonl'].includes('"epoch":39'));
  assert.ok(files['events.previous.jsonl'].includes('"type":"state"'));
});

test('ZIP writer rejects oversized and unsafe entries without producing an archive', () => {
  assert.throws(() => createZip({ '../escape': Buffer.from('no') }), /Invalid portable tool archive/);
  assert.throws(() => createZip({ 'events.jsonl': Buffer.alloc(512 * 1024 + 1) }), /превышает ограничение/);
});

test('snapshot omits raw addresses and text sanitization removes common secrets', () => {
  const session = sessionSnapshot(controller()), serialized = JSON.stringify(session);
  assert.ok(!serialized.includes('203.0.113.9')); assert.ok(!Object.hasOwn(session, 'savedIP')); assert.ok(!Object.hasOwn(session.metrics.dns, 'ip'));
  const safe = safeText('https://example.test/path?token=fixture-token proxy.example.com alice@example.com 00112233-4455-6677-8899-aabbccddeeff 00:11:22:33:44:55 203.0.113.9 /Users/alice/Profile Bearer fixture-token');
  for (const canary of ['fixture-token', '203.0.113.9', 'alice', 'proxy.example.com', '00112233', '00:11:22:33:44:55']) assert.ok(!safe.includes(canary));
  assert.ok(safeText('Проверка ipwho.is и claude.ai').includes('ipwho.is'));
  assert.equal(safeText('Win32Exception:5:ResumeThread'), 'Win32Exception-5-ResumeThread');
});

test('logging and export survive filesystem failures without changing the caller', async t => {
  const root = temporary(t), file = path.join(root, 'not-a-directory'); fs.writeFileSync(file, 'x');
  const store = new DiagnosticStore(file);
  assert.doesNotThrow(() => store.event('state', { state: 'blocked' }));
  await store.flush();
  const bundle = await store.bundle({ manifest: {}, session: {}, service: {} }), files = unpack(bundle);
  assert.ok(JSON.parse(files['manifest.json']).diagnostics.writeFailures > 0);
});
