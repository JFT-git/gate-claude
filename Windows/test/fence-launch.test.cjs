'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const util = require('node:util');
const { createRequire } = require('node:module');
const file = path.resolve(__dirname, '../src/fence-launch.cjs');
const originalRequire = createRequire(file);
function fixture(run) {
  const calls = [], module = { exports: {} };
  function exec() { throw Error('Callback API must not be used'); }
  exec[util.promisify.custom] = async (...args) => { calls.push(args); return run(...args); };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, exports: module.exports, Buffer,
    require(name) { return name === 'node:child_process' ? { execFile: exec } : originalRequire(name); }
  }, { filename: file });
  return { ...module.exports, calls };
}
const request = () => ({ helper: process.execPath, pipeName: 'gate-network-fence-' + 'a'.repeat(32), token: 'b'.repeat(64), ownerWindow: Buffer.from('3412000000000000', 'hex') });

test('native consent is bound to Guard HWND without a PowerShell or shell fallback', async () => {
  const h = fixture(async () => ({ stdout: '{"version":1,"launched":true,"code":0}', stderr: '' }));
  await h.requestElevation(request());
  assert.equal(h.calls.length, 1);
  const [exe, args, options] = h.calls[0];
  assert.equal(exe, process.execPath);
  assert.deepEqual(Array.from(args), ['--request-elevation', '--owner', '1234', '--pipe', request().pipeName, '--token', request().token]);
  assert.equal(options.timeout, 0); assert.equal(options.shell, undefined);
  assert.equal(options.windowsHide, true); assert.equal(options.maxBuffer, 4096);
});

test('cancel and Windows policy denial remain failures with fixed numeric diagnostics', async () => {
  for (const code of [1223, 5, 1260, 225, 226, 1400, 193, 87, 31]) {
    const h = fixture(async () => ({ stdout: JSON.stringify({ version: 1, launched: false, code }) }));
    await assert.rejects(h.requestElevation(request()), error => error.message.includes('Код Windows: ' + code + '.'));
    assert.equal(h.calls.length, 1);
  }
});

test('missing or blocked requester does not export stderr, environment, paths or tokens', async () => {
  const secret = 'private-account-body-' + request().token;
  const h = fixture(async () => { throw Error(secret); });
  await assert.rejects(h.requestElevation(request()), error => !error.message.includes(secret) && error.message.includes('Журнал защиты'));
  const unknown = h.elevationFailure(Error(secret));
  assert.equal(unknown.message.includes(secret), false);
});

test('malformed, incompatible or contradictory native receipts never authorize the broker', async () => {
  for (const stdout of ['{}', '[]', 'null', 'noise', '{"version":1,"launched":false,"code":0}', '{"version":1,"launched":true,"code":5}', '{"version":2,"launched":true,"code":0}', '{"version":1,"launched":true,"code":0,"extra":"private"}']) {
    const h = fixture(async () => ({ stdout }));
    await assert.rejects(h.requestElevation(request()));
    assert.equal(h.calls.length, 1);
  }
});

test('invalid window handles and command fields fail before launching anything', async () => {
  const h = fixture(async () => { throw Error('must not launch'); });
  for (const ownerWindow of ['1234', Buffer.alloc(0), Buffer.alloc(8), Buffer.alloc(8, 255)]) {
    await assert.rejects(h.requestElevation({ ...request(), ownerWindow }));
  }
  for (const patch of [{ helper: 'relative.exe' }, { pipeName: 'invalid' }, { token: 'bad' }]) await assert.rejects(h.requestElevation({ ...request(), ...patch }));
  assert.equal(h.calls.length, 0);
  assert.equal(h.ownerHandle(null), '0');
  assert.equal(h.ownerHandle(Buffer.from('34120000', 'hex')), '1234');
});

test('unanswered native consent remains a single pending request and never reports success', async () => {
  let complete;
  const h = fixture(() => new Promise(resolve => { complete = resolve; }));
  let finished = false;
  const pending = h.requestElevation(request()).then(() => { finished = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(finished, false); assert.equal(h.calls.length, 1);
  complete({ stdout: '{"version":1,"launched":true,"code":0}' }); await pending;
  assert.equal(finished, true); assert.equal(h.calls.length, 1);
});
