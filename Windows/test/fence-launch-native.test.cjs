'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { promisify } = require('node:util');
const run = promisify(require('node:child_process').execFile);

test('Windows native elevation requester refuses malformed arguments and invalid owners before consent', { skip: process.platform !== 'win32', timeout: 45000 }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-native-consent-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const exe = path.join(root, 'NetworkFence.exe');
  const csc = path.join(process.env.SystemRoot || 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  await run(csc, ['/nologo', '/optimize+', '/platform:x64', '/target:exe', '/out:' + exe,
    ...['NetworkFence.cs', 'CodeNetworkFence.cs', 'CodeFenceSession.cs'].map(f => path.resolve(__dirname, '../native', f))], { windowsHide: true, timeout: 30000 });
  const valid = ['--request-elevation', '--owner', '0', '--pipe', 'gate-network-fence-' + 'a'.repeat(32), '--token', 'b'.repeat(64)];
  // No valid request with a live owner or owner=0 is ever executed by this test.
  for (const [index, value, code] of [[2, '1', 1400], [2, 'ffffffffffffffff', 87], [2, 'bad\n', 87], [4, 'invalid', 87], [6, 'bad', 87], [6, 'b'.repeat(64) + '\n', 87], [1, '--other', 87]]) {
    const args = valid.slice(); args[index] = value;
    const result = await run(exe, args, { windowsHide: true, timeout: 5000 });
    assert.deepEqual(JSON.parse(result.stdout), { version: 1, launched: false, code });
    assert.equal(result.stderr, '');
  }
  const truncated = await run(exe, ['--request-elevation'], { windowsHide: true, timeout: 5000 });
  assert.deepEqual(JSON.parse(truncated.stdout), { version: 1, launched: false, code: 87 });
});
