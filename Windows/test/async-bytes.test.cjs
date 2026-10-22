'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { promisify } = require('node:util');
const run = promisify(require('node:child_process').execFile);
const { sha256 } = require('../src/async-bytes.cjs');
const { crc32, inflateEntryAsync } = require('../src/portable-zip.cjs');

test('cooperative authentication preserves SHA256 for empty, small and multi-chunk byte inputs', async () => {
  for (const bytes of [Buffer.alloc(0), Buffer.from('123456789'), Buffer.alloc(3 * 1024 * 1024 + 7, 0xa5)]) {
    assert.equal(await sha256(bytes), crypto.createHash('sha256').update(bytes).digest('hex'));
  }
  await assert.rejects(sha256('not bytes'), TypeError);
});

test('large asset authentication and inflation keep heartbeat and child output callbacks responsive', { timeout: 15000 }, async t => {
  const bytes = Buffer.alloc(32 * 1024 * 1024, 0xa5);
  const entry = { method: 8, compressed: zlib.deflateRawSync(bytes), size: bytes.length,
    crc: crc32(bytes), sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  let ticks = 0;
  const heartbeat = setInterval(() => { ticks++; }, 1);
  t.after(() => clearInterval(heartbeat));
  const [digest, inflated, child] = await Promise.all([
    sha256(bytes), inflateEntryAsync(entry),
    run(process.execPath, ['-e', 'process.stdout.write("[]\\n")'], { timeout: 4000, windowsHide: true })
  ]);
  assert.equal(digest, entry.sha256); assert.ok(inflated.equals(bytes));
  assert.equal(child.stdout.trim(), '[]'); assert.ok(ticks > 1, 'Asset work prevented monitor callbacks from running');
});

test('async extraction retains size, complete-stream, CRC and SHA rejection before returning bytes', async () => {
  const bytes = Buffer.from('private fixture contents');
  const entry = { method: 8, compressed: zlib.deflateRawSync(bytes), size: bytes.length,
    crc: crc32(bytes), sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  for (const changed of [
    { ...entry, crc: entry.crc ^ 1 }, { ...entry, sha256: '0'.repeat(64) }, { ...entry, size: 1 },
    { ...entry, compressed: entry.compressed.subarray(0, entry.compressed.length - 1) },
    { ...entry, compressed: Buffer.concat([entry.compressed, Buffer.from('hidden')]) }
  ]) await assert.rejects(inflateEntryAsync(changed));
  assert.ok((await inflateEntryAsync({ ...entry, method: 0, compressed: bytes })).equals(bytes));
  assert.equal((await inflateEntryAsync({ method: 0, compressed: Buffer.alloc(0), size: 0, crc: 0,
    sha256: crypto.createHash('sha256').digest('hex') })).length, 0);
});
