'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { LIMITS, sha256, crc32, validateName, validateFiles, zipEntry, zipEnd, parsePortableZip, inflateEntry } = require('../src/portable-zip.cjs');
function archive(input = [['dir/a.txt', Buffer.from('fixture-alpha')], ['empty.txt', Buffer.alloc(0)]]) {
  const local = [], central = [], files = []; let offset = 0;
  for (const [name, bytes] of input) { const entry = zipEntry(name, bytes, offset); local.push(...entry.local); central.push(entry.central); files.push(entry.file); offset += entry.size; }
  const directory = Buffer.concat(central); return { bytes: Buffer.concat([...local, directory, zipEnd(files.length, directory.length, offset)]), files, centralOffset: offset };
}
test('deterministic narrow ZIP round-trips deflate and empty files with independent CRC/SHA checks', () => {
  const first = archive(), second = archive(); assert.ok(first.bytes.equals(second.bytes));
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
  const parsed = parsePortableZip(first.bytes, first.files); assert.equal(parsed.expandedSize, 13); assert.deepEqual(parsed.entries.map(entry => inflateEntry(entry)), [Buffer.from('fixture-alpha'), Buffer.alloc(0)]);
});
test('Windows traversal, alternate streams, device names, aliases and ambiguous paths are refused', () => {
  for (const name of ['', '../escape', '/root', 'C:/root', 'dir/../file', './file', 'dir//file', 'dir/', 'dir\\file', 'file:stream', 'file ', 'file.', 'a/CON', 'a/nul.txt', 'COM1.exe', 'lpt9', 'CONIN$', 'dir/conout$.txt', 'a\u0000b', 'caf\u00e9.txt', 'a?b', 'a|b', 'a<b']) assert.throws(() => validateName(name), /Invalid portable/);
  assert.equal(validateName('Modules/Example/Example.psd1'), 'Modules/Example/Example.psd1'); assert.equal(validateName('.gitconfig'), '.gitconfig');
  const file = name => ({ path: name, size: 0, sha256: sha256(Buffer.alloc(0)) });
  for (const files of [[file('A'), file('a')], [file('A/one'), file('a/two')], [file('dir'), file('dir/file')], [file('z'), file('a')], [{ ...file('file'), ignored: true }], [{ ...file('file'), size: LIMITS.file + 1 }]]) assert.throws(() => validateFiles(files), /Invalid portable/);
});
test('ZIP refuses symlinks, reparse attributes, encryption, descriptors, extra fields and multi-disk input', () => {
  const original = archive();
  const mutations = [
    bytes => bytes.writeUInt32LE(0xa1ff0000, original.centralOffset + 38),
    bytes => bytes.writeUInt32LE(0x400, original.centralOffset + 38),
    bytes => bytes.writeUInt16LE(0x801, original.centralOffset + 8),
    bytes => bytes.writeUInt16LE(0x808, original.centralOffset + 8),
    bytes => bytes.writeUInt16LE(1, original.centralOffset + 30),
    bytes => bytes.writeUInt16LE(1, bytes.length - 18),
    bytes => bytes.writeUInt16LE(1, original.centralOffset + 34),
    bytes => bytes.writeUInt16LE(0xffff, bytes.length - 12)
  ];
  for (const mutate of mutations) { const bytes = Buffer.from(original.bytes); mutate(bytes); assert.throws(() => parsePortableZip(bytes, original.files), /Invalid portable/); }
});
test('ZIP refuses local/central disagreements, overlaps, orphan bytes, alternate directories and oversized declarations', () => {
  const original = archive();
  const mutations = [
    bytes => bytes.writeUInt32LE(1, original.centralOffset + 42),
    bytes => bytes.writeUInt16LE(0, 6),
    bytes => bytes.writeUInt16LE(0, 8),
    bytes => bytes.writeUInt32LE(0, 14),
    bytes => bytes.writeUInt16LE(1, 28),
    bytes => { bytes[30] = 'x'.charCodeAt(0); },
    bytes => bytes.writeUInt32LE(LIMITS.archive + 1, original.centralOffset + 20),
    bytes => bytes.writeUInt32LE(0, bytes.length - 6)
  ];
  for (const mutate of mutations) { const bytes = Buffer.from(original.bytes); mutate(bytes); assert.throws(() => parsePortableZip(bytes, original.files), /Invalid portable/); }
  assert.throws(() => parsePortableZip(Buffer.concat([original.bytes, Buffer.from('appended')]), original.files), /Invalid portable/);
  assert.throws(() => parsePortableZip(original.bytes.subarray(1), original.files), /Invalid portable/);
});
test('a corrupt, substituted, truncated or overproducing compressed stream never supplies file bytes', () => {
  const fixture = archive(), entry = parsePortableZip(fixture.bytes, fixture.files).entries[0];
  for (const changed of [
    { ...entry, sha256: '0'.repeat(64) }, { ...entry, crc: entry.crc ^ 1 }, { ...entry, size: 1 },
    { ...entry, compressed: entry.compressed.subarray(0, entry.compressed.length - 1) },
    { ...entry, compressed: Buffer.concat([entry.compressed, Buffer.from('hidden')]) }
  ]) assert.throws(() => inflateEntry(changed));
});
module.exports = { archive };
