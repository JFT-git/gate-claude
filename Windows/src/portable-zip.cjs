'use strict';
// Deliberately narrow ZIP format for Guard release sidecars. There are no
// executable extractors, data descriptors, links, ZIP64 records or extra fields.
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const inflateRaw = require('node:util').promisify(zlib.inflateRaw);
const { setImmediate: yieldTurn } = require('node:timers/promises');
const asyncSHA256 = require('./async-bytes.cjs').sha256;
const LIMITS = Object.freeze({ archive: 256 * 1024 * 1024, expanded: 512 * 1024 * 1024, file: 128 * 1024 * 1024, entries: 20000, path: 240 });
const HASH = /^[a-f0-9]{64}$/;
const bad = () => Error('Invalid portable tool archive');
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, n) => { for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1; return n >>> 0; });
function crc32(data) { let value = 0xffffffff; for (const byte of data) value = CRC_TABLE[(value ^ byte) & 255] ^ (value >>> 8); return (value ^ 0xffffffff) >>> 0; }
function validateName(name) {
  if (typeof name !== 'string' || !name.length || name.length > LIMITS.path || /[^\x20-\x7e]/.test(name) || /[<>:"\\|?*]/.test(name)) throw bad();
  const parts = name.split('/');
  if (parts.some(p => !p || p === '.' || p === '..' || /[. ]$/.test(p) || /^(?:con|prn|aux|nul|conin\$|conout\$|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p))) throw bad();
  return name;
}
function validateFiles(files) {
  if (!Array.isArray(files) || files.length < 1 || files.length > LIMITS.entries) throw bad();
  const names = new Set(), fileNames = new Set(), directories = new Set(), spellings = new Map(); let expanded = 0, previous;
  for (const entry of files) {
    if (!entry || Object.keys(entry).sort().join(',') !== 'path,sha256,size' || !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > LIMITS.file || !HASH.test(entry.sha256)) throw bad();
    validateName(entry.path);
    if (previous !== undefined && previous >= entry.path) throw bad(); previous = entry.path;
    const canonical = entry.path.toLowerCase(); if (names.has(canonical)) throw bad(); names.add(canonical); fileNames.add(canonical);
    const original = entry.path.split('/');
    for (let length = 1; length <= original.length; length++) {
      const spelling = original.slice(0, length).join('/'), folded = spelling.toLowerCase();
      if (spellings.has(folded) && spellings.get(folded) !== spelling) throw bad(); spellings.set(folded, spelling);
    }
    const parts = canonical.split('/'); parts.pop(); while (parts.length) { directories.add(parts.join('/')); parts.pop(); }
    expanded += entry.size; if (expanded > LIMITS.expanded) throw bad();
  }
  for (const directory of directories) if (fileNames.has(directory)) throw bad();
  return expanded;
}
function manifestSHA256(files) { validateFiles(files); return sha256(Buffer.from(JSON.stringify(files.map(({ path, size, sha256 }) => ({ path, size, sha256 }))))); }
function parsePortableZip(bytes, files) {
  const expandedSize = validateFiles(files);
  if (!Buffer.isBuffer(bytes) || bytes.length < 22 || bytes.length > LIMITS.archive) throw bad();
  // Our producer emits no comments. Requiring the EOCD at the end also excludes
  // appended executables and ambiguous alternate central directories.
  const end = bytes.length - 22;
  if (bytes.readUInt32LE(end) !== 0x06054b50 || bytes.readUInt16LE(end + 4) || bytes.readUInt16LE(end + 6) || bytes.readUInt16LE(end + 20)) throw bad();
  const count = bytes.readUInt16LE(end + 10), centralSize = bytes.readUInt32LE(end + 12), centralOffset = bytes.readUInt32LE(end + 16);
  if (count !== files.length || bytes.readUInt16LE(end + 8) !== count || centralOffset + centralSize !== end || centralOffset > end) throw bad();
  let central = centralOffset, local = 0; const result = [];
  for (let index = 0; index < count; index++) {
    if (central + 46 > end || bytes.readUInt32LE(central) !== 0x02014b50) throw bad();
    const flags = bytes.readUInt16LE(central + 8), method = bytes.readUInt16LE(central + 10), crc = bytes.readUInt32LE(central + 16), compressedSize = bytes.readUInt32LE(central + 20), size = bytes.readUInt32LE(central + 24);
    const nameSize = bytes.readUInt16LE(central + 28), extraSize = bytes.readUInt16LE(central + 30), commentSize = bytes.readUInt16LE(central + 32), disk = bytes.readUInt16LE(central + 34), attrs = bytes.readUInt32LE(central + 38), offset = bytes.readUInt32LE(central + 42);
    // Only ASCII names with an explicit UTF-8 flag are emitted by our producer.
    // Reject Unix file types and DOS reparse/directory attributes altogether.
    if (flags !== 0x800 || ![0, 8].includes(method) || extraSize || commentSize || disk || attrs || !nameSize || compressedSize > LIMITS.archive || size > LIMITS.file || offset !== local || central + 46 + nameSize > end) throw bad();
    const nameBytes = bytes.subarray(central + 46, central + 46 + nameSize), name = nameBytes.toString('ascii'), expected = files[index];
    if (nameBytes.some(byte => byte < 0x20 || byte > 0x7e) || validateName(name) !== expected.path || size !== expected.size) throw bad();
    if (local + 30 + nameSize > centralOffset || bytes.readUInt32LE(local) !== 0x04034b50 || bytes.readUInt16LE(local + 6) !== flags || bytes.readUInt16LE(local + 8) !== method || bytes.readUInt32LE(local + 14) !== crc || bytes.readUInt32LE(local + 18) !== compressedSize || bytes.readUInt32LE(local + 22) !== size || bytes.readUInt16LE(local + 26) !== nameSize || bytes.readUInt16LE(local + 28) || !bytes.subarray(local + 30, local + 30 + nameSize).equals(nameBytes)) throw bad();
    const start = local + 30 + nameSize, stop = start + compressedSize;
    if (stop > centralOffset || method === 0 && compressedSize !== size) throw bad();
    result.push({ ...expected, method, crc, compressed: bytes.subarray(start, stop) });
    local = stop; central += 46 + nameSize;
  }
  if (central !== end || local !== centralOffset) throw bad();
  return { entries: result, expandedSize };
}
function inflateEntry(entry) {
  let data;
  if (entry.method === 0) data = Buffer.from(entry.compressed);
  else {
    const result = zlib.inflateRawSync(entry.compressed, { maxOutputLength: Math.max(1, entry.size), info: true });
    if (result.engine.bytesWritten !== entry.compressed.length) throw bad();
    data = result.buffer;
  }
  if (data.length !== entry.size || crc32(data) !== entry.crc || sha256(data) !== entry.sha256) throw bad();
  return data;
}
async function inflateEntryAsync(entry) {
  let data;
  if (entry.method === 0) data = Buffer.from(entry.compressed);
  else {
    const result = await inflateRaw(entry.compressed, { maxOutputLength: Math.max(1, entry.size), info: true });
    if (result.engine.bytesWritten !== entry.compressed.length) throw bad();
    data = result.buffer;
  }
  if (data.length !== entry.size) throw bad();
  let crc = 0xffffffff;
  for (let offset = 0; offset < data.length; offset += 262144) {
    if (data.length > 262144) await yieldTurn();
    const end = Math.min(offset + 262144, data.length);
    for (let index = offset; index < end; index++) crc = CRC_TABLE[(crc ^ data[index]) & 255] ^ (crc >>> 8);
  }
  if (((crc ^ 0xffffffff) >>> 0) !== entry.crc || await asyncSHA256(data) !== entry.sha256) throw bad();
  return data;
}
// The release builder streams these pieces to a new file. No platform metadata,
// local timestamps, permission bits or random data enter the archive bytes.
function zipEntry(name, data, offset) {
  validateName(name);
  if (!Buffer.isBuffer(data) || data.length > LIMITS.file || !Number.isSafeInteger(offset) || offset < 0 || offset > LIMITS.archive) throw bad();
  const nameBytes = Buffer.from(name, 'ascii'), compressed = zlib.deflateRawSync(data, { level: 6 }), crc = crc32(data);
  const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x800, 6); local.writeUInt16LE(8, 8); local.writeUInt16LE(33, 12); local.writeUInt32LE(crc, 14); local.writeUInt32LE(compressed.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0x800, 8); central.writeUInt16LE(8, 10); central.writeUInt16LE(33, 14); central.writeUInt32LE(crc, 16); central.writeUInt32LE(compressed.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(nameBytes.length, 28); central.writeUInt32LE(offset, 42);
  return { local: [local, nameBytes, compressed], central: Buffer.concat([central, nameBytes]), size: 30 + nameBytes.length + compressed.length, file: { path: name, size: data.length, sha256: sha256(data) } };
}
function zipEnd(count, centralSize, centralOffset) {
  if (!Number.isSafeInteger(count) || count < 1 || count > LIMITS.entries || !Number.isSafeInteger(centralSize) || centralSize < 1 || !Number.isSafeInteger(centralOffset) || centralOffset < 1 || centralOffset + centralSize + 22 > LIMITS.archive) throw bad();
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(count, 8); end.writeUInt16LE(count, 10); end.writeUInt32LE(centralSize, 12); end.writeUInt32LE(centralOffset, 16); return end;
}
module.exports = { LIMITS, sha256, crc32, manifestSHA256, validateName, validateFiles, parsePortableZip, inflateEntry, inflateEntryAsync, zipEntry, zipEnd };
