'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { IPMemory, MISMATCH, UNAVAILABLE } = require('../src/ip-memory.cjs');
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-ip-memory-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return new IPMemory(root);
}
test('only the first committed IP survives a separate process, attempts to replace it and restart', t => {
  const memory = fixture(t); assert.equal(memory.load(), null);
  memory.commit('203.0.113.7');
  const before = fs.readFileSync(memory.file, 'utf8');
  const child = spawnSync(process.execPath, ['-e', `const {IPMemory}=require(process.argv[1]); const m=new IPMemory(process.argv[2]); console.log(m.load()); try {m.commit('203.0.113.8'); process.exit(2)} catch {} console.log(m.load())`, require.resolve('../src/ip-memory.cjs'), path.dirname(memory.file)], { encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr); assert.equal(child.stdout.trim(), '203.0.113.7\n203.0.113.7');
  assert.equal(memory.commit('203.0.113.7'), '203.0.113.7');
  assert.throws(() => memory.check('203.0.113.8'), { message: MISMATCH });
  assert.equal(fs.readFileSync(memory.file, 'utf8'), before);
  if (process.platform !== 'win32') assert.equal(fs.statSync(memory.file).mode & 0o777, 0o600);
});
test('equivalent IPv6 is accepted; another IPv6 or IP family cannot replace the pin', t => {
  const memory = fixture(t); memory.commit('2001:db8:0:0::7');
  assert.equal(memory.check('2001:db8::7'), '2001:db8::7');
  for (const value of ['2001:db8::8', '203.0.113.7']) assert.throws(() => memory.commit(value), { message: MISMATCH });
});
test('only an explicit reset permits a later new address and writes an unpinned record', t => {
  const memory = fixture(t); memory.commit('203.0.113.7'); memory.reset();
  assert.deepEqual(JSON.parse(fs.readFileSync(memory.file)), { version: 1, pinnedIP: null });
  assert.equal(new IPMemory(path.dirname(memory.file)).commit('203.0.113.8'), '203.0.113.8');
});
for (const value of ['', '{bad', '{"version":2,"pinnedIP":"203.0.113.7"}', '{"version":1}', '{"version":1,"pinnedIP":"bad"}', '{"version":1,"pinnedIP":"fe80::1%en0"}', '{"version":1,"pinnedIP":null,"extra":true}', 'x'.repeat(4097)]) {
  test('invalid memory fails closed without silently replacing the saved contents (' + value.slice(0, 40) + ')', t => {
    const memory = fixture(t); fs.writeFileSync(memory.file, value);
    assert.throws(() => memory.load(), { message: UNAVAILABLE });
    assert.throws(() => memory.commit('203.0.113.7'), { message: UNAVAILABLE });
    assert.equal(fs.readFileSync(memory.file, 'utf8'), value);
    memory.reset(); assert.equal(memory.load(), null);
  });
}
test('unpublished interrupted writes cannot replace a confirmed IP', t => {
  const memory = fixture(t); memory.commit('203.0.113.7');
  fs.writeFileSync(memory.file + '.interrupted.tmp', '{"version":1,"pinnedIP":"203.0.113.8"}');
  assert.equal(memory.load(), '203.0.113.7');
});
test('directories, symlinks and hardlinks are refused without touching their targets', t => {
  const memory = fixture(t), target = path.join(path.dirname(memory.file), 'target.json');
  fs.writeFileSync(target, '{"version":1,"pinnedIP":"203.0.113.7"}');
  for (const kind of ['directory', ...(process.platform === 'win32' ? [] : ['symlink', 'hardlink'])]) {
    if (kind === 'directory') fs.mkdirSync(memory.file);
    else if (kind === 'symlink') fs.symlinkSync(target, memory.file);
    else fs.linkSync(target, memory.file);
    assert.throws(() => memory.load(), { message: UNAVAILABLE });
    assert.throws(() => memory.reset(), { message: UNAVAILABLE });
    fs.rmSync(memory.file, { recursive: true });
    assert.equal(JSON.parse(fs.readFileSync(target)).pinnedIP, '203.0.113.7');
  }
});
test('an unwritable storage path cannot report a committed pin', t => {
  const memory = fixture(t); const file = path.join(path.dirname(memory.file), 'regular'); fs.writeFileSync(file, 'unchanged');
  const broken = new IPMemory(file); assert.throws(() => broken.commit('203.0.113.7'), { message: UNAVAILABLE });
  assert.equal(fs.readFileSync(file, 'utf8'), 'unchanged');
});
