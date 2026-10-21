"use strict";
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { prepareCodeFiles, SOURCE_POLICY, MAX_CLI_BYTES, validatePE } = require('../src/code-preparation.cjs');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const SID = 'S-1-15-2-1-2-3-4-5-6-7';
function pe() { const bytes = Buffer.alloc(1024); bytes.writeUInt16LE(0x5a4d); bytes.writeUInt32LE(128, 0x3c); bytes.writeUInt32LE(0x4550, 128); bytes.writeUInt16LE(0x8664, 132); bytes.writeUInt16LE(1, 134); bytes.writeUInt16LE(0x20b, 152); return bytes; }
async function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gate-code-prep-'))); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const sourceDir = path.join(root, 'Source'), resources = path.join(root, 'GuardResources'), guardRoot = path.join(root, 'Guard'), runtimeDirectory = path.join(guardRoot, 'Runtime-fixture');
  fs.mkdirSync(path.join(sourceDir, 'resources', 'preseed', 'claude-code'), { recursive: true }); fs.mkdirSync(resources); fs.mkdirSync(runtimeDirectory, { recursive: true });
  const sourcePath = path.join(sourceDir, 'claude.exe'), runtime = { signature: 'Valid', version: SOURCE_POLICY.desktopVersion, executable: path.join(runtimeDirectory, 'claude.exe') };
  fs.writeFileSync(sourcePath, pe()); fs.writeFileSync(runtime.executable, pe()); fs.writeFileSync(path.join(resources, 'CodeHost.exe'), pe()); fs.writeFileSync(path.join(sourceDir, 'resources', 'app.asar'), 'owned-archive-fixture');
  const compressed = Buffer.from('owned-compressed-fixture'), compressedPath = path.join(sourceDir, 'resources', 'preseed', 'claude-code', 'win32-x64.zst'); fs.writeFileSync(compressedPath, compressed);
  const calls = [], counts = { inspect: 0, decompress: 0 }, policy = { ...SOURCE_POLICY, compressedSize: compressed.length, compressedSHA256: sha(compressed), executableSize: pe().length, executableSHA256: sha(pe()) };
  const deps = { platform: 'win32', arch: 'x64', sourcePolicy: policy, inspectSource: async (bytes, checkedPolicy) => { counts.inspect++; assert.equal(bytes.toString(), 'owned-archive-fixture'); assert.equal(checkedPolicy, policy); },
    decompress: (bytes, options) => { counts.decompress++; assert.equal(bytes.toString(), compressed.toString()); assert.equal(options.maxOutputLength, MAX_CLI_BYTES); return pe(); },
    runFile: async (...args) => { calls.push(args); return { stdout: JSON.stringify({ sid: SID }) }; } };
  return { root, sourcePath, resources, guardRoot, runtime, deps, calls, counts, compressedPath, policy, prepare: extra => prepareCodeFiles(runtime, sourcePath, guardRoot, resources, { ...deps, ...extra }) };
}

test('production source policy pins signed Desktop, original SDK/main, compressed size and complete checksum', () => {
  assert.ok(Object.isFrozen(SOURCE_POLICY)); assert.equal(SOURCE_POLICY.desktopVersion, '3.1623.0'); assert.equal(SOURCE_POLICY.codeVersion, '2.1.304'); assert.equal(SOURCE_POLICY.compressedSize, 104965652); assert.equal(SOURCE_POLICY.compressedSHA256, 'aed62990b91e94efb35482fd7068cc616c6c2414084c6aa32148ca2a359e4e81'); assert.equal(SOURCE_POLICY.sdkSHA256, require('../src/managed-cli-patch.cjs').SDK_SHA256); assert.equal(SOURCE_POLICY.mainSHA256, '403a7d93388a723d2c0688cea83861ecfbe7e08caa63c6701bcd49684100c348');
});
test('prepares one hash-addressed native CLI, persistent workspace and exact vendor request mapping', async t => {
  const f = await fixture(t), code = await f.prepare(), executableSHA = sha(pe());
  assert.equal(code.approved[0].path, path.join(f.guardRoot, 'CodeBin', executableSHA, 'claude.exe')); assert.equal(code.approved[0].sha256, executableSHA); assert.equal(sha(fs.readFileSync(code.approved[0].path)), executableSHA);
  assert.equal(code.approved[0].requestedPath, path.join(f.guardRoot, 'Profile', 'claude-code', '2.1.304', f.policy.compressedSHA256.slice(0, 12), 'claude.exe')); assert.equal(code.workspaceRoot, path.join(f.guardRoot, 'CodeState', 'Workspace')); assert.equal(code.containerSid, SID); assert.match(code.containerName, /^gate-code-[a-f0-9]{24}$/); assert.equal(code.runtimeExecutable, f.runtime.executable);
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0][0], path.join(f.resources, 'CodeHost.exe')); assert.deepEqual(f.calls[0][1], ['--create-profile', code.containerName]); assert.equal(f.calls[0][2].windowsHide, true);
  const manifest = JSON.parse(fs.readFileSync(path.join(path.dirname(code.approved[0].path), 'guard-code-manifest.json'))); const { manifestSHA256, ...payload } = manifest; assert.equal(manifestSHA256, sha(Buffer.from(JSON.stringify(payload))));
  assert.equal(f.counts.inspect, 1); assert.equal(f.counts.decompress, 1); await code.cleanupProfile(); await code.cleanupProfile(); assert.equal(f.calls.length, 2); assert.deepEqual(f.calls[1][1], ['--delete-profile', code.containerName]);
});
test('reuse verifies bytes against trusted decompression and preserves all existing workspace files', async t => {
  const f = await fixture(t), first = await f.prepare(); fs.writeFileSync(path.join(first.workspaceRoot, 'project.txt'), 'persistent-owned-fixture'); const before = fs.statSync(first.approved[0].path).mtimeMs;
  const second = await f.prepare(); assert.equal(second.approved[0].path, first.approved[0].path); assert.equal(fs.statSync(second.approved[0].path).mtimeMs, before); assert.equal(fs.readFileSync(path.join(second.workspaceRoot, 'project.txt'), 'utf8'), 'persistent-owned-fixture'); assert.equal(f.counts.decompress, 2);
});
test('a writable cached CLI or manifest cannot substitute new trusted content and is not silently replaced', async t => {
  const f = await fixture(t), first = await f.prepare(), tampered = pe(); tampered[700] = 99; fs.writeFileSync(first.approved[0].path, tampered);
  await assert.rejects(f.prepare(), /Не удалось безопасно/); assert.ok(fs.readFileSync(first.approved[0].path).equals(tampered)); assert.equal(f.calls.length, 1);
});
test('invalid signatures or releases and unknown source archives fail before decompression, native calls or CodeBin creation', async t => {
  const f = await fixture(t); for (const signature of ['UnknownError', 'NotSigned', 'unavailable']) { f.runtime.signature = signature; await assert.rejects(f.prepare(), /Не удалось безопасно/); }
  f.runtime.signature = 'Valid'; f.runtime.version = 'future-version'; await assert.rejects(f.prepare(), /Не удалось безопасно/); f.runtime.version = SOURCE_POLICY.desktopVersion;
  await assert.rejects(f.prepare({ inspectSource: async () => { throw Error('Unsupported fixture source'); } }), /Не удалось безопасно/); assert.equal(f.counts.decompress, 0); assert.equal(f.calls.length, 0); assert.equal(fs.existsSync(path.join(f.guardRoot, 'CodeBin')), false);
});
test('compressed checksum and bounded native PE output are checked before any launch', async t => {
  const f = await fixture(t); fs.writeFileSync(f.compressedPath, Buffer.alloc(f.policy.compressedSize, 1)); await assert.rejects(f.prepare(), /Не удалось безопасно/); assert.equal(f.counts.decompress, 0); assert.equal(f.calls.length, 0);
});
test('invalid decompressed binaries and missing broker fail without a process or persistent workspace changes', async t => {
  const f = await fixture(t); await assert.rejects(f.prepare({ decompress: () => Buffer.from('not a PE') }), /Не удалось безопасно/); assert.equal(f.calls.length, 0); assert.equal(fs.existsSync(path.join(f.guardRoot, 'CodeState')), false);
  fs.unlinkSync(path.join(f.resources, 'CodeHost.exe')); await assert.rejects(f.prepare(), /Не удалось безопасно/); assert.equal(f.counts.decompress, 0);
});
test('hard-linked source files and symlinked output directories are rejected rather than followed', async t => {
  const f = await fixture(t); fs.linkSync(f.compressedPath, path.join(f.root, 'compressed-link')); await assert.rejects(f.prepare(), /Не удалось безопасно/); assert.equal(f.counts.decompress, 0);
  fs.unlinkSync(path.join(f.root, 'compressed-link')); const outside = path.join(f.root, 'Outside'); fs.mkdirSync(outside); fs.symlinkSync(outside, path.join(f.guardRoot, 'CodeState'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(f.prepare(), /Не удалось безопасно/); assert.equal(fs.existsSync(path.join(outside, 'Workspace')), false); assert.equal(f.calls.length, 0);
});
test('malformed profile responses clean up only the newly requested random profile and disclose no raw errors', async t => {
  const f = await fixture(t), calls = [];
  await assert.rejects(f.prepare({ runFile: async (host, argv) => { calls.push(argv); return { stdout: JSON.stringify({ sid: 'fixture-private-invalid' }) }; } }), error => /Не удалось безопасно/.test(error.message) && !error.message.includes('fixture-private'));
  assert.equal(calls.length, 2); assert.equal(calls[0][0], '--create-profile'); assert.equal(calls[1][0], '--delete-profile'); assert.equal(calls[1][1], calls[0][1]);
});
test('a native creation failure still attempts bounded cleanup of its own generated profile', async t => {
  const f = await fixture(t), calls = []; await assert.rejects(f.prepare({ runFile: async (host, argv) => { calls.push(argv); if (argv[0] === '--create-profile') throw Error('fixture-private-native-error'); return { stdout: '' }; } }), error => !error.message.includes('fixture-private'));
  assert.equal(calls.length, 2); assert.deepEqual(calls[1], ['--delete-profile', calls[0][1]]);
});
test('PE validation refuses nonnative, malformed or incompatible images', () => {
  for (const value of [null, Buffer.from('MZ'), Buffer.alloc(300), (() => { const b = pe(); b.writeUInt16LE(0x14c, 132); return b; })(), (() => { const b = pe(); b.writeUInt32LE(0xffffff00, 0x3c); return b; })()]) assert.throws(() => validatePE(value), /Не удалось безопасно/);
  assert.equal(validatePE(pe()).length, 1024);
});

test('Store packages without optional preseed use only the complete hash-pinned trusted NativeCode sidecar', async t => {
  const f = await fixture(t), sidecar = path.join(f.resources, 'NativeCode', 'win32-x64.zst');
  fs.mkdirSync(path.dirname(sidecar)); fs.renameSync(f.compressedPath, sidecar);
  const code = await f.prepare(); assert.equal(sha(fs.readFileSync(code.approved[0].path)), sha(pe()));
  assert.equal(f.counts.decompress, 1); assert.equal(f.calls.length, 1);
});
test('absent, substituted and linked sidecars cannot fall back to writable Profile CLI', async t => {
  const f = await fixture(t); fs.unlinkSync(f.compressedPath);
  const untrusted = path.join(f.guardRoot, 'Profile', 'claude-code', SOURCE_POLICY.codeVersion, 'claude.exe');
  fs.mkdirSync(path.dirname(untrusted), { recursive: true }); fs.writeFileSync(untrusted, pe());
  await assert.rejects(f.prepare(), /Не удалось безопасно/);
  const sidecar = path.join(f.resources, 'NativeCode', 'win32-x64.zst'); fs.mkdirSync(path.dirname(sidecar)); fs.writeFileSync(sidecar, Buffer.alloc(f.policy.compressedSize, 1));
  await assert.rejects(f.prepare(), /Не удалось безопасно/); fs.writeFileSync(sidecar, 'owned-compressed-fixture'); fs.linkSync(sidecar, path.join(f.root, 'sidecar-link'));
  await assert.rejects(f.prepare(), /Не удалось безопасно/); assert.equal(f.counts.decompress, 0); assert.equal(f.calls.length, 0);
});
test('a present but invalid vendor preseed is rejected even when a valid sidecar is available', async t => {
  const f = await fixture(t), sidecar = path.join(f.resources, 'NativeCode', 'win32-x64.zst');
  fs.mkdirSync(path.dirname(sidecar)); fs.copyFileSync(f.compressedPath, sidecar); fs.writeFileSync(f.compressedPath, Buffer.alloc(f.policy.compressedSize, 1));
  await assert.rejects(f.prepare(), /Не удалось безопасно/); assert.equal(f.counts.decompress, 0); assert.equal(f.calls.length, 0);
});

test('an explicit downloaded asset is accepted only at the fixed hash path and is reverified before decompression', async t => {
  const f = await fixture(t), fixed = path.join(f.guardRoot, 'CodeAssets', f.policy.compressedSHA256, f.policy.platform + '.zst');
  fs.mkdirSync(path.dirname(fixed), { recursive: true }); fs.copyFileSync(f.compressedPath, fixed);
  const prepare = assets => prepareCodeFiles(f.runtime, f.sourcePath, f.guardRoot, f.resources, f.deps, assets);
  await assert.rejects(prepare({ nativeAssetPath: f.compressedPath }), /Не удалось безопасно/);
  await assert.rejects(prepare({ nativeAssetPath: fixed, untrusted: true }), /Не удалось безопасно/);
  const code = await prepare({ nativeAssetPath: fixed }); assert.equal(sha(fs.readFileSync(code.approved[0].path)), sha(pe()));
  fs.writeFileSync(fixed, Buffer.alloc(f.policy.compressedSize, 1)); await assert.rejects(prepare({ nativeAssetPath: fixed }), /Не удалось безопасно/);
  assert.equal(f.counts.decompress, 1); assert.equal(f.calls.length, 1);
});

test('the decompressed executable must also match its independent complete release pin', async t => {
  const f = await fixture(t), different = pe(); different[700] = 17;
  await assert.rejects(f.prepare({ decompress: () => different }), /Не удалось безопасно/);
  assert.equal(f.calls.length, 0); assert.equal(fs.existsSync(path.join(f.guardRoot, 'CodeBin')), false);
});
