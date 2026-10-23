'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createPreparationProgress, TOOL_IDS, STAGES } = require('../src/preparation-progress.cjs');
const { prepareCodeFiles, SOURCE_POLICY: CODE_POLICY } = require('../src/code-preparation.cjs');
const { prepareCodeTools, SOURCE_POLICY: TOOLS_POLICY } = require('../src/code-tools.cjs');
const { sha256, manifestSHA256, zipEntry, zipEnd } = require('../src/portable-zip.cjs');
const denied = /Не удалось безопасно подготовить/;
const sid = 'S-1-15-2-1-2-3-4-5-6-7';

function checkEvents(events) {
  let elapsed = 0, previous;
  assert.ok(events.length > 0);
  for (const event of events) {
    assert.deepEqual(Object.keys(event).sort(), ['done', 'elapsedMS', 'stage', 'toolId', 'total']);
    assert.ok(Object.isFrozen(event)); assert.ok(TOOL_IDS.includes(event.toolId)); assert.ok(STAGES.includes(event.stage));
    assert.ok(Number.isSafeInteger(event.done) && event.done >= 0 && event.done <= event.total);
    assert.ok(Number.isSafeInteger(event.total) && event.total > 0); assert.ok(Number.isSafeInteger(event.elapsedMS) && event.elapsedMS >= elapsed);
    if (previous?.toolId === event.toolId && previous.stage === event.stage) { assert.equal(event.total, previous.total); assert.ok(event.done >= previous.done); }
    elapsed = event.elapsedMS; previous = event;
  }
}
function phaseStarts(events) { return events.filter(event => event.done === 0).map(event => `${event.toolId}:${event.stage}`); }
function ownedRoot(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gate-preparation-progress-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true })); return root;
}
function pe() {
  const bytes = Buffer.alloc(1024); bytes.writeUInt16LE(0x5a4d); bytes.writeUInt32LE(128, 0x3c); bytes.writeUInt32LE(0x4550, 128);
  bytes.writeUInt16LE(0x8664, 132); bytes.writeUInt16LE(1, 134); bytes.writeUInt16LE(0x20b, 152); return bytes;
}
function codeFixture(t) {
  const root = ownedRoot(t), sourceRoot = path.join(root, 'Source'), guardRoot = path.join(root, 'Guard'), resources = path.join(root, 'Resources');
  fs.mkdirSync(path.join(sourceRoot, 'resources', 'preseed', 'claude-code'), { recursive: true }); fs.mkdirSync(guardRoot); fs.mkdirSync(resources);
  const sourcePath = path.join(sourceRoot, 'claude.exe'), runtime = { signature: 'Valid', version: CODE_POLICY.desktopVersion, executable: path.join(guardRoot, 'claude.exe') };
  for (const name of [sourcePath, runtime.executable, path.join(resources, 'CodeHost.exe')]) fs.writeFileSync(name, pe());
  fs.writeFileSync(path.join(sourceRoot, 'resources', 'app.asar'), 'owned-archive');
  const compressed = Buffer.from('owned-compressed'), compressedPath = path.join(sourceRoot, 'resources', 'preseed', 'claude-code', 'win32-x64.zst'); fs.writeFileSync(compressedPath, compressed);
  const sourcePolicy = { ...CODE_POLICY, compressedSize: compressed.length, compressedSHA256: sha256(compressed), executableSize: pe().length, executableSHA256: sha256(pe()) }, calls = [];
  const deps = { platform: 'win32', arch: 'x64', sourcePolicy, inspectSource: async bytes => { assert.equal(bytes.toString(), 'owned-archive'); }, decompress: async () => pe(),
    runFile: async (host, argv) => { calls.push(argv); return { stdout: JSON.stringify({ sid }) }; } };
  return { guardRoot, compressedPath, calls, prepare: (options, extra = {}) => prepareCodeFiles(runtime, sourcePath, guardRoot, resources, { ...deps, ...extra }, undefined, options) };
}
function archive(entries) {
  const local = [], central = [], files = []; let offset = 0;
  for (const [name, text] of entries.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
    const entry = zipEntry(name, Buffer.from(text), offset); local.push(...entry.local); central.push(entry.central); files.push(entry.file); offset += entry.size;
  }
  const directory = Buffer.concat(central), bytes = Buffer.concat([...local, directory, zipEnd(files.length, directory.length, offset)]);
  return { bytes, files, archiveSHA256: sha256(bytes), archiveSize: bytes.length, expandedSize: files.reduce((sum, file) => sum + file.size, 0) };
}
function toolsFixture(t) {
  const root = ownedRoot(t), resources = path.join(root, 'Resources'), guardRoot = path.join(root, 'Guard'), systemRoot = path.join(root, 'Windows');
  fs.mkdirSync(path.join(resources, 'CodeTools'), { recursive: true }); fs.mkdirSync(guardRoot); fs.mkdirSync(path.join(systemRoot, 'System32'), { recursive: true });
  const entries = { git: [['bin/bash.exe', 'bash'], ['cmd/git.exe', 'git'], ['usr/bin/bash.exe', 'msys-bash']],
    powershell: [['Guard.PowerShell.ps1', 'prelude'], ['Guard.PowerShell.pssc', 'config'], ['GuardPwsh.exe', 'apphost'], ['powershell.exe', 'launcher'], ['pwsh.exe', 'launcher']] };
  const sourcePolicy = {}, policy = { schemaVersion: 1, platform: 'win32-x64', tools: [] }, archives = {};
  for (const id of ['git', 'powershell']) {
    const { bytes, files, ...zip } = archive(entries[id]), source = TOOLS_POLICY[id];
    sourcePolicy[id] = { ...source, treeSHA256: manifestSHA256(files), anchors: Object.fromEntries(files.map(file => [file.path, file.sha256])) };
    policy.tools.push({ id, version: source.version, archiveName: source.archiveName, ...zip, files, source: { name: source.sourceName, size: source.sourceSize, sha256: source.sourceSHA256 } });
    const destination = path.join(resources, 'CodeTools', source.archiveName); fs.writeFileSync(destination, bytes); archives[id === 'git' ? 'gitArchive' : 'powerShellArchive'] = destination;
  }
  fs.writeFileSync(path.join(resources, 'code-tools-policy.json'), JSON.stringify(policy));
  const deps = { platform: 'win32', arch: 'x64', sourcePolicy, environment: { SystemRoot: systemRoot } };
  return { guardRoot, archives, policy, prepare: options => prepareCodeTools(guardRoot, resources, archives, deps, options) };
}

test('preparation progress throttles counts, forces stage/completion and keeps monotonic scalar records', () => {
  let clock = 1000; const events = [], progress = createPreparationProgress({ onProgress: event => events.push(event) }, { now: () => clock });
  progress.begin('git', 'extract', 4); clock += 10; progress.update(1); clock += 240; progress.update(2); clock -= 100; progress.update(1); progress.update(3); clock += 101; progress.complete();
  progress.begin('git', 'staging-verify', 4); progress.update(4); progress.begin('private/path', 'extract', 1); progress.begin('git', 'private-stage', 1);
  checkEvents(events);
  assert.deepEqual(events.map(({ stage, done, elapsedMS }) => [stage, done, elapsedMS]), [['extract', 0, 0], ['extract', 2, 250], ['extract', 4, 251], ['staging-verify', 0, 251], ['staging-verify', 4, 251]]);
  assert.throws(() => { events[0].toolId = 'private'; }, TypeError);
});

test('observer throws, rejected promises and pending promises do not control progress or require awaiting', async () => {
  for (const observer of [() => { throw Error('observer-private'); }, () => Promise.reject(Error('observer-private')), () => new Promise(() => {})]) {
    const progress = createPreparationProgress({ onProgress: observer }); progress.begin('git', 'extract', 2); progress.complete();
  }
  const options = Object.defineProperty({}, 'onProgress', { get() { throw Error('observer-private'); } });
  assert.doesNotThrow(() => { const progress = createPreparationProgress(options); progress.begin('git', 'extract', 2); progress.complete(); });
  await new Promise(resolve => setImmediate(resolve));
});

test('Code reports cold and warm verification separately, exposes no paths and finishes after the valid profile response', async t => {
  const f = codeFixture(t), events = [];
  const first = await f.prepare({ onProgress: event => { events.push(event); event.done = 999; } }); checkEvents(events);
  assert.deepEqual(phaseStarts(events), ['source-verify', 'host-verify', 'asset-verify', 'decompress', 'executable-verify', 'publish', 'target-verify', 'profile-create', 'ready'].map(stage => 'claude-code:' + stage));
  assert.equal(events.at(-1).stage, 'ready'); assert.equal(events.at(-1).done, 1); assert.equal(f.calls.length, 1);
  const warm = []; const second = await f.prepare({ onProgress: event => warm.push(event) }); checkEvents(warm);
  assert.ok(phaseStarts(warm).includes('claude-code:cache-verify')); assert.ok(!phaseStarts(warm).includes('claude-code:publish'));
  assert.equal(second.approved[0].path, first.approved[0].path); await first.cleanupProfile(); await second.cleanupProfile();
});

test('throwing Code observer cannot accept an unverified asset or create output/profile', async t => {
  const f = codeFixture(t), events = []; fs.writeFileSync(f.compressedPath, 'wrong-compressed');
  await assert.rejects(f.prepare({ onProgress: event => { events.push(event); throw Error('observer-private'); } }), denied);
  assert.equal(f.calls.length, 0); assert.equal(fs.existsSync(path.join(f.guardRoot, 'CodeBin')), false);
  assert.ok(!events.some(event => event.stage === 'ready' || event.stage === 'asset-verify' && event.done === event.total));
});

test('async observer rejection cannot turn an invalid profile response into a ready event or prevent cleanup', async t => {
  const f = codeFixture(t), events = [], calls = [];
  await assert.rejects(f.prepare({ onProgress: event => { events.push(event); return Promise.reject(Error('observer-private')); } }, {
    runFile: async (host, argv) => { calls.push(argv); return { stdout: JSON.stringify({ sid: 'private-invalid' }) }; }
  }), denied);
  assert.deepEqual(calls.map(argv => argv[0]), ['--create-profile', '--delete-profile']);
  assert.ok(!events.some(event => event.stage === 'ready' || event.stage === 'profile-create' && event.done === event.total));
});

test('tools report authenticated extraction, both complete tree checks and warm-cache file counts', async t => {
  const f = toolsFixture(t), events = [], result = await f.prepare({ onProgress: event => events.push(event) }); checkEvents(events);
  for (const tool of f.policy.tools) {
    const phases = phaseStarts(events).filter(value => value.startsWith(tool.id + ':'));
    assert.deepEqual(phases, ['archive-read', 'archive-verify', 'archive-index', 'extract', 'staging-verify', 'publish', 'target-verify'].map(stage => tool.id + ':' + stage));
    for (const stage of ['extract', 'staging-verify', 'target-verify']) {
      const phase = events.filter(event => event.toolId === tool.id && event.stage === stage); assert.equal(phase[0].done, 0); assert.equal(phase.at(-1).done, tool.files.length); assert.equal(phase.at(-1).total, tool.files.length);
    }
  }
  assert.equal(events.at(-1).toolId, 'tools'); assert.equal(events.at(-1).stage, 'ready');
  const warm = []; const again = await f.prepare({ onProgress: event => { warm.push(event); return new Promise(() => {}); } }); checkEvents(warm);
  assert.deepEqual(again.toolRoots, result.toolRoots); assert.ok(!warm.some(event => event.stage === 'extract'));
  for (const tool of f.policy.tools) assert.equal(warm.findLast(event => event.toolId === tool.id && event.stage === 'cache-verify').done, tool.files.length);
});

test('throwing tools observer cannot accept a corrupt archive or create a tools tree', async t => {
  const f = toolsFixture(t), bytes = fs.readFileSync(f.archives.powerShellArchive), events = []; bytes[0] ^= 255; fs.writeFileSync(f.archives.powerShellArchive, bytes);
  await assert.rejects(f.prepare({ onProgress: event => { events.push(event); throw Error('observer-private'); } }), denied);
  assert.equal(fs.existsSync(path.join(f.guardRoot, 'CodeTools')), false); assert.ok(!events.some(event => event.stage === 'ready'));
  assert.ok(!events.some(event => event.toolId === 'powershell' && event.stage === 'archive-verify' && event.done === event.total));
});

test('all expected file hashes alone cannot emit a complete tree check when an unexpected directory remains', async t => {
  const f = toolsFixture(t), result = await f.prepare(), events = []; fs.mkdirSync(path.join(result.gitRoot, 'zzz-unexpected'));
  await assert.rejects(f.prepare({ onProgress: event => { events.push(event); throw Error('observer-private'); } }), denied);
  assert.ok(events.some(event => event.toolId === 'git' && event.stage === 'cache-verify' && event.done === 0));
  assert.ok(!events.some(event => event.toolId === 'git' && event.stage === 'cache-verify' && event.done === event.total));
  assert.ok(!events.some(event => event.stage === 'ready')); assert.ok(fs.existsSync(path.join(result.gitRoot, 'zzz-unexpected')));
});
