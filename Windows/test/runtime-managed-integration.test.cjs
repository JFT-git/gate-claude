"use strict";
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const A = require('../src/asar.cjs');
const P = require('../src/managed-cli-patch.cjs');
const basePath = path.resolve(__dirname, '../../Resources/RuntimeBootstrap.cjs'), base = fs.readFileSync(basePath, 'utf8');
function archive(files) {
  const header = { files: {} }; let payload = Buffer.alloc(0);
  for (const [filename, bytes] of Object.entries(files)) {
    const parts = filename.split('/'); let parent = header;
    for (const part of parts.slice(0, -1)) parent = (parent.files[part] ||= { files: {} });
    parent.files[parts.at(-1)] = { offset: String(payload.length), size: bytes.length }; payload = Buffer.concat([payload, bytes]);
  }
  const raw = Buffer.from(JSON.stringify(header)), pad = (4 - raw.length % 4) % 4, prefix = Buffer.alloc(16); prefix.writeUInt32LE(4); prefix.writeUInt32LE(raw.length + pad + 8, 4); prefix.writeUInt32LE(raw.length + pad + 4, 8); prefix.writeUInt32LE(raw.length, 12); return Buffer.concat([prefix, raw, Buffer.alloc(pad), payload]);
}
function fixtureArchive() { return archive({ 'package.json': Buffer.from(JSON.stringify({ name: '@ant/desktop', version: 'fixture', main: '.vite/build/main.js' })), '.vite/build/main.js': Buffer.from('module.exports.vendorFixture=true;'), '.vite/build/index.chunk-fixture.js': Buffer.from('module.exports.queryFixture=true;'), '.vite/build/index.chunk-main-fixture.js': Buffer.from('module.exports.pluginFixture=true;'), '.vite/build/index.chunk-sessions-fixture.js': Buffer.from('module.exports.sessionsFixture=true;') }); }
function guardSection(options, code) {
  const fake = 'module.exports.installNetworkGuard=function(){events.push("guard");return {spawnCodeBroker:capability}};';
  const generated = A.windowsBootstrap(base, fake, options).toString(), start = generated.indexOf('\n{const guardModule='), end = generated.indexOf('\nconst sessions =', start);
  assert.ok(start !== -1 && end > start); const events = [], capability = () => {};
  const context = { cfg: { code }, events, capability, require: name => { assert.equal(name, './proxy-guard-managed-cli.cjs'); return { initCodeTransport: (received, spawn) => { assert.equal(received, code); assert.equal(spawn, capability); events.push('init'); } }; } };
  return { events, run: () => vm.runInNewContext(generated.slice(start, end), context), generated };
}

test('optional ASAR entries replace only the selected SDK and add its private sibling with integrity hashes', () => {
  const original = fixtureArchive(), unchanged = Buffer.from(original), sdk = Buffer.from('module.exports.protectedFixture=true;'), transport = Buffer.from('module.exports.initCodeTransport=function(){};');
  const result = A.addBootstrap(original, Buffer.from('/* bootstrap fixture */'), [{ name: '.vite/build/index.chunk-fixture.js', source: sdk }, { name: '.vite/build/proxy-guard-managed-cli.cjs', source: transport }]); const parsed = A.parseArchive(result.archive);
  assert.ok(original.equals(unchanged)); assert.ok(parsed.read('.vite/build/index.chunk-fixture.js').equals(sdk)); assert.ok(parsed.read('.vite/build/proxy-guard-managed-cli.cjs').equals(transport)); assert.equal(parsed.entry('.vite/build/proxy-guard-managed-cli.cjs').integrity.hash, A.hash(transport)); assert.match(parsed.read('.vite/build/main.js').toString(), /proxy-guard-boot/);
});
test('additional ASAR entries cannot replace the main/bootstrap or use traversals, duplicate names, aliases or packed directories', () => {
  const original = fixtureArchive(), boot = Buffer.from('own boot');
  for (const name of ['../escape.cjs', '/escape.cjs', '.vite/../escape.cjs', '.vite\\escape.cjs', '.vite//escape.cjs', '.vite/build/main.js', '.vite/build/proxy-guard-boot.cjs', '.vite/build/MAIN.JS', '.vite/build']) assert.throws(() => A.addBootstrap(original, boot, [{ name, source: Buffer.from('x') }]));
  assert.throws(() => A.addBootstrap(original, boot, [{ name: '.vite/build/one.cjs', source: Buffer.from('a') }, { name: '.vite/build/ONE.cjs', source: Buffer.from('b') }])); assert.throws(() => A.addBootstrap(original, boot, [{ name: '.vite/build/one.cjs', source: 'not a Buffer' }]));
});
test('bootstrap initializes the managed transport synchronously after the guard and before the vendor can load', () => {
  const f = guardSection({ codeEnabled: true }, { hostPath: 'fixture' }); f.run(); assert.deepEqual(f.events, ['guard', 'init']); new vm.Script(f.generated); assert.equal(fs.readFileSync(basePath, 'utf8'), base);
  const absent = guardSection({ codeEnabled: true }, undefined); absent.run(); assert.deepEqual(absent.events, ['guard']);
});
test('ordinary bootstraps never initialize Code and refuse an unexpected enabled configuration', () => {
  const ordinary = guardSection({}, undefined); ordinary.run(); assert.deepEqual(ordinary.events, ['guard']);
  const mismatch = guardSection({}, { hostPath: 'fixture' }); assert.throws(mismatch.run, /has not been prepared/); assert.deepEqual(mismatch.events, ['guard']); assert.throws(() => A.windowsBootstrap(base, '', { codeEnabled: true }), /native network guard/); assert.throws(() => A.windowsBootstrap(base, '', { codeEnabled: 'yes' }), /Неверный режим/);
});
test('the actual original ASAR receives the pinned SDK and marketplace patches with their shared sibling transport', t => {
  const filename = path.resolve(__dirname, '../../../../work/windows/source/app/resources/app.asar'); if (!fs.existsSync(filename)) return t.skip('Original vendor source cache is not distributed.');
  const original = fs.readFileSync(filename), unchangedHash = A.hash(original), parsed = A.parseArchive(original), sdk = P.findManagedCliSDK(parsed), codeMain = P.findManagedCliMain(parsed), codeSessions = P.findManagedCliSessions(parsed), own = fs.readFileSync(path.join(__dirname, '../src/managed-cli.cjs'));
  const patched = A.addBootstrap(original, A.windowsBootstrap(base, fs.readFileSync(path.join(__dirname, '../src/runtime-network-guard.cjs'), 'utf8'), { codeEnabled: true }), [{ name: sdk.filename, source: P.patchManagedCliSDK(sdk.source) }, { name: codeMain.filename, source: P.patchManagedCliMain(codeMain.source) }, { name: codeSessions.filename, source: P.patchManagedCliSessions(codeSessions.source) }, { name: '.vite/build/proxy-guard-managed-cli.cjs', source: own }]);
  const result = A.parseArchive(patched.archive); assert.equal(A.hash(original), unchangedHash); assert.ok(result.read('.vite/build/proxy-guard-managed-cli.cjs').equals(own)); assert.match(result.read(sdk.filename).toString(), /__gateCli\.spawnManaged\(e\)/); new vm.Script(result.read(sdk.filename).toString()); new vm.Script(result.read('.vite/build/proxy-guard-boot.cjs').toString());
  assert.equal(A.hash(parsed.read(codeMain.filename)), P.MAIN_SHA256); assert.ok(result.read(codeMain.filename).equals(P.patchManagedCliMain(codeMain.source))); assert.equal(result.entry(codeMain.filename).integrity.hash, A.hash(result.read(codeMain.filename))); new vm.Script(result.read(codeMain.filename).toString());
  assert.equal(A.hash(parsed.read(codeSessions.filename)), P.SESSIONS_SHA256); assert.ok(result.read(codeSessions.filename).equals(P.patchManagedCliSessions(codeSessions.source))); assert.equal(result.entry(codeSessions.filename).integrity.hash, A.hash(result.read(codeSessions.filename))); new vm.Script(result.read(codeSessions.filename).toString());
});
async function runtimeFixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gate-runtime-managed-'))); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const sourceDir = path.join(root, 'Source'), guardRoot = path.join(root, 'Guard'); fs.mkdirSync(path.join(sourceDir, 'resources'), { recursive: true }); const source = path.join(sourceDir, 'claude.exe'); fs.writeFileSync(source, 'owned-executable-fixture'); fs.writeFileSync(path.join(sourceDir, 'resources', 'app.asar'), fixtureArchive());
  let transport = Buffer.from('module.exports={initCodeTransport(){}};/* fixture-v1 */'), patchCalls = 0, selections = 0, mainPatchCalls = 0, mainSelections = 0, rejectMain = false, rejectSessions = false; const status = [];
  const asar = { ...A, updatePEIntegrity: (bytes, before, after) => Buffer.from('owned-prepared-exe-' + after) };
  const patch = { findManagedCliSDK: parsed => { selections++; return { filename: '.vite/build/index.chunk-fixture.js', source: parsed.read('.vite/build/index.chunk-fixture.js') }; }, patchManagedCliSDK: bytes => { patchCalls++; return Buffer.concat([Buffer.from('const protectedFixture=true;'), bytes]); },
    findManagedCliMain: parsed => { mainSelections++; if (rejectMain) throw Error('Unsupported fixture main'); return { filename: '.vite/build/index.chunk-main-fixture.js', source: parsed.read('.vite/build/index.chunk-main-fixture.js') }; }, patchManagedCliMain: bytes => { mainPatchCalls++; return Buffer.concat([Buffer.from('const protectedMainFixture=true;'), bytes]); },
    findManagedCliSessions: parsed => { if (rejectSessions) throw Error('Unsupported fixture sessions'); return { filename: '.vite/build/index.chunk-sessions-fixture.js', source: parsed.read('.vite/build/index.chunk-sessions-fixture.js') }; }, patchManagedCliSessions: bytes => Buffer.concat([Buffer.from('const protectedSessionsFixture=true;'), bytes]) };
  const module = { exports: {} }, realRequire = require;
  const localRequire = name => {
    if (name === './raw-fs.cjs') return { promises: fs.promises }; if (name === './asar.cjs') return asar; if (name === './managed-cli-patch.cjs') return patch;
    if (name === './windows.cjs') return { powershell: async () => { throw Error('No system calls are allowed in this fixture'); }, psQuote: value => value };
    if (name === 'node:fs') return { readFileSync: file => path.basename(file) === 'managed-cli.cjs' ? transport : Buffer.from('module.exports.installNetworkGuard=()=>({spawnCodeBroker(){}});').toString() };
    return realRequire(name);
  };
  new Function('require', 'module', 'exports', 'process', '__dirname', fs.readFileSync(path.join(__dirname, '../src/runtime.cjs'), 'utf8'))(localRequire, module, module.exports, { platform: 'darwin' }, path.resolve(__dirname, '../src'));
  return { root, guardRoot, source, status, prepare: options => module.exports.prepareRuntime(source, guardRoot, basePath, value => status.push(value), options), counters: () => ({ patchCalls, selections, mainPatchCalls, mainSelections }), setTransport: value => { transport = Buffer.from(value); }, rejectMain: () => { rejectMain = true; }, rejectSessions: () => { rejectSessions = true; } };
}
test('runtime Code preparation is explicit, has its own cache fingerprint and reuses only matching actual module bytes', async t => {
  const f = await runtimeFixture(t), originalArchive = fs.readFileSync(path.join(path.dirname(f.source), 'resources', 'app.asar')), ordinary = await f.prepare(); assert.equal(ordinary.codeEnabled, false); assert.deepEqual(f.counters(), { patchCalls: 0, selections: 0, mainPatchCalls: 0, mainSelections: 0 });
  const enabled = await f.prepare({ codeEnabled: true }); assert.equal(enabled.codeEnabled, true); assert.notEqual(enabled.executable, ordinary.executable); assert.equal(f.status.length, 2);
  fs.writeFileSync(path.join(enabled.profile, 'owned-project-state'), 'persistent'); const again = await f.prepare({ codeEnabled: true }); assert.equal(again.executable, enabled.executable); assert.equal(f.status.length, 2); assert.equal(fs.readFileSync(path.join(again.profile, 'owned-project-state'), 'utf8'), 'persistent');
  const archivePath = path.join(path.dirname(enabled.executable), 'resources', 'app.asar'), bytes = fs.readFileSync(archivePath), parsed = A.parseArchive(bytes), entry = parsed.entry('.vite/build/proxy-guard-managed-cli.cjs'); bytes[parsed.payloadStart + Number(entry.offset)] ^= 1; fs.writeFileSync(archivePath, bytes);
  await f.prepare({ codeEnabled: true }); assert.equal(f.status.length, 3, 'A module payload change must force reconstruction even when its ASAR header hash is unchanged');
  const mainBytes = fs.readFileSync(archivePath), mainArchive = A.parseArchive(mainBytes), mainEntry = mainArchive.entry('.vite/build/index.chunk-main-fixture.js'); mainBytes[mainArchive.payloadStart + Number(mainEntry.offset)] ^= 1; fs.writeFileSync(archivePath, mainBytes);
  await f.prepare({ codeEnabled: true }); assert.equal(f.status.length, 4, 'A changed marketplace module payload must also invalidate the cache');
  const sessionBytes = fs.readFileSync(archivePath), sessionArchive = A.parseArchive(sessionBytes), sessionEntry = sessionArchive.entry('.vite/build/index.chunk-sessions-fixture.js'); sessionBytes[sessionArchive.payloadStart + Number(sessionEntry.offset)] ^= 1; fs.writeFileSync(archivePath, sessionBytes);
  await f.prepare({ codeEnabled: true }); assert.equal(f.status.length, 5, 'A changed session factory payload must invalidate the cache');
  f.setTransport('module.exports={initCodeTransport(){}};/* fixture-v2 */'); const updated = await f.prepare({ codeEnabled: true }); assert.notEqual(updated.executable, enabled.executable); assert.equal(f.status.length, 6);
  assert.ok(fs.readFileSync(path.join(path.dirname(f.source), 'resources', 'app.asar')).equals(originalArchive), 'Original signed source remains the hash authority');
});
test('an unsupported Code main fails before creating a runtime while ordinary Chat remains available', async t => {
  const f = await runtimeFixture(t); f.rejectMain(); await assert.rejects(f.prepare({ codeEnabled: true }), /Unsupported fixture main/); assert.equal(f.status.length, 0); assert.equal(fs.existsSync(f.guardRoot), false);
  const ordinary = await f.prepare(); assert.equal(ordinary.codeEnabled, false); assert.equal(f.status.length, 1); assert.equal(f.counters().mainPatchCalls, 0);
});

test('an unsupported local session module cannot create a protected runtime', async t => {
  const f = await runtimeFixture(t); f.rejectSessions(); await assert.rejects(f.prepare({ codeEnabled: true }), /Unsupported fixture sessions/); assert.equal(f.status.length, 0); assert.equal(fs.existsSync(f.guardRoot), false);
  assert.equal((await f.prepare()).codeEnabled, false);
});
