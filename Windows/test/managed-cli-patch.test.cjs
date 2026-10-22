"use strict";
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const P = require('../src/managed-cli-patch.cjs');
const implementation = fs.readFileSync(path.join(__dirname, '../src/managed-cli-patch.cjs'), 'utf8');
const SPAWN = 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=(0,h.spawn)(t,n,{cwd:r,stdio:["pipe","pipe","pipe"],signal:a,env:i,windowsHide:!0});';
function fixture(extra = '') { const source = 'class Transport{' + SPAWN + 'if(o.pid!==void 0&&this.options.onProcessSpawned)this.options.onProcessSpawned(o.pid);o.stderr.on("data",this.options.stderr);return o}};let p={managedSettings:l?O(l):void 0};exports.query=Ske;' + extra; return Buffer.concat([Buffer.from(source), Buffer.alloc(P.SDK_BYTES - Buffer.byteLength(source), 32)]); }
function transformerWithDigestFixture(expected = P.SDK_SHA256) { // Digest substitution is confined to this test VM; the public patcher always pins real SHA256.
  const module = { exports: {} }, crypto = { createHash: () => ({ update() { return this; }, digest: () => expected }) };
  vm.runInNewContext(implementation, { require: name => name === 'node:crypto' ? crypto : require(name), module, exports: module.exports, Buffer, Object, Error }, { filename: 'managed-cli-patch.cjs' }); return module.exports;
}
function archive(entries) { const files = {}; for (const [name] of entries) files[name] = { size: P.SDK_BYTES }; return { header: { files: { '.vite': { files: { build: { files } } } } }, read: filename => entries.find(([name]) => filename.endsWith('/' + name))[1] }; }
test('public patcher refuses unknown, truncated and already modified vendor SDKs', () => {
  for (const value of [null, 'source', Buffer.from('unknown'), fixture()]) assert.throws(() => P.patchManagedCliSDK(value), /Unsupported Claude Code SDK/);
});
test('SDK adapter changes only the launch operation and managed proxy merge, preserving existing SDK lifecycle code', () => {
  const p = transformerWithDigestFixture(), changed = p.patchManagedCliSDK(fixture()).toString();
  new vm.Script(changed); assert.equal(changed.split('require("./proxy-guard-managed-cli.cjs")').length, 2); assert.equal(changed.split('__gateCli.spawnManaged(e)').length, 2); assert.equal(changed.split('managedSettings:O(__gateCli.mergeManagedSettings(l))').length, 2);
  assert.ok(changed.includes('if(o.pid!==void 0&&this.options.onProcessSpawned)this.options.onProcessSpawned(o.pid);o.stderr.on("data",this.options.stderr);return o'));
  assert.ok(changed.endsWith(fixture().toString().slice(fixture().toString().indexOf('exports.query=Ske')))); assert.ok(!changed.includes('(0,h.spawn)(t,n,'));
});
test('every required anchor must occur exactly once and lexical adapter cannot be injected twice', () => {
  const p = transformerWithDigestFixture(); for (const extra of [SPAWN, 'managedSettings:l?O(l):void 0', 'exports.query=Ske', '__gateCli']) assert.throws(() => p.patchManagedCliSDK(fixture(extra)), /Unsupported Claude Code SDK/);
  const noSpawn = fixture().toString().replace('spawnLocalProcess', 'otherLocalProcess'); assert.throws(() => p.patchManagedCliSDK(Buffer.from(noSpawn)), /Unsupported Claude Code SDK/);
});
test('ASAR selection requires one packed SDK chunk with the pinned content and refuses ambiguity or links', () => {
  const p = transformerWithDigestFixture(), bytes = fixture(); const found = p.findManagedCliSDK(archive([['index.chunk-fixture.js', bytes]])); assert.equal(found.filename, '.vite/build/index.chunk-fixture.js'); assert.equal(found.source, bytes);
  assert.throws(() => p.findManagedCliSDK(archive([])), /Unsupported/); assert.throws(() => p.findManagedCliSDK(archive([['index.chunk-a.js', bytes], ['index.chunk-b.js', bytes]])), /Unsupported/);
  const linked = archive([['index.chunk-fixture.js', bytes]]); linked.header.files['.vite'].files.build.files['index.chunk-fixture.js'].link = '../other'; assert.throws(() => p.findManagedCliSDK(linked), /Unsupported/);
});
test('original installed source SDK passes the real digest and exact-anchor gate when source cache is present', t => {
  const file = path.resolve(__dirname, '../../../../work/windows/source/app/resources/app.asar'); if (!fs.existsSync(file)) return t.skip('Original vendor source cache is not distributed with tests.');
  const { parseArchive } = require('../src/asar.cjs'), archive = parseArchive(fs.readFileSync(file)), item = P.findManagedCliSDK(archive), changed = P.patchManagedCliSDK(item.source);
  assert.equal(item.filename, '.vite/build/index.chunk-Ghv0q1hg.js'); assert.equal(item.sha256, P.SDK_SHA256); new vm.Script(changed.toString());
  const before = item.source.toString(), after = changed.toString(); for (const marker of ['sdk-exit-after-stderr-drained', 'onProcessSpawned', 'spawnClaudeCodeProcess:p.spawnClaudeCodeProcess']) assert.equal(after.split(marker).length, before.split(marker).length);
});

test('unrelated unpacked or linked ASAR directories are never read and do not hide the single pinned SDK', () => {
  const p = transformerWithDigestFixture(), a = archive([['index.chunk-fixture.js', fixture()]]);
  a.header.files.native = { unpacked: true, files: { 'addon.node': { size: 1 } } };
  a.header.files.linked = { link: '../outside', files: { 'index.chunk-evil.js': { size: P.SDK_BYTES } } };
  assert.equal(p.findManagedCliSDK(a).filename, '.vite/build/index.chunk-fixture.js');
});

const PLUGIN_RUN = 'Yf(i,e,{timeout:r,env:{...t.env,...o.env,PATH:s,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1"},cwd:t.cwd,stdin:t.stdin,ignoreExitCode:!0})';
const PLUGIN_AUTH = 'let o=await dAa({tag:"plugin_cli",versionIdentity:a});';
const PREFIX = '"use strict";const __gateCli=require("./proxy-guard-managed-cli.cjs");\n';
const HOST_PRESEED = 'async getHostPreseedInPlacePath(){if(!pi()||this.skipPreseedThisProcess)return null;let e=this.getHostTarget();return BHr(e.platform,e.binaryName)}';
const COMPRESSED_SHA = 'aed62990b91e94efb35482fd7068cc616c6c2414084c6aa32148ca2a359e4e81';
const MANAGED_PRESEED = 'async getHostPreseedInPlacePath(){let e=this.getHostTarget();if(e.platform!=="win32-x64"||this.targetVersion!=="2.1.304"||this.expectedChecksumForTarget(e)!=="' + COMPRESSED_SHA + '")throw Error("Unsupported Claude Code version; protected launch is unavailable.");return __gateCli.resolveManagedCliPath(this.getBinaryPathForTarget(e,this.targetVersion))}';
const SESSIONS_FACTORY = 'function Kt(e,t){let n={...t};';
function sessionsFixture(extra = '') {
  const source = SESSIONS_FACTORY + 'return n}exports.createLocalSessionsApi=(api)=>Kt({},api);' + extra;
  return Buffer.concat([Buffer.from(source), Buffer.alloc(P.SESSIONS_BYTES - Buffer.byteLength(source), 32)]);
}
function sessionsArchive(bytes = sessionsFixture()) {
  return { header: { files: { '.vite': { files: { build: { files: { 'index.chunk-CFHSNuch.js': { size: P.SESSIONS_BYTES } } } } } } }, read: filename => { assert.equal(filename, P.SESSIONS_FILE); return bytes; } };
}
test('local session adapter requires the exact pinned module and one factory anchor', () => {
  for (const value of [null, 'source', Buffer.from('unknown'), sessionsFixture()]) assert.throws(() => P.patchManagedCliSessions(value), /Unsupported/);
  const p = transformerWithDigestFixture(P.SESSIONS_SHA256), changed = p.patchManagedCliSessions(sessionsFixture());
  new vm.Script(changed.toString());
  for (const extra of [SESSIONS_FACTORY, '__gateCli']) assert.throws(() => p.patchManagedCliSessions(sessionsFixture('/*' + extra + '*/')), /Unsupported/);
  assert.throws(() => p.patchManagedCliSessions(Buffer.from(sessionsFixture().toString().replace(SESSIONS_FACTORY, ' '.repeat(SESSIONS_FACTORY.length)))), /Unsupported/);
  assert.throws(() => p.patchManagedCliSessions(changed), /Unsupported/);
});
test('local session factory receives the Guard adapter before exposing any API methods', () => {
  const p = transformerWithDigestFixture(P.SESSIONS_SHA256), events = [], module = { exports: {} };
  vm.runInNewContext(p.patchManagedCliSessions(sessionsFixture()).toString(), { module, exports: module.exports, require: name => {
    assert.equal(name, './proxy-guard-managed-cli.cjs'); return { configureLocalSessions: api => { events.push(api); return { ...api, guarded: true }; } };
  } });
  const api = { start() {} }, wrapped = module.exports.createLocalSessionsApi(api);
  assert.equal(events[0], api); assert.equal(wrapped.guarded, true); assert.equal(wrapped.start, api.start);
});
test('local session selection refuses linked, unpacked, renamed or changed modules', () => {
  const p = transformerWithDigestFixture(P.SESSIONS_SHA256);
  assert.equal(p.findManagedCliSessions(sessionsArchive()).filename, P.SESSIONS_FILE);
  for (const level of ['.vite', 'build', 'index.chunk-CFHSNuch.js']) for (const attribute of ['link', 'unpacked']) {
    const a = sessionsArchive(); let entry = a.header.files['.vite']; if (level !== '.vite') entry = entry.files.build; if (level === 'index.chunk-CFHSNuch.js') entry = entry.files[level];
    entry[attribute] = attribute === 'link' ? '../outside' : true; assert.throws(() => p.findManagedCliSessions(a), /Unsupported/);
  }
  const bad = sessionsArchive(); bad.header.files['.vite'].files.build.files['index.chunk-CFHSNuch.js'].size--; assert.throws(() => p.findManagedCliSessions(bad), /Unsupported/);
  assert.throws(() => P.findManagedCliSessions(sessionsArchive()), /Unsupported/);
});
test('the installed original local session factory passes its real digest and retains vendor lifecycle guards', t => {
  const file = path.resolve(__dirname, '../../../../work/windows/source/app/resources/app.asar'); if (!fs.existsSync(file)) return t.skip('Original vendor source cache is not distributed.');
  const archive = require('../src/asar.cjs').parseArchive(fs.readFileSync(file)), item = P.findManagedCliSessions(archive), changed = P.patchManagedCliSessions(item.source).toString();
  new vm.Script(changed); assert.equal(item.sha256, P.SESSIONS_SHA256);
  assert.equal(changed, PREFIX + item.source.toString().replace(SESSIONS_FACTORY, 'function Kt(e,t){t=__gateCli.configureLocalSessions(t);let n={...t};'));
  for (const marker of ['isHiddenPrewarm', 'isParkedSession', 'saveWorkspaceTrust', 'startSession(f,']) assert.equal(changed.split(marker).length, item.source.toString().split(marker).length);
});
test('scratch lifecycle selection rejects unknown bytes, links, unpacked entries and size changes', () => {
  const bytes = Buffer.alloc(P.SCRATCH_BYTES, 32);
  function fixture() { return { header: { files: { '.vite': { files: { build: { files: { 'index.chunk-zA4nMcEF.js': { size: P.SCRATCH_BYTES } } } } } } }, read: () => bytes }; }
  assert.throws(() => P.findManagedCliScratch(fixture()), /Unsupported/);
  const p = transformerWithDigestFixture(P.SCRATCH_SHA256);
  assert.equal(p.findManagedCliScratch(fixture()).filename, P.SCRATCH_FILE);
  for (const level of ['.vite', 'build', 'index.chunk-zA4nMcEF.js']) for (const attribute of ['link', 'unpacked']) {
    const a = fixture(); let entry = a.header.files['.vite']; if (level !== '.vite') entry = entry.files.build; if (level === 'index.chunk-zA4nMcEF.js') entry = entry.files[level];
    entry[attribute] = attribute === 'link' ? '../outside' : true; assert.throws(() => p.findManagedCliScratch(a), /Unsupported/);
  }
  const bad = fixture(); bad.header.files['.vite'].files.build.files['index.chunk-zA4nMcEF.js'].size--; assert.throws(() => p.findManagedCliScratch(bad), /Unsupported/);
});
test('actual pinned vendor scratch recognition and removal never classify or delete the permanent Workspace', async t => {
  const file = path.resolve(__dirname, '../../../../work/windows/source/app/resources/app.asar'); if (!fs.existsSync(file)) return t.skip('Original vendor source cache is not distributed.');
  const archive = require('../src/asar.cjs').parseArchive(fs.readFileSync(file)), main = P.findManagedCliMain(archive).source.toString(), scratch = P.findManagedCliScratch(archive);
  const begin = main.indexOf('var ACr="scratch-workspaces";'), end = main.indexOf('var ICr=', begin); assert.ok(begin > 0 && end > begin);
  const profile = 'C:\\Guard\\Profile', workspace = 'C:\\Guard\\CodeState\\Workspace', context = { n: path.win32, a: { app: { getPath: () => profile } } };
  vm.runInNewContext(main.slice(begin, end) + ';globalThis.recognize=MCr;globalThis.isScratch=NCr;globalThis.matchesScratch=FCr;', context);
  const calls = [], module = { exports: {} };
  vm.runInNewContext(scratch.source.toString(), { module, exports: module.exports, process: { env: {} }, require: name => {
    if (name === './index.chunk-7dsQFims.js') return { yO: context.recognize, WD: async paths => calls.push(['forget', ...paths]) };
    if (name === 'node:fs/promises') return { rm: async (cwd, options) => calls.push(['remove', cwd, options.recursive, options.force]) };
    if (name === 'node:path') return path.win32;
    if (name.startsWith('./') || name === 'electron') return {};
    return require(name);
  } });
  for (const cwd of [workspace, workspace + '\\project', profile, profile + '\\scratch-workspaces-other\\account\\org\\scratch-2026-10-22-aabbcc']) {
    assert.equal(context.recognize(cwd), null); assert.equal(context.isScratch(cwd), false); assert.equal(context.matchesScratch(cwd), false);
    await module.exports.removeScratchWorkspace(cwd);
  }
  assert.deepEqual(calls, [], 'Persistent directory must never reach removal or trust-forgetting');
  const disposable = path.win32.join(profile, 'scratch-workspaces', 'account', 'org', 'scratch-2026-10-22-aabbcc');
  assert.equal(context.recognize(disposable), disposable); assert.equal(context.isScratch(disposable), true); assert.equal(context.matchesScratch(disposable), true);
  await module.exports.removeScratchWorkspace(disposable);
  assert.deepEqual(calls, [['remove', disposable, true, true], ['forget', disposable]], 'Positive control exercises the real vendor removal guard');
});
function expectedMainPatch(source) { return PREFIX + source.replace(PLUGIN_RUN, PLUGIN_RUN.replace('Yf(', '__gateCli.runManagedCommand(')).replace(HOST_PRESEED, MANAGED_PRESEED); }
function mainFixture(extra = '') {
  const source = 'async function hAa(e,t={}){const i=t.command,a="identity";' + PLUGIN_AUTH + 'const r=t.timeout??3e4,s="vendor-path";return await ' + PLUGIN_RUN + '}function unrelated(){return Yf("other.exe",[],{})}class CodeManager{' + HOST_PRESEED + '}' + extra;
  return Buffer.concat([Buffer.from(source), Buffer.alloc(P.MAIN_BYTES - Buffer.byteLength(source), 32)]);
}
function mainArchive(bytes = mainFixture()) {
  return { header: { files: { '.vite': { files: { build: { files: { 'index.chunk-7dsQFims.js': { size: P.MAIN_BYTES } } } } } } }, read: filename => { assert.equal(filename, P.MAIN_FILE); return bytes; } };
}
test('public main patcher refuses unknown, truncated, mutated and previously patched originals', () => {
  for (const value of [null, 'source', Buffer.from('unknown'), mainFixture()]) assert.throws(() => P.patchManagedCliMain(value), /Unsupported Claude Code main module/);
  const p = transformerWithDigestFixture(P.MAIN_SHA256), patched = p.patchManagedCliMain(mainFixture());
  assert.throws(() => p.patchManagedCliMain(patched), /Unsupported/);
});
test('main patch changes only the Code marketplace call and prepared host binary resolver', () => {
  const p = transformerWithDigestFixture(P.MAIN_SHA256), original = mainFixture(), changed = p.patchManagedCliMain(original).toString();
  new vm.Script(changed); assert.equal(changed, expectedMainPatch(original.toString()));
  assert.ok(changed.includes(PLUGIN_AUTH)); assert.ok(changed.includes('function unrelated(){return Yf("other.exe",[],{})}'));
});
test('Code marketplace dispatch retains host-auth environment and cannot authorize unrelated spawn helpers', async () => {
  const p = transformerWithDigestFixture(P.MAIN_SHA256), calls = [], context = {
    dAa: async identity => { calls.push(['auth', identity.tag, identity.versionIdentity]); return { env: { HOST_TOKEN: 'fixture-token' } }; },
    require: name => { assert.equal(name, './proxy-guard-managed-cli.cjs'); return { runManagedCommand: async (...args) => { calls.push(['managed', ...args]); return { stdout: 'ok', stderr: '', code: 0 }; } }; },
    Yf: () => { throw Error('general spawn is blocked'); }
  };
  vm.runInNewContext(p.patchManagedCliMain(mainFixture()).toString() + ';globalThis.invoke=hAa;globalThis.other=unrelated;', context);
  const result = await context.invoke(['plugin', 'marketplace', 'list'], { command: 'C:\\approved\\claude.exe', cwd: 'C:\\Guard\\CodeState\\Workspace', timeout: 73, env: { VENDOR_VALUE: 'kept' }, stdin: 'fixture input' });
  assert.equal(result.stdout, 'ok'); assert.deepEqual(calls[0], ['auth', 'plugin_cli', 'identity']);
  assert.equal(calls[1][0], 'managed'); assert.equal(calls[1][1], 'C:\\approved\\claude.exe'); assert.deepEqual(calls[1][2], ['plugin', 'marketplace', 'list']);
  const options = calls[1][3]; assert.equal(options.cwd, 'C:\\Guard\\CodeState\\Workspace'); assert.equal(options.timeout, 73); assert.equal(options.stdin, 'fixture input'); assert.equal(options.ignoreExitCode, true);
  assert.equal(options.env.HOST_TOKEN, 'fixture-token'); assert.equal(options.env.VENDOR_VALUE, 'kept'); assert.equal(options.env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, '1');
  assert.throws(context.other, /general spawn is blocked/); assert.equal(calls.length, 2);
});
test('main exact anchors must be unique, present, and free of a previous lexical adapter', () => {
  const p = transformerWithDigestFixture(P.MAIN_SHA256);
  for (const extra of [PLUGIN_RUN, PLUGIN_AUTH, HOST_PRESEED, 'async function hAa(e,t={})', '__gateCli']) assert.throws(() => p.patchManagedCliMain(mainFixture('/*' + extra + '*/')), /Unsupported/);
  for (const anchor of [PLUGIN_RUN, PLUGIN_AUTH, HOST_PRESEED, 'async function hAa(e,t={})']) {
    const changed = mainFixture().toString().replace(anchor, ' '.repeat(anchor.length)); assert.throws(() => p.patchManagedCliMain(Buffer.from(changed)), /Unsupported/);
  }
});
test('main selection refuses linked or unpacked ancestors and an unpinned filename, size or source', () => {
  const p = transformerWithDigestFixture(P.MAIN_SHA256), bytes = mainFixture(), found = p.findManagedCliMain(mainArchive(bytes));
  assert.equal(found.filename, P.MAIN_FILE); assert.equal(found.source, bytes); assert.equal(found.sha256, P.MAIN_SHA256);
  for (const level of ['.vite', 'build', 'index.chunk-7dsQFims.js']) for (const attribute of ['link', 'unpacked']) {
    const a = mainArchive(bytes); let entry = a.header.files['.vite']; if (level !== '.vite') entry = entry.files.build; if (level === 'index.chunk-7dsQFims.js') entry = entry.files[level];
    entry[attribute] = attribute === 'link' ? '../other' : true; assert.throws(() => p.findManagedCliMain(a), /Unsupported/);
  }
  const wrongSize = mainArchive(bytes); wrongSize.header.files['.vite'].files.build.files['index.chunk-7dsQFims.js'].size--; assert.throws(() => p.findManagedCliMain(wrongSize), /Unsupported/);
  const wrongName = mainArchive(bytes); delete wrongName.header.files['.vite'].files.build.files['index.chunk-7dsQFims.js']; assert.throws(() => p.findManagedCliMain(wrongName), /Unsupported/);
  assert.throws(() => P.findManagedCliMain(mainArchive(bytes)), /Unsupported/);
});
test('the pinned original main passes real hashes, preserves host-auth and generic wrappers, and agrees with source policy', t => {
  const file = path.resolve(__dirname, '../../../../work/windows/source/app/resources/app.asar'); if (!fs.existsSync(file)) return t.skip('Original vendor source cache is not distributed with tests.');
  const A = require('../src/asar.cjs'), { SOURCE_POLICY } = require('../src/code-preparation.cjs'), original = A.parseArchive(fs.readFileSync(file)), item = P.findManagedCliMain(original), changed = P.patchManagedCliMain(item.source);
  assert.equal(item.sha256, SOURCE_POLICY.mainSHA256); assert.equal(item.filename, SOURCE_POLICY.mainFile); assert.equal(A.hash(item.source), P.MAIN_SHA256); assert.notEqual(A.hash(changed), P.MAIN_SHA256);
  new vm.Script(changed.toString()); assert.equal(changed.toString(), expectedMainPatch(item.source.toString()));
  assert.equal(COMPRESSED_SHA, SOURCE_POLICY.compressedSHA256); assert.equal(SOURCE_POLICY.codeVersion, '2.1.304'); assert.equal(SOURCE_POLICY.platform, 'win32-x64');
  const corrupt = Buffer.from(item.source); corrupt[0] ^= 1; assert.throws(() => P.patchManagedCliMain(corrupt), /Unsupported/); assert.throws(() => P.patchManagedCliMain(changed), /Unsupported/);
});

test('prepared resolver rejects unknown platform, version and complete checksum before any path mapping', async () => {
  const calls = [], context = { require: () => ({ resolveManagedCliPath: requested => { calls.push(requested); return 'approved'; } }) };
  const changed = transformerWithDigestFixture(P.MAIN_SHA256).patchManagedCliMain(mainFixture());
  vm.runInNewContext(changed.toString() + ';globalThis.manager=new CodeManager;', context);
  const manager = context.manager;
  manager.getHostTarget = () => ({ platform: 'win32-x64' }); manager.targetVersion = '2.1.304'; manager.expectedChecksumForTarget = () => COMPRESSED_SHA;
  manager.getBinaryPathForTarget = () => 'original-pinned-request';
  assert.equal(await manager.getHostPreseedInPlacePath(), 'approved'); assert.deepEqual(calls, ['original-pinned-request']);
  for (const [platform, version, checksum] of [['win32-arm64', '2.1.304', COMPRESSED_SHA], ['linux-x64', '2.1.304', COMPRESSED_SHA], ['win32-x64', '2.1.305', COMPRESSED_SHA], ['win32-x64', '2.1.304', COMPRESSED_SHA.slice(0, 12) + '0'.repeat(52)], ['win32-x64', '2.1.304', undefined]]) {
    manager.getHostTarget = () => ({ platform }); manager.targetVersion = version; manager.expectedChecksumForTarget = () => checksum;
    await assert.rejects(manager.getHostPreseedInPlacePath(), /Unsupported Claude Code version/);
  }
  assert.equal(calls.length, 1);
});

test('prepared resolver never falls back to vendor installation when the managed identity is denied', async () => {
  const context = { require: () => ({ resolveManagedCliPath: () => { throw Object.assign(Error('denied fixture identity'), { code: 'ERR_GUARD_CODE_DENIED' }); } }) };
  vm.runInNewContext(transformerWithDigestFixture(P.MAIN_SHA256).patchManagedCliMain(mainFixture()).toString() + ';globalThis.manager=new CodeManager;', context);
  const manager = context.manager; manager.getHostTarget = () => ({ platform: 'win32-x64' }); manager.targetVersion = '2.1.304'; manager.expectedChecksumForTarget = () => COMPRESSED_SHA; manager.getBinaryPathForTarget = () => 'unknown';
  await assert.rejects(manager.getHostPreseedInPlacePath(), { code: 'ERR_GUARD_CODE_DENIED' });
});

test('actual pinned manager prepares a fresh Profile from CodeBin without filesystem checks or vendor downloads', async t => {
  const file = path.resolve(__dirname, '../../../../work/windows/source/app/resources/app.asar'); if (!fs.existsSync(file)) return t.skip('Original vendor source cache is not distributed with tests.');
  const archive = require('../src/asar.cjs').parseArchive(fs.readFileSync(file)), original = P.findManagedCliMain(archive), changed = P.patchManagedCliMain(original.source).toString();
  const begin = changed.indexOf('var tUr=class{'), end = changed.indexOf(';function nUr(', begin); assert.ok(begin > 0 && end > begin);
  const profile = 'C:\\Guard\\Profile', executable = 'C:\\Guard\\CodeBin\\' + 'a'.repeat(64) + '\\claude.exe', requested = path.win32.join(profile, 'claude-code', '2.1.304', COMPRESSED_SHA.slice(0, 12), 'claude.exe');
  const module = { exports: {} }, managedSource = fs.readFileSync(path.join(__dirname, '../src/managed-cli.cjs'), 'utf8');
  new Function('require', 'module', 'exports', 'process', managedSource)(require, module, module.exports, { platform: 'win32', execPath: 'C:\\Guard\\Runtime\\claude.exe', env: {} });
  const forbidden = []; const fail = operation => { forbidden.push(operation); throw Error('Unexpected profile access or vendor download: ' + operation); };
  module.exports.initCodeTransport({ hostPath: 'C:\\Guard\\CodeHost.exe', containerName: 'GateClaudeCode.fixture', containerSid: 'S-1-15-2-1-2-3-4-5-6-7', relayURL: 'http://127.0.0.1:31415', stateRoot: 'C:\\Guard\\CodeState', runtimeExecutable: 'C:\\Guard\\Runtime\\claude.exe', gatePipe: '\\\\.\\pipe\\gate-claude-code-' + 'b'.repeat(32), gateToken: 'c'.repeat(64), codeJobName: 'Global\\gate-code-job-' + 'd'.repeat(32), approved: [{ path: executable, sha256: 'a'.repeat(64), requestedPath: requested }] }, () => fail('spawn'));
  const manifest = { platforms: { 'win32-x64': { checksum: COMPRESSED_SHA, size: 104965652 } } }, context = {
    __gateCli: module.exports, n: { default: path.win32 }, a: { app: { getPath: () => profile } },
    Eg: () => ({ version: '2.1.304', manifest, sdkWrapperVersion: '2.1.304', baseUrl: 'unused' }), XVr: () => path.win32.join(profile, 'claude-code'), N: { info() {}, warn() {}, error() {} },
    process: { platform: 'win32', arch: 'x64', env: {} }, pi: () => fail('package preseed'), BHr: () => fail('package binary'), Sw: () => ({ allowsLocalSpawn: true }),
    zK: () => 0, BK() {}, Q() {}, p: { default: new Proxy({}, { get: (_, name) => () => fail('fs.' + name) }) }, o: { constants: { X_OK: 1 } },
    eHr: (root, version, checksum) => path.win32.join(root, version, checksum.slice(0, 12)), v_: { Ready: 'ready', NotInstalled: 'missing' }
  };
  vm.runInNewContext(changed.slice(begin, end) + ';globalThis.manager=new tUr;', context);
  const manager = context.manager; manager.prepareForTarget = () => fail('vendor prepare'); manager.downloadBinaryForTarget = () => fail('vendor download');
  assert.equal(await manager.getStatus(), 'ready');
  const resolved = await manager.resolveHostBinary(); assert.equal(resolved.path, executable); assert.equal(resolved.resolution, 'preseed_in_place'); assert.equal(resolved.version, '2.1.304'); assert.equal(resolved.manifest, manifest);
  assert.equal(JSON.stringify(await manager.prepare()), JSON.stringify({ ready: true, path: executable }));
  const identity = 'preseed_in_place:2.1.304:' + COMPRESSED_SHA;
  assert.equal(await manager.getHostVersionIdentityForPath(executable), identity);
  assert.equal((await manager.getBinaryPathIfReadyWithIdentity()).versionIdentity, identity);
  assert.equal((await manager.installUpdatedHostTarget('2.1.305', {})).ready, false);
  manager.notePossibleHostSpawnFailure(); assert.equal((await manager.prepare()).path, executable);
  assert.deepEqual(forbidden, []);
  // VM preparation stays the vendor's original method, not the host CodeBin route.
  const old = original.source.toString(), vmStart = old.indexOf('async prepareForVM('), vmEnd = old.indexOf('async prefetchForVM(', vmStart);
  assert.ok(changed.includes(old.slice(vmStart, vmEnd)));
});
