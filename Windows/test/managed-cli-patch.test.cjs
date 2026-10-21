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
function mainFixture(extra = '') {
  const source = 'async function hAa(e,t={}){const i=t.command,a="identity";' + PLUGIN_AUTH + 'const r=t.timeout??3e4,s="vendor-path";return await ' + PLUGIN_RUN + '}function unrelated(){return Yf("other.exe",[],{})}' + extra;
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
test('main patch changes exactly one Code marketplace call and retains every other original byte', () => {
  const p = transformerWithDigestFixture(P.MAIN_SHA256), original = mainFixture(), changed = p.patchManagedCliMain(original).toString();
  new vm.Script(changed); assert.equal(changed, PREFIX + original.toString().replace(PLUGIN_RUN, PLUGIN_RUN.replace('Yf(', '__gateCli.runManagedCommand(')));
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
  for (const extra of [PLUGIN_RUN, PLUGIN_AUTH, 'async function hAa(e,t={})', '__gateCli']) assert.throws(() => p.patchManagedCliMain(mainFixture('/*' + extra + '*/')), /Unsupported/);
  for (const anchor of [PLUGIN_RUN, PLUGIN_AUTH, 'async function hAa(e,t={})']) {
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
  new vm.Script(changed.toString()); assert.equal(changed.toString(), PREFIX + item.source.toString().replace(PLUGIN_RUN, PLUGIN_RUN.replace('Yf(', '__gateCli.runManagedCommand(')));
  const corrupt = Buffer.from(item.source); corrupt[0] ^= 1; assert.throws(() => P.patchManagedCliMain(corrupt), /Unsupported/); assert.throws(() => P.patchManagedCliMain(changed), /Unsupported/);
});
