"use strict";
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { ChildProcess } = require('node:child_process');
const { PassThrough } = require('node:stream');
const source = fs.readFileSync(path.join(__dirname, '../src/managed-cli.cjs'), 'utf8');
const FAILURE = 'Guard could not launch the protected Claude Code process.';
const SID = 'S-1-15-2-1-2-3-4-5-6-7';
function config() { return { hostPath: 'C:\\Guard\\CodeHost.exe', containerName: 'GateClaudeCode.fixture', containerSid: SID, relayURL: 'http://127.0.0.1:31415', stateRoot: 'C:\\Guard\\CodeState', runtimeExecutable: 'C:\\Guard\\Runtime\\claude.exe', gatePipe: '\\\\.\\pipe\\gate-claude-code-' + 'b'.repeat(32), gateToken: 'c'.repeat(64), codeJobName: 'Global\\gate-code-job-' + 'd'.repeat(32), approved: [{ path: 'C:\\Guard\\CodeBin\\abc\\claude.exe', sha256: 'a'.repeat(64) }] }; }
function load() {
  const module = { exports: {} }, fakeProcess = { platform: 'win32', execPath: config().runtimeExecutable, pid: 313, env: { SystemRoot: 'C:\\Windows', TEMP: 'C:\\Temp', PROXY_GUARD_CONFIG: 'fixture-secret', ANTHROPIC_AUTH_TOKEN: 'fixture-auth' } };
  new Function('require', 'module', 'exports', 'process', source)(require, module, module.exports, fakeProcess);
  return { api: module.exports, process: fakeProcess };
}
function childFixture() {
  const child = new ChildProcess(); child.pid = 414; child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kills = 0; child.kill = () => { child.kills++; return true; }; return child;
}
function harness() {
  const { api, process } = load(), calls = [], child = childFixture();
  const spawn = (...args) => { calls.push(args); return child; };
  api.initCodeTransport(config(), spawn);
  return { api, process, calls, child, spawn };
}
function request(extra = {}) { return { command: config().approved[0].path, args: ['--input-format', 'stream-json', '--auth-token', 'fixture-only-private'], cwd: config().stateRoot + '\\Workspace', env: { Path: 'C:\\Windows', ANTHROPIC_AUTH_TOKEN: 'fixture-auth' }, ...extra }; }
function packet(child) { const chunks = []; let chunk; while ((chunk = child.stdin.read()) !== null) chunks.push(chunk); const bytes = Buffer.concat(chunks); const length = bytes.readUInt32LE(0); return { data: JSON.parse(bytes.subarray(4, length + 4).toString()), trailing: bytes.subarray(length + 4) }; }
function rejects(fn) { assert.throws(fn, error => error.code === 'ERR_GUARD_CODE_DENIED' && error.message === FAILURE && !error.message.includes('fixture-only-private')); }

test('refuses launch and managed settings before immutable broker initialization', () => {
  const { api } = load(); rejects(() => api.spawnManaged(request())); rejects(() => api.mergeManagedSettings({}));
});
test('queues bounded private header before SDK input and returns the actual synchronous ChildProcess', async () => {
  const h = harness(), signal = new AbortController().signal, child = h.api.spawnManaged(request({ signal }));
  assert.equal(child, h.child); assert.equal(child.pid, 414); child.stdin.write('SDK-frame\n'); await new Promise(resolve => setImmediate(resolve));
  const p = packet(child); assert.equal(p.trailing.toString(), 'SDK-frame\n');
  assert.equal(p.data.version, 1); assert.equal(p.data.gatePipe, config().gatePipe); assert.equal(p.data.gateToken, config().gateToken); assert.equal(p.data.executableSHA256, 'a'.repeat(64)); assert.equal(p.data.executable, config().approved[0].path);
  assert.equal(p.data.ownerPid, 313); assert.equal(p.data.ownerExecutable, config().runtimeExecutable); assert.equal(p.data.containerSid, SID); assert.equal(p.data.args.at(-1), 'fixture-only-private');
  const [host, argv, options] = h.calls[0]; assert.equal(host, config().hostPath); assert.deepEqual(Array.from(argv), ['--managed']); assert.equal(options.cwd, config().stateRoot); assert.deepEqual(Array.from(options.stdio), ['pipe', 'pipe', 'pipe']); assert.equal(options.windowsHide, true); assert.equal(options.signal, signal);
  assert.equal(options.env.SystemRoot, 'C:\\Windows'); assert.equal(options.env.PROXY_GUARD_CONFIG, undefined); assert.equal(options.env.ANTHROPIC_AUTH_TOKEN, undefined); assert.ok(!JSON.stringify(argv).includes('fixture'));
});
test('cannot change approved paths, hashes or broker capability after initialization', () => {
  const h = harness(); h.api.initCodeTransport(config(), h.spawn);
  const changed = config(); changed.approved[0].sha256 = 'b'.repeat(64); rejects(() => h.api.initCodeTransport(changed, h.spawn)); rejects(() => h.api.initCodeTransport(config(), () => h.child));
  const raw = config(), fresh = load(), calls = []; fresh.api.initCodeTransport(raw, (...args) => { calls.push(args); return childFixture(); }); raw.approved[0].path = 'C:\\evil\\claude.exe'; raw.hostPath = 'C:\\evil\\CodeHost.exe';
  const c = fresh.api.spawnManaged(request()); assert.equal(calls[0][0], config().hostPath); assert.equal(packet(c).data.executable, config().approved[0].path);
});
test('only the approved native CLI can be requested; dynamic profile paths and shell executables fail closed', () => {
  const h = harness();
  for (const command of ['cmd.exe', 'C:\\Windows\\System32\\cmd.exe', 'C:\\Guard\\CodeBin\\abc\\node.exe', 'C:\\Profile\\claude-code\\2.1.304\\abc\\claude.exe', '\\\\server\\share\\claude.exe', '\\\\?\\C:\\Guard\\CodeBin\\abc\\claude.exe', 'C:\\Guard\\CodeBin\\abc\\..\\abc\\claude.exe', 'C:\\Guard\\CodeBin\\abc\\claude.exe:payload', 'C:\\Guard\\CodeBin\\abc\\claude.exe ']) rejects(() => h.api.spawnManaged(request({ command })));
  assert.equal(h.calls.length, 0);
});
test('rejects malformed configuration before exposing the spawn capability', () => {
  for (const edit of [c => { c.relayURL = 'http://localhost:31415'; }, c => { c.relayURL = 'http://127.0.0.1:31415@evil'; }, c => { c.relayURL = 'http://127.0.0.1:31415/path'; }, c => { c.runtimeExecutable = 'C:\\Other\\claude.exe'; }, c => { c.containerSid = 'S-1-5-18'; }, c => { c.approved[0].sha256 = 'fixture'; }, c => { c.approved.push(c.approved[0]); }, c => { c.approved[0].path = 'C:\\Guard\\CodeHost.exe'; }]) { const { api } = load(), cfg = config(); edit(cfg); rejects(() => api.initCodeTransport(cfg, () => childFixture())); }
  const h = load(); h.process.platform = 'darwin'; rejects(() => h.api.initCodeTransport(config(), () => childFixture()));
});
test('sanitizes case variants of proxy bypass and private Guard environment without losing SDK auth', () => {
  const h = harness(); h.api.spawnManaged(request({ env: { Path: 'first', PATH: 'last', HTTPS_PROXY: 'http://evil', https_proxy: 'http://other', All_Proxy: 'socks://evil', nO_pRoXy: '*', ELECTRON_RUN_AS_NODE: '1', node_OPTIONS: '--inspect', PROXY_GUARD_CONFIG: 'private', GATE_TOKEN: 'private', CLAUDE_CDP_AUTH: 'private', SSLKEYLOGFILE: 'C:\\secret', ANTHROPIC_AUTH_TOKEN: 'fixture-auth' } }));
  const env = packet(h.child).data.env;
  assert.equal(env.Path, undefined); assert.equal(env.PATH, 'last'); assert.equal(env.ANTHROPIC_AUTH_TOKEN, 'fixture-auth');
  for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) assert.equal(env[name], config().relayURL);
  assert.equal(env.NO_PROXY, ''); assert.equal(Object.keys(env).filter(key => /proxy/i.test(key)).length, 4);
  for (const name of ['ELECTRON_RUN_AS_NODE', 'node_OPTIONS', 'PROXY_GUARD_CONFIG', 'GATE_TOKEN', 'CLAUDE_CDP_AUTH', 'SSLKEYLOGFILE']) assert.equal(env[name], undefined);
});
test('managed policy merges proxy values ephemerally and preserves all unrelated nested organization settings', () => {
  const h = harness(), original = { permissions: { deny: ['Bash(secret)'], defaultMode: 'plan' }, sandbox: { enabled: true }, env: { https_proxy: 'http://evil', NO_PROXY: '*', ORGANIZATION: 'fixture' } }, before = JSON.stringify(original);
  const merged = h.api.mergeManagedSettings(original); assert.equal(JSON.stringify(original), before); assert.equal(JSON.stringify(merged.permissions), JSON.stringify(original.permissions)); assert.equal(merged.sandbox.enabled, true); assert.equal(merged.env.ORGANIZATION, 'fixture');
  for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) assert.equal(merged.env[name], config().relayURL);
  assert.equal(merged.env.NO_PROXY, ''); assert.equal(merged.env.no_proxy, ''); assert.equal(h.api.mergeManagedSettings(undefined).env.HTTPS_PROXY, config().relayURL);
  merged.permissions.deny.push('changed'); assert.equal(original.permissions.deny.length, 1);
});
test('malformed argv/env, aborted starts, cyclic settings and oversized packets never start a broker', () => {
  const h = harness(), abort = new AbortController(); abort.abort();
  const bad = [{ args: ['\0'] }, { args: Array(257).fill('x') }, { args: ['x'.repeat(16385)] }, { cwd: '..\\outside' }, { env: { 'BAD=NAME': 'value' } }, { env: { TOKEN: 'x\0y' } }, { env: { TOKEN: 'x'.repeat(32768) } }, { signal: abort.signal }];
  for (const extra of bad) rejects(() => h.api.spawnManaged(request(extra))); assert.equal(h.calls.length, 0);
  const settings = {}; settings.circular = settings; rejects(() => h.api.mergeManagedSettings(settings)); rejects(() => h.api.mergeManagedSettings({ env: { bad: false } }));
  let getters = 0; const env = {}; Object.defineProperty(env, 'TOKEN', { enumerable: true, get() { getters++; return 'secret'; } }); rejects(() => h.api.spawnManaged(request({ env }))); assert.equal(getters, 0);
});
test('a failed or malformed broker is killed and only a fixed error escapes', () => {
  const { api } = load(); let killed = 0; api.initCodeTransport(config(), () => ({ pid: 1, kill() { killed++; } })); rejects(() => api.spawnManaged(request())); assert.equal(killed, 1);
  const fresh = load(); fresh.api.initCodeTransport(config(), () => { throw Error('fixture-only-private'); }); rejects(() => fresh.api.spawnManaged(request()));
});
test('header pipe failure terminates the owned broker instead of continuing without a valid configuration', () => {
  const h = harness(); h.api.spawnManaged(request()); h.child.stdin.emit('error', Error('fixture transport failure')); assert.equal(h.child.kills, 1);
});

test('only an exact pinned SDK request maps to the fixed approved clone without reading its writable profile file', () => {
  const h = load(), cfg = config(), calls = [], requested = 'C:\\Profile\\claude-code\\2.1.304\\aed62990b91e\\claude.exe';
  cfg.approved[0].requestedPath = requested;
  h.api.initCodeTransport(cfg, (...args) => { calls.push(args); return childFixture(); });
  const child = h.api.spawnManaged(request({ command: requested.toUpperCase() }));
  assert.equal(packet(child).data.executable, cfg.approved[0].path);
  rejects(() => h.api.spawnManaged(request({ command: requested.replace('2.1.304', '2.1.305') })));
  rejects(() => h.api.spawnManaged(request({ command: requested.replace('aed62990b91e', 'aaaaaaaaaaaa') })));
  assert.equal(calls.length, 1);
});
test('a malformed or conflicting authenticated gate is refused before any process starts', () => {
  for (const edit of [c => { c.gateToken = 'short'; }, c => { c.gatePipe = '\\\\other\\pipe\\gate-claude-code-' + 'b'.repeat(32); }, c => { c.approved[0].requestedPath = 'relative\\claude.exe'; }, c => { c.approved.push({ path: 'C:\\Guard\\Another\\claude.exe', sha256: 'b'.repeat(64), requestedPath: c.approved[0].path }); }]) { const h = load(), cfg = config(); edit(cfg); rejects(() => h.api.initCodeTransport(cfg, () => childFixture())); }
});

test('CLI cwd maps only default locations to the permanent Guard workspace and refuses other selected projects clearly', () => {
  const h = harness(), workspace = config().stateRoot + '\\Workspace';
  for (const cwd of [undefined, workspace, config().stateRoot, 'C:\\Guard\\Runtime']) {
    const child = h.api.spawnManaged(request({ cwd })); assert.equal(packet(child).data.cwd, workspace);
  }
  assert.throws(() => h.api.spawnManaged(request({ cwd: 'C:\\OtherProject' })), error => error.code === 'ERR_GUARD_CODE_WORKSPACE_REQUIRED' && error.message === 'Откройте проект в постоянной рабочей папке Guard.');
  const probe = h.api.spawnManaged(request({ args: ['--version'], cwd: 'C:\\OtherProject' })); assert.equal(packet(probe).data.cwd, workspace);
});
test('global managed job and workspace are immutable and all packets use the native size ceiling', () => {
  const h = harness(); assert.equal(h.api.MAX_PACKET_BYTES, 262144);
  const child = h.api.spawnManaged(request()); const p = packet(child).data; assert.equal(p.codeJobName, config().codeJobName); assert.equal(p.cwd, config().stateRoot + '\\Workspace'); assert.equal(Object.keys(p).length, 15);
  for (const edit of [c => { c.codeJobName = 'Local\\gate-code-job-' + 'd'.repeat(32); }, c => { c.workspaceRoot = 'C:\\OtherProject'; }]) { const f = load(), cfg = config(); edit(cfg); rejects(() => f.api.initCodeTransport(cfg, () => childFixture())); }
});

test('verified tool selection overrides vendor and managed settings case variants and remains immutable', () => {
  const h = load(), cfg = config(), child = childFixture();
  cfg.tools = { environment: { PATH: 'C:\\Guard\\CodeTools\\Git\\cmd;C:\\Guard\\CodeTools\\PowerShell', CLAUDE_CODE_GIT_BASH_PATH: 'C:\\Guard\\CodeTools\\Git\\bin\\bash.exe', POWERSHELL_UPDATECHECK: 'Off' } };
  const wanted = cfg.tools.environment.PATH;
  h.api.initCodeTransport(cfg, () => child);
  cfg.tools.environment.PATH = 'C:\\Untrusted';
  h.api.spawnManaged(request({ env: { Path: 'C:\\Other', path: 'C:\\Other2', ANTHROPIC_AUTH_TOKEN: 'fixture-auth' } }));
  const env = packet(child).data.env;
  assert.equal(env.PATH, wanted); assert.equal(env.Path, undefined); assert.equal(env.path, undefined); assert.equal(env.ANTHROPIC_AUTH_TOKEN, 'fixture-auth');
  const settings = h.api.mergeManagedSettings({ env: { Path: 'C:\\Other', HTTPS_PROXY: 'http://bypass.invalid' } });
  assert.equal(settings.env.PATH, wanted); assert.equal(settings.env.Path, undefined); assert.equal(settings.env.HTTPS_PROXY, cfg.relayURL);
  const other = load(), unsafe = config(); unsafe.tools = { environment: { HTTPS_PROXY: 'http://bypass.invalid' } }; rejects(() => other.api.initCodeTransport(unsafe, () => childFixture()));
});

test('approved buffered CLI commands preserve framed input and fragmented UTF8, with explicit exit handling', async () => {
  const h = harness(), req = request();
  const pending = h.api.runManagedCommand(req.command, req.args, { env: req.env, cwd: req.cwd, stdin: 'plugin-input', ignoreExitCode: true });
  const output = Buffer.from('готово'); h.child.stdout.write(output.subarray(0, 3)); h.child.stdout.write(output.subarray(3)); h.child.stderr.write('fixture-warning');
  const input = packet(h.child); assert.equal(input.trailing.toString(), 'plugin-input'); assert.equal(Object.keys(input.data).length, 15);
  h.child.emit('close', 7); const value = await pending;
  assert.equal(value.code, 7); assert.equal(value.stdout, 'готово'); assert.equal(value.stderr, 'fixture-warning'); assert.ok(value.stdoutBuffer.equals(output));
  const failed = harness(), request2 = request(); const rejected = failed.api.runManagedCommand(request2.command, request2.args, { env: request2.env });
  failed.child.emit('close', 9); await assert.rejects(rejected, error => error.code === 'ERR_GUARD_CODE_EXIT' && error.result.code === 9);
});

test('buffered CLI deadlines and output floods kill the broker and return only bounded partial results', async () => {
  const h = harness(), req = request(); h.child.kill = () => { h.child.kills++; setImmediate(() => h.child.emit('close', 125)); return true; };
  const timeout = h.api.runManagedCommand(req.command, req.args, { env: req.env, timeout: 10, ignoreExitCode: true });
  const timeoutAssertion = assert.rejects(timeout, error => error.code === 'ETIMEDOUT' && error.result.code === null);
  await Promise.all([timeoutAssertion, new Promise(resolve => setTimeout(resolve, 20))]); assert.equal(h.child.kills, 1);
  const flood = harness(); flood.child.kill = () => { flood.child.kills++; setImmediate(() => flood.child.emit('close', 125)); return true; };
  const rejected = flood.api.runManagedCommand(req.command, req.args, { env: req.env });
  flood.child.stdout.write(Buffer.alloc(10 * 1024 * 1024)); flood.child.stderr.write('x');
  await assert.rejects(rejected, error => error.code === 'ERR_GUARD_CODE_MAXBUFFER' && error.result.stdoutBuffer.length + error.result.stderrBuffer.length <= 10 * 1024 * 1024);
  assert.equal(flood.child.kills, 1);
});


test('projects inside the permanent workspace retain their canonical working directory', () => {
  const h = harness(), nested = config().stateRoot + '\\Workspace\\my-project\\src';
  h.api.spawnManaged(request({ cwd: nested })); assert.equal(packet(h.child).data.cwd, nested);
  for (const cwd of [config().stateRoot + '\\Workspace-other', config().stateRoot + '\\Workspace\\..\\Other']) {
    const outside = harness(); assert.throws(() => outside.api.spawnManaged(request({ cwd }))); assert.equal(outside.calls.length, 0);
  }
});
