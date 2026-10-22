'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const runtime = require('../src/runtime.cjs'), preparation = require('../src/code-preparation.cjs');
const toolsModule = require('../src/code-tools.cjs');
const assetModule = require('../src/native-code-asset.cjs');
const policyModule = require('../src/policy.cjs');
const checker = require('../src/ip-check.cjs'), relays = require('../src/relay.cjs');
const { NetworkFence } = require('../src/fence.cjs');
const gateModule = require('../src/code-gate.cjs'), channelModule = require('../src/channel.cjs'), inspectorModule = require('../src/inspector.cjs');
const child = require('node:child_process');
let context;
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function until(check) { for (let n = 0; n < 200; n++) { if (check()) return; await turn(); } throw Error('Code controller fixture condition was not reached'); }
const source = 'C:\\Program Files\\WindowsApps\\Claude_fixture\\app\\Claude.exe';
const input = { mode: 'network', interval: 2, claudePath: source, codeEnabled: true };
// Module substitutions are confined to this Node test worker. No executable or UAC is used.
runtime.prepareRuntime = async (...args) => {
  const c = context; c.runtimeOptions = args[4]; c.runtimeStatus = args[3]; c.events.push('runtime-prepare');
  if (c.runtimePending) await c.runtimePending.promise;
  c.events.push('runtime-prepared'); return c.runtime;
};
assetModule.ensureNativeCodeAsset = async (...args) => {
  const c = context; c.assetArguments = args; c.assetCalls++; c.events.push('asset-download');
  assert.equal(c.controller.policy.pinned, '203.0.113.7'); assert.equal(c.relay.unlocked, true);
  assert.equal(args[2].active(), true); assert.equal(args[2].signal.aborted, false);
  if (c.assetError) throw Error('verified native asset unavailable');
  if (c.onAssetDownload) return c.onAssetDownload();
  if (c.assetPending) await c.assetPending.promise;
  return { path: c.assetPath };
};
preparation.prepareCodeFiles = async (...args) => {
  const c = context; c.codeFileArguments = args; c.events.push('code-files'); c.fileCalls++;
  if (c.filesError) throw Error('CodeHost missing or unsupported fixture source');
  if (c.filesPending) await c.filesPending.promise;
  return c.code;
};
toolsModule.prepareCodeTools = async (...args) => {
  const c = context; c.toolArguments = args; c.events.push('code-tools');
  if (c.toolsError) throw Error('verified Code tools are missing');
  if (c.toolsPending) await c.toolsPending.promise;
  return c.tools;
};
checker.initialIP = async () => { const c = context; c.events.push('initial-ip'); c.ipChecks++; return c.initialReply || { ip: '203.0.113.7', country_code: 'NL' }; };
checker.currentIP = async () => {
  const c = context; c.events.push('current-ip'); c.ipChecks++;
  if (c.onCurrentIP) return c.onCurrentIP();
  return { ip: c.currentAddress || '203.0.113.7' };
};
policyModule.networkFingerprint = () => context.fingerprint || 'fixture-network';
class Relay extends EventEmitter {
  constructor(options) { super(); this.owner = context; this.upstream = options?.upstream; this.port = 12345; this.unlocked = false; this.closed = false; this.checkToken = 'b'.repeat(64); this.owner.relay = this; }
  pinIPFamily(family) { this.ipFamily = family; this.owner.events.push('family-pin'); }
  async start() { this.owner.events.push('relay-listen'); return this.port; }
  unlock() { this.unlocked = true; this.owner.events.push('relay-unlock'); }
  resume() { this.unlock(); }
  pause() { this.unlocked = false; this.owner.events.push('relay-pause'); }
  close() { this.closed = true; this.unlocked = false; this.owner.events.push('relay-close'); }
}
relays.NetworkRelay = Relay;
class Gate {
  constructor(config, active) { this.config = config; this.active = active; this.owner = context; this.owner.gate = this; this.closed = false; this.pipe = '\\\\.\\pipe\\gate-claude-code-' + 'c'.repeat(32); this.token = 'c'.repeat(64); }
  async listen() { this.owner.events.push('gate-listen'); }
  close() { if (!this.closed) { this.closed = true; this.owner.events.push('gate-close'); } }
}
gateModule.CodeGate = Gate;
class Channel extends EventEmitter {
  constructor() { super(); this.closed = false; this.path = 'fixture-channel'; this.token = 'd'.repeat(64); this.socket = {}; }
  async listen() {}
  async connected() {}
  async command() { return {}; }
  close() { this.closed = true; context.events.push('channel-close'); }
}
channelModule.Channel = Channel;
inspectorModule.Inspector = class extends EventEmitter { async start() {} stop() { context.events.push('inspector-stop'); } };
NetworkFence.prepare = async (...args) => {
  const c = context; c.fenceOptions = args[2]; c.events.push('fence-prepare'); c.fenceCalls++;
  if (c.fencePending) await c.fencePending.promise;
  if (c.fencePrepareError) throw Error('fixture native install not confirmed');
  const code = args[2].code;
  const fence = new EventEmitter(); fence.installed = true; fence.closed = false; fence.socket = { destroyed: false };
  fence.codeProof = code ? { sid: code.containerSid, jobName: code.codeJobName, filters: c.badCodeProof ? 9 : 10 } : null;
  fence.close = async () => {
    c.events.push('fence-close-begin');
    if (c.fenceCloseError) throw Error('fixture drain not confirmed');
    if (c.fenceClosePending) await c.fenceClosePending.promise;
    fence.installed = false; c.events.push('fence-drained');
  };
  c.fence = fence; return fence;
};
function processFixture(owner) {
  const process = new EventEmitter(); process.stdin = new PassThrough(); process.stdout = new PassThrough(); process.stderr = new PassThrough();
  process.exitCode = null; process.signalCode = null; process.killed = false;
  process.finish = status => {
    if (process.exitCode != null) return;
    process.exitCode = status; process.stdout.end(); process.stderr.end(); process.emit('exit', status); process.emit('close', status);
  };
  process.kill = () => { process.killed = true; queueMicrotask(() => process.finish(125)); return true; };
  owner.processes.push(process); return process;
}
child.spawn = (executable, args, options) => {
  const c = context, process = processFixture(c);
  if (args[0] === '--prepare-state') {
    c.prepareProcess = process; c.events.push('state-helper'); c.prepareOptions = options;
    process.once('close', () => c.events.push('state-helper-closed'));
    if (c.ignoreStateKill) process.kill = () => { process.killed = true; return true; };
    const chunks = []; process.stdin.on('data', chunk => chunks.push(chunk));
    process.stdin.once('finish', () => queueMicrotask(() => {
      if (process.exitCode != null) return;
      const bytes = Buffer.concat(chunks), length = bytes.readUInt32LE(0);
      assert.equal(length, bytes.length - 4); c.preparePacket = JSON.parse(bytes.subarray(4).toString('utf8')); c.events.push('state-request');
      if (c.stateProcessError) { process.emit('error', Error('fixture helper failure')); return; }
      if (c.holdStatePreparation) return;
      const reply = c.stateReply || { prepared: true, name: c.code.containerName, sid: c.code.containerSid, entries: 0 };
      process.stdout.write(c.hugeStateReply ? Buffer.alloc(8193, 0x20) : JSON.stringify(reply));
      if (process.exitCode == null && !process.killed) { c.events.push('state-prepared'); process.finish(0); }
    }));
  } else {
    c.host = process; c.hostSpawns++; c.runtimeEnvironment = options.env; c.events.push('runtime-spawn');
    queueMicrotask(() => process.stdout.write('{"pid":42}\n'));
    process.stdin.once('finish', () => { if (!c.holdHostExit) queueMicrotask(() => process.finish(0)); });
  }
  return process;
};
const { GuardController } = require('../src/controller.cjs');
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-code-controller-'));
  const c = { events: [], processes: [], assetCalls: 0, fileCalls: 0, fenceCalls: 0, hostSpawns: 0, ipChecks: 0, cleanups: 0 };
  c.assetPath = path.join(root, 'CodeAssets', 'a'.repeat(64), 'win32-x64.zst');
  c.runtime = { executable: 'C:\\Guard\\Runtime-' + 'a'.repeat(24) + '\\Claude.exe', profile: 'C:\\Guard\\Profile', signature: 'Valid', version: '3.1623.0' };
  c.code = {
    hostPath: 'C:\\GuardApp\\resources\\CodeHost.exe', stateRoot: 'C:\\Guard\\CodeState', workspaceRoot: 'C:\\Guard\\CodeState\\Workspace', runtimeExecutable: c.runtime.executable,
    containerName: 'gate-code-' + 'a'.repeat(24), containerSid: 'S-1-15-2-1-2-3-4-5-6-7',
    approved: [{ path: 'C:\\Guard\\CodeBin\\' + 'b'.repeat(64) + '\\claude.exe', sha256: 'b'.repeat(64), requestedPath: 'C:\\Guard\\Profile\\claude-code\\claude.exe' }],
    cleanupProfile: async () => { c.cleanups++; c.events.push('profile-cleanup'); }
  };
  c.tools = { toolRoots: ['C:\\Guard\\CodeTools\\Git-' + 'e'.repeat(64), 'C:\\Guard\\CodeTools\\PowerShell-' + 'f'.repeat(64)],
    environment: { PATH: 'C:\\Guard\\CodeTools\\Git-' + 'e'.repeat(64) + '\\cmd;C:\\Guard\\CodeTools\\PowerShell-' + 'f'.repeat(64), GIT_CONFIG_NOSYSTEM: '1' } };
  context = c; c.controller = new GuardController(root, root); c.controller.routeFingerprint = async () => '';
  c.proxyDescriptor = Object.freeze({ kind: 'direct', host: '', port: 0, fingerprint: 'd'.repeat(64) });
  c.controller.networkProxyConfiguration = async () => c.proxyDescriptor;
  c.controller.requestDestinationIP = async (_epoch, hostname) => ({ hostname, ip: hostname === 'claude.ai' ? '203.0.113.20' : '203.0.113.21', country_code: 'NL' });
  t.after(async () => {
    c.runtimePending?.resolve(); c.assetPending?.resolve(); c.filesPending?.resolve(); c.toolsPending?.resolve(); c.fencePending?.resolve(); c.fenceClosePending?.resolve();
    c.controller.stop(); for (const process of c.processes) process.finish(0);
    await turn(); await turn(); await fs.rm(root, { recursive: true, force: true });
  });
  return c;
}

test('Code downloads only after pinning, prepares before WFP, and launches only after fresh IP confirmation', async t => {
  const c = await fixture(t); await c.controller.start(input);
  assert.equal(c.controller.state, 'starting'); assert.equal(c.hostSpawns, 1); assert.deepEqual(c.runtimeOptions, { codeEnabled: true });
  assert.deepEqual(Object.keys(c.preparePacket).sort(), ['containerName', 'containerSid', 'executable', 'executableSHA256', 'runtimeExecutable', 'stateRoot', 'toolRoots', 'version'].sort());
  assert.deepEqual(c.preparePacket.toolRoots, c.tools.toolRoots);
  assert.ok(c.events.indexOf('code-tools') < c.events.indexOf('state-helper'));
  assert.equal(c.toolArguments[1], c.controller.resources);
  assert.deepEqual(c.toolArguments[2], {
    gitArchive: path.join(c.controller.resources, 'CodeTools', toolsModule.SOURCE_POLICY.git.archiveName),
    powerShellArchive: path.join(c.controller.resources, 'CodeTools', toolsModule.SOURCE_POLICY.powershell.archiveName)
  });
  assert.equal(c.preparePacket.version, 1); assert.equal(c.preparePacket.containerSid, c.code.containerSid); assert.equal(c.preparePacket.executableSHA256, c.code.approved[0].sha256);
  assert.ok(c.events.indexOf('initial-ip') < c.events.indexOf('relay-unlock'));
  assert.ok(c.events.indexOf('relay-unlock') < c.events.indexOf('asset-download'));
  assert.ok(c.events.indexOf('asset-download') < c.events.indexOf('code-files'));
  assert.ok(c.events.indexOf('state-prepared') < c.events.indexOf('fence-prepare'));
  assert.ok(c.events.indexOf('fence-prepare') < c.events.lastIndexOf('current-ip'));
  assert.ok(c.events.lastIndexOf('current-ip') < c.events.indexOf('runtime-spawn'));
  assert.equal(c.ipChecks, 3); assert.equal(c.assetArguments[0], c.controller.root); assert.equal(c.assetArguments[1], c.relay.port);
  assert.deepEqual(c.codeFileArguments.slice(4), [undefined, { nativeAssetPath: c.assetPath }]);
  const config = JSON.parse(c.runtimeEnvironment.PROXY_GUARD_CONFIG);
  assert.deepEqual(config.code.tools, { environment: c.tools.environment });
  assert.equal(Object.isFrozen(c.code.tools), true); assert.equal(Object.isFrozen(c.code.tools.environment), true);
  assert.equal(config.code.gatePipe, c.gate.pipe); assert.equal(config.code.gateToken, c.gate.token); assert.equal(config.code.workspaceRoot, c.code.workspaceRoot);
  assert.equal(config.code.relayURL, 'http://127.0.0.1:12345'); assert.match(config.code.codeJobName, /^Global\\gate-code-job-[a-f0-9]{32}$/);
  assert.equal(c.fenceOptions.code.codeJobName, config.code.codeJobName); assert.equal(c.fenceOptions.code.relayExecutable, process.execPath);
  assert.ok(!Object.hasOwn(config.code, 'cleanupProfile')); assert.ok(!c.runtimeEnvironment.PROXY_GUARD_CONFIG.includes('cleanupProfile'));
});
test('CodeGate is active only for the current runtime, matching fence proof, pinned IP and open relay', async t => {
  const c = await fixture(t); await c.controller.start(input); const controller = c.controller;
  assert.deepEqual(c.gate.active(), { runtimePID: 42 });
  for (const state of ['checking', 'rechecking', 'blocked', 'idle']) { controller.state = state; assert.equal(c.gate.active(), null); }
  controller.state = 'running'; assert.deepEqual(c.gate.active(), { runtimePID: 42 });
  c.relay.pause(); assert.equal(c.gate.active(), null); c.relay.resume();
  for (const change of [{ sid: 'foreign' }, { jobName: 'foreign' }, { filters: 9 }]) {
    const saved = c.fence.codeProof; c.fence.codeProof = { ...saved, ...change }; assert.equal(c.gate.active(), null); c.fence.codeProof = saved;
  }
  c.gate.closed = true; assert.equal(c.gate.active(), null); c.gate.closed = false;
  c.fence.installed = false; assert.equal(c.gate.active(), null); c.fence.installed = true;
  c.fence.closing = true; assert.equal(c.gate.active(), null); c.fence.closing = false;
  c.fence.closed = true; assert.equal(c.gate.active(), null); c.fence.closed = false;
  const socket = c.fence.socket;
  c.fence.socket = null; assert.equal(c.gate.active(), null); c.fence.socket = socket;
  socket.destroyed = true; assert.equal(c.gate.active(), null); socket.destroyed = false;
  c.host.killed = true; assert.equal(c.gate.active(), null); c.host.killed = false;
  controller.runtimePID = null; assert.equal(c.gate.active(), null); controller.runtimePID = 42;
  const policy = controller.policy; controller.policy = { blocked: false, pinned: null };
  assert.equal(c.gate.active(), null); controller.policy = policy;
  controller.policy.block(); assert.equal(c.gate.active(), null);
});
test('Code captures the static system proxy and pins family and both destination exits before downloading', async t => {
  const c = await fixture(t);
  c.proxyDescriptor = Object.freeze({ kind: 'http', host: '127.0.0.1', port: 9697, fingerprint: 'e'.repeat(64) });
  c.onAssetDownload = () => {
    assert.equal(c.controller.destinationPolicies.size, 2); assert.equal(c.relay.ipFamily, 4);
    assert.equal(c.controller.destinationPolicies.get('claude.ai').pinned, '203.0.113.20');
    return { path: c.assetPath };
  };
  await c.controller.start(input);
  assert.deepEqual(c.relay.upstream, c.proxyDescriptor); assert.equal(Object.isFrozen(c.relay.upstream), true);
  assert.ok(c.events.indexOf('family-pin') < c.events.indexOf('current-ip'));
  assert.equal(c.hostSpawns, 1); assert.equal(c.controller.policy.blocked, false);
});
test('an initial RU destination prevents every Code download and guest launch', async t => {
  const c = await fixture(t);
  c.controller.requestDestinationIP = async (_epoch, hostname) => ({ hostname, ip: '203.0.113.20', country_code: 'RU' });
  await c.controller.start(input);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.assetCalls, 0); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
});
test('stable mixed-family destination exits are pinned independently before Code starts', async t => {
  const c = await fixture(t);
  c.controller.requestDestinationIP = async (_epoch, hostname) => ({ hostname, ip: hostname === 'claude.ai' ? '2001:db8::20' : '203.0.113.21', country_code: 'NL' });
  await c.controller.start(input); await c.controller.poll(c.controller.epoch);
  assert.equal(c.controller.policy.pinned, '203.0.113.7');
  assert.equal(c.controller.destinationPolicies.get('claude.ai').pinned, '2001:db8::20');
  assert.equal(c.controller.destinationPolicies.get('api.anthropic.com').pinned, '203.0.113.21');
  assert.equal(c.hostSpawns, 1); assert.equal(c.controller.policy.blocked, false); assert.equal(c.relay.unlocked, true);
});
test('the final Code confirmation checks destination exits even when its route read fails', async t => {
  const c = await fixture(t), normal = c.controller.requestDestinationIP; let routes = 0;
  c.controller.routeFingerprint = async () => { if (++routes > 1) throw Error('fixture route timeout'); return 'route-A'; };
  c.controller.requestDestinationIP = async (...args) => {
    const result = await normal(...args);
    return c.fenceCalls && result.hostname === 'claude.ai' ? { ...result, ip: '203.0.113.22' } : result;
  };
  await c.controller.start(input); await until(() => c.cleanups === 1);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.hostSpawns, 0); assert.equal(c.gate.closed, true);
  assert.ok(c.controller.events.some(event => event.kind === 'blocked' && event.message.includes('маршрута Claude изменился')));
});
test('a removed system proxy during WFP approval prevents the final Code launch', async t => {
  const c = await fixture(t);
  c.proxyDescriptor = Object.freeze({ kind: 'http', host: '127.0.0.1', port: 9697, fingerprint: 'e'.repeat(64) });
  c.controller.networkProxyConfiguration = async () => c.fenceCalls ? { kind: 'direct', host: '', port: 0, fingerprint: 'd'.repeat(64) } : c.proxyDescriptor;
  await c.controller.start(input); await until(() => c.cleanups === 1);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.hostSpawns, 0); assert.equal(c.gate.closed, true);
});
test('gate closes first, and the AppContainer profile is deleted only after host exit and confirmed fence drain', async t => {
  const c = await fixture(t); c.holdHostExit = true; c.fenceClosePending = deferred(); await c.controller.start(input);
  const before = c.events.length; c.controller.stop(); const events = c.events.slice(before);
  assert.equal(events[0], 'gate-close'); assert.equal(c.cleanups, 0); assert.ok(!events.includes('fence-close-begin'));
  c.host.finish(0); await until(() => c.events.includes('fence-close-begin')); assert.equal(c.cleanups, 0);
  c.fenceClosePending.resolve(); await until(() => c.cleanups === 1);
  assert.ok(c.events.indexOf('fence-drained') < c.events.indexOf('profile-cleanup'));
});
test('unconfirmed native drain retains the AppContainer profile and never reopens its gate', async t => {
  const c = await fixture(t); c.fenceCloseError = true; await c.controller.start(input); c.controller.stop(); await turn(); await turn();
  assert.equal(c.gate.closed, true); assert.equal(c.cleanups, 0); assert.equal(c.controller.state, 'blocked');
});
test('a missing CodeHost or unsupported Code source refuses Code startup before WFP and runtime launch', async t => {
  const c = await fixture(t); c.filesError = true; await c.controller.start(input);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.ipChecks, 2); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
});
test('wrong native Code proof prevents final confirmation, gate creation and runtime launch', async t => {
  const c = await fixture(t); c.badCodeProof = true; await c.controller.start(input); await until(() => c.cleanups === 1);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.ipChecks, 2); assert.equal(c.hostSpawns, 0); assert.equal(c.gate, undefined);
});
test('bad, foreign or oversized prepare-state acknowledgements fail before native fence and guest launch', async t => {
  for (const reply of [{ prepared: false }, { prepared: true, name: 'foreign', sid: 'foreign', entries: 0 }, 'oversized']) {
    const c = await fixture(t); if (reply === 'oversized') c.hugeStateReply = true; else c.stateReply = reply;
    await c.controller.start(input); await until(() => c.cleanups === 1);
    assert.equal(c.controller.state, 'blocked'); assert.equal(c.ipChecks, 2); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
  }
});
test('stop while trusted Code files are pending latches cancellation and cleans the late unused profile without spawning', async t => {
  const c = await fixture(t); c.filesPending = deferred(); const starting = c.controller.start(input);
  await until(() => c.fileCalls === 1); c.controller.stop(); await assert.rejects(c.controller.start(input), /перезапуска/);
  c.filesPending.resolve(); await starting; assert.equal(c.cleanups, 1); assert.equal(c.hostSpawns, 0); assert.equal(c.ipChecks, 2);
});
test('stop during state ACL preparation terminates its helper before cleaning the unused profile', async t => {
  const c = await fixture(t); c.holdStatePreparation = true; const starting = c.controller.start(input);
  await until(() => c.preparePacket); c.controller.stop(); await starting;
  assert.equal(c.prepareProcess.killed, true); assert.equal(c.cleanups, 1); assert.equal(c.hostSpawns, 0); assert.equal(c.ipChecks, 2);
  assert.ok(c.events.indexOf('state-helper-closed') < c.events.indexOf('profile-cleanup'));
});
test('a late fence result after cancellation drains before cleanup; no Code process or runtime can start', async t => {
  const c = await fixture(t); c.fencePending = deferred(); c.fenceClosePending = deferred(); const starting = c.controller.start(input);
  await until(() => c.fenceCalls === 1); c.controller.stop(); assert.equal(c.cleanups, 0);
  c.fencePending.resolve(); await until(() => c.events.includes('fence-close-begin')); assert.equal(c.cleanups, 0);
  c.fenceClosePending.resolve(); await starting;
  assert.equal(c.cleanups, 1); assert.equal(c.hostSpawns, 0); assert.equal(c.ipChecks, 2);
});
test('ordinary Chat mode does not prepare or expose Code configuration', async t => {
  const c = await fixture(t); await c.controller.start({ ...input, codeEnabled: false });
  assert.equal(c.fileCalls, 0); assert.equal(c.fenceOptions.code, undefined); assert.equal(c.runtimeOptions, undefined);
  assert.equal(c.gate, undefined); assert.equal(JSON.parse(c.runtimeEnvironment.PROXY_GUARD_CONFIG).code, undefined); assert.equal(c.hostSpawns, 1);
  assert.equal(c.assetCalls, 0); assert.ok(c.events.indexOf('fence-prepare') < c.events.indexOf('initial-ip'));
});

test('persistent CodeState and Workspace files survive normal shutdown and temporary profile cleanup', async t => {
  const c = await fixture(t);
  c.code.stateRoot = path.join(c.controller.root, 'CodeState'); c.code.workspaceRoot = path.join(c.code.stateRoot, 'Workspace');
  await fs.mkdir(c.code.workspaceRoot, { recursive: true });
  const marker = path.join(c.code.workspaceRoot, 'owned-project.txt'); await fs.writeFile(marker, 'persistent fixture');
  await c.controller.start(input); c.controller.stop(); await until(() => c.cleanups === 1);
  assert.equal(await fs.readFile(marker, 'utf8'), 'persistent fixture');
});

test('missing verified Code sidecars fail closed before state preparation, fence or runtime launch', async t => {
  const c = await fixture(t); c.toolsError = true;
  await c.controller.start(input); await until(() => c.cleanups === 1);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.prepareProcess, undefined);
  assert.equal(c.fenceCalls, 0); assert.equal(c.ipChecks, 2); assert.equal(c.hostSpawns, 0);
});
test('cancelling tool provisioning cannot prepare state or start Code after the tools eventually finish', async t => {
  const c = await fixture(t); c.toolsPending = deferred(); const starting = c.controller.start(input);
  await until(() => c.toolArguments); c.controller.stop(); await assert.rejects(c.controller.start(input), /перезапуска/);
  c.toolsPending.resolve(); await starting;
  assert.equal(c.cleanups, 1); assert.equal(c.prepareProcess, undefined); assert.equal(c.ipChecks, 2); assert.equal(c.hostSpawns, 0);
});

test('stop during Code runtime preparation latches cancellation and ignores late preparation status', async t => {
  const c = await fixture(t); c.runtimePending = deferred(); const starting = c.controller.start(input);
  await until(() => c.runtimeStatus); c.controller.stop();
  const message = c.controller.message; c.runtimeStatus('late copy progress');
  assert.equal(c.controller.message, message); assert.equal(c.controller.state, 'blocked');
  await assert.rejects(c.controller.start(input), /перезапуска/);
  c.runtimePending.resolve(); await starting;
  assert.equal(c.fileCalls, 0); assert.equal(c.cleanups, 0); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
});

test('a cancelled Chat preparation cannot clear the cancellation latch of a newer Code preparation', async t => {
  const c = await fixture(t), oldCopy = deferred(), codeCopy = deferred(); c.runtimePending = oldCopy;
  const oldStart = c.controller.start({ ...input, codeEnabled: false }); await until(() => c.runtimeStatus);
  c.controller.stop(); assert.equal(c.controller.state, 'idle');
  c.runtimePending = codeCopy; const codeStart = c.controller.start(input);
  oldCopy.resolve(); await oldStart;
  assert.equal(c.controller.codePreparationPending, true);
  c.controller.stop(); assert.equal(c.controller.state, 'blocked');
  codeCopy.resolve(); await codeStart;
  assert.equal(c.fileCalls, 0); assert.equal(c.hostSpawns, 0);
});

test('state-helper cancellation settles within a bound while retaining its profile until a confirmed late close', { timeout: 5000 }, async t => {
  const c = await fixture(t); c.holdStatePreparation = true; c.ignoreStateKill = true;
  const starting = c.controller.start(input); await until(() => c.preparePacket); c.controller.stop();
  await starting;
  assert.equal(c.prepareProcess.killed, true); assert.equal(c.cleanups, 0);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
  await assert.rejects(c.controller.start(input), /перезапуска/);
  c.prepareProcess.finish(125); await until(() => c.cleanups === 1);
  assert.ok(c.events.indexOf('state-helper-closed') < c.events.indexOf('profile-cleanup'));
  c.controller.stop(); await turn(); assert.equal(c.cleanups, 1);
});

test('a helper error without close is bounded and cannot trigger profile cleanup while the helper survives', { timeout: 5000 }, async t => {
  const c = await fixture(t); c.stateProcessError = true; c.ignoreStateKill = true;
  await c.controller.start(input);
  assert.equal(c.prepareProcess.killed, true); assert.equal(c.cleanups, 0);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.ipChecks, 2); assert.equal(c.fenceCalls, 0);
  c.prepareProcess.finish(125); await until(() => c.cleanups === 1);
});

test('state-helper timeout fails closed even when termination produces no close event', async t => {
  const c = await fixture(t); c.holdStatePreparation = true; c.ignoreStateKill = true;
  c.controller.schedulePoll = () => {}; // Isolate this helper deadline from the separate monitor tests.
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const starting = c.controller.start(input); await until(() => c.preparePacket);
  t.mock.timers.tick(60000); assert.equal(c.prepareProcess.killed, true);
  t.mock.timers.tick(1000); await starting; t.mock.timers.reset();
  assert.equal(c.cleanups, 0); assert.equal(c.controller.state, 'blocked');
  assert.equal(c.ipChecks, 2); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
  c.prepareProcess.finish(125); await until(() => c.cleanups === 1);
});

test('unconfirmed fence installation retains the profile because no drain can be proven', async t => {
  const c = await fixture(t); c.fencePrepareError = true; await c.controller.start(input); await turn();
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.cleanups, 0);
  assert.equal(c.ipChecks, 2); assert.equal(c.hostSpawns, 0); assert.equal(c.gate, undefined);
});

test('cancelled fence installation with failed drain retains the profile and never launches', async t => {
  const c = await fixture(t); c.fencePending = deferred(); c.fenceCloseError = true;
  const starting = c.controller.start(input); await until(() => c.fenceCalls === 1);
  c.controller.stop(); c.fencePending.resolve(); await starting;
  assert.ok(c.events.includes('fence-close-begin')); assert.equal(c.cleanups, 0);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.ipChecks, 2); assert.equal(c.hostSpawns, 0);
});

test('Code opt-in requires the literal boolean true', async t => {
  for (const enabled of [undefined, 'true', 1]) {
    const c = await fixture(t); await c.controller.start({ ...input, codeEnabled: enabled });
    assert.equal(c.fileCalls, 0); assert.equal(c.toolArguments, undefined); assert.equal(c.runtimeOptions, undefined);
    assert.equal(c.fenceOptions.code, undefined); assert.equal(JSON.parse(c.runtimeEnvironment.PROXY_GUARD_CONFIG).code, undefined);
    c.controller.stop(); await turn();
  }
});

test('private runtime uses the native Code state config directory and discards an inherited config override', async t => {
  const inherited = process.env.CLAUDE_CONFIG_DIR;
  const external = 'C:\\Users\\outside-user\\.claude'; process.env.CLAUDE_CONFIG_DIR = external;
  try {
    for (const codeEnabled of [true, false]) {
      const c = await fixture(t); await c.controller.start({ ...input, codeEnabled });
      const config = JSON.parse(c.runtimeEnvironment.PROXY_GUARD_CONFIG);
      if (codeEnabled) {
        assert.equal(config.code.stateRoot, c.code.stateRoot);
        assert.equal(c.runtimeEnvironment.CLAUDE_CONFIG_DIR, path.join(config.code.stateRoot, '.claude'));
      } else {
        assert.equal(config.code, undefined); assert.equal(Object.hasOwn(c.runtimeEnvironment, 'CLAUDE_CONFIG_DIR'), false);
      }
      assert.equal(process.env.CLAUDE_CONFIG_DIR, external);
      c.controller.stop(); await turn();
    }
  } finally {
    if (inherited === undefined) delete process.env.CLAUDE_CONFIG_DIR;
    else process.env.CLAUDE_CONFIG_DIR = inherited;
  }
});

test('a rejected country, malformed initial IP or changed confirmation IP prevents every Code asset request', async t => {
  for (const mode of ['country', 'malformed', 'changed']) {
    const c = await fixture(t);
    if (mode === 'country') c.initialReply = { ip: '203.0.113.7', country_code: 'RU' };
    if (mode === 'malformed') c.initialReply = { ip: 'invalid', country_code: 'NL' };
    if (mode === 'changed') c.currentAddress = '203.0.113.8';
    await c.controller.start(input);
    assert.equal(c.controller.state, 'blocked'); assert.equal(c.relay.closed, true);
    assert.equal(c.assetCalls, 0); assert.equal(c.fileCalls, 0); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
  }
});

test('an unverified runtime signature or unavailable native asset never reaches Code preparation or guest launch', async t => {
  for (const mode of ['signature', 'asset']) {
    const c = await fixture(t);
    if (mode === 'signature') c.runtime.signature = 'Invalid'; else c.assetError = true;
    await c.controller.start(input);
    assert.equal(c.controller.state, 'blocked'); assert.equal(c.assetCalls, mode === 'signature' ? 0 : 1);
    assert.equal(c.fileCalls, 0); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
  }
});

test('stop aborts an in-flight native asset and rejects its late successful result', async t => {
  const c = await fixture(t); c.assetPending = deferred(); const starting = c.controller.start(input);
  await until(() => c.assetCalls === 1); c.controller.stop();
  assert.equal(c.assetArguments[2].signal.aborted, true); assert.equal(c.assetArguments[2].active(), false);
  assert.equal(c.relay.closed, true); await assert.rejects(c.controller.start(input), /перезапуска/);
  c.assetPending.resolve(); await starting;
  assert.equal(c.fileCalls, 0); assert.equal(c.fenceCalls, 0); assert.equal(c.hostSpawns, 0);
});

test('scheduled IP monitoring remains active during native asset download and aborts it on a changed IP', async t => {
  const c = await fixture(t); c.assetPending = deferred(); t.mock.timers.enable({ apis: ['setTimeout'] });
  const starting = c.controller.start(input); await until(() => c.assetCalls === 1);
  t.mock.timers.tick(2000); await until(() => c.ipChecks === 3 && !c.controller.checkTask);
  assert.equal(c.hostSpawns, 0); assert.equal(c.fenceCalls, 0); assert.equal(c.controller.policy.blocked, false);
  c.currentAddress = '203.0.113.8'; t.mock.timers.tick(2000);
  await until(() => c.controller.state === 'blocked');
  assert.equal(c.relay.closed, true); assert.equal(c.assetArguments[2].signal.aborted, true);
  c.assetPending.resolve(); await starting; t.mock.timers.reset();
  assert.equal(c.fileCalls, 0); assert.equal(c.hostSpawns, 0);
});

test('a paused asset download retries after fresh same-IP confirmation without blocking a stable session', async t => {
  const c = await fixture(t);
  c.onAssetDownload = () => {
    if (c.assetCalls === 1) { c.controller.pauseForRevalidation('fixture route transition'); throw Error('fixture paused stream'); }
    return { path: c.assetPath };
  };
  await c.controller.start(input);
  assert.equal(c.assetCalls, 2); assert.equal(c.ipChecks, 4); assert.equal(c.controller.policy.blocked, false);
  assert.equal(c.hostSpawns, 1); assert.equal(c.relay.unlocked, true);
  const first = c.events.indexOf('asset-download'), second = c.events.lastIndexOf('asset-download');
  assert.ok(c.events.slice(first + 1, second).includes('current-ip'));
});

test('scheduled monitoring continues through UAC and drains a late installed fence after an IP change', async t => {
  const c = await fixture(t); c.fencePending = deferred(); t.mock.timers.enable({ apis: ['setTimeout'] });
  const starting = c.controller.start(input); await until(() => c.fenceCalls === 1);
  t.mock.timers.tick(2000); await until(() => c.ipChecks === 3 && !c.controller.checkTask);
  c.currentAddress = '203.0.113.8'; t.mock.timers.tick(2000); await until(() => c.controller.state === 'blocked');
  assert.equal(c.cleanups, 0); assert.equal(c.hostSpawns, 0);
  c.fencePending.resolve(); await starting; t.mock.timers.reset();
  assert.equal(c.cleanups, 1); assert.equal(c.hostSpawns, 0);
  assert.ok(c.events.indexOf('fence-drained') < c.events.indexOf('profile-cleanup'));
});

test('a changed IP in the final post-WFP check closes the gate and never launches the private runtime', async t => {
  const c = await fixture(t); c.onCurrentIP = () => ({ ip: c.ipChecks >= 3 ? '203.0.113.8' : '203.0.113.7' });
  await c.controller.start(input); await until(() => c.cleanups === 1);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.hostSpawns, 0); assert.equal(c.gate.closed, true);
  assert.ok(c.events.indexOf('fence-prepare') < c.events.lastIndexOf('current-ip'));
});

test('a failed prelaunch route read cannot suppress a changed IP or launch Code', async t => {
  const c = await fixture(t); let routes = 0;
  c.controller.routeFingerprint = async () => { if (++routes > 1) throw Error('fixture route timeout'); return 'route-A'; };
  c.onCurrentIP = () => ({ ip: c.ipChecks >= 3 ? '203.0.113.8' : '203.0.113.7' });
  await c.controller.start(input); await until(() => c.cleanups === 1);
  assert.equal(c.ipChecks, 3); assert.equal(routes, 2); assert.equal(c.hostSpawns, 0);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.gate.closed, true); assert.equal(c.relay.closed, true);
  assert.ok(c.controller.events.some(event => event.kind === 'blocked' && event.message.includes('Внешний IP изменился')));
});

test('repeated prelaunch route failures still inspect unchanged IP and never reopen or launch Code', async t => {
  const c = await fixture(t); let routes = 0;
  c.controller.routeFingerprint = async () => { if (++routes > 1) throw Error('fixture route timeout'); return 'route-A'; };
  await c.controller.start(input); await until(() => c.cleanups === 1);
  assert.equal(c.ipChecks, 5); assert.equal(routes, 4); assert.equal(c.hostSpawns, 0);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.gate.closed, true); assert.equal(c.relay.closed, true);
  assert.equal(c.events.slice(c.events.indexOf('relay-pause') + 1).includes('relay-unlock'), false);
  assert.equal(c.controller.events.some(event => event.message.includes('Внешний IP изменился')), false);
});

test('a temporary prelaunch route failure requires a fresh successful route-IP-route bracket', async t => {
  const c = await fixture(t), order = []; let routes = 0;
  c.controller.routeFingerprint = async () => {
    if (++routes === 2) { order.push('route-error'); throw Error('fixture route timeout'); }
    order.push('route'); return 'route-A';
  };
  c.onCurrentIP = () => { order.push('ip'); return { ip: '203.0.113.7' }; };
  await c.controller.start(input);
  assert.equal(c.ipChecks, 4); assert.equal(c.hostSpawns, 1); assert.equal(c.controller.policy.blocked, false);
  assert.equal(c.relay.unlocked, true);
  assert.deepEqual(order, ['route', 'ip', 'route-error', 'ip', 'route', 'ip', 'route']);
});

test('stop after a failed prelaunch route read rejects the late unchanged IP without launching Code', async t => {
  const c = await fixture(t), answer = deferred(); let routes = 0;
  c.controller.routeFingerprint = async () => { if (++routes > 1) throw Error('fixture route timeout'); return 'route-A'; };
  c.onCurrentIP = () => c.ipChecks === 3 ? answer.promise : { ip: '203.0.113.7' };
  const starting = c.controller.start(input); await until(() => c.ipChecks === 3);
  c.controller.stop(); const stoppedEpoch = c.controller.epoch; answer.resolve({ ip: '203.0.113.7' }); await starting;
  assert.equal(c.controller.epoch, stoppedEpoch); assert.equal(c.controller.state, 'blocked'); assert.equal(c.hostSpawns, 0);
  assert.equal(c.gate.closed, true); assert.equal(c.relay.closed, true);
  assert.equal(c.events.slice(c.events.indexOf('relay-pause') + 1).includes('relay-unlock'), false);
});

test('stable-IP interface and route transitions are freshly rechecked before launch without blocking the session', async t => {
  const c = await fixture(t); let routes = 0;
  c.controller.routeFingerprint = async () => ++routes <= 2 ? 'before-route' : 'after-route';
  c.onCurrentIP = () => { if (c.ipChecks === 3) c.fingerprint = 'after-interface'; return { ip: '203.0.113.7' }; };
  await c.controller.start(input);
  assert.equal(c.ipChecks, 4); assert.equal(c.hostSpawns, 1); assert.equal(c.controller.policy.blocked, false);
  assert.equal(c.relay.unlocked, true); assert.equal(c.controller.route, 'after-route'); assert.equal(c.controller.fingerprint, 'after-interface');
  assert.ok(c.events.indexOf('relay-pause') < c.events.lastIndexOf('current-ip'));
});

test('final confirmation fails closed after bounded malformed answers and cancellation cannot launch after a late answer', async t => {
  const failed = await fixture(t); failed.onCurrentIP = () => ({ ip: failed.ipChecks >= 3 ? 'malformed' : '203.0.113.7' });
  await failed.controller.start(input); await until(() => failed.cleanups === 1);
  assert.equal(failed.ipChecks, 5); assert.equal(failed.hostSpawns, 0); assert.equal(failed.controller.state, 'blocked');
  const c = await fixture(t), finalReply = deferred();
  c.onCurrentIP = () => c.ipChecks === 3 ? finalReply.promise : { ip: '203.0.113.7' };
  const starting = c.controller.start(input); await until(() => c.ipChecks === 3); c.controller.stop();
  finalReply.resolve({ ip: '203.0.113.7' }); await starting;
  assert.equal(c.hostSpawns, 0); assert.equal(c.controller.state, 'blocked'); assert.equal(c.gate.closed, true);
});

test('losing the WFP socket during final confirmation or stopping at the launch transition prevents every guest spawn', async t => {
  const disconnected = await fixture(t); disconnected.fenceCloseError = true;
  disconnected.onCurrentIP = () => {
    if (disconnected.ipChecks === 3) disconnected.fence.socket.destroyed = true;
    return { ip: '203.0.113.7' };
  };
  await disconnected.controller.start(input);
  assert.equal(disconnected.controller.state, 'blocked'); assert.equal(disconnected.hostSpawns, 0); assert.equal(disconnected.cleanups, 0);
  const c = await fixture(t);
  c.controller.on('state', snapshot => { if (snapshot.state === 'starting') c.controller.stop(); });
  await c.controller.start(input);
  assert.equal(c.controller.state, 'blocked'); assert.equal(c.hostSpawns, 0); assert.equal(c.gate.closed, true);
});
