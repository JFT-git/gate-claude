'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const dgram = require('node:dgram');
const { once } = require('node:events');
const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);
const { NetworkFence, collectExecutables, installRequest } = require('../src/fence.cjs');

async function fixture(t, automaticCleanup = true) {
  const parent = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gate-fence-')));
  const root = path.join(parent, 'Runtime-' + 'a'.repeat(24));
  await fs.mkdir(root); await fs.writeFile(path.join(root, 'guard-manifest.json'), '{}');
  if (automaticCleanup) t.after(() => fs.rm(parent, { recursive: true, force: true }));
  return { parent, root, executable: path.join(root, 'Claude.exe') };
}

test('fence inventory includes bundled executables and rejects a foreign runtime path', async t => {
  const item = await fixture(t);
  await fs.writeFile(item.executable, Buffer.alloc(32));
  await fs.mkdir(path.join(item.root, 'resources'));
  await fs.writeFile(path.join(item.root, 'resources', 'Helper.EXE'), Buffer.alloc(32));
  await fs.writeFile(path.join(item.root, 'resources', 'library.node'), Buffer.alloc(32));
  const result = await collectExecutables(item);
  assert.equal(result.root, item.root); assert.equal(result.files.length, 2);
  assert.ok(result.files.some(file => file.endsWith('Helper.EXE')));
  await assert.rejects(collectExecutables({ executable: path.join(item.parent, 'Claude.exe') }), /отдельной копии/);
});

test('fence refuses symlink directories and executable links before UAC', { skip: process.platform === 'win32' && process.env.GATE_WINDOWS_SYMLINK_TEST !== '1' }, async t => {
  const item = await fixture(t);
  await fs.writeFile(item.executable, Buffer.alloc(32));
  const external = path.join(item.parent, 'external'); await fs.mkdir(external);
  await fs.writeFile(path.join(external, 'outside.exe'), Buffer.alloc(32));
  await fs.symlink(external, path.join(item.root, 'linked'));
  await assert.rejects(collectExecutables(item), /ссылка/);
  await fs.unlink(path.join(item.root, 'linked'));
  await fs.symlink(path.join(external, 'outside.exe'), path.join(item.root, 'outside.exe'));
  await assert.rejects(collectExecutables(item), /ссылка/);
});

test('fence validates port and encodes paths without shell or protocol injection', () => {
  for (const value of [0, -1, 65536, 1.1, NaN, '8080']) assert.throws(() => installRequest('C:\\Runtime-a', ['C:\\Runtime-a\\Claude.exe'], value));
  assert.throws(() => installRequest('C:\\Runtime-a', ['C:\\fake\nremove-after-job-exit'], 2345));
  const root = "C:\\User's directory\\Runtime-" + 'a'.repeat(24), file = root + '\\Claude.exe';
  const fields = installRequest(root, [file], 2345).trimEnd().split('\t');
  assert.equal(fields.length, 4); assert.equal(fields[0], 'install'); assert.equal(fields[2], '2345');
  assert.equal(Buffer.from(fields[1], 'base64').toString(), root);
  assert.equal(Buffer.from(fields[3], 'base64').toString(), file);
});

test('Code fence install binds its profile, shared job and relay image without changing the legacy request', () => {
  const code = { containerName: 'gate-code-' + 'a'.repeat(24), codeJobName: 'Global\\gate-code-job-' + 'b'.repeat(32), relayExecutable: path.resolve('Guard.exe') };
  const values = installRequest('root', ['file.exe'], 2345, code).trimEnd().split('\t');
  assert.equal(values.length, 7);
  assert.deepEqual(values.slice(4).map(value => Buffer.from(value, 'base64').toString()), [code.containerName, code.codeJobName, code.relayExecutable]);
  for (const changed of [{ containerName: 'foreign' }, { codeJobName: 'Local\\foreign' }, { relayExecutable: 'relative.exe' }, { relayExecutable: code.relayExecutable + '\n' }]) assert.throws(() => installRequest('root', ['file.exe'], 2345, { ...code, ...changed }));
});

test('fence rejects executable hard-link aliases', async t => {
  const item = await fixture(t); await fs.writeFile(item.executable, Buffer.alloc(32));
  await fs.link(item.executable, path.join(item.parent, 'alias.exe'));
  await assert.rejects(collectExecutables(item), /Не удалось проверить/);
});

test('abandon never sends a filter removal command', () => {
  const fence = new NetworkFence(), writes = [];
  fence.socket = { destroy() { writes.push('destroy'); }, write(value) { writes.push(value); } };
  fence.server = { close() { writes.push('close'); } };
  fence.installed = true; fence.abandon();
  assert.deepEqual(writes, ['destroy', 'close']); assert.equal(fence.installed, true);
});

test('native WFP fence blocks direct TCP, UDP and IPv6; survives broker loss; retires only after runtime exit', {
  skip: process.platform !== 'win32' || !process.env.GATE_FENCE_HELPER,
  timeout: 180000
}, async t => {
  const phase = value => { if (process.env.GATE_FENCE_DEBUG === '1') process.stderr.write('[fence-test] ' + value + '\n'); };
  phase('fixture-start');
  const item = await fixture(t, false); await fs.copyFile(process.execPath, item.executable);
  const helper = path.resolve(process.env.GATE_FENCE_HELPER);
  const sockets = new Set(), counts = { allowed: 0, other: 0, lan: 0, udp: 0, v6: 0 };
  async function server(label, host) {
    const listener = net.createServer(socket => {
      sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
      counts[label]++; socket.end('ok');
    });
    listener.listen(0, host); await once(listener, 'listening');
    t.after(() => { for (const socket of sockets) socket.destroy(); listener.close(); });
    return listener.address().port;
  }
  const allowed = await server('allowed', '127.0.0.1'), other = await server('other', '127.0.0.1');
  const lanAddress = Object.values(os.networkInterfaces()).flat().find(value => value?.family === 'IPv4' && !value.internal)?.address;
  assert.ok(lanAddress, 'native fence test requires an active IPv4 interface');
  const lan = await server('lan', '0.0.0.0'), v6 = await server('v6', '::1');
  const udp = dgram.createSocket('udp4'); udp.on('message', () => counts.udp++); udp.bind(0, '127.0.0.1'); await once(udp, 'listening');
  t.after(() => udp.close());
  const ports = { allowed, other, lan, lanAddress, v6, udp: udp.address().port };
  const probe = `
    const net=require('net'),dgram=require('dgram'),p=JSON.parse(process.argv[1]);
    async function tcp(host,port){return new Promise(resolve=>{const s=net.createConnection({host,port});let done=false;function end(ok){if(done)return;done=true;s.destroy();resolve(ok)}s.once('connect',()=>end(true));s.once('error',()=>end(false));s.setTimeout(700,()=>end(false));});}
    (async()=>{const result={allowed:await tcp('127.0.0.1',p.allowed),other:await tcp('127.0.0.1',p.other),lan:await tcp(p.lanAddress,p.lan),v6:await tcp('::1',p.v6)};const u=dgram.createSocket('udp4');u.on('error',()=>{});for(let i=0;i<3;i++)u.send(Buffer.from('fixture'),p.udp,'127.0.0.1',()=>{});await new Promise(r=>setTimeout(r,300));u.close();console.log(JSON.stringify(result));})();`;
  const invoke = async () => JSON.parse((await run(item.executable, ['-e', probe, JSON.stringify(ports)], { timeout: 15000, windowsHide: true })).stdout.trim());
  // All local fixture endpoints must be reachable without this fence, otherwise
  // a timeout would not be evidence that WFP enforced the proposed policy.
  phase('baseline-before-fence');
  assert.deepEqual(await invoke(), { allowed: true, other: true, lan: true, v6: true });
  assert.ok(counts.udp > 0); Object.keys(counts).forEach(key => { counts[key] = 0; });
  let fence, live, pendingFence, activePort=allowed;
  t.after(async () => {
    phase('cleanup-start');
    // A failed assertion still retires only our fixture filters after its probe
    // has exited. No system applications or other firewall rules are changed.
    if (live && live.exitCode == null && live.signalCode == null) { const exited = once(live, 'exit'); live.kill(); await exited; }
    try {
      if (pendingFence) {
        if (fence && !fence.closed) await fence.close();
        const replacement=await pendingFence.catch(() => null); if(replacement) fence=replacement;
        pendingFence=null;
      }
      if (!fence || (fence.closed && fence.installed)) fence = await NetworkFence.prepare(item, activePort, { helperPath: helper });
      if (!fence.closed) await fence.close();
      await fs.rm(item.parent, { recursive: true, force: true });
      phase('cleanup-complete');
    } catch { /* Keep fixture paths available for safe recovery if cleanup failed. */ }
  });
  phase('install-fence');
  fence = await NetworkFence.prepare(item, allowed, { helperPath: helper });
  assert.equal(fence.proof.persistent, true); assert.equal(fence.proof.paths, 1); assert.equal(fence.proof.filters, 6);
  phase('probe-fenced');
  assert.deepEqual(await invoke(), { allowed: true, other: false, lan: false, v6: false });
  assert.equal(counts.allowed, 1); assert.equal(counts.other, 0); assert.equal(counts.lan, 0); assert.equal(counts.udp, 0); assert.equal(counts.v6, 0);
  phase('overlapping-prepare-waits-for-old-broker');
  const previousFence=fence; let replacementSettled=false;
  pendingFence=NetworkFence.prepare(item,other,{helperPath:helper});
  pendingFence.then(() => { replacementSettled=true; }, () => { replacementSettled=true; });
  await new Promise(resolve => setTimeout(resolve,2000));
  assert.equal(replacementSettled,false,'a second broker replaced filters while the first broker still owned their lifecycle');
  await previousFence.close();
  fence=await pendingFence; pendingFence=null; activePort=other;
  await previousFence.close(); // A stale owner must not remove B's installed policy.
  Object.assign(ports,{allowed:other,other:allowed});
  assert.deepEqual(await invoke(), { allowed: true, other: false, lan: false, v6: false }, 'old broker cleanup removed the replacement policy');
  phase('broker-disconnect');
  fence.abandon(); await new Promise(resolve => setTimeout(resolve, 300));
  assert.deepEqual(await invoke(), { allowed: true, other: false, lan: false, v6: false }, 'broker disconnection removed persistent filters');
  phase('recover-fence');
  fence = await NetworkFence.prepare(item, activePort, { helperPath: helper });
  live = spawn(item.executable, ['-e', 'setTimeout(()=>{},30000)'], { windowsHide: true, stdio: 'ignore' });
  await once(live, 'spawn');
  phase('reject-premature-cleanup');
  await assert.rejects(fence.close(), /ещё работает|не подтверждено/);
  const exited = once(live, 'exit'); live.kill(); await exited;
  live = null;
  phase('runtime-stopped');
  assert.deepEqual(await invoke(), { allowed: true, other: false, lan: false, v6: false }, 'premature cleanup removed active runtime filters');
  fence = await NetworkFence.prepare(item, activePort, { helperPath: helper });
  phase('final-remove');
  await fence.close();
  assert.deepEqual(await invoke(), { allowed: true, other: true, lan: true, v6: true });
  phase('baseline-restored');
});
