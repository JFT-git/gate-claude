'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const run = promisify(require('node:child_process').execFile);
const { NativeServiceBackend, parseStatus } = require('../src/service-backend.cjs');
const { NetworkFence } = require('../src/fence.cjs');

const enabled = process.platform === 'win32' && process.env.GATE_SERVICE_HELPER && process.env.GATE_FENCE_HELPER;
test('installed service authorizes only a profile Runtime and launches the pinned fence without per-session UAC', {
  skip: !enabled, timeout: 180000
}, async t => {
  const servicePath = path.resolve(process.env.GATE_SERVICE_HELPER || '');
  const fencePath = path.resolve(process.env.GATE_FENCE_HELPER || '');
  const initial = parseStatus((await run(servicePath, ['--status'], { windowsHide: true, timeout: 10000 })).stdout);
  assert.equal(initial.state, 'running', 'fixture refuses to trigger install/update/UAC; install the owned current service first');
  assert.equal(initial.sessionRoutingSupported, true);

  const backend = new NativeServiceBackend({ helperPath: servicePath, ownerWindow: () => null });
  const suffix = process.pid.toString(16).padStart(24, '0').slice(-24);
  const outside = 'C:\\Windows\\Temp\\Runtime-' + suffix;
  await fs.mkdir(outside); t.after(() => fs.rm(outside, { recursive: true, force: true }));
  await assert.rejects(backend.launchFence({ root: outside, pipeName: 'gate-network-fence-' + 'e'.repeat(32), token: 'f'.repeat(64) }),
    error => error.code === 'SERVICE_LAUNCH_REJECTED');

  const parent = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gate-service-native-')));
  const root = path.join(parent, 'Runtime-' + 'a'.repeat(24));
  await fs.mkdir(root); await fs.writeFile(path.join(root, 'guard-manifest.json'), '{}');
  const executable = path.join(root, 'Claude.exe'); await fs.copyFile(process.execPath, executable);
  let fence;
  t.after(async () => {
    if (fence && !fence.closed) await fence.close();
    await fs.rm(parent, { recursive: true, force: true });
  });
  fence = await NetworkFence.prepare({ executable }, 23456, {
    helperPath: fencePath,
    serviceLaunch: request => backend.launchFence(request),
    timeout: 30000
  });
  assert.deepEqual(fence.proof, { coverage: 'private-runtime-executables', paths: 1, filters: 6, persistent: true });
  await fence.close(); assert.equal(fence.installed, false);
  const final = parseStatus((await run(servicePath, ['--status'], { windowsHide: true, timeout: 10000 })).stdout);
  assert.equal(final.state, 'running'); assert.ok(final.actions.includes('stop'), 'a completed broker must not block service stop');
});

const lifecycleEnabled = enabled && process.env.GATE_SERVICE_ADMIN_TEST === '1';
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function nativeStatus(servicePath) {
  return parseStatus((await run(servicePath, ['--status'], { windowsHide: true, timeout: 10000 })).stdout);
}
async function nativeFailure(servicePath, args) {
  await assert.rejects(run(servicePath, args, { windowsHide: true, timeout: 30000, maxBuffer: 8192 }), error => error.code === 2);
}
async function serviceExists() {
  const script = "$s=Get-Service -Name ClaudeProxyGuard -ErrorAction SilentlyContinue; Write-Output ([bool]$s)";
  return (await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 10000 })).stdout.trim() === 'True';
}
async function protectedBrokerCount() {
  const script = "$expected=Join-Path $env:ProgramData 'Claude Proxy Guard\\Service\\NetworkFence.exe'; " +
    "$items=Get-CimInstance Win32_Process -Filter \"Name='NetworkFence.exe'\" | Where-Object {$_.ExecutablePath -eq $expected}; Write-Output @($items).Count";
  return Number((await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 10000 })).stdout.trim());
}
async function waitProtectedBrokers(expected) {
  for (let i = 0; i < 100; i++) {
    if (await protectedBrokerCount() === expected) return;
    await delay(100);
  }
  throw Error('protected broker count did not reach ' + expected);
}
async function crashOwnedService() {
  const script = "$expected=[char]34+(Join-Path $env:ProgramData 'Claude Proxy Guard\\Service\\GuardService.exe')+[char]34; " +
    "$s=Get-CimInstance Win32_Service | Where-Object {$_.Name -eq 'ClaudeProxyGuard'}; " +
    "if($null-eq$s -or $s.PathName-ne$expected){exit 17}; Stop-Process -Id $s.ProcessId -Force";
  await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 10000 });
  for (let i = 0; i < 100; i++) {
    const result = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "(Get-Service -Name ClaudeProxyGuard).Status.ToString()"], { windowsHide: true, timeout: 10000 });
    if (result.stdout.trim() === 'Stopped') return;
    await delay(100);
  }
  throw Error('owned service did not reach stopped after crash fixture');
}

test('service lifecycle serializes stop/update/uninstall and blocks orphan broker replacement', {
  skip: !lifecycleEnabled, timeout: 300000
}, async t => {
  const servicePath = path.resolve(process.env.GATE_SERVICE_HELPER || '');
  const fencePath = path.resolve(process.env.GATE_FENCE_HELPER || '');
  const protectedService = path.join(process.env.ProgramData, 'Claude Proxy Guard', 'Service', 'GuardService.exe');
  const protectedFence = path.join(process.env.ProgramData, 'Claude Proxy Guard', 'Service', 'NetworkFence.exe');
  const backend = new NativeServiceBackend({ helperPath: servicePath, ownerWindow: () => null });
  const parent = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gate-service-lifecycle-')));
  const root = path.join(parent, 'Runtime-' + 'b'.repeat(24));
  await fs.mkdir(root); await fs.writeFile(path.join(root, 'guard-manifest.json'), '{}');
  const executable = path.join(root, 'Claude.exe'); await fs.copyFile(process.execPath, executable);
  const fences = new Set();
  const closeFence = async fence => {
    if (!fence) return;
    try { if (!fence.closed) await fence.close(); }
    finally { fences.delete(fence); }
  };
  const prepare = async port => {
    const fence = await NetworkFence.prepare({ executable }, port, {
      helperPath: fencePath, serviceLaunch: request => backend.launchFence(request), timeout: 15000
    });
    fences.add(fence); return fence;
  };
  t.after(async () => {
    for (const fence of [...fences]) await closeFence(fence).catch(() => {});
    await waitProtectedBrokers(0).catch(() => {});
    if (await serviceExists()) {
      const current = await nativeStatus(servicePath).catch(() => null);
      if (current?.state === 'stopped') await run(servicePath, ['--start'], { windowsHide: true, timeout: 30000 }).catch(() => {});
      await run(servicePath, ['--request-uninstall', '--owner', '0'], { windowsHide: true, timeout: 30000 }).catch(() => {});
    }
    await fs.rm(parent, { recursive: true, force: true });
  });

  assert.equal((await nativeStatus(servicePath)).state, 'running');
  let active = await prepare(24600);
  assert.equal(await protectedBrokerCount(), 1);
  const running = await nativeStatus(servicePath);
  assert.equal(running.state, 'running'); assert.ok(!running.actions.includes('stop')); assert.ok(!running.actions.includes('uninstall'));
  await nativeFailure(servicePath, ['--stop']);
  assert.equal((await nativeStatus(servicePath)).state, 'running', 'active broker stop must restore accepting and leave service running');
  const before = crypto.createHash('sha256').update(await fs.readFile(protectedService)).digest('hex');
  await nativeFailure(servicePath, ['--install']);
  assert.equal(crypto.createHash('sha256').update(await fs.readFile(protectedService)).digest('hex'), before);
  await nativeFailure(servicePath, ['--uninstall']);
  assert.equal((await nativeStatus(servicePath)).state, 'running');
  await closeFence(active); await waitProtectedBrokers(0);

  let stoppedRaces = 0, launchedRaces = 0;
  for (let attempt = 0; attempt < 8; attempt++) {
    if ((await nativeStatus(servicePath)).state === 'stopped') await run(servicePath, ['--start'], { windowsHide: true, timeout: 30000 });
    let preparation, stop;
    if (attempt % 2 === 0) {
      preparation = prepare(24610 + attempt); stop = run(servicePath, ['--stop'], { windowsHide: true, timeout: 30000 });
    } else {
      stop = run(servicePath, ['--stop'], { windowsHide: true, timeout: 30000 });
      await delay(10); preparation = prepare(24610 + attempt);
    }
    const [launched, stopped] = await Promise.allSettled([preparation, stop]);
    if (stopped.status === 'fulfilled') {
      if (launched.status === 'fulfilled') {
        launchedRaces++;
        assert.equal((await nativeStatus(servicePath)).state, 'running', 'ensure-ready may restart service, but never leave a broker under stopped service');
        await closeFence(launched.value);
      } else {
        stoppedRaces++;
        assert.equal((await nativeStatus(servicePath)).state, 'stopped');
      }
      await waitProtectedBrokers(0);
      if ((await nativeStatus(servicePath)).state === 'stopped') await run(servicePath, ['--start'], { windowsHide: true, timeout: 30000 });
    } else {
      assert.equal(stopped.reason.code, 2);
      if (launched.status === 'fulfilled') { launchedRaces++; await closeFence(launched.value); }
      assert.equal((await nativeStatus(servicePath)).state, 'running');
      await waitProtectedBrokers(0);
    }
  }
  assert.ok(stoppedRaces > 0, 'fixture must cover stop-before-launch admission');
  assert.ok(launchedRaces > 0, 'fixture must cover launch-before-stop admission');

  await Promise.all([
    run(servicePath, ['--install'], { windowsHide: true, timeout: 60000, maxBuffer: 8192 }),
    run(servicePath, ['--install'], { windowsHide: true, timeout: 60000, maxBuffer: 8192 })
  ]);
  assert.equal((await nativeStatus(servicePath)).state, 'running');
  const repeated = JSON.parse((await run(servicePath, ['--request-install', '--owner', '0'], { windowsHide: true, timeout: 10000 })).stdout);
  assert.deepEqual(repeated, { version: 1, operation: 'install', code: 0, elevated: false, state: 'running' });

  active = await prepare(24700);
  await waitProtectedBrokers(1);
  await crashOwnedService();
  assert.equal((await nativeStatus(servicePath)).state, 'stopped');
  assert.equal(await protectedBrokerCount(), 1, 'crash fixture must leave an orphan protected broker');
  const orphanHash = crypto.createHash('sha256').update(await fs.readFile(protectedFence)).digest('hex');
  await nativeFailure(servicePath, ['--uninstall']);
  assert.equal(await protectedBrokerCount(), 1);
  assert.equal(crypto.createHash('sha256').update(await fs.readFile(protectedFence)).digest('hex'), orphanHash);
  await nativeFailure(servicePath, ['--install']);
  assert.equal(await protectedBrokerCount(), 1);
  assert.equal(crypto.createHash('sha256').update(await fs.readFile(protectedFence)).digest('hex'), orphanHash);
  await closeFence(active); await waitProtectedBrokers(0);
  await run(servicePath, ['--start'], { windowsHide: true, timeout: 30000 });
  assert.equal((await nativeStatus(servicePath)).state, 'running');

  await run(servicePath, ['--request-uninstall', '--owner', '0'], { windowsHide: true, timeout: 30000 });
  assert.equal(await serviceExists(), false);
  assert.equal(await protectedBrokerCount(), 0);
  await assert.rejects(fs.access(protectedService));
});
