'use strict';
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');
const run = promisify(require('node:child_process').execFile);
const { NativeServiceBackend } = require('../src/service-backend.cjs');
const { NetworkFence } = require('../src/fence.cjs');

const argv = process.argv.slice(2), argument = name => argv[argv.indexOf(name) + 1];
const service = path.resolve(argument('--service')), fenceHelper = path.resolve(argument('--fence'));
const mutexProbe = path.resolve(argument('--mutex-probe')), proofPath = path.resolve(argument('--proof'));
const work = path.resolve(argument('--work'));
const proof = { schema: 1, sessions: [], failures: [] };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function result(executable, args, timeout = 30000) {
  try {
    const value = await run(executable, args, { windowsHide: true, timeout, maxBuffer: 8192 });
    return { code: 0, stdout: value.stdout.trim() };
  } catch (error) { return { code: Number.isInteger(error.code) ? error.code : 1, stdout: typeof error.stdout === 'string' ? error.stdout.trim() : '' }; }
}
async function status() { return JSON.parse((await result(service, ['--status'])).stdout); }
async function main() {
  await fs.mkdir(work, { recursive: true });
  const execution = JSON.parse((await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    "[pscustomobject]@{elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);session=(Get-Process -Id $PID).SessionId}|ConvertTo-Json -Compress"],
    { windowsHide: true, timeout: 10000 })).stdout);
  proof.executionContext = { elevated: execution.elevated, interactive: execution.session > 0 };
  if (execution.elevated || execution.session <= 0) throw Error('STANDARD_INTERACTIVE_TOKEN_REQUIRED');
  const backend = new NativeServiceBackend({ helperPath: service, ownerWindow: () => null });
  const initial = await status(); proof.initialStatus = initial;
  if (initial.state !== 'running' || !initial.sessionRoutingSupported) throw Error('SERVICE_NOT_READY');

  const mutex = await result(mutexProbe, []);
  proof.globalMutex = { ...mutex, parsed: mutex.stdout ? JSON.parse(mutex.stdout) : null };

  const stop = await result(service, ['--stop']); proof.stop = { code: stop.code };
  if (stop.code === 0) {
    proof.stoppedStatus = await status();
    const start = await result(service, ['--start']); proof.start = { code: start.code };
  } else proof.start = { code: 'NOT_RUN_STOP_FAILED' };
  proof.afterStartStopStatus = await status();

  const parent = await fs.realpath(await fs.mkdtemp(path.join(work, 'standard-runtime-')));
  const root = path.join(parent, 'Runtime-' + 'c'.repeat(24));
  await fs.mkdir(root); await fs.writeFile(path.join(root, 'guard-manifest.json'), '{}');
  const executable = path.join(root, 'Claude.exe'); await fs.copyFile(process.execPath, executable);
  for (let index = 0; index < 2; index++) {
    const fence = await NetworkFence.prepare({ executable }, 25100 + index, {
      helperPath: fenceHelper, serviceLaunch: request => backend.launchFence(request), timeout: 30000
    });
    const installed = { ...fence.proof };
    await fence.close();
    proof.sessions.push({ index: index + 1, installed, removed: fence.installed === false });
  }
  const repeated = await result(service, ['--request-install', '--owner', '0']);
  proof.currentInstall = { code: repeated.code, receipt: JSON.parse(repeated.stdout) };
  const serviceInfo = JSON.parse((await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    "$s=Get-CimInstance Win32_Service | Where-Object {$_.Name -eq 'ClaudeProxyGuard'}; [pscustomobject]@{StartMode=$s.StartMode;PathName=$s.PathName}|ConvertTo-Json -Compress"],
    { windowsHide: true, timeout: 10000 })).stdout);
  const acl = JSON.parse((await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    "$root=Join-Path $env:ProgramData 'Claude Proxy Guard\\Service'; $a=Get-Acl -LiteralPath $root; [pscustomobject]@{Owner=$a.Owner;Access=$a.AccessToString}|ConvertTo-Json -Compress"],
    { windowsHide: true, timeout: 10000 })).stdout);
  proof.serviceConfiguration = serviceInfo; proof.protectedAcl = acl;
  proof.finalStatus = await status();
  if (serviceInfo.StartMode !== 'Auto') throw Error('SERVICE_NOT_AUTO_START');
  if (proof.sessions.some(session => session.removed !== true)) throw Error('FENCE_CLEANUP_FAILED');
  if (proof.currentInstall.receipt.elevated !== false) throw Error('REPEATED_UAC');
  if (mutex.code !== 0) throw Error('GLOBAL_MUTEX_FAILED_' + mutex.code);
  if (stop.code !== 0) throw Error('SERVICE_STOP_FAILED_' + stop.code);
  if (proof.start.code !== 0) throw Error('SERVICE_START_FAILED_' + proof.start.code);
  proof.result = 'PASS';
}
main().catch(error => { proof.result = 'FAIL'; proof.failures.push(error.code || error.message.split('\n')[0].slice(0, 80)); process.exitCode = 1; })
  .finally(async () => {
    await fs.mkdir(path.dirname(proofPath), { recursive: true }); await fs.writeFile(proofPath, JSON.stringify(proof, null, 2));
    if (work) await fs.rm(work, { recursive: true, force: true });
  });
