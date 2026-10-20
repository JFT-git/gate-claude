'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { powershell, psQuote } = require('../src/runtime.cjs');

test('Windows Job Object kills child and grandchild on EOF, helper crash and missing heartbeat', { skip: process.platform !== 'win32', timeout: 45000 }, async t => {
  const helper = process.env.GATE_HOST || path.resolve(__dirname, '..', 'dist', 'Claude Proxy Guard-win32-x64', 'resources', 'GuardHost.exe');
  await fs.access(helper);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-job-test-')); t.after(() => fs.rm(dir, { recursive: true, force: true }));
  for (const mode of ['eof', 'crash', 'heartbeat-timeout']) {
    const output = path.join(dir, mode + '.json');
    const script = `$child=Start-Process powershell.exe -ArgumentList '-NoLogo -NoProfile -NonInteractive -Command Start-Sleep 120' -PassThru -WindowStyle Hidden; @{child=$PID;grandchild=$child.Id}|ConvertTo-Json|Set-Content -Encoding UTF8 -LiteralPath ${psQuote(output)}; Start-Sleep 120`;
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    const host = spawn(helper, [path.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    host.stdin.on('error', () => {}); let pid;
    t.after(() => { host.kill(); if (pid) { try { process.kill(pid.child); } catch {} try { process.kill(pid.grandchild); } catch {} } });
    const started = Date.now();
    while (Date.now() - started < 15000) {
      try { pid = JSON.parse((await fs.readFile(output, 'utf8')).replace(/^\uFEFF/, '')); break; } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    assert.ok(pid, 'fixture process tree did not start');
    const exited = once(host, 'exit');
    if (mode === 'eof') host.stdin.end(); else if (mode === 'crash') host.kill();
    await exited;
    for (let attempt = 0; attempt < 30; attempt++) {
      const alive = [pid.child, pid.grandchild].some(value => { try { process.kill(value, 0); return true; } catch { return false; } });
      if (!alive) break; await new Promise(resolve => setTimeout(resolve, 100));
    }
    for (const value of [pid.child, pid.grandchild]) assert.throws(() => process.kill(value, 0), 'process survived job closure: ' + value);
  }
});
