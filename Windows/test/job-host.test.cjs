'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomUUID } = require('node:crypto');
const { spawn } = require('node:child_process');
const { powershell, psQuote } = require('../src/windows.cjs');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function tracked(executable, args, options = {}) {
  const process = spawn(executable, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], ...options });
  let done = false, result;
  const completion = new Promise((resolve, reject) => {
    process.once('error', error => { done = true; result = { error }; reject(error); });
    process.once('exit', (code, signal) => { done = true; result = { code, signal }; resolve(result); });
  });
  completion.catch(() => {});
  process.stdin?.on('error', () => {}); process.stdout?.resume(); process.stderr?.resume();
  return { process, completion, get done() { return done; }, get result() { return result; } };
}
async function finished(child, timeout = 12000) {
  let timer;
  try {
    return await Promise.race([child.completion, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Owned fixture process did not exit in time.')), timeout); })]);
  } finally { clearTimeout(timer); }
}

async function createFixture(t) {
  const helper = process.env.GATE_HOST || path.resolve(__dirname, '..', 'dist', 'Claude Proxy Guard-win32-x64', 'resources', 'GuardHost.exe');
  await fs.access(helper);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-job-atomic-'));
  const executable = path.join(root, 'GateJobCanary-' + randomUUID().replaceAll('-', '') + '.exe');
  await fs.copyFile(process.execPath, executable);
  const script = path.join(root, 'tree.cjs');
  await fs.writeFile(script, `
    const fs=require('node:fs'),{spawn}=require('node:child_process');
    if(process.argv[2]==='leaf'){setInterval(()=>{},1000);}else{
      const child=spawn(process.execPath,[__filename,'leaf'],{windowsHide:true,stdio:'ignore'});
      child.once('error',()=>process.exit(71));
      child.once('spawn',()=>{
        fs.writeFileSync(process.argv[2],JSON.stringify({root:process.pid,leaf:child.pid}));
        if(process.argv[3]==='root-exit')setTimeout(()=>process.exit(0),100);
      });
      setInterval(()=>{},1000);
    }
  `);
  const owned = new Set();
  async function surviving() {
    // The image basename contains a fresh 128-bit identifier and is used only
    // by this fixture. Avoid MainModule/PEB reads: an orphan could still be
    // CREATE_SUSPENDED, before its loader initialized those user-mode fields.
    const name = path.basename(executable, '.exe');
    const output = await powershell('ConvertTo-Json -InputObject @((Get-Process -Name ' + psQuote(name) + ' -ErrorAction SilentlyContinue) | ForEach-Object { $_.Id }) -Compress', 10000);
    return JSON.parse(output || '[]');
  }
  async function assertNoSurvivors() {
    let pids = [];
    for (let attempt = 0; attempt < 3; attempt++) {
      pids = await surviving(); if (!pids.length) return;
      await delay(200);
    }
    assert.deepEqual(pids, [], 'An owned child or suspended process survived closure of its helper job.');
  }
  t.after(async () => {
    for (const child of owned) if (!child.done) { child.process.stdin?.destroy(); child.process.kill(); }
    await Promise.allSettled([...owned].map(child => finished(child, 5000)));
    // Only our random executable basename is eligible for emergency cleanup.
    const pids = await surviving();
    for (const pid of pids) { try { process.kill(pid); } catch {} }
    if (pids.length) await delay(200);
    await fs.rm(root, { recursive: true, force: true });
  });
  function start(exe, args, options) { const child = tracked(exe, args, options); owned.add(child); return child; }
  function startHost(output, mode = '') { return start(helper, [executable, script, output, mode]); }
  async function proof(output, child) {
    const started = Date.now();
    while (Date.now() - started < 12000) {
      try { return JSON.parse(await fs.readFile(output, 'utf8')); } catch {}
      if (child.done) throw Error('The atomic job fixture exited before its process tree was ready.');
      await delay(50);
    }
    throw Error('The atomic job fixture process tree did not become ready.');
  }
  return { helper, root, executable, script, start, startHost, proof, assertNoSurvivors };
}

test('atomic GuardHost job closes its root and descendant on EOF, heartbeat timeout, helper crash and root exit', {
  skip: process.platform !== 'win32', timeout: 65000
}, async t => {
  const fixture = await createFixture(t);
  for (const mode of ['eof', 'heartbeat-timeout', 'helper-crash', 'root-exit']) {
    const output = path.join(fixture.root, mode + '.json'), host = fixture.startHost(output, mode);
    const heartbeat = setInterval(() => { if (!host.done && !host.process.stdin.destroyed) host.process.stdin.write('ping\n'); }, 200);
    try {
      const pids = await fixture.proof(output, host);
      assert.ok(Number.isInteger(pids.root) && Number.isInteger(pids.leaf));
      if (mode === 'eof') host.process.stdin.end();
      if (mode === 'heartbeat-timeout') clearInterval(heartbeat);
      if (mode === 'helper-crash') host.process.kill();
      await finished(host, 12000);
      await fixture.assertNoSurvivors();
    } finally { clearInterval(heartbeat); }
  }
});

test('GuardHost closes its job after its controlling parent dies', {
  skip: process.platform !== 'win32', timeout: 40000
}, async t => {
  const fixture = await createFixture(t), output = path.join(fixture.root, 'parent-death.json');
  const launcher = path.join(fixture.root, 'launcher.cjs');
  await fs.writeFile(launcher, `
    const {spawn}=require('node:child_process');
    const child=spawn(process.argv[2],process.argv.slice(3),{windowsHide:true,stdio:['pipe','ignore','ignore']});
    child.once('error',()=>process.exit(72));child.stdin.on('error',()=>{});
    setInterval(()=>{if(!child.stdin.destroyed)child.stdin.write('ping\\n');},200);
  `);
  const parent = fixture.start(process.execPath, [launcher, fixture.helper, fixture.executable, fixture.script, output]);
  const pids = await fixture.proof(output, parent); assert.ok(pids.root && pids.leaf);
  parent.process.kill(); await finished(parent);
  // Closing the parent pipe normally produces EOF immediately. Even if an
  // unexpected inherited writer delays EOF, the five-second watchdog must win.
  await delay(5500); await fixture.assertNoSurvivors();
});

test('forcing GuardHost termination during process creation leaves no running or suspended canary image', {
  skip: process.platform !== 'win32', timeout: 65000
}, async t => {
  const fixture = await createFixture(t);
  const delays = [0, 1, 3, 5, 8, 12, 16, 24, 32, 40, 56, 72, 96, 128];
  for (let round = 0; round < delays.length; round++) {
    const host = fixture.startHost(path.join(fixture.root, 'launch-' + round + '.json'));
    await delay(delays[round]);
    if (!host.done) host.process.kill();
    await finished(host, 10000);
  }
  await delay(300); await fixture.assertNoSurvivors();
});
