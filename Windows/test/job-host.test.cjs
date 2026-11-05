'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomUUID } = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
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

function hostCommand(host, command, id) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const cleanup = () => { clearTimeout(timer); host.process.stdout.off('data', receive); };
    const receive = chunk => {
      buffer += chunk.toString(); let end;
      while ((end = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0,end); buffer = buffer.slice(end + 1);
        let message; try { message = JSON.parse(line); } catch { continue; }
        if (message[command + 'Ack'] === id) { cleanup(); resolve(message); return; }
      }
    };
    const timer = setTimeout(() => { cleanup(); reject(Error('GuardHost acknowledgement timed out.')); }, 5000);
    host.process.stdout.on('data',receive); host.process.stdin.write(command + ' ' + id + '\n');
  });
}
async function counter(file) {
  for (let attempt = 0; attempt < 20; attempt++) {
    try { const value = Number(await fs.readFile(file,'utf8')); if (Number.isSafeInteger(value)) return value; } catch {}
    await delay(25);
  }
  throw Error('The native counter was not readable.');
}

async function createFixture(t, freezeCanary = false) {
  const helper = process.env.GATE_HOST || path.resolve(__dirname, '..', 'dist', 'Claude Proxy Guard-win32-x64', 'resources', 'GuardHost.exe');
  await fs.access(helper);
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'gate-job-atomic-'));
  const executable = path.join(root, 'GateJobCanary-' + randomUUID().replaceAll('-', '') + '.exe');
  const script = path.join(root, 'tree.cjs');
  if (freezeCanary) {
    const csc = path.join(process.env.SystemRoot || 'C:\\Windows', 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
    execFileSync(csc, ['/nologo', '/optimize+', '/platform:x64', '/target:exe', '/out:' + executable, path.join(__dirname, 'helpers', 'GuardFreezeCanary.cs')], { windowsHide: true, timeout: 15000 });
  } else {
    await fs.copyFile(process.execPath, executable);
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
  }
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
  function startHost(output, mode = '') { return start(helper, freezeCanary ? [executable, output] : [executable, script, output, mode]); }
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

test('freeze and thaw acknowledge root, child and nested-job processes and a frozen crash leaves no survivors', {
  skip: process.platform !== 'win32', timeout: 45000
}, async t => {
  const fixture = await createFixture(t, true), output = path.join(fixture.root,'freeze.json'), host = fixture.startHost(output);
  const heartbeat = setInterval(() => { if (!host.done && !host.process.stdin.destroyed) host.process.stdin.write('ping\n'); },200);
  try {
    const pids = await fixture.proof(output,host); assert.ok(pids.root && pids.leaf && pids.nested);
    const files = [output + '.root',output + '.child',output + '.nested',output + '.root.churn',output + '.child.churn',output + '.nested.churn'];
    for (const file of files) await counter(file);
    const frozen = await hostCommand(host,'freeze',1);
    assert.equal(frozen.ok,true,JSON.stringify(frozen)); assert.ok(frozen.count>=3);
    const repeated = await hostCommand(host,'freeze',2); assert.equal(repeated.ok,true); assert.equal(repeated.count,frozen.count);
    await delay(150); const stopped = []; for (const file of files) stopped.push(await counter(file));
    await delay(5200); assert.equal(host.done,false,'heartbeat must remain live while the owned tree is frozen');
    assert.deepEqual(await Promise.all(files.map(counter)),stopped);
    const thawed = await hostCommand(host,'thaw',3); assert.equal(thawed.ok,true); assert.equal(thawed.count,frozen.count);
    for (let index = 0; index < files.length; index++) {
      const file = files[index], before = stopped[index], started = Date.now();
      while (await counter(file) <= before && Date.now() - started < 5000) await delay(50);
      assert.ok(await counter(file) > before,'native counter did not resume: ' + file);
    }
    const repeatedThaw = await hostCommand(host,'thaw',4); assert.equal(repeatedThaw.ok,true); assert.equal(repeatedThaw.count,0);
    const refrozen = await hostCommand(host,'freeze',5); assert.equal(refrozen.ok,true); assert.equal(refrozen.count,frozen.count);
    host.process.kill(); await finished(host); await fixture.assertNoSurvivors();
  } finally { clearInterval(heartbeat); }
});
