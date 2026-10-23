'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { createRequire } = require('node:module');
const unit = (name, body) => test(name, { timeout: 5000 }, body);
const turn = () => new Promise(resolve => setImmediate(resolve));

// Execute the production handshake with a controllable OS elevation boundary.
// No real UAC, named pipes or Windows policies are touched by these tests.
async function fixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'gate-approval-')));
  const directory = path.join(root, 'Runtime-' + 'a'.repeat(24));
  await fs.mkdir(directory); await fs.writeFile(path.join(directory, 'guard-manifest.json'), '{}');
  const executable = path.join(directory, 'Claude.exe'); await fs.writeFile(executable, Buffer.alloc(32));
  const file = path.resolve(__dirname, '../src/fence.cjs'), originalRequire = createRequire(file);
  let now = 0, nextTimer = 0, resolveLaunch, rejectLaunch;
  const timers = new Map(), servers = [], sockets = [], preparations = [], launches = [];
  const launch = new Promise((resolve, reject) => { resolveLaunch = resolve; rejectLaunch = reject; });
  const net = { createServer() {
    const server = new EventEmitter(); servers.push(server); server.closed = false;
    server.listen = () => queueMicrotask(() => server.emit('listening'));
    server.close = () => { server.closed = true; };
    return server;
  } };
  const module = { exports: {} };
  vm.runInNewContext(await fs.readFile(file, 'utf8'), {
    module, exports: module.exports, __dirname: path.dirname(file), Buffer, process: { platform: 'win32' },
    require(name) {
      if (name === 'node:net') return net;
      if (name === './fence-launch.cjs') return { ...originalRequire(name), requestElevation(request) { launches.push(request); return launch; } };
      return originalRequire(name);
    },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, at: now + delay }); return id; },
    clearTimeout(id) { timers.delete(id); }
  }, { filename: file });
  const { NetworkFence } = module.exports;
  const h = {
    NetworkFence, launches, servers, sockets, resolveLaunch, rejectLaunch,
    begin() {
      const value = NetworkFence.prepare({ executable }, 23456, { helperPath: process.execPath, timeout: 120000 });
      preparations.push(value); value.catch(() => {}); return value;
    },
    async untilLaunch() {
      for (let i = 0; i < 1000 && !launches.length; i++) await new Promise(resolve => setTimeout(resolve, 1));
      assert.equal(launches.length, 1);
    },
    connect(token) {
      const socket = new EventEmitter(); sockets.push(socket); socket.destroyed = false; socket.writes = [];
      socket.setEncoding = () => {};
      socket.write = value => {
        socket.writes.push(value);
        if (value === 'remove-after-job-exit\n') queueMicrotask(() => socket.emit('data', '{"type":"removed","removed":true}\n'));
      };
      socket.destroy = () => { if (!socket.destroyed) { socket.destroyed = true; queueMicrotask(() => socket.emit('close')); } };
      servers[0].emit('connection', socket);
      const expected = launches[0].token;
      assert.ok(expected);
      socket.emit('data', JSON.stringify({ type: 'hello', version: 1, token: token ?? expected }) + '\n');
      return socket;
    },
    proof(socket, changes = {}) {
      socket.emit('data', JSON.stringify({ type: 'installed', version: 1, coverage: 'private-runtime-executables', paths: 1, filters: 6, persistent: true, ...changes }) + '\n');
    },
    async advance(milliseconds) {
      now += milliseconds;
      for (const [id, timer] of [...timers]) if (timer.at <= now) { timers.delete(id); timer.callback(); }
      await turn();
    }
  };
  t.after(async () => {
    rejectLaunch(Error('fixture cleanup'));
    for (const server of servers) server.emit('error', Error('fixture cleanup'));
    for (const socket of sockets) socket.destroy();
    await Promise.allSettled(preparations); await turn();
    await fs.rm(root, { recursive: true, force: true });
  });
  return h;
}

unit('human UAC waiting does not consume the broker deadline or repeat native elevation', async t => {
  const h = await fixture(t); let outcome = 'pending';
  const pending = h.begin(); pending.then(() => { outcome = 'installed'; }, () => { outcome = 'failed'; });
  await h.untilLaunch(); assert.equal(h.launches[0].helper, process.execPath);
  await h.advance(180000);
  assert.equal(outcome, 'pending'); assert.equal(h.NetworkFence.approvalPending, true);
  assert.equal(h.servers[0].closed, false);
  h.resolveLaunch(123); await turn();
  const socket = h.connect(); h.proof(socket);
  const fence = await pending; assert.equal(fence.installed, true); await fence.close();
});

unit('a launched broker that never connects still has a bounded fail-closed deadline', async t => {
  const h = await fixture(t), pending = h.begin(); await h.untilLaunch();
  h.resolveLaunch(123); await turn(); assert.equal(h.NetworkFence.approvalPending, false);
  await h.advance(120000);
  await assert.rejects(pending, /не подключился/);
  assert.equal(h.servers[0].closed, true); assert.equal(h.sockets.length, 0);
});

unit('authenticated installation gets its own deadline and rejects a malformed proof', async t => {
  const h = await fixture(t), pending = h.begin(); await h.untilLaunch();
  await h.advance(180000); h.resolveLaunch(123); await turn();
  const socket = h.connect(); let settled = false; pending.finally(() => { settled = true; }).catch(() => {});
  await h.advance(119999); assert.equal(settled, false);
  h.proof(socket, { persistent: false }); await assert.rejects(pending, /не подтвердила/);
  assert.equal(socket.destroyed, true);
  assert.equal(socket.writes.includes('remove-after-job-exit\n'), false);
});

unit('an authenticated broker that stalls cannot leave installation waiting indefinitely', async t => {
  const h = await fixture(t), pending = h.begin(); await h.untilLaunch();
  await h.advance(180000); const socket = h.connect();
  await h.advance(120000); await assert.rejects(pending, /установку сетевой защиты за отведённое время/);
  assert.equal(socket.destroyed, true); assert.equal(h.NetworkFence.approvalPending, true);
  assert.equal(socket.writes.includes('remove-after-job-exit\n'), false);
  h.resolveLaunch(123); await turn(); assert.equal(h.NetworkFence.approvalPending, false);
});

unit('a late launcher rejection cannot abandon an authenticated installed fence', async t => {
  const h = await fixture(t), pending = h.begin(); await h.untilLaunch();
  const socket = h.connect(); h.proof(socket); const fence = await pending;
  h.rejectLaunch(Error('late shell failure')); await turn();
  assert.equal(h.NetworkFence.approvalPending, false); assert.equal(fence.installed, true);
  assert.equal(fence.closed, false); assert.equal(socket.destroyed, false);
  assert.equal(socket.writes.includes('remove-after-job-exit\n'), false);
  await fence.close();
});

unit('an unanswered Windows request prevents a second elevation and denial releases the gate', async t => {
  const h = await fixture(t), first = h.begin(); await h.untilLaunch();
  await assert.rejects(h.begin(), /предыдущий запрос Windows/);
  assert.equal(h.launches.length, 1); assert.equal(h.NetworkFence.approvalPending, true);
  h.rejectLaunch(Error('user cancelled')); await assert.rejects(first, /отменено/); await turn();
  assert.equal(h.NetworkFence.approvalPending, false); assert.equal(h.servers[0].closed, true);
});

unit('an untrusted broker hello cannot write an installation request or obtain proof', async t => {
  const h = await fixture(t), pending = h.begin(); await h.untilLaunch();
  h.resolveLaunch(123); await turn(); const socket = h.connect('0'.repeat(64));
  await assert.rejects(pending, /закрылся до подтверждения/);
  assert.equal(socket.writes.length, 0); assert.equal(socket.destroyed, true);
});
