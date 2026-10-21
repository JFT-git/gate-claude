'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { once, EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const { IPPolicy, canonicalIP, validateSettings } = require('../src/policy.cjs');
const { SOCKSRelay, NetworkRelay, SocketReader, connectTunnel } = require('../src/relay.cjs');
const { Inspector } = require('../src/inspector.cjs');
const { Channel } = require('../src/channel.cjs');
const S = require('../src/sanitize.cjs');
const A = require('../src/asar.cjs');

test('IP pin cannot be reset; RU, unknown country, malformed IP fail closed', () => {
  for (const country of ['RU', '', 'Netherlands', 'ZZ']) {
    const policy = new IPPolicy(); assert.throws(() => policy.pin({ ip: '203.0.113.7', country_code: country })); assert.equal(policy.blocked, true);
  }
  const policy = new IPPolicy(); policy.pin({ ip: '203.0.113.7', country_code: 'NL' }); policy.check('203.0.113.7');
  assert.throws(() => policy.check('203.0.113.8')); assert.equal(policy.blocked, true);
  assert.throws(() => policy.pin({ ip: '203.0.113.8', country_code: 'NL' }));
  assert.equal(new IPPolicy().blocked, false);
  assert.equal(canonicalIP('2001:0DB8:0000::1'), canonicalIP('2001:db8::1'));
  assert.throws(() => canonicalIP('not-an-ip'));
});
test('settings do not accept URL credentials or invalid profiles', () => {
  assert.throws(() => validateSettings({ host: 'socks5://user:pass@host', port: 1080 }));
  assert.throws(() => validateSettings({ host: 'localhost', port: 1080, language: 'ru-RU' }));
  assert.equal(validateSettings({ host: 'localhost', port: 1080 }).timezone, 'Europe/Amsterdam');
  assert.equal(validateSettings({ mode: 'network' }).mode, 'network');
  assert.equal(validateSettings({ mode: 'network', password: 'unused' }).password, '');
  assert.equal(validateSettings({ mode: 'network', host: 'socks5://user:secret@host' }).host, '127.0.0.1');
  assert.throws(() => validateSettings({ mode: 'automatic-fallback' }));
  assert.throws(() => validateSettings({ host: 'localhost', port: 0 }));
});
test('traffic masks headers, nested JSON, SSE bearer tokens and URL credentials', () => {
  assert.equal(S.headers({ Authorization: 'secret-a', Cookie: 'secret-b' }).includes('secret-'), false);
  assert.equal(S.body('{"nested":{"access_token":"secret-c"},"list":[{"password":"secret-d"}]}').includes('secret-'), false);
  assert.equal(S.body('data: {"refresh_token":"secret-e"}\nBearer secret-f').includes('secret-'), false);
  assert.equal(S.safeURL('https://user:pass@example.test/path?token=secret#private'), 'https://example.test/path');
  assert.equal(S.body('x'.repeat(100000)).length < 33000, true);
  assert.equal(S.auditRequestHeaders({ 'Accept-Language': 'ru-RU' }, 'en-US').length, 1);
  assert.deepEqual(S.auditRequestHeaders({ 'Accept-Language': 'en-US' }, 'en-US'), []);
});

async function mockSOCKS(t, auth = true) {
  const sockets = new Set(), targets = [];
  const server = net.createServer(async socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    const reader = new SocketReader(socket);
    try {
      const greeting = await reader.read(2); await reader.read(greeting[1]); socket.write(Buffer.from([5, auth ? 2 : 0]));
      if (auth) {
        const header = await reader.read(2), username = (await reader.read(header[1])).toString();
        const size = (await reader.read(1))[0], password = (await reader.read(size)).toString();
        const valid = username === 'fixture' && password === 'fixture-password'; socket.write(Buffer.from([1, valid ? 0 : 1]));
        if (!valid) { reader.release(); socket.end(); return; }
      }
      const request = await reader.read(5); assert.equal(request[3], 3);
      const host = (await reader.read(request[4])).toString(), port = (await reader.read(2)).readUInt16BE(); targets.push({ host, port });
      if (host === 'refused.test') { socket.write(Buffer.from([5, 2, 0, 1, 0, 0, 0, 0, 0, 0])); reader.release(); socket.end(); return; }
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
      reader.release(); socket.on('data', data => { if (data.toString() === 'RESET') socket.resetAndDestroy(); else socket.write(data); }); socket.resume();
    } catch { reader.release(); socket.destroy(); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); server.close(); });
  return { port: server.address().port, targets };
}
test('CONNECT SOCKS5: precheck gate, auth, remote DNS, stream reset and kill', async t => {
  const socks = await mockSOCKS(t), relay = new SOCKSRelay({ host: '127.0.0.1', port: socks.port, username: 'fixture', password: 'fixture-password' });
  const failures = []; relay.on('fatal', x => failures.push(x)); await relay.start(); t.after(() => relay.close());
  await assert.rejects(connectTunnel(relay.port, 'example.test')); assert.equal(socks.targets.length, 0);
  await assert.rejects(connectTunnel(relay.port, 'ipwho.is'));
  const pre = await connectTunnel(relay.port, 'ipwho.is', 443, relay.checkToken); pre.destroy();
  relay.unlock();
  await assert.rejects(connectTunnel(relay.port, 'refused.test')); assert.equal(failures.length, 0);
  const socket = await connectTunnel(relay.port, 'example.test'); socket.resume(); socket.write('echo');
  assert.equal((await once(socket, 'data'))[0].toString(), 'echo');
  assert.deepEqual(socks.targets.at(-1), { host: 'example.test', port: 443 });
  const closed = once(socket, 'close'); socket.write('RESET'); await closed;
  assert.equal(failures.length, 0);
  const active = await connectTunnel(relay.port, 'stream.test'); active.resume(); const ended = once(active, 'close');
  const port = relay.port; relay.close(); await ended;
  await assert.rejects(connectTunnel(port, 'new.test')); assert.equal(failures.length, 0);
});
test('wrong SOCKS credentials signal a global failure, without fallback', async t => {
  const socks = await mockSOCKS(t), relay = new SOCKSRelay({ host: '127.0.0.1', port: socks.port, username: 'fixture', password: 'wrong' });
  const fatal = once(relay, 'fatal'); await relay.start(); relay.unlock(); t.after(() => relay.close());
  await assert.rejects(connectTunnel(relay.port, 'example.test')); assert.match((await fatal)[0], /SOCKS5/); assert.equal(socks.targets.length, 0);
});
test('current network/VPN works without SOCKS, gates precheck and closes live connections', async t => {
  let accepted = 0; const clients = new Set();
  const echo = net.createServer(socket => { accepted++; clients.add(socket); socket.on('error', () => {}); socket.once('close', () => clients.delete(socket)); socket.pipe(socket); });
  echo.listen(0, '127.0.0.1'); await once(echo, 'listening');
  t.after(() => { for (const socket of clients) socket.destroy(); echo.close(); });
  const relay = new NetworkRelay(), failures = []; relay.on('fatal', x => failures.push(x)); await relay.start(); t.after(() => relay.close());
  await assert.rejects(connectTunnel(relay.port, '127.0.0.1', echo.address().port)); assert.equal(accepted, 0);
  relay.unlock();
  const socket = await connectTunnel(relay.port, '127.0.0.1', echo.address().port); socket.resume(); socket.write('current-network-fixture');
  assert.equal((await once(socket, 'data'))[0].toString(), 'current-network-fixture');
  const ended = once(socket, 'close'), port = relay.port; relay.close(); await ended;
  await assert.rejects(connectTunnel(port, '127.0.0.1', echo.address().port)); assert.equal(failures.length, 0);
});

class MockChannel extends EventEmitter {
  constructor(profile) { super(); this.profile = profile; this.conflict = true; }
  async command(method, params, sid) {
    if (method === 'Browser.getVersion') return { userAgent: 'fixture' };
    if (method === 'Emulation.setLocaleOverride' && this.conflict) throw Error('Another locale override is already in effect');
    if (method === 'Runtime.evaluate') return { result: { value: this.profile } };
    if (method === 'Runtime.enable') queueMicrotask(() => this.emit('event', 'Runtime.executionContextCreated', { context: { id: 1, auxData: { isDefault: true } } }, sid));
    return {};
  }
}
const profile = { timezone: 'Europe/Amsterdam', language: 'en-US', locale: 'en-US', url: 'https://fixture.test/' };
const tick = () => new Promise(resolve => setTimeout(resolve, 20));
test('shared renderer locale is allowed only with mandatory actual en-US and timezone', async t => {
  const channel = new MockChannel(profile), inspector = new Inspector(channel, profile, true); t.after(() => inspector.stop());
  const proof = once(inspector, 'verified'); await inspector.start(); channel.emit('event', 'Target.attachedToTarget', { sessionId: 'page1' }, '');
  assert.equal((await proof)[0].locale, 'en-US'); assert.equal(inspector.running, true);
  channel.emit('event', 'Target.detachedFromTarget', { sessionId: 'page1' }, ''); assert.equal(inspector.running, true);
});
for (const invalid of [{ locale: 'fr-FR' }, { locale: '' }, { language: 'ru-RU' }, { timezone: 'Europe/Moscow' }]) {
  test('wrong or unconfirmed profile fails closed: ' + JSON.stringify(invalid), async t => {
    const channel = new MockChannel({ ...profile, ...invalid }), inspector = new Inspector(channel, profile, true); t.after(() => inspector.stop());
    const fatal = once(inspector, 'fatal'); await inspector.start(); channel.emit('event', 'Target.attachedToTarget', { sessionId: 'p' }, '');
    await fatal; assert.equal(inspector.running, false);
  });
}
test('closed target and retired context replies cannot kill live pages', async t => {
  const channel = new MockChannel(profile), inspector = new Inspector(channel, profile, false); t.after(() => inspector.stop());
  channel.command = async method => { if (method === 'Browser.getVersion') return { userAgent: 'fixture' }; if (method === 'Emulation.setTimezoneOverride') throw Error('Target closed'); return {}; };
  await inspector.start(); channel.emit('event', 'Target.attachedToTarget', { sessionId: 'closed' }, ''); await tick();
  assert.equal(inspector.running, true); assert.equal(inspector.sessions.size, 0);
});
test('named channel requires token, parses fragmented messages, closes pending work', async t => {
  const channel = new Channel(); await channel.listen(); t.after(() => channel.close());
  const unauthorized = net.connect(channel.path); unauthorized.on('error', () => {}); await once(unauthorized, 'connect');
  unauthorized.write(JSON.stringify({ method: 'ProxyGuard.hello', params: { token: 'x'.repeat(64) } }) + '\0');
  await once(unauthorized, 'close'); assert.equal(channel.socket, undefined);
  const socket = net.connect(channel.path); socket.on('error', () => {}); t.after(() => socket.destroy()); await once(socket, 'connect');
  const connected = channel.connected(); const hello = JSON.stringify({ method: 'ProxyGuard.hello', params: { token: channel.token } }) + '\0';
  socket.write(hello.slice(0, 20)); socket.write(hello.slice(20)); await connected;
  const data = once(socket, 'data'); const pending = channel.command('Browser.getVersion');
  const command = JSON.parse((await data)[0].toString().replace(/\0$/, '')); socket.write(JSON.stringify({ id: command.id, result: { ok: true } }) + '\0');
  assert.deepEqual(await pending, { ok: true });
  const stopped = channel.command('pending'); const rejection = assert.rejects(stopped); channel.close(); await rejection;
});

function fixtureArchive() {
  const files = { 'package.json': Buffer.from('{"name":"@ant/desktop","version":"fixture","main":"main.js"}'), 'main.js': Buffer.from('console.log("fixture");') };
  let payload = Buffer.alloc(0); const header = { files: {} };
  for (const [name, bytes] of Object.entries(files)) { header.files[name] = { offset: String(payload.length), size: bytes.length }; payload = Buffer.concat([payload, bytes]); }
  const raw = Buffer.from(JSON.stringify(header)), pad = (4 - raw.length % 4) % 4, prefix = Buffer.alloc(16);
  prefix.writeUInt32LE(4, 0); prefix.writeUInt32LE(raw.length + pad + 8, 4); prefix.writeUInt32LE(raw.length + pad + 4, 8); prefix.writeUInt32LE(raw.length, 12);
  return Buffer.concat([prefix, raw, Buffer.alloc(pad), payload]);
}
test('ASAR bootstrap keeps original source and recomputes header and block hashes', () => {
  const original = fixtureArchive(), before = Buffer.from(original), boot = Buffer.from('/* own boot */');
  const result = A.addBootstrap(original, boot), parsed = A.parseArchive(result.archive);
  assert.deepEqual(original, before); assert.match(parsed.read('main.js').toString(), /proxy-guard-boot/);
  assert.deepEqual(parsed.read('proxy-guard-boot.cjs'), boot);
  assert.equal(parsed.digest, result.digest);
  assert.equal(parsed.entry('main.js').integrity.hash, A.hash(parsed.read('main.js')));
  const base = fs.readFileSync(path.join(__dirname, '..', '..', 'Resources', 'RuntimeBootstrap.cjs'), 'utf8');
  const win = A.windowsBootstrap(base).toString(); assert.ok(win.includes('ProxyGuard.hello')); assert.ok(!win.includes('fd: 3'));
  assert.throws(() => A.parseArchive(Buffer.from('broken'))); assert.throws(() => A.updatePEIntegrity(Buffer.alloc(128), 'x', 'y'));
});
