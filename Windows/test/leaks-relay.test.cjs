'use strict';
// All peers and DNS answers are fixtures on loopback. No public service is contacted.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const dns = require('node:dns');
const { once } = require('node:events');
const { SOCKSRelay, NetworkRelay, connectTunnel } = require('../src/relay.cjs');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function eventually(predicate, message, timeout = 1200) {
  const until = Date.now() + timeout;
  while (!predicate()) { if (Date.now() >= until) assert.fail(message); await delay(5); }
}
async function listening(t, handler, host = '127.0.0.1') {
  const peers = new Set();
  const server = net.createServer(socket => {
    peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket)); handler(socket);
  });
  server.listen(0, host); await once(server, 'listening');
  t.after(async () => {
    for (const socket of peers) socket.destroy();
    if (server.listening) await new Promise(resolve => server.close(resolve));
  });
  return { server, peers, port: server.address().port };
}
async function proxyFixture(t, hold = '') {
  const targets = [], greetings = [], applicationBytes = [];
  const fixture = await listening(t, socket => {
    let pending = Buffer.alloc(0), state = 'greeting';
    const parse = () => {
      if (state === 'greeting' && pending.length >= 2 + pending[1]) {
        const count = pending[1]; assert.equal(pending[0], 5);
        greetings.push(pending.subarray(0, 2 + count)); pending = pending.subarray(2 + count);
        state = hold === 'greeting' ? 'held-greeting' : 'request';
        if (state === 'request') socket.write(Buffer.from([5, 0]));
      }
      if (state === 'request' && pending.length >= 5 && pending.length >= 7 + pending[4]) {
        assert.equal(pending[0], 5); assert.equal(pending[1], 1); assert.equal(pending[3], 3);
        const length = pending[4];
        targets.push({ host: pending.subarray(5, 5 + length).toString(), port: pending.readUInt16BE(5 + length) });
        pending = pending.subarray(7 + length); state = hold === 'connect' ? 'held-connect' : 'stream';
        if (state === 'stream') socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
      }
      if (state === 'stream' && pending.length) {
        applicationBytes.push(Buffer.from(pending)); socket.write(pending); pending = Buffer.alloc(0);
      }
    };
    socket.on('data', chunk => { pending = Buffer.concat([pending, chunk]); parse(); });
    socket.releaseFixture = () => {
      if (state === 'held-greeting') { state = 'request'; socket.write(Buffer.from([5, 0])); }
      else if (state === 'held-connect') { state = 'stream'; socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])); }
      parse();
    };
  });
  return { ...fixture, targets, greetings, applicationBytes,
    release() { for (const socket of fixture.peers) socket.releaseFixture(); } };
}
async function startRelay(t, proxy, network = false, family = 4) {
  const relay = network ? new NetworkRelay() : new SOCKSRelay({ host: '127.0.0.1', port: proxy.port });
  if (network) relay.pinIPFamily(family);
  const fatals = []; relay.on('fatal', error => fatals.push(error)); await relay.start();
  t.after(() => relay.close()); return { relay, fatals };
}
async function client(t, port) {
  const socket = net.createConnection({ host: '127.0.0.1', port }); socket.on('error', () => {});
  t.after(() => socket.destroy()); await once(socket, 'connect'); return socket;
}
function responseHeader(socket) {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    const data = chunk => {
      bytes = Buffer.concat([bytes, chunk]); const end = bytes.indexOf('\r\n\r\n');
      if (end !== -1) { cleanup(); resolve(bytes.subarray(0, end + 4).toString('ascii')); }
    };
    const closed = () => { cleanup(); reject(Error('Fixture connection closed before response')); };
    const cleanup = () => { socket.off('data', data); socket.off('close', closed); };
    socket.on('data', data); socket.once('close', closed);
  });
}
async function request(t, relay, authority, payload = '', headers = '') {
  const socket = await client(t, relay.port), response = responseHeader(socket);
  socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ignored.fixture\r\n${headers}\r\n${payload}`);
  const header = await response; return { socket, header };
}
function mockDNS(t, implementation) {
  const previous = dns.lookup; dns.lookup = implementation; t.after(() => { dns.lookup = previous; });
}
function dnsAnswer(options, callback, address = '127.0.0.1') {
  if (options?.all) callback(null, [{ address, family: 4 }]); else callback(null, address, 4);
}

test('proxy headers preserve optional spaces, tabs and empty values while normalizing private authorization', async t => {
  const proxy = await proxyFixture(t), { relay } = await startRelay(t, proxy);
  const headers = `Proxy-Authorization:\t  Bearer ${relay.checkToken} \t\r\nX-Empty:\t  \r\nX-Visible:  first\tsecond \t\r\n`;
  const result = await request(t, relay, 'ipwho.is:443', '', headers);
  assert.match(result.header, /^HTTP\/1\.1 200 /);
  assert.deepEqual(proxy.targets, [{ host: 'ipwho.is', port: 443 }]);
  const echoed = once(result.socket, 'data'); result.socket.write('whitespace-fixture');
  assert.equal((await echoed)[0].toString(), 'whitespace-fixture');
  assert.equal(Buffer.concat(proxy.applicationBytes).includes(Buffer.from(relay.checkToken)), false);
});

test('complete headers at the 16 KiB boundary reject whitespace followed by bare CR or LF before opening an upstream', { timeout: 5000 }, async t => {
  const proxy = await proxyFixture(t), { relay } = await startRelay(t, proxy); relay.unlock();
  const lookups = []; mockDNS(t, (host, options, callback) => { lookups.push(host); callback(Error('Unexpected malformed-header DNS')); });
  for (const requestLine of ['CONNECT malformed-header.invalid:443 HTTP/1.1', 'GET http://malformed-header.invalid/ HTTP/1.1']) {
    for (const invalid of ['\r', '\n']) {
      const prefix = requestLine + '\r\nX-Padding:', suffix = invalid + '\r\n\r\n';
      const bytes = prefix + ' '.repeat(16384 - prefix.length - suffix.length) + suffix;
      assert.equal(Buffer.byteLength(bytes), 16384);
      assert.equal(bytes.indexOf('\r\n\r\n'), 16380, 'Complete input must reach header parsing within the existing size bound');
      const socket = await client(t, relay.port), reply = responseHeader(socket);
      socket.write(bytes); assert.match(await reply, /^HTTP\/1\.1 502 /); socket.destroy();
    }
  }
  assert.deepEqual(lookups, []); assert.equal(proxy.greetings.length, 0); assert.equal(proxy.targets.length, 0); assert.equal(proxy.applicationBytes.length, 0);
  const valid = await request(t, relay, 'valid-after-malformed.invalid:443');
  assert.match(valid.header, /^HTTP\/1\.1 200 /);
  assert.deepEqual(proxy.targets, [{ host: 'valid-after-malformed.invalid', port: 443 }]);
});

test('leak boundary: locked relay rejects disguised precheck names, ports and malformed authorities before opening SOCKS', async t => {
  const proxy = await proxyFixture(t), { relay } = await startRelay(t, proxy);
  const blocked = ['ipwho.is:443', 'api64.ipify.org:443', 'api.ipify.org:443', 'api6.ipify.org:443', 'ipwho.is:80', 'ipwho.is:444', 'ipwho.is.:443', 'ipwho.is.evil.test:443',
    'evil-ipwho.is:443', 'api64.ipify.org.evil.test:443', 'api64.ipify.org:1',
    '127.0.0.1:443', '[::1]:443', 'example.test:443'];
  const malformed = ['ipwho.is:0', 'ipwho.is:65536', 'ipwho.is:-1', 'ipwho.is:443/path',
    'ipwho.is@evil.test:443', 'user:pass@ipwho.is:443', 'https://ipwho.is:443',
    '[::1%lo0]:443', '[:::1]:443', '::1:443', ':443'];
  for (const target of blocked) {
    const { socket, header } = await request(t, relay, target, 'private-payload');
    assert.match(header, /^HTTP\/1\.1 403 /, target); socket.destroy();
  }
  for (const target of malformed) {
    const { socket, header } = await request(t, relay, target, 'private-payload');
    assert.match(header, /^HTTP\/1\.1 502 /, target); socket.destroy();
  }
  // IPv4-mapped spelling may be rejected by a strict parser or by precheck policy.
  const mapped = await request(t, relay, '[::ffff:127.0.0.1]:443', 'private-payload');
  assert.match(mapped.header, /^HTTP\/1\.1 [45]\d\d /); mapped.socket.destroy();
  assert.equal(proxy.greetings.length, 0); assert.equal(proxy.targets.length, 0); assert.equal(proxy.peers.size, 0);
});

test('leak boundary: SOCKS sends the destination hostname to proxy without local destination DNS', async t => {
  const proxy = await proxyFixture(t), { relay } = await startRelay(t, proxy); relay.unlock();
  const lookups = [];
  mockDNS(t, (host, options, callback) => { lookups.push(host); callback(Error('Local target DNS is forbidden in this fixture')); });
  const { socket, header } = await request(t, relay, 'remote-dns-only.invalid:443');
  assert.match(header, /^HTTP\/1\.1 200 /); assert.deepEqual(lookups, []);
  assert.deepEqual(proxy.targets, [{ host: 'remote-dns-only.invalid', port: 443 }]);
  const echoed = once(socket, 'data'); socket.write('private-fixture');
  assert.equal((await echoed)[0].toString(), 'private-fixture');
});

test('leak boundary: explicitly selected current-network mode uses the OS DNS route', async t => {
  let accepted = 0;
  const echo = await listening(t, socket => { accepted++; socket.pipe(socket); });
  const { relay } = await startRelay(t, null, true); relay.unlock();
  const lookups = [];
  mockDNS(t, (host, options, callback) => { lookups.push(host); queueMicrotask(() => dnsAnswer(options, callback)); });
  const { socket, header } = await request(t, relay, `current-network.invalid:${echo.port}`);
  assert.match(header, /^HTTP\/1\.1 200 /); assert.deepEqual(lookups, ['current-network.invalid']); assert.equal(accepted, 1);
  const echoed = once(socket, 'data'); socket.write('current-route-fixture');
  assert.equal((await echoed)[0].toString(), 'current-route-fixture');
});

test('leak boundary: closing relay during delayed DNS prevents a later TCP connection', async t => {
  let accepted = 0, answer;
  const echo = await listening(t, socket => { accepted++; socket.pipe(socket); });
  const { relay, fatals } = await startRelay(t, null, true); relay.unlock();
  mockDNS(t, (host, options, callback) => {
    assert.equal(host, 'delayed-answer.invalid'); answer = () => dnsAnswer(options, callback);
  });
  const socket = await client(t, relay.port);
  socket.write(`CONNECT delayed-answer.invalid:${echo.port} HTTP/1.1\r\n\r\nprivate-payload`);
  await eventually(() => answer, 'Fixture never reached pending DNS');
  const closed = once(socket, 'close'); relay.close(); await closed; answer(); await delay(100);
  assert.equal(accepted, 0); assert.deepEqual(fatals, []); assert.equal(relay.sockets.size, 0);
  assert.throws(() => relay.unlock(), /закрыт/);
});

for (const phase of ['greeting', 'connect']) test(`leak boundary: kill during SOCKS ${phase} destroys pending sockets and cannot forward buffered payload`, async t => {
  const proxy = await proxyFixture(t, phase), { relay, fatals } = await startRelay(t, proxy); relay.unlock();
  const socket = await client(t, relay.port);
  socket.write('CONNECT delayed-destination.invalid:443 HTTP/1.1\r\n\r\nprivate-payload');
  await eventually(() => phase === 'greeting' ? proxy.greetings.length === 1 : proxy.targets.length === 1, 'Fixture handshake was not reached');
  const closed = once(socket, 'close'); relay.close(); proxy.release(); await closed;
  await eventually(() => proxy.peers.size === 0, 'Upstream SOCKS connection survived kill');
  assert.equal(proxy.applicationBytes.length, 0); assert.deepEqual(fatals, []); assert.equal(relay.sockets.size, 0);
});

test('leak boundary: client cancellation during SOCKS greeting cannot initiate a destination connection afterwards', async t => {
  const proxy = await proxyFixture(t, 'greeting'), { relay } = await startRelay(t, proxy); relay.unlock();
  const socket = await client(t, relay.port);
  socket.write('CONNECT cancelled-destination.invalid:443 HTTP/1.1\r\n\r\nprivate-payload');
  await eventually(() => proxy.greetings.length === 1, 'Fixture greeting was not reached');
  const closed = once(socket, 'close'); socket.destroy(); await closed;
  await delay(30); proxy.release(); await delay(120);
  assert.equal(proxy.targets.length, 0, 'A new destination CONNECT reached the SOCKS server after its client had disconnected');
  assert.equal(proxy.applicationBytes.length, 0);
  await eventually(() => proxy.peers.size === 0, 'Cancelled client left an upstream connection alive');
});

test('leak boundary: client cancellation during DNS cannot open a destination after its answer arrives', async t => {
  let accepted = 0, answer;
  const echo = await listening(t, socket => { accepted++; socket.pipe(socket); });
  const { relay } = await startRelay(t, null, true); relay.unlock();
  mockDNS(t, (host, options, callback) => {
    assert.equal(host, 'cancelled-dns.invalid'); answer = () => dnsAnswer(options, callback);
  });
  const socket = await client(t, relay.port);
  socket.write(`CONNECT cancelled-dns.invalid:${echo.port} HTTP/1.1\r\n\r\nprivate-payload`);
  await eventually(() => answer, 'Fixture never reached pending DNS');
  const closed = once(socket, 'close'); socket.destroy(); await closed;
  await delay(30); answer(); await delay(120);
  assert.equal(accepted, 0, 'A destination accepted TCP after its CONNECT client had disconnected');
  assert.equal(echo.peers.size, 0);
});

test('leak boundary: SOCKS refusal never falls back to target DNS or current-network TCP', async t => {
  // Reserve then close a loopback port to force a proxy-transport failure.
  const reserved = await listening(t, socket => socket.destroy()); const port = reserved.port;
  await new Promise(resolve => reserved.server.close(resolve));
  const { relay, fatals } = await startRelay(t, { port }); relay.unlock();
  const revalidations = []; relay.on('revalidate', reason => revalidations.push(reason));
  const lookups = [];
  mockDNS(t, (host, options, callback) => { lookups.push(host); callback(Error('Unexpected fallback lookup')); });
  const { socket, header } = await request(t, relay, 'must-not-resolve.invalid:443', 'private-payload');
  assert.match(header, /^HTTP\/1\.1 502 /); socket.destroy();
  assert.deepEqual(lookups, []); assert.equal(fatals.length, 0); assert.equal(revalidations.length, 1);
});

test('leak boundary: bracketed IPv6 uses the selected tunnel and never attempts local destination DNS in SOCKS mode', async t => {
  const proxy = await proxyFixture(t), { relay } = await startRelay(t, proxy); relay.unlock();
  const lookups = [];
  mockDNS(t, (host, options, callback) => { lookups.push(host); callback(Error('Unexpected IPv6 DNS lookup')); });
  const { socket, header } = await request(t, relay, '[2001:db8::7]:443');
  assert.match(header, /^HTTP\/1\.1 200 /); assert.deepEqual(lookups, []);
  assert.deepEqual(proxy.targets, [{ host: '2001:db8::7', port: 443 }]);
  const echoed = once(socket, 'data'); socket.write('ipv6-fixture');
  assert.equal((await echoed)[0].toString(), 'ipv6-fixture');
});

test('leak boundary: current-network IPv6 stays in relay tracking and is closed by kill', async t => {
  let echo;
  try { echo = await listening(t, socket => socket.pipe(socket), '::1'); }
  catch (error) { if (['EAFNOSUPPORT', 'EADDRNOTAVAIL'].includes(error.code)) { t.skip('IPv6 loopback unavailable'); return; } throw error; }
  const { relay } = await startRelay(t, null, true, 6); relay.unlock();
  const { socket, header } = await request(t, relay, `[::1]:${echo.port}`);
  assert.match(header, /^HTTP\/1\.1 200 /);
  const echoed = once(socket, 'data'); socket.write('ipv6-current-network');
  assert.equal((await echoed)[0].toString(), 'ipv6-current-network');
  const closed = once(socket, 'close'); relay.close(); await closed;
  await eventually(() => echo.peers.size === 0, 'IPv6 destination survived kill');
});

test('leak boundary: fragmented authority and tunnel payload cannot escape a locked gate', async t => {
  const proxy = await proxyFixture(t), { relay } = await startRelay(t, proxy);
  const socket = await client(t, relay.port), header = responseHeader(socket);
  const fragments = ['CON', 'NECT example.test', ':44', '3 HTTP/1.1\r', '\nHost: ipwho.is\r\n', '\r', '\nprivate-payload'];
  for (const fragment of fragments) { socket.write(fragment); await delay(2); }
  assert.match(await header, /^HTTP\/1\.1 403 /);
  assert.equal(proxy.greetings.length, 0); assert.equal(proxy.targets.length, 0); assert.equal(proxy.applicationBytes.length, 0);
});

test('leak boundary: kill closes every concurrent pending SOCKS connection', async t => {
  const proxy = await proxyFixture(t, 'greeting'), { relay, fatals } = await startRelay(t, proxy); relay.unlock();
  const clients = await Promise.all(Array.from({ length: 24 }, async (_, index) => {
    const socket = await client(t, relay.port);
    socket.write(`CONNECT queued-${index}.invalid:443 HTTP/1.1\r\n\r\nprivate-payload`); return socket;
  }));
  await eventually(() => proxy.greetings.length === clients.length, 'Concurrent handshakes did not all reach fixture');
  const closed = clients.map(socket => once(socket, 'close')); relay.close(); proxy.release(); await Promise.all(closed);
  await eventually(() => proxy.peers.size === 0, 'A pending proxy connection survived mass kill');
  assert.equal(proxy.targets.length, 0); assert.equal(proxy.applicationBytes.length, 0); assert.equal(relay.sockets.size, 0); assert.deepEqual(fatals, []);
});

const authorization = token => 'Proxy-Authorization: Bearer ' + token + '\r\n';
test('leak boundary: only its private control token can use precheck destinations while locked or paused', async t => {
  const proxy = await proxyFixture(t), { relay } = await startRelay(t, proxy);
  const other = await startRelay(t, proxy);
  const rejected = [
    ['', 'ipwho.is:443'], ['', 'api64.ipify.org:443'], ['', 'api.ipify.org:443'], ['', 'api6.ipify.org:443'],
    [authorization('0'.repeat(64)), 'ipwho.is:443'],
    [authorization(other.relay.checkToken), 'ipwho.is:443'],
    [authorization(relay.checkToken) + authorization(relay.checkToken), 'ipwho.is:443'],
    [authorization(relay.checkToken), 'example.test:443'],
    [authorization(relay.checkToken), 'ipwho.is:80'],
    [authorization(relay.checkToken), 'ipwho.is.evil.test:443']
  ];
  for (const paused of [false, true]) {
    if (paused) { relay.unlock(); relay.pause(); }
    const before = proxy.targets.length;
    for (const [headers, target] of rejected) {
      const result = await request(t, relay, target, '', headers);
      assert.match(result.header, /^HTTP\/1\.1 403 /, target); result.socket.destroy();
    }
    assert.equal(proxy.targets.length, before);
    for (const target of ['ipwho.is:443', 'api64.ipify.org:443', 'api.ipify.org:443', 'api6.ipify.org:443']) {
      const result = await request(t, relay, target, '', authorization(relay.checkToken));
      assert.match(result.header, /^HTTP\/1\.1 200 /);
      const echoed = once(result.socket, 'data'); result.socket.write('control-proof');
      assert.equal((await echoed)[0].toString(), 'control-proof'); result.socket.destroy();
    }
  }
  assert.equal(JSON.stringify(proxy.applicationBytes).includes(relay.checkToken), false);
});

for (const mode of ['socks5', 'network']) test(`leak boundary: pause closes 24 live application tunnels but preserves private control probes; resume works (${mode})`, async t => {
  let relay, destination;
  if (mode === 'socks5') {
    const proxy = await proxyFixture(t); ({ relay } = await startRelay(t, proxy)); destination = 'live-app.invalid:443';
  } else {
    const echo = await listening(t, socket => socket.pipe(socket)); ({ relay } = await startRelay(t, null, true)); destination = `127.0.0.1:${echo.port}`;
    const original = net.createConnection;
    net.createConnection = function (options, ...args) {
      if (options?.host === 'ipwho.is' && options.port === 443)
        return original.call(this, { ...options, host: '127.0.0.1', port: echo.port }, ...args);
      return original.call(this, options, ...args);
    };
    t.after(() => { net.createConnection = original; });
  }
  relay.unlock();
  const apps = await Promise.all(Array.from({ length: 24 }, async () => {
    const result = await request(t, relay, destination); assert.match(result.header, /^HTTP\/1\.1 200 /); return result.socket;
  }));
  const control = await request(t, relay, 'ipwho.is:443', '', authorization(relay.checkToken));
  assert.match(control.header, /^HTTP\/1\.1 200 /);
  const closed = apps.map(socket => once(socket, 'close')); relay.pause(); await Promise.all(closed);
  assert.equal(control.socket.destroyed, false);
  const echoed = once(control.socket, 'data'); control.socket.write('control-during-pause');
  assert.equal((await echoed)[0].toString(), 'control-during-pause');
  for (const target of [destination, 'ipwho.is:443', 'api64.ipify.org:443']) {
    const rejected = await request(t, relay, target); assert.match(rejected.header, /^HTTP\/1\.1 403 /); rejected.socket.destroy();
  }
  relay.resume(); const resumed = await request(t, relay, destination);
  assert.match(resumed.header, /^HTTP\/1\.1 200 /);
  const resumedEcho = once(resumed.socket, 'data'); resumed.socket.write('app-after-revalidation');
  assert.equal((await resumedEcho)[0].toString(), 'app-after-revalidation');
  relay.close(); assert.throws(() => relay.resume(), /закрыт/); assert.throws(() => relay.unlock(), /закрыт/);
});

test('leak boundary: pause cancels pending application DNS before a delayed answer can connect', async t => {
  let accepted = 0, answer;
  const echo = await listening(t, socket => { accepted++; socket.pipe(socket); });
  const { relay } = await startRelay(t, null, true); relay.unlock();
  mockDNS(t, (host, options, callback) => { assert.equal(host, 'pause-dns.invalid'); answer = () => dnsAnswer(options, callback); });
  const socket = await client(t, relay.port);
  socket.write(`CONNECT pause-dns.invalid:${echo.port} HTTP/1.1\r\n\r\nprivate-payload`);
  await eventually(() => answer, 'Fixture DNS was not reached');
  const closed = once(socket, 'close'); relay.pause(); await closed; answer(); await delay(100);
  assert.equal(accepted, 0); relay.resume();
  const resumed = await request(t, relay, `127.0.0.1:${echo.port}`); assert.match(resumed.header, /^HTTP\/1\.1 200 /);
});

for (const phase of ['greeting', 'connect']) test(`leak boundary: pause cancels a pending SOCKS ${phase} without forwarding application payload`, async t => {
  const proxy = await proxyFixture(t, phase), { relay, fatals } = await startRelay(t, proxy); relay.unlock();
  const socket = await client(t, relay.port);
  socket.write('CONNECT pause-pending.invalid:443 HTTP/1.1\r\n\r\nprivate-payload');
  await eventually(() => phase === 'greeting' ? proxy.greetings.length === 1 : proxy.targets.length === 1, 'Fixture handshake was not reached');
  const closed = once(socket, 'close'); relay.pause(); proxy.release(); await closed;
  await eventually(() => proxy.peers.size === 0, 'Pending application SOCKS connection survived pause');
  assert.equal(proxy.applicationBytes.length, 0); assert.deepEqual(fatals, []);
  assert.equal(proxy.targets.length, phase === 'greeting' ? 0 : 1); relay.resume(); assert.equal(relay.unlocked, true);
});

test('leak boundary: transport closure during an application SOCKS greeting requests one revalidation without a fatal block', async t => {
  const proxy = await listening(t, socket => socket.end());
  const { relay, fatals } = await startRelay(t, proxy); relay.unlock();
  const revalidations = []; relay.on('revalidate', reason => revalidations.push(reason));
  const result = await request(t, relay, 'temporary-proxy-outage.invalid:443');
  assert.match(result.header, /^HTTP\/1\.1 502 /); result.socket.destroy();
  assert.equal(revalidations.length, 1); assert.deepEqual(fatals, []);
});

test('leak boundary: control-probe transport closure rejects its caller without triggering application revalidation or fatal events', async t => {
  const proxy = await listening(t, socket => socket.end());
  const { relay, fatals } = await startRelay(t, proxy);
  const revalidations = []; relay.on('revalidate', reason => revalidations.push(reason));
  await assert.rejects(connectTunnel(relay.port, 'ipwho.is', 443, relay.checkToken));
  await delay(20); assert.deepEqual(revalidations, []); assert.deepEqual(fatals, []);
});

test('leak boundary: a caller can capture and cancel the local tunnel before its SOCKS greeting completes', async t => {
  const proxy = await proxyFixture(t, 'greeting'), { relay, fatals } = await startRelay(t, proxy); relay.unlock();
  const revalidations = []; relay.on('revalidate', reason => revalidations.push(reason));
  let captured, settled = false, rejected = false;
  const pending = connectTunnel(relay.port, 'captured-cancellation.invalid', 443, '', socket => { captured = socket; });
  pending.then(() => { settled = true; }, () => { settled = true; rejected = true; });
  await eventually(() => proxy.greetings.length === 1, 'Fixture greeting was not reached');
  assert.ok(captured instanceof net.Socket, 'connectTunnel must expose its local socket before awaiting CONNECT');
  captured.destroy();
  await eventually(() => settled, 'Cancelling the captured socket did not settle CONNECT', 600);
  assert.equal(rejected, true); proxy.release(); await delay(60);
  assert.equal(proxy.targets.length, 0); assert.deepEqual(revalidations, []); assert.deepEqual(fatals, []);
  await eventually(() => proxy.peers.size === 0, 'Cancelled caller left a pending upstream alive', 600);
});

test('leak boundary: an IP-query deadline closes its pending tunnel before the eight-second SOCKS timeout', async t => {
  const proxy = await proxyFixture(t, 'greeting'), { relay, fatals } = await startRelay(t, proxy);
  const revalidations = []; relay.on('revalidate', reason => revalidations.push(reason));
  const { queryJSON } = require('../src/ip-check.cjs');
  const started = Date.now(), query = queryJSON(relay.port, 'ipwho.is', '/', 250, relay.checkToken);
  const rejection = assert.rejects(query);
  await eventually(() => proxy.greetings.length === 1, 'IP checker did not reach fixture greeting');
  await rejection;
  await eventually(() => proxy.peers.size === 0, 'IP query left upstream alive after its own deadline', 700);
  assert.ok(Date.now() - started < 1500, 'Cancellation waited for the SOCKS transport timeout');
  proxy.release(); await delay(60);
  assert.equal(proxy.targets.length, 0); assert.deepEqual(revalidations, []); assert.deepEqual(fatals, []);
});
