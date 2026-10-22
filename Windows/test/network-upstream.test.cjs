'use strict';
// Real owned loopback proxy/origin sockets; destination DNS is never public.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const dns = require('node:dns');
const { once } = require('node:events');
const { NetworkRelay, connectHTTP, connectTunnel, SocketReader } = require('../src/relay.cjs');
const wireConnect = net.createConnection.bind(net), delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, message) { const end = Date.now() + 1500; while (!predicate()) { if (Date.now() > end) assert.fail(message); await delay(5); } }
async function server(t, handler, family = 4) {
  const peers = new Set(), s = net.createServer(socket => { peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket)); handler(socket); });
  s.listen({ host: family === 6 ? '::1' : '127.0.0.1', port: 0, ipv6Only: family === 6 }); await once(s, 'listening');
  t.after(async () => { for (const socket of peers) socket.destroy(); if (s.listening) await new Promise(resolve => s.close(resolve)); });
  return { host: family === 6 ? '::1' : '127.0.0.1', port: s.address().port, peers, server: s };
}
async function echo(t, family = 4) { let accepted = 0; const received = []; const target = await server(t, socket => { accepted++; socket.on('data', data => { received.push(Buffer.from(data)); socket.write(data); }); }, family); return { ...target, received, get accepted() { return accepted; } }; }
async function positive(t, target) { const socket = wireConnect({ host: target.host, port: target.port }); socket.on('error', () => {}); t.after(() => socket.destroy()); await once(socket, 'connect'); const received = once(socket, 'data'); socket.write('unrestricted-baseline'); assert.equal((await received)[0].toString(), 'unrestricted-baseline'); socket.destroy(); }
async function httpProxy(t, target, options = {}) {
  const requests = [], upstreams = new Set();
  const proxy = await server(t, socket => {
    let bytes = Buffer.alloc(0), done = false;
    socket.on('data', data => {
      if (done) return; bytes = Buffer.concat([bytes, data]); const end = bytes.indexOf('\r\n\r\n'); if (end < 0) return; done = true;
      const header = bytes.subarray(0, end + 4).toString('latin1'); requests.push(header);
      if (options.hold) return;
      if (options.response) { socket.end(options.response); return; }
      const upstream = wireConnect({ host: target.host, port: target.port }); upstreams.add(upstream); upstream.on('error', () => socket.destroy());
      upstream.once('close', () => { upstreams.delete(upstream); socket.destroy(); }); socket.once('close', () => upstream.destroy());
      upstream.once('connect', () => { socket.write('HTTP/1.1 200 Connection Established\r\nX-Fixture: proxy\r\n\r\n'); const head = bytes.subarray(end + 4); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
    });
  }, options.family || 4);
  t.after(() => { for (const socket of upstreams) socket.destroy(); }); return { ...proxy, requests };
}
async function socksProxy(t, target, family = 4) {
  const targets = [], upstreams = new Set(), proxy = await server(t, async socket => {
    const reader = new SocketReader(socket); let upstream;
    try {
      const greeting = await reader.read(2); await reader.read(greeting[1]); socket.write(Buffer.from([5, 0]));
      const request = await reader.read(5); assert.equal(request[3], 3); const host = (await reader.read(request[4])).toString(), port = (await reader.read(2)).readUInt16BE(); targets.push({ host, port });
      upstream = wireConnect({ host: target.host, port: target.port }); upstreams.add(upstream); upstream.on('error', () => socket.destroy()); await once(upstream, 'connect');
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])); reader.release(); socket.once('close', () => upstream.destroy()); upstream.once('close', () => { upstreams.delete(upstream); socket.destroy(); }); socket.pipe(upstream); upstream.pipe(socket); socket.resume();
    } catch { reader.release(); socket.destroy(); upstream?.destroy(); }
  }, family); t.after(() => { for (const socket of upstreams) socket.destroy(); }); return { ...proxy, targets };
}
async function configured(t, proxy, kind = 'http', family = 4) { const r = new NetworkRelay({ upstream: { kind, host: proxy.host, port: proxy.port, fingerprint: 'owned-fixture' } }); r.pinIPFamily(family); await r.start(); t.after(() => r.close()); return r; }
function forbidTargetDNS(t, permitted = '') { const original = dns.lookup, lookedUp = []; dns.lookup = (host, options, callback) => { lookedUp.push(host); if (host === permitted) { if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]); else callback(null, '127.0.0.1', 4); } else callback(Error('Unexpected target DNS')); }; t.after(() => { dns.lookup = original; }); return lookedUp; }
async function tunnelEcho(t, r, host, port, payload = 'guarded-through-proxy') { const socket = await connectTunnel(r.port, host, port); t.after(() => socket.destroy()); socket.resume(); const received = once(socket, 'data'); socket.write(payload); assert.equal((await received)[0].toString(), payload); return socket; }

test('upstream descriptors are captured, immutable, credential-free and distinguish remote-proxy family scope', () => {
  const direct = new NetworkRelay({ upstream: { kind: 'direct', host: '', port: 0, fingerprint: 'direct-fixture' } }); assert.equal(direct.ipFamilyBound, 'direct'); direct.close();
  const supplied = { kind: 'http', host: '127.0.0.1', port: 9697 }, r = new NetworkRelay({ upstream: supplied }); supplied.host = 'changed.invalid'; assert.equal(r.upstream.host, '127.0.0.1'); assert.equal(r.ipFamilyBound, 'upstream-proxy'); assert.ok(Object.isFrozen(r.upstream)); assert.throws(() => { r.upstream.port = 80; }, TypeError); r.close();
  for (const upstream of [null, { kind: 'pac' }, { kind: 'http', host: 'user:pass@proxy', port: 80 }, { kind: 'http', host: 'proxy.invalid', port: 80, password: 'forbidden' }, { kind: 'http', host: 'proxy.invalid\r\nInjected: yes', port: 80 }, { kind: 'http', host: '', port: 80 }, { kind: 'direct', host: 'proxy.invalid', port: 80 }, { kind: 'socks5', host: 'proxy.invalid', port: 0 }]) assert.throws(() => new NetworkRelay({ upstream }));
});

for (const kind of ['http', 'socks5']) test(`network mode uses captured ${kind} upstream and never resolves an application hostname locally`, { timeout: 5000 }, async t => {
  const target = await echo(t); await positive(t, target); const proxy = kind === 'http' ? await httpProxy(t, target) : await socksProxy(t, target), r = await configured(t, proxy, kind); r.unlock();
  const lookups = forbidTargetDNS(t), destination = 'remote-only.invalid'; await tunnelEcho(t, r, destination, target.port);
  assert.deepEqual(lookups, []); assert.equal(target.accepted, 2);
  if (kind === 'http') assert.deepEqual(proxy.requests, [`CONNECT ${destination}:${target.port} HTTP/1.1\r\nHost: ${destination}:${target.port}\r\n\r\n`]);
  else assert.deepEqual(proxy.targets, [{ host: destination, port: target.port }]);
});

for (const kind of ['http', 'socks5']) test(`a local IPv6 ${kind} proxy remains reachable when the observed remote exit is pinned IPv4`, { timeout: 5000 }, async t => {
  const target = await echo(t); await positive(t, target); const proxy = kind === 'http' ? await httpProxy(t, target, { family: 6 }) : await socksProxy(t, target, 6), r = await configured(t, proxy, kind, 4); r.unlock();
  await tunnelEcho(t, r, 'remote-v4-exit.invalid', target.port); assert.equal(target.accepted, 2); assert.equal(r.ipFamilyBound, 'upstream-proxy'); assert.equal(r.upstream.host, '::1');
});

test('the proxy endpoint may resolve locally, while every target hostname remains opaque to local DNS', { timeout: 5000 }, async t => {
  const target = await echo(t), proxy = await httpProxy(t, target), r = await configured(t, { ...proxy, host: 'configured-proxy.invalid' }); r.unlock();
  const lookups = forbidTargetDNS(t, 'configured-proxy.invalid'); await tunnelEcho(t, r, 'private-target.invalid', target.port); assert.deepEqual(lookups, ['configured-proxy.invalid']); assert.equal(target.accepted, 1);
});

for (const kind of ['http', 'socks5']) for (const family of [4, 6]) test(`${kind} upstream transport failure never falls back to a reachable IPv${family} receiver or destination DNS`, { timeout: 5000 }, async t => {
  const target = await echo(t, family); await positive(t, target); const reserve = await server(t, socket => socket.destroy()); await new Promise(resolve => reserve.server.close(resolve));
  const r = await configured(t, reserve, kind, family); r.unlock(); const lookups = forbidTargetDNS(t); let directAttempts = 0; const original = net.createConnection;
  net.createConnection = function (options, ...args) { if (options?.host === target.host && options.port === target.port) directAttempts++; return original.call(this, options, ...args); }; t.after(() => { net.createConnection = original; });
  await assert.rejects(connectTunnel(r.port, target.host, target.port)); await assert.rejects(connectTunnel(r.port, 'no-fallback.invalid', target.port)); await delay(25);
  assert.equal(directAttempts, 0); assert.deepEqual(lookups, []); assert.equal(target.accepted, 1); assert.equal(Buffer.concat(target.received).toString(), 'unrestricted-baseline');
});

test('HTTP CONNECT strips private Guard authorization, request cookies and proxy credentials from upstream negotiation', { timeout: 5000 }, async t => {
  const target = await echo(t), proxy = await httpProxy(t, target), r = await configured(t, proxy);
  const socket = wireConnect({ host: '127.0.0.1', port: r.port }); socket.on('error', () => {}); t.after(() => socket.destroy()); await once(socket, 'connect');
  const reply = once(socket, 'data'); socket.write(`CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\nProxy-Authorization: Bearer ${r.checkToken}\r\nCookie: private-cookie\r\nAuthorization: Bearer private-application-key\r\nProxy-Connection: keep-alive\r\n\r\n`); assert.match((await reply)[0].toString(), /^HTTP\/1\.1 200 /); assert.deepEqual(proxy.requests, ['CONNECT ipwho.is:443 HTTP/1.1\r\nHost: ipwho.is:443\r\n\r\n']); assert.ok(!proxy.requests[0].includes(r.checkToken));
});

for (const response of ['HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="fixture"\r\n\r\n', 'HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\n\r\n', 'HTTP/1.1 2000 Invalid\r\n\r\n', 'HTTP/1.1 200 OK\r\n Folded: bad\r\n\r\n', 'HTTP/1.1 200 OK\r\nX-Bare: bad\nInjected: yes\r\n\r\n', 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n', 'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody']) test('HTTP upstream rejects an untrusted CONNECT response: ' + JSON.stringify(response.slice(0, 48)), { timeout: 5000 }, async t => {
  const target = await echo(t), proxy = await httpProxy(t, target, { response }), r = await configured(t, proxy); r.unlock();
  await assert.rejects(connectTunnel(r.port, 'rejected-response.invalid', 443)); assert.equal(target.accepted, 0); assert.equal(proxy.requests.length, 1);
});

test('HTTP proxy headers stay bounded and early tunnel bytes survive a fragmented successful CONNECT', { timeout: 5000 }, async t => {
  let socketCount = 0;
  const proxy = await server(t, socket => socket.once('data', () => { if (++socketCount === 1) socket.end('HTTP/1.1 200 OK\r\nX-Large: ' + 'x'.repeat(17000) + '\r\n\r\n'); else { socket.write('HTTP/1.1 200 Con'); setTimeout(() => socket.write('nection Established\r\n\r\nearly-tunnel-data'), 5); socket.on('data', data => socket.write(data)); } }));
  await assert.rejects(connectHTTP(proxy, 'fixture.invalid', 443));
  const socket = await connectHTTP(proxy, 'fixture.invalid', 443); t.after(() => socket.destroy()); const received = once(socket, 'data'); socket.resume(); assert.equal((await received)[0].toString(), 'early-tunnel-data');
});

for (const action of ['pause', 'close']) test(`${action} destroys a pending HTTP upstream handshake and its local client`, { timeout: 5000 }, async t => {
  const target = await echo(t), proxy = await httpProxy(t, target, { hold: true }), r = await configured(t, proxy); r.unlock();
  const pending = connectTunnel(r.port, 'held-http-proxy.invalid', 443); pending.catch(() => {}); await until(() => proxy.requests.length === 1, 'Proxy did not receive CONNECT'); r[action](); await assert.rejects(pending);
  await until(() => proxy.peers.size === 0, 'Held HTTP proxy socket survived cancellation'); assert.equal(target.accepted, 0); assert.equal(r.sockets.size, 0);
});
