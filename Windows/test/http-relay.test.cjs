"use strict";
// Only owned loopback peers and fake DNS answers are used by these tests.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const dns = require('node:dns');
const { once } = require('node:events');
const { NetworkRelay, SOCKSRelay } = require('../src/relay.cjs');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, message) { const end = Date.now() + 1500; while (!predicate()) { if (Date.now() > end) assert.fail(message); await delay(5); } }
async function server(t, handler) {
  const peers = new Set(), s = net.createServer({ allowHalfOpen: true }, socket => { peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket)); handler(socket); });
  s.listen(0, '127.0.0.1'); await once(s, 'listening'); t.after(async () => { for (const socket of peers) socket.destroy(); if (s.listening) await new Promise(resolve => s.close(resolve)); }); return { port: s.address().port, peers, server: s };
}
async function relayFixture(t, proxy) { const relay = proxy ? new SOCKSRelay({ host: '127.0.0.1', port: proxy.port }) : new NetworkRelay(); const fatals = [], revalidations = []; relay.on('fatal', value => fatals.push(value)); relay.on('revalidate', value => revalidations.push(value)); await relay.start(); t.after(() => relay.close()); return { relay, fatals, revalidations }; }
async function open(t, port) { const socket = net.createConnection({ host: '127.0.0.1', port }); socket.on('error', () => {}); await once(socket, 'connect'); t.after(() => socket.destroy()); return socket; }
function response(socket) { return new Promise(resolve => { const chunks = []; socket.on('data', chunk => chunks.push(chunk)); const done = () => resolve(Buffer.concat(chunks)); socket.once('end', done).once('close', done); }); }
async function exchange(t, relay, bytes) { const socket = await open(t, relay.port), result = response(socket); socket.write(bytes); return { socket, bytes: await result }; }
function split(bytes) { const end = bytes.indexOf('\r\n\r\n'); return { header: bytes.subarray(0, end).toString('latin1'), body: bytes.subarray(end + 4) }; }
async function origin(t, hold = false) {
  const requests = [], ended = []; const peer = await server(t, socket => { const chunks = []; socket.on('data', chunk => chunks.push(chunk)); socket.on('end', () => { const all = Buffer.concat(chunks); requests.push(all); ended.push(socket); if (!hold) socket.end('HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello'); }); socket.getFixtureBytes = () => Buffer.concat(chunks); }); return { ...peer, requests, ended };
}
async function socks(t, hold = '', refusal = false) {
  const targets = [], greetings = [], application = []; const peer = await server(t, socket => {
    let pending = Buffer.alloc(0), state = 'greeting'; const chunks = [];
    const parse = () => {
      if (state === 'greeting' && pending.length >= 2 + pending[1]) { greetings.push(Buffer.from(pending.subarray(0, 2 + pending[1]))); pending = pending.subarray(2 + pending[1]); state = hold === 'greeting' ? 'held-greeting' : 'request'; if (state === 'request') socket.write(Buffer.from([5, 0])); }
      if (state === 'request' && pending.length >= 5 && pending.length >= 7 + pending[4]) { const n = pending[4]; assert.equal(pending[3], 3); targets.push({ host: pending.subarray(5, 5 + n).toString(), port: pending.readUInt16BE(5 + n) }); pending = pending.subarray(7 + n); state = hold === 'connect' ? 'held-connect' : 'stream'; if (state === 'stream') socket.write(Buffer.from([5, refusal ? 5 : 0, 0, 1, 127, 0, 0, 1, 0, 0])); }
      if (state === 'stream' && pending.length) { chunks.push(Buffer.from(pending)); application.push(Buffer.from(pending)); pending = Buffer.alloc(0); }
    };
    socket.on('data', chunk => { pending = Buffer.concat([pending, chunk]); parse(); }); socket.on('end', () => { if (state === 'stream' && !refusal) socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'); else socket.end(); });
    socket.release = () => { if (state === 'held-greeting') { state = 'request'; socket.write(Buffer.from([5, 0])); } else if (state === 'held-connect') { state = 'stream'; socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])); } parse(); };
  }); return { ...peer, targets, greetings, application, release() { for (const socket of peer.peers) socket.release(); } };
}
function mockDNS(t, implementation) { const original = dns.lookup; dns.lookup = implementation; t.after(() => { dns.lookup = original; }); }
function answer(options, callback) { if (options?.all) callback(null, [{ address: '127.0.0.1', family: 4 }]); else callback(null, '127.0.0.1', 4); }

test('HTTP current-network POST preserves exact binary body, rewrites origin/Host and strips all proxy and hop-by-hop credentials', async t => {
  const dest = await origin(t), { relay } = await relayFixture(t); relay.unlock();
  const body = Buffer.from([0, 255, 10, 13, 71, 69, 84]), uri = `http://127.0.0.1:${dest.port}/upload?q=fixture`;
  const headers = `POST ${uri} HTTP/1.1\r\nHost: 127.0.0.1:${dest.port}\r\nContent-Length: ${body.length}\r\nProxy-Authorization: Bearer private-one\r\npRoXy-AuThOrIzAtIoN: private-two\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, X-Hop\r\nX-Hop: private-hop\r\nKeep-Alive: timeout=99\r\nTE: trailers\r\nUpgrade: websocket\r\nAuthorization: fixture-origin-auth\r\nContent-Type: application/octet-stream\r\n\r\n`;
  const result = await exchange(t, relay, Buffer.concat([Buffer.from(headers), body])); assert.match(result.bytes.toString(), /^HTTP\/1\.1 200 /); assert.ok(result.bytes.toString().endsWith('hello'));
  const actual = split(dest.requests[0]); assert.ok(actual.header.startsWith(`POST /upload?q=fixture HTTP/1.1\r\nHost: 127.0.0.1:${dest.port}\r\n`)); assert.match(actual.header, /authorization: fixture-origin-auth/); assert.match(actual.header, /Connection: close$/); assert.ok(!/proxy-|x-hop|keep-alive|^te:|upgrade:/mi.test(actual.header)); assert.ok(actual.body.equals(body));
});
test('HTTP SOCKS forwarding keeps destination DNS remote and never sends proxy authorization as application bytes', async t => {
  const proxy = await socks(t), { relay } = await relayFixture(t, proxy); relay.unlock(); const lookups = []; mockDNS(t, (host, options, callback) => { lookups.push(host); callback(Error('Unexpected local DNS')); });
  const result = await exchange(t, relay, 'POST http://http-only.invalid/path HTTP/1.1\r\nHost: http-only.invalid:80\r\nProxy-Authorization: fixture-secret\r\nContent-Length: 4\r\n\r\nbody'); assert.match(result.bytes.toString(), /^HTTP\/1\.1 200 /); assert.deepEqual(proxy.targets, [{ host: 'http-only.invalid', port: 80 }]); assert.deepEqual(lookups, []);
  const actual = split(Buffer.concat(proxy.application)); assert.ok(actual.header.startsWith('POST /path HTTP/1.1\r\nHost: http-only.invalid\r\n')); assert.ok(!actual.header.includes('fixture-secret')); assert.equal(actual.body.toString(), 'body');
});
test('strict chunked body survives fragmented framing and reaches only one HTTP origin request', async t => {
  const dest = await origin(t), { relay } = await relayFixture(t); relay.unlock(); const socket = await open(t, relay.port), result = response(socket), ready = once(relay, 'tunnel');
  socket.write(`POST http://127.0.0.1:${dest.port}/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n`); await ready;
  for (const part of ['3\r', '\n', 'ab', 'c\r\n0\r', '\n\r', '\n']) { socket.write(part); await delay(2); }
  assert.match((await result).toString(), /^HTTP\/1\.1 200 /); const actual = split(dest.requests[0]); assert.equal(actual.body.toString(), '3\r\nabc\r\n0\r\n\r\n'); assert.equal(actual.header.match(/Transfer-Encoding: chunked/g).length, 1);
});
test('ambiguous framing, unsafe absolute URIs and malformed headers cannot open any upstream', async t => {
  const proxy = await socks(t), { relay } = await relayFixture(t, proxy); relay.unlock();
  const cases = [
    'GET https://http-only.invalid/ HTTP/1.1\r\n\r\n', 'GET /relative HTTP/1.1\r\n\r\n', 'GET http://user:password@http-only.invalid/ HTTP/1.1\r\n\r\n', 'GET http://http-only.invalid/#fragment HTTP/1.1\r\n\r\n', 'GET http://http-only.invalid/\\evil HTTP/1.1\r\n\r\n', 'GET http://http-only.invalid/%zz HTTP/1.1\r\n\r\n', 'GET http://http-only.invalid/%0d%0aX HTTP/1.1\r\n\r\n',
    'GET http://http-only.invalid/ HTTP/1.1\r\nHost: http-only.invalid\r\nhost: http-only.invalid\r\n\r\n', 'GET http://http-only.invalid/ HTTP/1.1\r\nHost: different.invalid\r\n\r\n', 'POST http://http-only.invalid/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n', 'POST http://http-only.invalid/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx', 'POST http://http-only.invalid/ HTTP/1.1\r\nContent-Length: +1\r\n\r\nx', 'POST http://http-only.invalid/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n', 'POST http://http-only.invalid/ HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n', 'POST http://http-only.invalid/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTrailer: X-Secret\r\n\r\n', 'GET http://http-only.invalid/ HTTP/1.1\r\n Folded: forbidden\r\n\r\n', 'GET http://http-only.invalid/ HTTP/1.1\r\nX-Test: bad\nInjected: header\r\n\r\n', 'GET http://http-only.invalid/ HTTP/1.1\r\nConnection: content-length\r\nContent-Length: 0\r\n\r\n'
  ];
  for (const raw of cases) { const result = await exchange(t, relay, raw); assert.match(result.bytes.toString(), /^HTTP\/1\.1 502 /, raw.slice(0, 100)); }
  assert.equal(proxy.greetings.length, 0); assert.equal(proxy.targets.length, 0);
});
test('pipelined requests, body overruns, chunk extensions and trailers in the initial buffer are rejected before SOCKS', async t => {
  const proxy = await socks(t), { relay } = await relayFixture(t, proxy); relay.unlock();
  for (const tail of ['Content-Length: 0\r\n\r\nGET http://second.invalid/ HTTP/1.1\r\n\r\n', 'Content-Length: 3\r\n\r\nbody', 'Transfer-Encoding: chunked\r\n\r\n1;extra=x\r\nx\r\n0\r\n\r\n', 'Transfer-Encoding: chunked\r\n\r\n0\r\nX-Secret: forbidden\r\n\r\n']) { const result = await exchange(t, relay, 'POST http://first.invalid/ HTTP/1.1\r\n' + tail); assert.match(result.bytes.toString(), /^HTTP\/1\.1 502 /); }
  assert.equal(proxy.greetings.length, 0); assert.equal(proxy.application.length, 0);
});
test('oversized HTTP headers are closed before a DNS or proxy connection', async t => {
  const proxy = await socks(t), { relay } = await relayFixture(t, proxy); relay.unlock(); const result = await exchange(t, relay, 'GET http://oversized.invalid/ HTTP/1.1\r\nX-Large: ' + 'x'.repeat(17000) + '\r\n\r\n'); assert.equal(result.bytes.length, 0); assert.equal(proxy.greetings.length, 0);
});
test('plain HTTP cannot borrow the private CONNECT control exception while locked or paused', async t => {
  const proxy = await socks(t), { relay } = await relayFixture(t, proxy);
  for (const paused of [false, true]) { if (paused) { relay.unlock(); relay.pause(); } const result = await exchange(t, relay, `GET http://ipwho.is/ HTTP/1.1\r\nProxy-Authorization: Bearer ${relay.checkToken}\r\n\r\n`); assert.match(result.bytes.toString(), /^HTTP\/1\.1 403 /); }
  assert.equal(proxy.greetings.length, 0); assert.equal(relay.controlSockets.size, 0);
});
for (const action of ['pause', 'close']) test(`HTTP ${action} cancels delayed destination DNS and prevents a later connection`, async t => {
  const dest = await origin(t), { relay } = await relayFixture(t); relay.unlock(); let finish;
  mockDNS(t, (host, options, callback) => { assert.equal(host, 'delayed-http.invalid'); finish = () => answer(options, callback); });
  const socket = await open(t, relay.port); socket.write(`POST http://delayed-http.invalid:${dest.port}/ HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody`); await until(() => finish, 'DNS was not reached'); const closed = once(socket, 'close'); relay[action](); await closed; finish(); await delay(80); assert.equal(dest.peers.size, 0); assert.equal(dest.requests.length, 0);
});
for (const phase of ['greeting', 'connect']) test(`HTTP pause cancels pending SOCKS ${phase} and never forwards its buffered request`, async t => {
  const proxy = await socks(t, phase), { relay, fatals } = await relayFixture(t, proxy); relay.unlock(); const socket = await open(t, relay.port); socket.write('POST http://pending-http.invalid/ HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody'); await until(() => phase === 'greeting' ? proxy.greetings.length : proxy.targets.length, 'SOCKS phase was not reached'); const closed = once(socket, 'close'); relay.pause(); proxy.release(); await closed; await until(() => proxy.peers.size === 0, 'A pending HTTP proxy socket survived'); assert.equal(proxy.application.length, 0); assert.deepEqual(fatals, []);
});
test('HTTP SOCKS target refusal has no direct DNS/TCP fallback and forwards no application data', async t => {
  const proxy = await socks(t, '', true), { relay, revalidations, fatals } = await relayFixture(t, proxy); relay.unlock(); const lookups = []; mockDNS(t, (host, options, callback) => { lookups.push(host); callback(Error('Forbidden fallback')); }); const result = await exchange(t, relay, 'GET http://refused-http.invalid/ HTTP/1.1\r\n\r\n'); assert.match(result.bytes.toString(), /^HTTP\/1\.1 502 /); assert.deepEqual(lookups, []); assert.equal(proxy.targets.length, 1); assert.equal(proxy.application.length, 0); assert.deepEqual(revalidations, []); assert.deepEqual(fatals, []);
});
test('streaming a large body after target readiness preserves bytes under TCP backpressure', async t => {
  const dest = await origin(t), { relay } = await relayFixture(t); relay.unlock(); const socket = await open(t, relay.port), result = response(socket), ready = once(relay, 'tunnel'), body = Buffer.alloc(512 * 1024, 197);
  socket.write(`POST http://127.0.0.1:${dest.port}/large HTTP/1.1\r\nContent-Length: ${body.length}\r\n\r\n`); await ready;
  for (let at = 0; at < body.length; at += 32768) { if (!socket.write(body.subarray(at, at + 32768))) await once(socket, 'drain'); }
  assert.match((await result).toString(), /^HTTP\/1\.1 200 /); assert.ok(split(dest.requests[0]).body.equals(body));
});
test('pause destroys a live partial HTTP body and every associated upstream before resume', async t => {
  const dest = await origin(t, true), { relay } = await relayFixture(t); relay.unlock(); const socket = await open(t, relay.port), ready = once(relay, 'tunnel'); socket.write(`POST http://127.0.0.1:${dest.port}/live HTTP/1.1\r\nContent-Length: 100\r\n\r\npartial`); await ready; const closed = once(socket, 'close'); relay.pause(); await closed; await until(() => relay.sockets.size === 0 && dest.ended.length === 1, 'Guard sockets or the origin read side survived pause'); assert.ok([...dest.peers].every(peer => peer.readableEnded)); relay.resume(); assert.equal(relay.unlocked, true);
});
test('a second HTTP request sent after the framed body never reaches the first destination', async t => {
  const dest = await origin(t, true), { relay } = await relayFixture(t); relay.unlock(); const socket = await open(t, relay.port), ready = once(relay, 'tunnel'); socket.write(`POST http://127.0.0.1:${dest.port}/first HTTP/1.1\r\nContent-Length: 4\r\n\r\n`); await ready; socket.write('body'); await until(() => dest.requests.length === 1, 'First framed request did not complete'); const closed = once(socket, 'close'); socket.write('GET http://second.invalid/ HTTP/1.1\r\nProxy-Authorization: private-not-forwarded\r\n\r\n'); await closed; assert.equal(split(dest.requests[0]).body.toString(), 'body'); assert.ok(!dest.requests[0].toString().includes('private-not-forwarded'));
});

test('a clean HTTP upstream close drains a large response under downstream backpressure without truncation', async t => {
  const body = Buffer.alloc(2 * 1024 * 1024, 211), dest = await server(t, socket => { socket.on('data', () => {}); socket.on('end', () => socket.end(Buffer.concat([Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`), body]))); });
  const { relay } = await relayFixture(t); relay.unlock(); const socket = await open(t, relay.port), ready = once(relay, 'tunnel'), result = response(socket);
  socket.pause(); socket.write(`GET http://127.0.0.1:${dest.port}/large-response HTTP/1.1\r\n\r\n`); await ready; await delay(60); socket.resume();
  const actual = split(await result); assert.ok(actual.body.equals(body));
});
