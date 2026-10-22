'use strict';
// Independent TCP4/TCP6 receivers and DNS fixtures only; no public IP is contacted.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const dns = require('node:dns');
const { once } = require('node:events');
const { NetworkRelay, connectTunnel } = require('../src/relay.cjs');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, message) { const end = Date.now() + 1500; while (!predicate()) { if (Date.now() > end) assert.fail(message); await delay(5); } }
async function receiver(t, family) {
  const sockets = new Set(), received = [], accepted = [];
  const server = net.createServer(socket => {
    sockets.add(socket); accepted.push(socket.remoteFamily); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    socket.on('data', data => { received.push(Buffer.from(data)); socket.write(data); });
  });
  server.listen({ host: family === 4 ? '127.0.0.1' : '::1', port: 0, ipv6Only: family === 6 }); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); if (server.listening) await new Promise(resolve => server.close(resolve)); });
  return { port: server.address().port, host: family === 4 ? '127.0.0.1' : '::1', accepted, received, sockets };
}
async function baseline(t, destination, host = destination.host) {
  const socket = net.createConnection({ host, port: destination.port, autoSelectFamily: false }); socket.on('error', () => {}); t.after(() => socket.destroy());
  await once(socket, 'connect'); const echoed = once(socket, 'data'); socket.write('positive-baseline'); assert.equal((await echoed)[0].toString(), 'positive-baseline'); socket.destroy();
}
async function relay(t, family) { const relay = new NetworkRelay(); if (family) relay.pinIPFamily(family); await relay.start(); t.after(() => relay.close()); return relay; }
async function echoTunnel(t, relay, destination, host = destination.host) {
  const socket = await connectTunnel(relay.port, host, destination.port); t.after(() => socket.destroy()); socket.resume();
  const echoed = once(socket, 'data'); socket.write('guarded-echo'); assert.equal((await echoed)[0].toString(), 'guarded-echo'); socket.destroy();
}
async function proxyReply(t, relay, bytes) {
  const socket = net.createConnection({ host: '127.0.0.1', port: relay.port }); socket.on('error', () => {}); t.after(() => socket.destroy()); await once(socket, 'connect');
  const reply = new Promise((resolve, reject) => {
    let buffer = ''; socket.on('data', data => { buffer += data.toString('latin1'); if (buffer.includes('\r\n\r\n')) resolve(buffer); }); socket.once('error', reject); socket.once('end', () => resolve(buffer));
  }); socket.write(bytes); return reply;
}
function mockDNS(t, implementation) { const original = dns.lookup; dns.lookup = implementation; t.after(() => { dns.lookup = original; }); }

test('current-network family must be pinned before unlock and stays immutable through pause and resume', async t => {
  const r = await relay(t);
  assert.equal(r.ipFamily, 0); assert.throws(() => r.unlock(), /ещё не закреплено/); assert.throws(() => r.resume(), /ещё не закреплено/);
  for (const value of [0, 5, '4', null, undefined, NaN]) assert.throws(() => r.pinIPFamily(value), /4 или 6/);
  r.pinIPFamily(4); assert.equal(r.ipFamily, 4); assert.throws(() => { r.ipFamily = 6; }, TypeError);
  for (const family of [4, 6]) assert.throws(() => r.pinIPFamily(family), /уже закреплено/);
  r.unlock(); r.pause(); assert.equal(r.ipFamily, 4); assert.throws(() => r.pinIPFamily(6), /уже закреплено/); r.resume(); assert.equal(r.unlocked, true);
  r.close(); assert.throws(() => r.pinIPFamily(4), /закрыт/); assert.throws(() => r.unlock(), /закрыт/);
});

for (const family of [4, 6]) test(`only the pinned IPv${family} family can reach literal receivers over CONNECT or ordinary HTTP`, { timeout: 5000 }, async t => {
  const destinations = { 4: await receiver(t, 4), 6: await receiver(t, 6) };
  await baseline(t, destinations[4]); await baseline(t, destinations[6]);
  const r = await relay(t, family), denied = destinations[family === 4 ? 6 : 4], allowed = destinations[family]; r.unlock();
  await echoTunnel(t, r, allowed); assert.equal(allowed.accepted.length, 2);
  const allowedAuthority = (family === 6 ? '[::1]' : '127.0.0.1') + ':' + allowed.port;
  const allowedBody = 'allowed-http-body';
  const forwarded = await proxyReply(t, r, `POST http://${allowedAuthority}/pinned HTTP/1.1\r\nContent-Length: ${Buffer.byteLength(allowedBody)}\r\n\r\n${allowedBody}`);
  assert.match(forwarded, /^POST \/pinned HTTP\/1\.1/); assert.equal(allowed.accepted.length, 3);
  await until(() => Buffer.concat(allowed.received).includes(Buffer.from(allowedBody)), 'Allowed-family HTTP body did not reach its receiver');
  const attempts = [], original = net.createConnection;
  net.createConnection = function (options, ...args) { if (options?.host === denied.host && options.port === denied.port) attempts.push(options); return original.call(this, options, ...args); };
  t.after(() => { net.createConnection = original; });
  await assert.rejects(connectTunnel(r.port, denied.host, denied.port));
  const authority = (family === 4 ? '[::1]' : '127.0.0.1') + ':' + denied.port;
  const deniedBody = 'private-cross-family-payload';
  assert.match(await proxyReply(t, r, `POST http://${authority}/ HTTP/1.1\r\nContent-Length: ${Buffer.byteLength(deniedBody)}\r\n\r\n${deniedBody}`), /^HTTP\/1\.1 502 /);
  assert.equal(attempts.length, 0, 'A refused literal must not create an upstream socket');
  assert.equal(denied.accepted.length, 1, 'Only the unrestricted positive baseline reached the opposite-family receiver');
  assert.equal(Buffer.concat(denied.received).toString(), 'positive-baseline');
});

for (const family of [4, 6]) test(`hostname DNS is constrained to IPv${family} without automatic family fallback or accepting wrong-family answers`, { timeout: 5000 }, async t => {
  const destinations = { 4: await receiver(t, 4), 6: await receiver(t, 6) }; await baseline(t, destinations[4]); await baseline(t, destinations[6]);
  const r = await relay(t, family); r.unlock(); const optionsSeen = [], lookups = [], original = net.createConnection;
  net.createConnection = function (options, ...args) { if (options?.host?.endsWith('.invalid')) optionsSeen.push({ family: options.family, autoSelectFamily: options.autoSelectFamily }); return original.call(this, options, ...args); };
  t.after(() => { net.createConnection = original; });
  mockDNS(t, (host, options, callback) => {
    lookups.push({ host, family: options.family, all: options.all });
    const answerFamily = host === 'wrong-family.invalid' ? (family === 4 ? 6 : 4) : family;
    queueMicrotask(() => callback(null, destinations[answerFamily].host, answerFamily));
  });
  await echoTunnel(t, r, destinations[family], 'pinned-family.invalid');
  const other = destinations[family === 4 ? 6 : 4]; await assert.rejects(connectTunnel(r.port, 'wrong-family.invalid', other.port));
  assert.deepEqual(optionsSeen, [{ family, autoSelectFamily: false }, { family, autoSelectFamily: false }]);
  assert.deepEqual(lookups, [{ host: 'pinned-family.invalid', family, all: false }, { host: 'wrong-family.invalid', family, all: false }]);
  assert.equal(other.accepted.length, 1); assert.equal(destinations[family].accepted.length, 2);
});

test('IPv4-mapped IPv6 literals and AAAA answers cannot bypass an IPv6 pin', { timeout: 5000 }, async t => {
  const destination = await receiver(t, 4); await baseline(t, destination, '::ffff:127.0.0.1');
  const r = await relay(t, 6); r.unlock(); let upstreamAttempts = 0; const original = net.createConnection;
  net.createConnection = function (options, ...args) { if (options?.port === destination.port && net.isIP(options.host)) upstreamAttempts++; return original.call(this, options, ...args); };
  t.after(() => { net.createConnection = original; });
  for (const address of ['::ffff:127.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:ffff:7f00:1']) await assert.rejects(connectTunnel(r.port, address, destination.port));
  assert.equal(upstreamAttempts, 0);
  mockDNS(t, (host, options, callback) => { assert.equal(options.family, 6); queueMicrotask(() => callback(null, '::ffff:127.0.0.1', 6)); });
  await assert.rejects(connectTunnel(r.port, 'mapped-answer.invalid', destination.port));
  assert.equal(destination.accepted.length, 1); assert.equal(Buffer.concat(destination.received).toString(), 'positive-baseline');
});

test('pin retires bootstrap controls and constrains subsequent private control probes to the monitored family', { timeout: 5000 }, async t => {
  const tcp4 = await receiver(t, 4), tcp6 = await receiver(t, 6); await baseline(t, tcp4); await baseline(t, tcp6);
  const r = await relay(t), dials = [], original = net.createConnection;
  net.createConnection = function (options, ...args) {
    if (options?.host === 'ipwho.is' && options.port === 443) { dials.push({ family: options.family, autoSelectFamily: options.autoSelectFamily }); return original.call(this, { ...options, port: options.family === 4 ? tcp4.port : tcp6.port }, ...args); }
    return original.call(this, options, ...args);
  }; t.after(() => { net.createConnection = original; });
  mockDNS(t, (host, options, callback) => {
    assert.equal(host, 'ipwho.is'); const family = options.family === 4 ? 4 : 6, address = family === 4 ? tcp4.host : tcp6.host;
    queueMicrotask(() => options.all ? callback(null, [{ address, family }]) : callback(null, address, family));
  });
  const bootstrap = await connectTunnel(r.port, 'ipwho.is', 443, r.checkToken); t.after(() => bootstrap.destroy()); bootstrap.resume();
  const echoed = once(bootstrap, 'data'); bootstrap.write('bootstrap-echo'); assert.equal((await echoed)[0].toString(), 'bootstrap-echo'); assert.equal(tcp6.accepted.length, 2);
  const closed = once(bootstrap, 'close'); r.pinIPFamily(4); await closed; await until(() => tcp6.sockets.size === 0, 'Bootstrap IPv6 control survived IPv4 pin');
  const pinned = await connectTunnel(r.port, 'ipwho.is', 443, r.checkToken); t.after(() => pinned.destroy()); pinned.resume();
  const pinnedEcho = once(pinned, 'data'); pinned.write('pinned-echo'); assert.equal((await pinnedEcho)[0].toString(), 'pinned-echo');
  assert.equal(tcp4.accepted.length, 2); assert.equal(tcp6.accepted.length, 2); assert.equal(dials[1].family, 4); assert.equal(dials[1].autoSelectFamily, false); assert.equal(r.unlocked, false);
});

test('pin cancels bootstrap DNS before its delayed opposite-family answer and subsequent controls reject opposite-family answers', { timeout: 5000 }, async t => {
  const destination = await receiver(t, 6); await baseline(t, destination);
  const r = await relay(t), original = net.createConnection; let answer, pinnedLookup;
  net.createConnection = function (options, ...args) {
    if (options?.host === 'ipwho.is' && options.port === 443) return original.call(this, { ...options, port: destination.port }, ...args);
    return original.call(this, options, ...args);
  }; t.after(() => { net.createConnection = original; });
  mockDNS(t, (host, options, callback) => {
    assert.equal(host, 'ipwho.is'); const resolve = () => options.all ? callback(null, [{ address: '::1', family: 6 }]) : callback(null, '::1', 6);
    if (!r.ipFamily) answer = resolve; else { pinnedLookup = { family: options.family, all: options.all }; queueMicrotask(resolve); }
  });
  const pending = connectTunnel(r.port, 'ipwho.is', 443, r.checkToken); pending.catch(() => {});
  await until(() => answer, 'Bootstrap DNS did not start'); r.pinIPFamily(4); answer(); await assert.rejects(pending);
  await assert.rejects(connectTunnel(r.port, 'ipwho.is', 443, r.checkToken));
  await delay(50); assert.deepEqual(pinnedLookup, { family: 4, all: false }); assert.equal(destination.accepted.length, 1); assert.equal(Buffer.concat(destination.received).toString(), 'positive-baseline');
});
