'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const dgram = require('node:dgram');
const { once } = require('node:events');
const { setPinnedLocalAddresses, connectCurrentNetwork, NetworkRelay, connectTunnel } = require('../src/relay.cjs');
function pin(t, value) { setPinnedLocalAddresses(value); t.after(() => setPinnedLocalAddresses(null)); }
async function receiver(t) {
  const peers = new Set();
  const server = net.createServer(socket => { peers.add(socket); socket.on('error', () => {}); socket.on('close', () => peers.delete(socket)); });
  t.after(() => { for (const peer of peers) peer.destroy(); server.close(); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port;
}
async function dnsServer(t, respond) {
  const server = dgram.createSocket('udp4');
  t.after(() => { try { server.close(); } catch {} });
  server.bind(0, '127.0.0.1'); await once(server, 'listening');
  server.on('message', (query, remote) => respond(server, query, remote));
  return '127.0.0.1:' + server.address().port;
}
function answer(server, query, remote, mapped = false) {
  const header = Buffer.from(query.subarray(0, 12)); header.writeUInt16BE(0x8180, 2); header.writeUInt16BE(1, 6);
  const data = mapped ? Buffer.from('00000000000000000000ffff7f000001', 'hex') : Buffer.from([127, 0, 0, 1]);
  const record = Buffer.alloc(12); record.writeUInt16BE(0xc00c); record.writeUInt16BE(mapped ? 28 : 1, 2); record.writeUInt16BE(1, 4); record.writeUInt16BE(data.length, 10);
  server.send(Buffer.concat([header, query.subarray(12), record, data]), remote.port, remote.address);
}
test('IPv4 socket binds the pinned address', async t => {
  const port = await receiver(t); pin(t, { v4: '127.0.0.1', v6: null });
  const socket = await connectCurrentNetwork('127.0.0.1', port, undefined, 4); t.after(() => socket.destroy());
  assert.equal(socket.localAddress, '127.0.0.1');
});
test('missing IPv4 pin refuses before opening a socket', async t => {
  pin(t, { v4: null, v6: '::1' });
  await assert.rejects(connectCurrentNetwork('127.0.0.1', 443, undefined, 4), error => error.targetRefused && /Локальный адрес/.test(error.message));
});
test('bound DNS resolves a compressed A answer from the pinned source', async t => {
  const port = await receiver(t); let source;
  const server = await dnsServer(t, (socket, query, remote) => { source = remote.address; answer(socket, query, remote); });
  pin(t, { v4: '127.0.0.1', v6: null, dnsServers: [server] });
  const socket = await connectCurrentNetwork('bound.invalid', port, undefined, 4); t.after(() => socket.destroy());
  assert.equal(source, '127.0.0.1'); assert.equal(socket.remoteAddress, '127.0.0.1');
});
test('bound DNS refuses mapped AAAA answers', async t => {
  const server = await dnsServer(t, (socket, query, remote) => answer(socket, query, remote, true));
  pin(t, { v4: '127.0.0.1', v6: '::1', dnsServers: [server] });
  await assert.rejects(connectCurrentNetwork('mapped.invalid', 443, undefined, 6), error => error.targetRefused);
});
test('DNS timeout closes CONNECT without system lookup fallback', { timeout: 7500 }, async t => {
  const server = await dnsServer(t, () => {});
  pin(t, { v4: '127.0.0.1', v6: null, dnsServers: [server] });
  const relay = new NetworkRelay(); await relay.start(); t.after(() => relay.close()); relay.pinIPFamily(4); relay.unlock();
  const dns = require('node:dns'), original = dns.lookup; let fallbacks = 0;
  dns.lookup = () => { fallbacks++; throw Error('Unexpected system DNS'); }; t.after(() => { dns.lookup = original; });
  await assert.rejects(connectTunnel(relay.port, 'timeout.invalid', 443)); assert.equal(fallbacks, 0);
});
