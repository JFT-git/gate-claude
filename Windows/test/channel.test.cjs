'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { once } = require('node:events');
const { performance } = require('node:perf_hooks');
const { Channel } = require('../src/channel.cjs');

const encode = value => Buffer.from(JSON.stringify(value) + '\0');
const hello = token => ({ method: 'ProxyGuard.hello', params: { token } });
const turn = () => new Promise(resolve => setImmediate(resolve));
function closed(socket) { return socket.closed ? Promise.resolve() : new Promise(resolve => socket.once('close', resolve)); }
async function fixture(t) {
  const channel = new Channel(), fatals = [], sockets = [];
  channel.on('fatal', reason => fatals.push(reason));
  await channel.listen();
  t.after(async () => {
    const finished = channel.server.listening ? new Promise(resolve => channel.server.once('close', resolve)) : Promise.resolve();
    for (const socket of sockets) socket.destroy();
    channel.close(); await finished;
  });
  async function open() {
    const socket = net.connect(channel.path); sockets.push(socket);
    socket.on('error', () => {});
    await once(socket, 'connect'); socket.resume(); return socket;
  }
  async function authenticate() {
    const connected = channel.connected(2000), socket = await open(); socket.write(encode(hello(channel.token))); await connected;
    assert.equal(channel.socket.destroyed, false); return socket;
  }
  return { channel, fatals, open, authenticate };
}
async function commandRoundTrip(channel, peer) {
  let buffer = Buffer.alloc(0);
  const receive = chunk => {
    buffer = Buffer.concat([buffer, chunk]); const end = buffer.indexOf(0);
    if (end < 0) return;
    peer.off('data', receive);
    const message = JSON.parse(buffer.subarray(0, end).toString());
    assert.equal(message.method, 'Fixture.echo');
    assert.deepEqual(message.params, { owned: true });
    peer.write(encode({ id: message.id, result: { reply: 'fixture' } }));
  };
  peer.on('data', receive);
  assert.deepEqual(await channel.command('Fixture.echo', { owned: true }), { reply: 'fixture' });
}

const malformed = [
  ['null', () => encode(null)],
  ['array', () => encode([])],
  ['string', () => encode('hello')],
  ['number', () => encode(123)],
  ['boolean', () => encode(true)],
  ['empty object', () => encode({})],
  ['invalid JSON', () => Buffer.from('{bad json\0')],
  ['empty packet', () => Buffer.from('\0')],
  ['params null', () => encode({ method: 'ProxyGuard.hello', params: null })],
  ['params array', () => encode({ method: 'ProxyGuard.hello', params: [] })],
  ['wrong method', c => encode({ method: 'Other.hello', params: { token: c.token } })],
  ['missing token', () => encode({ method: 'ProxyGuard.hello', params: {} })],
  ['token null', () => encode(hello(null))],
  ['token number', () => encode(hello(42))],
  ['token boolean', () => encode(hello(true))],
  ['token object', () => encode(hello({}))],
  ['token object coercion', () => encode(hello({ toString: null }))],
  ['token array coercion', c => encode(hello([c.token]))],
  ['short token', c => encode(hello(c.token.slice(1)))],
  ['long token', c => encode(hello(c.token + '0'))],
  ['wrong token', c => encode(hello(c.token[0] === 'a' ? 'b' + c.token.slice(1) : 'a' + c.token.slice(1)))],
];
for (const [name, packet] of malformed) {
  test('unauthenticated ' + name + ' is rejected without a process error or fatal and the next peer can authenticate', { timeout: 5000 }, async t => {
    const f = await fixture(t), attacker = await f.open(), close = closed(attacker);
    attacker.write(packet(f.channel)); await close;
    assert.equal(f.channel.socket, undefined);
    assert.deepEqual(f.fatals, []);
    const legitimate = await f.authenticate();
    await commandRoundTrip(f.channel, legitimate);
    assert.deepEqual(f.fatals, []);
  });
}

test('fragmented authentication waits for its delimiter, then exchanges commands normally', { timeout: 5000 }, async t => {
  const f = await fixture(t), peer = await f.open(), packet = encode(hello(f.channel.token));
  for (const part of [packet.subarray(0, 2), packet.subarray(2, 19), packet.subarray(19, packet.length - 1)]) {
    peer.write(part); await turn(); assert.equal(f.channel.socket, undefined);
  }
  const connected = f.channel.connected(2000); peer.write(packet.subarray(-1)); await connected;
  await commandRoundTrip(f.channel, peer); assert.deepEqual(f.fatals, []);
});

test('a fragmented UTF-8 event and multiple packets in a read retain their framing', { timeout: 5000 }, async t => {
  const f = await fixture(t), events = []; f.channel.on('event', (...args) => events.push(args));
  const peer = await f.authenticate(), packet = encode({ method: 'Fixture.event', params: { text: 'Привет 🌍' }, sessionId: 'owned-session' });
  const split = packet.indexOf(Buffer.from('🌍')) + 1;
  peer.write(packet.subarray(0, split)); await turn(); assert.deepEqual(events, []);
  peer.write(Buffer.concat([packet.subarray(split), encode({ method: 'Fixture.second', params: { count: 2 } })]));
  const deadline = Date.now() + 2000;
  while (events.length < 2 && Date.now() < deadline) await turn();
  assert.deepEqual(events, [['Fixture.event', { text: 'Привет 🌍' }, 'owned-session'], ['Fixture.second', { count: 2 }, '']]);
  assert.deepEqual(f.fatals, []);
});

test('an oversized unauthenticated frame closes only its peer and admits a subsequent legitimate connection', { timeout: 10000 }, async t => {
  const f = await fixture(t), attacker = await f.open(), close = closed(attacker);
  attacker.write(Buffer.alloc(8 * 1024 * 1024 + 1, 0x78)); await close;
  assert.equal(f.channel.socket, undefined); assert.deepEqual(f.fatals, []);
  await commandRoundTrip(f.channel, await f.authenticate()); assert.deepEqual(f.fatals, []);
});

test('closing an unauthenticated incomplete frame leaves the channel available', { timeout: 5000 }, async t => {
  const f = await fixture(t), peer = await f.open(), close = closed(peer);
  peer.end('{"method":'); await close;
  assert.equal(f.channel.socket, undefined); assert.deepEqual(f.fatals, []);
  await commandRoundTrip(f.channel, await f.authenticate());
});

for (const value of [null, [], 42, 'invalid']) {
  test('malformed authenticated ' + JSON.stringify(value) + ' closes the session without an uncaught exception', { timeout: 5000 }, async t => {
    const f = await fixture(t), peer = await f.authenticate(), close = closed(peer);
    const pending = f.channel.command('Fixture.pending'), rejected = assert.rejects(pending, /Канал/);
    peer.write(encode(value)); await close; await rejected;
    assert.equal(f.channel.pending.size, 0); assert.equal(f.fatals.length, 1);
  });
}

test('an authenticated disconnect rejects pending commands and emits a fatal once', { timeout: 5000 }, async t => {
  const f = await fixture(t), peer = await f.authenticate();
  const rejected = assert.rejects(f.channel.command('Fixture.pending'), /Канал/);
  const fatal = once(f.channel, 'fatal'); peer.destroy(); await rejected; await fatal;
  assert.equal(f.channel.pending.size, 0); assert.equal(f.fatals.length, 1);
});

test('intentional close rejects pending commands and marks the channel closed', { timeout: 5000 }, async t => {
  const f = await fixture(t); await f.authenticate();
  const rejected = assert.rejects(f.channel.command('Fixture.pending'), /Канал/);
  f.channel.close(); await rejected; await turn();
  assert.equal(f.channel.closed, true); assert.equal(f.channel.pending.size, 0);
  await assert.rejects(f.channel.command('Fixture.after-close'), /Канал/);
});

test('CDP deadlines pause while frozen and a late reply is accepted after thaw', { timeout: 5000 }, async t => {
  const f = await fixture(t), peer = await f.authenticate();
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: 0 });
  t.mock.method(performance, 'now', () => Date.now());
  const data = once(peer, 'data'), pending = f.channel.command('Fixture.frozen');
  const message = JSON.parse((await data)[0].toString().replace(/\0$/, ''));
  f.channel.setFrozen(true); t.mock.timers.tick(20000);
  assert.equal(f.channel.pending.has(message.id), true);
  f.channel.setFrozen(false); peer.write(encode({ id: message.id, result: { survived: true } }));
  assert.deepEqual(await pending, { survived: true });
});

test('CDP timeout retains only the active-time budget across a long freeze', { timeout: 5000 }, async t => {
  const f = await fixture(t); await f.authenticate();
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: 0 });
  t.mock.method(performance, 'now', () => Date.now());
  const pending = f.channel.command('Fixture.frozen'), rejection = assert.rejects(pending, /CDP timeout/);
  const id = [...f.channel.pending.keys()][0];
  t.mock.timers.tick(2000); f.channel.setFrozen(true); t.mock.timers.tick(30000);
  assert.equal(f.channel.pending.has(id), true);
  f.channel.setFrozen(false); t.mock.timers.tick(3999); assert.equal(f.channel.pending.has(id), true);
  t.mock.timers.tick(1); await rejection; assert.equal(f.channel.pending.size, 0);
});
