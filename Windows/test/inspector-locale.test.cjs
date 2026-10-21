'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { once, EventEmitter } = require('node:events');
const { Inspector } = require('../src/inspector.cjs');
const { auditRequestHeaders } = require('../src/sanitize.cjs');

const profile = { timezone: 'Europe/Amsterdam', language: 'en-US', locale: 'en-US', url: 'https://fixture.test/' };
class Channel extends EventEmitter {
  constructor(actual = profile) { super(); this.actual = actual; }
  async command(method, params, sid) {
    if (method === 'Browser.getVersion') return { userAgent: 'fixture' };
    if (method === 'Runtime.enable') queueMicrotask(() => this.emit('event', 'Runtime.executionContextCreated', { context: { id: 1, auxData: { isDefault: true } } }, sid));
    if (method === 'Runtime.evaluate') return { result: { value: this.actual } };
    return {};
  }
}
async function fixture(t, captureBodies = true) {
  const channel = new Channel(), inspector = new Inspector(channel, profile, captureBodies);
  t.after(() => inspector.stop());
  const verified = once(inspector, 'verified'); await inspector.start(); await inspector.configure('page'); await verified;
  return { inspector, emit: (method, params) => channel.emit('event', method, params, 'page') };
}

// These fields may be account preferences, translation requests, tool examples or
// quoted chat content. None is evidence of the browser's actual system profile.
const content = JSON.stringify({ account: { language: 'ru-RU', timezone: 'Europe/Moscow' }, content: { locale: 'ru', message: 'Напиши Europe/Moscow в примере.' }, tools: [{ example: { 'Accept-Language': 'ru-RU', locale: 'ru_RU' } }] });
for (const captureBodies of [false, true]) for (const order of ['before', 'after']) {
  test(`Russian account/content locale remains content (capture=${captureBodies}, ExtraInfo=${order})`, async t => {
    const { inspector, emit } = await fixture(t, captureBodies), fatal = []; inspector.on('fatal', reason => fatal.push(reason));
    const request = { url: 'https://fixture.test/chat?token=private', method: 'POST', headers: { 'Accept-Language': 'en-US' }, postData: content };
    const extra = () => emit('Network.requestWillBeSentExtraInfo', { requestId: '1', headers: { 'aCcEpT-LaNgUaGe': 'en-US', 'X-User-Locale': 'ru-RU', 'Content-Language': 'ru', 'X-Timezone': 'Europe/Moscow' } });
    if (order === 'before') extra();
    emit('Network.requestWillBeSent', { requestId: '1', type: 'Fetch', request });
    if (order === 'after') extra();
    const record = inspector.records.get('page:1');
    assert.equal(request.postData, content, 'Inspection must not rewrite application content');
    assert.deepEqual(record.warnings, []); assert.deepEqual(fatal, []); assert.equal(inspector.running, true);
    assert.equal(record.url, 'https://fixture.test/chat');
    if (captureBodies) assert.deepEqual(JSON.parse(record.sent), JSON.parse(content));
    else assert.equal(record.sent, '[содержимое отключено]');
  });
}

test('request header audit checks exact actual header name and all language ranges', () => {
  for (const headers of [undefined, {}, { 'X-Locale': 'ru-RU', 'X-Accept-Language': 'ru-RU', 'Content-Language': 'ru' }, { 'Accept-Language': 'en-US' }, { 'accept-language': 'EN-us, en;q=0.9' }]) {
    assert.deepEqual(auditRequestHeaders(headers, 'en-US'), []);
  }
  assert.deepEqual(auditRequestHeaders({ 'Accept-Language': 'nl-NL,nl;q=0.9' }, 'nl-NL'), []);
  for (const headers of [
    { 'Accept-Language': 'ru-RU' }, { 'Accept-Language': ' ru-RU' },
    { 'Accept-Language': 'en-US,ru-RU;q=0.9' }, { 'Accept-Language': 'en-US,ru;q=0' },
    { 'aCcEpT-LaNgUaGe': 'fr-FR' }, { 'Accept-Language': 'en-US', 'accept-language': 'ru-RU' },
    { 'Accept-Language': 'en-US\r\nX-Locale: ru-RU' }, { 'Accept-Language': ['en-US', 'ru-RU'] },
    { 'Accept-Language': '' }, { 'Accept-Language': '*' }, { 'Accept-Language': 'en-US;q=2' }
  ]) assert.ok(auditRequestHeaders(headers, 'en-US').length > 0, JSON.stringify(headers));
});

for (const captureBodies of [false, true]) for (const order of ['before', 'after']) {
  test(`actual Russian Accept-Language fails closed (capture=${captureBodies}, ExtraInfo=${order})`, async t => {
    const { inspector, emit } = await fixture(t, captureBodies), fatal = []; inspector.on('fatal', reason => fatal.push(reason));
    const extra = () => emit('Network.requestWillBeSentExtraInfo', { requestId: 'bad', headers: { 'Accept-Language': 'en-US,ru-RU;q=0.9' } });
    if (order === 'before') extra();
    emit('Network.requestWillBeSent', { requestId: 'bad', request: { url: 'https://fixture.test/chat?token=private', headers: { 'Accept-Language': 'en-US' }, postData: '{"message":"English content"}' } });
    if (order === 'after') extra();
    assert.equal(inspector.running, false); assert.equal(fatal.length, 1);
    assert.match(fatal[0], /transport\.Accept-Language\.mismatch/);
    assert.doesNotMatch(fatal[0], /ru-RU|private|English|https:/);
  });
}

test('actual ExtraInfo mismatch blocks even if the corresponding request record never arrives', async t => {
  const { inspector, emit } = await fixture(t), fatal = []; inspector.on('fatal', reason => fatal.push(reason));
  emit('Network.requestWillBeSentExtraInfo', { requestId: 'missing-record', headers: { 'Accept-Language': 'ru-RU' } });
  assert.equal(inspector.running, false); assert.equal(fatal.length, 1);
  assert.match(fatal[0], /transport\.Accept-Language\.mismatch/);
});

test('initial actual header and WebSocket handshake language both remain enforced', async t => {
  for (const transport of ['HTTP', 'WebSocket']) {
    const { inspector, emit } = await fixture(t), fatal = []; inspector.on('fatal', reason => fatal.push(reason));
    if (transport === 'WebSocket') {
      emit('Network.webSocketCreated', { requestId: 'bad', url: 'wss://fixture.test/' });
      emit('Network.webSocketWillSendHandshakeRequest', { requestId: 'bad', request: { headers: { 'Accept-Language': 'ru-RU' } } });
    } else emit('Network.requestWillBeSent', { requestId: 'bad', request: { headers: { 'Accept-Language': 'ru-RU' } } });
    assert.equal(inspector.running, false); assert.equal(fatal.length, 1);
  }
});

test('Russian HTTP response, SSE and WebSocket content never substitutes for browser metadata', async t => {
  const { inspector, emit } = await fixture(t), fatal = []; inspector.on('fatal', reason => fatal.push(reason));
  emit('Network.requestWillBeSent', { requestId: 'sse', request: { headers: { 'Accept-Language': 'en-US' } } });
  emit('Network.responseReceived', { requestId: 'sse', response: { status: 200, headers: { 'Content-Language': 'ru-RU' }, mimeType: 'text/event-stream' } });
  emit('Network.eventSourceMessageReceived', { requestId: 'sse', data: content });
  emit('Network.dataReceived', { requestId: 'sse', data: Buffer.from(content).toString('base64') });
  emit('Network.webSocketCreated', { requestId: 'ws', url: 'wss://fixture.test/' });
  emit('Network.webSocketWillSendHandshakeRequest', { requestId: 'ws', request: { headers: { 'Accept-Language': 'en-US' } } });
  for (const method of ['Network.webSocketFrameSent', 'Network.webSocketFrameReceived']) emit(method, { requestId: 'ws', response: { opcode: 1, payloadData: content } });
  assert.equal(inspector.running, true); assert.deepEqual(fatal, []);
  for (const record of inspector.records.values()) assert.deepEqual(record.warnings, []);
  assert.match(inspector.records.get('page:sse').received, /Europe\/Moscow/);
  assert.match(inspector.records.get('page:ws').sent, /ru-RU/);
  assert.match(inspector.records.get('page:ws').received, /ru-RU/);
});

for (const [field, actual, category] of [
  ['language', 'ru-RU', 'renderer.navigator.language'],
  ['locale', 'ru-RU', 'renderer.Intl.locale'],
  ['timezone', 'Europe/Moscow?token=private', 'renderer.Intl.timeZone']
]) test(`actual renderer ${field} mismatch still blocks with safe field diagnostic`, async t => {
  const channel = new Channel({ ...profile, [field]: actual }), inspector = new Inspector(channel, profile, true);
  t.after(() => inspector.stop()); const fatal = once(inspector, 'fatal');
  await inspector.start(); await inspector.configure('page');
  const [reason] = await fatal; assert.equal(inspector.running, false);
  assert.ok(reason.includes(category)); assert.equal(reason.includes(actual), false); assert.doesNotMatch(reason, /private|https:/);
});
