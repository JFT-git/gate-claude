'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { createRequire } = require('node:module');
const { NetworkCheckError } = require('../src/ip-check.cjs');
const secret = 'PRIVATE_ACCOUNT_TOKEN_PROXY_IP_BODY';
const turn = () => new Promise(resolve => setImmediate(resolve));
const trace = 'h=claude.ai\nip=198.51.100.20\nloc=NL\n';

// Production callbacks run against bounded, deterministic TLS/HTTP boundaries.
// These tests create no listener, external request, credentials or registry read.
function fixture(options = {}) {
  const file = path.resolve(__dirname, '../src/ip-check.cjs'), localRequire = createRequire(file);
  const agents = [], requests = [], responses = [], rawSockets = [], secureSockets = [], timers = new Map();
  let tick = 0, nextID = 0;
  const privateError = () => Object.assign(Error(secret), { cause: secret, headers: secret, body: secret, address: secret });
  class Socket extends EventEmitter { destroy() { this.destroyed = true; } }
  class Agent {
    constructor() { if (options.agentThrow) throw privateError(); agents.push(this); }
    destroy() { this.destroyed = true; }
  }
  const https = { Agent, request(settings, receive) {
    if (options.requestThrow) throw privateError();
    const request = new Socket(); requests.push(request);
    request.end = () => {
      if (options.requestError) { request.emit('error', privateError()); return; }
      settings.agent.createConnection({}, error => {
        if (options.callbackThrow) throw privateError();
        if (error) { request.emit('error', error); return; }
        const response = new Socket(); responses.push(response); response.complete = false;
        response.statusCode = options.status ?? 200;
        response.headers = options.malformedHeaders ? null : { 'content-type': 'text/plain', ...options.headers };
        receive(response);
        if (response.destroyed || options.holdBody) return;
        if (options.aborted) { response.emit('aborted'); return; }
        if (options.responseError) { response.emit('error', privateError()); return; }
        if (options.prematureClose) { response.emit('close'); return; }
        const body = options.body ?? (settings.hostname === 'claude.ai' ? trace : '{"ip":"198.51.100.20"}');
        for (const chunk of options.chunks || [Buffer.from(body)]) { response.emit('data', chunk); if (response.destroyed) return; }
        response.complete = true; response.emit('end');
      });
    };
    return request;
  } };
  const tls = { connect() {
    if (options.tlsThrow) throw privateError();
    const socket = options.malformedTLS ? { destroy() { this.destroyed = true; } } : new Socket(); secureSockets.push(socket);
    if (!options.holdTLS && !options.malformedTLS) queueMicrotask(() => socket.emit(options.tlsError ? 'error' : 'secureConnect', privateError()));
    return socket;
  } };
  const connectTunnel = (_port, _host, _targetPort, _token, capture) => {
    const socket = new Socket(); rawSockets.push(socket); capture(socket);
    if (options.connectThrow) throw privateError();
    if (options.holdConnect) return new Promise(resolve => { socket.release = () => resolve(socket); });
    return options.connectError ? Promise.reject(privateError()) : Promise.resolve(socket);
  };
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, Buffer, URL,
    require: name => name === 'node:https' ? https : name === 'node:tls' ? tls : name === './relay.cjs' ? { connectTunnel } : localRequire(name),
    setTimeout(callback, delay) { const id = ++nextID; timers.set(id, { callback, at: tick + delay }); return id; },
    clearTimeout(id) { timers.delete(id); }
  }, { filename: file });
  return { api: module.exports, agents, requests, responses, rawSockets, secureSockets, timers,
    run(kind) { return kind === 'destination' ? this.api.queryDestinationIP(12345, 'b'.repeat(64), 'claude.ai', 4) : this.api.queryJSON(12345, 'api.ipify.org', '/?format=json', 4000, 'b'.repeat(64)); },
    async advance(ms) { tick += ms; for (const [id, value] of [...timers]) if (value.at <= tick) { timers.delete(id); value.callback(); } await turn(); },
    closed() {
      for (const list of [agents, requests, responses, rawSockets, secureSockets]) for (const stream of list) assert.equal(stream.destroyed, true);
      assert.equal(timers.size, 0);
    }
  };
}
function safeError(f, kind, code, phase, status) {
  return error => {
    assert.ok(error instanceof f.api.NetworkCheckError);
    assert.equal(error.name, 'NetworkCheckError'); assert.equal(error.code, code); assert.equal(error.phase, phase);
    assert.equal(error.service, kind === 'destination' ? 'claude.ai' : 'api.ipify.org');
    assert.equal(error.message, kind === 'destination' ? 'Не удалось проверить маршрут Claude. Соединение закрыто.' : 'Проверка внешнего IP не завершилась. Соединение закрыто.');
    assert.equal(error.httpStatus, status);
    assert.deepEqual(Object.keys(error).sort(), ['code', 'phase', 'service', ...(status == null ? [] : ['httpStatus'])].sort());
    assert.equal(error.cause, undefined); assert.equal(JSON.stringify(error).includes(secret), false); assert.equal(error.stack.includes(secret), false);
    return true;
  };
}

test('network error constructor accepts only allowlisted public metadata and fixed messages', () => {
  const error = new NetworkCheckError({ code: secret, service: secret, phase: secret, httpStatus: secret, message: secret, cause: Error(secret), kind: secret });
  assert.equal(error.code, 'REQUEST'); assert.equal(error.service, 'unknown'); assert.equal(error.phase, 'request');
  assert.equal(error.httpStatus, undefined); assert.equal(error.cause, undefined); assert.equal(JSON.stringify(error).includes(secret), false);
  assert.equal(error.message.includes(secret), false);
  for (const httpStatus of [99, 600, 200.5, '403', NaN]) assert.equal(new NetworkCheckError({ httpStatus }).httpStatus, undefined);
  for (const httpStatus of [100, 403, 599]) assert.equal(new NetworkCheckError({ httpStatus }).httpStatus, httpStatus);
});

for (const kind of ['json', 'destination']) {
  for (const [label, options, code, phase] of [
    ['connection rejection', { connectError: true }, 'CONNECT', 'connect'],
    ['synchronous connection failure', { connectThrow: true }, 'CONNECT', 'connect'],
    ['TLS rejection', { tlsError: true }, 'TLS', 'tls'],
    ['synchronous TLS failure', { tlsThrow: true }, 'TLS', 'tls'],
    ['malformed TLS stream', { malformedTLS: true }, 'TLS', 'tls'],
    ['HTTP status', { status: 403 }, 'HTTP_STATUS', 'headers'],
    ['body parse', { body: secret }, 'BODY', 'body'],
    ['body size', { body: 'x'.repeat(32769) }, 'SIZE', 'body'],
    ['aborted response', { aborted: true }, 'ABORTED', 'response'],
    ['response error', { responseError: true }, 'RESPONSE', 'response'],
    ['premature response close', { prematureClose: true }, 'RESPONSE', 'response'],
    ['request construction', { requestThrow: true }, 'REQUEST', 'request'],
    ['request event', { requestError: true }, 'REQUEST', 'request'],
    ['agent construction', { agentThrow: true }, 'REQUEST', 'request'],
    ['callback failure', { callbackThrow: true }, 'REQUEST', 'request']
  ]) test(kind + ' error metadata: ' + label + ' closes every allocated resource without raw details', async () => {
    const f = fixture(options); await assert.rejects(f.run(kind), safeError(f, kind, code, phase, code === 'HTTP_STATUS' ? 403 : undefined)); f.closed();
  });
  for (const [stage, options, phase] of [['CONNECT', { holdConnect: true }, 'connect'], ['TLS', { holdTLS: true }, 'tls'], ['body', { holdBody: true }, 'body']]) {
    test(kind + ' retains its four-second deadline during ' + stage + ' and ignores late callbacks', async () => {
      const f = fixture(options), pending = f.run(kind); const rejected = assert.rejects(pending, safeError(f, kind, 'TIMEOUT', phase));
      await turn(); await f.advance(3999); assert.equal(f.requests[0].destroyed, undefined);
      await f.advance(1); await rejected; f.closed();
      f.rawSockets[0]?.release?.(); if (f.secureSockets[0]?.emit) f.secureSockets[0].emit('secureConnect');
      f.responses[0]?.emit('end'); await turn(); f.closed();
    });
  }
  test(kind + ' successful check also closes its response, TLS, socket and agent', async () => {
    const f = fixture(); const result = await f.run(kind); assert.equal(result.ip, '198.51.100.20'); f.closed();
    assert.equal(f.responses.length, 1); assert.equal(f.responses[0].destroyed, true);
  });
}

test('destination distinguishes rejected headers and declared size without exposing header contents', async () => {
  for (const options of [{ headers: { 'content-type': secret } }, { headers: { 'content-encoding': secret } }, { malformedHeaders: true }]) {
    const f = fixture(options); await assert.rejects(f.run('destination'), safeError(f, 'destination', 'HEADERS', 'headers')); f.closed();
  }
  const f = fixture({ headers: { 'content-length': '16385' } });
  await assert.rejects(f.run('destination'), safeError(f, 'destination', 'SIZE', 'headers')); f.closed();
});

test('invalid arguments are classified before requests while existing messages stay unchanged', async () => {
  const f = fixture();
  await assert.rejects(f.api.queryJSON(12345, secret, '/'), error => error instanceof f.api.NetworkCheckError && error.code === 'INVALID_ARGUMENT' && error.service === 'unknown' && error.phase === 'arguments' && error.message === 'Неизвестный сервис проверки IP.');
  await assert.rejects(f.api.queryDestinationIP(12345, secret, 'claude.ai', 4), safeError(f, 'destination', 'INVALID_ARGUMENT', 'arguments'));
  assert.equal(f.agents.length, 0); assert.equal(f.requests.length, 0);
});

test('geolocation starts all providers in parallel and keeps a four-second deadline', async () => {
  const f = fixture({ holdConnect: true }), pending = f.api.initialIP(12345, 'b'.repeat(64));
  const rejected = assert.rejects(pending, error => error instanceof f.api.NetworkCheckError && error.code === 'TIMEOUT' && error.service === 'ipwho.is' && error.phase === 'connect');
  await turn(); assert.equal(f.requests.length, 3);
  await f.advance(3999); for (const request of f.requests) assert.equal(request.destroyed, undefined);
  await f.advance(1); await rejected; f.closed();
});

const { queryConsensus, normalizeGeo, parseDNSProbe } = require('../src/ip-check.cjs');
const providers = ['ipwho.is', 'ipinfo.io', 'ipapi.co'].map(hostname => ({ hostname, path: '/json' }));
const identity = value => value.ip + '|' + value.country_code;
test('matching providers finish together and normalize public ASN and organization metadata', async () => {
  let active = 0, maximum = 0;
  const request = async (_port, hostname) => {
    active++; maximum = Math.max(maximum, active);
    await turn(); active--;
    if (hostname === 'ipwho.is') throw Error('one provider is unavailable');
    if (hostname === 'ipinfo.io') return { ip: '203.0.113.7', country: 'NL', org: 'AS41436 Example Hosting' };
    return { ip: '203.0.113.7', country_code: 'NL', asn: 'AS41436', org: 'Example Hosting' };
  };
  const result = await queryConsensus(providers, 1, '', normalizeGeo, identity, request);
  assert.equal(maximum, 3);
  assert.equal(result.ip, '203.0.113.7');
  assert.equal(result.asn, 'AS41436');
  assert.equal(result.organization, 'Example Hosting');
  assert.deepEqual(result.providers, ['ipinfo.io', 'ipapi.co']);
});

test('conflicting public routes fail closed, while a single healthy provider is an explicit fallback', async () => {
  const addresses = { 'ipwho.is': '203.0.113.1', 'ipinfo.io': '203.0.113.2', 'ipapi.co': '203.0.113.3' };
  await assert.rejects(queryConsensus(providers, 1, '', normalizeGeo, identity, async (_port, hostname) => ({ ip: addresses[hostname], country: 'NL' })), error => error.code === 'BODY');
  const result = await queryConsensus(providers, 1, '', normalizeGeo, identity, async (_port, hostname) => {
    if (hostname !== 'ipinfo.io') throw Error('offline');
    return { ip: '203.0.113.7', country: 'NL' };
  });
  assert.deepEqual(result.providers, ['ipinfo.io']);
});

test('provider-specific metadata and external DNS responses are bounded and validated', () => {
  const who = normalizeGeo({ hostname: 'ipwho.is' }, { success: true, ip: '203.0.113.7', country_code: 'NL', connection: { asn: 41436, org: 'Example Org' } });
  assert.equal(who.asn, 'AS41436'); assert.equal(who.organization, 'Example Org');
  assert.throws(() => normalizeGeo({ hostname: 'ipwho.is' }, { success: false, ip: '203.0.113.7', country_code: 'NL' }));
  assert.deepEqual(parseDNSProbe({ dns: { ip: '203.0.113.9', geo: 'Germany - Google LLC' } }), { ip: '203.0.113.9', geo: 'Germany - Google LLC' });
  assert.throws(() => parseDNSProbe({ dns: { ip: secret, geo: secret } }), error => error.code === 'BODY' && error.service === 'edns.ip-api.com' && !error.message.includes(secret));
});
