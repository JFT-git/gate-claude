'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { createRequire } = require('node:module');
const { parseDestinationTrace } = require('../src/ip-check.cjs');
const token = 'b'.repeat(64), turn = () => new Promise(resolve => setImmediate(resolve));
const errorText = 'Не удалось проверить маршрут Claude. Соединение закрыто.';
const trace = (host = 'claude.ai', ip = '198.51.100.17', loc = 'NL') =>
  `fl=fixture\nh=${host}\nip=${ip}\nts=1792700000.1\nvisit_scheme=https\nuag=gate-claude/network-check\nloc=${loc}\nhttp=http/1.1\n`;

// Exercise the production request/cleanup code with controllable TLS and relay
// boundaries. No test connects to the Internet or reads an account's cookies.
function fixture(options = {}) {
  const file = path.resolve(__dirname, '../src/ip-check.cjs'), originalRequire = createRequire(file);
  const agents = [], tunnels = [], requests = [], tlsCalls = [], responses = [], timers = new Map();
  let now = 0, nextTimer = 0;
  class Socket extends EventEmitter {
    constructor() { super(); this.destroyed = false; this.destroyCalls = 0; }
    destroy() { this.destroyed = true; this.destroyCalls++; }
  }
  class Agent {
    constructor(settings) { this.settings = settings; this.destroyed = false; agents.push(this); }
    destroy() { this.destroyed = true; }
  }
  const https = { Agent, request(settings, receive) {
    const request = new Socket(); request.settings = settings; requests.push(request);
    request.end = () => {
      settings.agent.createConnection({}, error => {
        if (error) { request.emit('error', error); return; }
        const response = new Socket(); responses.push(response);
        response.statusCode = options.statusCode ?? 200;
        response.headers = { 'content-type': 'text/plain; charset=utf-8', ...options.headers };
        response.complete = false; receive(response);
        if (response.destroyed || options.holdResponse) return;
        if (options.abortResponse) { response.emit('aborted'); return; }
        if (options.closeResponse) { response.emit('close'); return; }
        const body = options.body ?? trace(settings.hostname, options.ip ?? '198.51.100.17');
        for (const chunk of options.chunks ?? [Buffer.from(body)]) {
          response.emit('data', chunk);
          if (response.destroyed) return;
        }
        response.complete = true; response.emit('end');
      });
    };
    return request;
  } };
  const tls = { connect(settings) {
    const secure = new Socket(); tlsCalls.push({ settings, secure });
    if (!options.holdTLS) queueMicrotask(() => secure.emit(options.tlsError ? 'error' : 'secureConnect', Error('TLS fixture private detail')));
    return secure;
  } };
  function connectTunnel(port, host, targetPort, checkToken, capture) {
    const raw = new Socket();
    const tunnel = { port, host, targetPort, checkToken, raw }; tunnels.push(tunnel); capture(raw);
    if (options.holdTunnel) return new Promise((resolve, reject) => { tunnel.resolve = resolve; tunnel.reject = reject; });
    return options.tunnelError ? Promise.reject(Error('proxy fixture private detail')) : Promise.resolve(raw);
  }
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, exports: module.exports, Buffer, URL,
    require(name) {
      if (name === 'node:https') return https;
      if (name === 'node:tls') return tls;
      if (name === './relay.cjs') return { connectTunnel };
      return originalRequire(name);
    },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, at: now + delay }); return id; },
    clearTimeout(id) { timers.delete(id); }
  }, { filename: file });
  return { ...module.exports, agents, tunnels, requests, tlsCalls, responses, timers,
    async advance(milliseconds) {
      now += milliseconds;
      for (const [id, value] of [...timers]) if (value.at <= now) { timers.delete(id); value.callback(); }
      await turn();
    },
    assertClosed() {
      for (const list of [agents, requests, responses]) for (const item of list) assert.equal(item.destroyed, true);
      for (const { raw } of tunnels) assert.equal(raw.destroyed, true);
      for (const { secure } of tlsCalls) assert.equal(secure.destroyed, true);
      assert.equal(timers.size, 0);
    }
  };
}

test('destination trace requires the exact host and country while accepting either ordinary IP family', () => {
  for (const host of ['claude.ai', 'api.anthropic.com']) {
    assert.deepEqual(parseDestinationTrace(trace(host), host, 4), { ip: '198.51.100.17', country_code: 'NL', hostname: host });
    assert.deepEqual(parseDestinationTrace(trace(host, '2001:db8::17', 'RU'), host, 6), { ip: '2001:db8::17', country_code: 'RU', hostname: host });
    assert.deepEqual(parseDestinationTrace(trace(host, '2001:db8::17'), host, 4), { ip: '2001:db8::17', country_code: 'NL', hostname: host });
    assert.deepEqual(parseDestinationTrace(trace(host), host, 6), { ip: '198.51.100.17', country_code: 'NL', hostname: host });
  }
});

test('destination trace rejects duplicate or missing security fields and malformed lines', () => {
  for (const body of [trace() + 'h=claude.ai\n', trace() + 'ip=198.51.100.17\n', trace() + 'loc=NL\n',
    trace().replace('h=claude.ai\n', ''), trace().replace('ip=198.51.100.17\n', ''), trace().replace('loc=NL\n', ''),
    trace() + 'malformed\n', trace() + '=value\n', trace() + 'h =claude.ai\n', trace() + 'bad\0key=value\n', trace() + 'fl=bare\rreturn\n']) {
    assert.throws(() => parseDestinationTrace(body, 'claude.ai', 4), { message: errorText });
  }
});

test('destination trace rejects host substitution, invalid IP, mapped IPv6 and malformed countries', () => {
  for (const [body, host, family] of [
    [trace('api.anthropic.com'), 'claude.ai', 4], [trace('claude.ai.evil.invalid'), 'claude.ai', 4],
    [trace('claude.ai '), 'claude.ai', 4], [trace(), 'CLAUDE.AI', 4], [trace(), 'claude.ai', 0],
    [trace('claude.ai', 'not-an-address'), 'claude.ai', 4], [trace('claude.ai', '198.51.100.17 '), 'claude.ai', 4],
    [trace('claude.ai', '::ffff:198.51.100.17'), 'claude.ai', 4],
    [trace('claude.ai', '::ffff:198.51.100.17'), 'claude.ai', 6],
    [trace('claude.ai', '0:0:0:0:0:ffff:c633:6411'), 'claude.ai', 6],
    [trace('claude.ai', 'fe80::1%eth0'), 'claude.ai', 6],
    ...['', 'nl', 'UNKNOWN', 'NL ', '--'].map(country => [trace('claude.ai', '198.51.100.17', country), 'claude.ai', 4])
  ]) assert.throws(() => parseDestinationTrace(body, host, family), { message: errorText });
});

test('destination HTTPS probe accepts a proxy-selected family independent of the general IP hint', async () => {
  const f = fixture({ ip: '2001:db8::17' });
  const result = await f.queryDestinationIP(12345, token, 'claude.ai', 4);
  assert.equal(result.hostname, 'claude.ai'); assert.equal(result.ip, '2001:db8::17'); assert.equal(result.country_code, 'NL');
  f.assertClosed();
});

test('destination checker creates a fresh authenticated tunnel and fresh TLS for each destination', async () => {
  const h = fixture();
  for (const host of ['claude.ai', 'api.anthropic.com', 'claude.ai']) {
    const result = await h.queryDestinationIP(12345, token, host, 4);
    assert.equal(result.ip, '198.51.100.17'); assert.equal(result.hostname, host);
  }
  assert.equal(h.agents.length, 3); assert.equal(new Set(h.agents).size, 3); assert.equal(h.tunnels.length, 3); assert.equal(h.tlsCalls.length, 3);
  for (const item of h.agents) assert.deepEqual(JSON.parse(JSON.stringify(item.settings)), { keepAlive: false, maxSockets: 1, maxCachedSessions: 0 });
  for (const item of h.tunnels) { assert.equal(item.port, 12345); assert.equal(item.targetPort, 443); assert.equal(item.checkToken, token); }
  for (let i = 0; i < h.tlsCalls.length; i++) {
    const item = h.tlsCalls[i]; assert.equal(item.settings.socket, h.tunnels[i].raw);
    assert.equal(item.settings.servername, h.tunnels[i].host); assert.equal(item.settings.rejectUnauthorized, true);
    assert.equal(item.settings.minVersion, 'TLSv1.2'); assert.equal(item.settings.session, undefined);
  }
  h.assertClosed();
});

test('destination HTTP request has no cookies, account auth, control token or redirect behaviour', async () => {
  const h = fixture(); await h.queryDestinationIP(12345, token, 'claude.ai', 4);
  const settings = h.requests[0].settings;
  assert.equal(settings.path, '/cdn-cgi/trace'); assert.equal(settings.method, 'GET'); assert.equal(settings.port, 443);
  assert.equal(settings.auth, undefined); assert.equal(settings.maxHeaderSize, 8192);
  assert.deepEqual(Object.keys(settings.headers).map(x => x.toLowerCase()).sort(),
    ['accept', 'accept-encoding', 'cache-control', 'connection', 'pragma', 'user-agent']);
  assert.equal(settings.headers['Accept-Encoding'], 'identity'); assert.equal(settings.headers.Connection, 'close');
  assert.equal(JSON.stringify(settings.headers).includes(token), false); h.assertClosed();
});

test('destination checker returns a changed egress immediately without pinning it internally', async () => {
  const first = fixture(), changed = fixture({ ip: '203.0.113.22' });
  const before = await first.queryDestinationIP(12345, token, 'claude.ai', 4);
  const after = await changed.queryDestinationIP(12345, token, 'claude.ai', 4);
  assert.notEqual(before.ip, after.ip); assert.equal(after.ip, '203.0.113.22');
  first.assertClosed(); changed.assertClosed();
});

test('destination checker rejects non-whitelisted hosts, missing control tokens and invalid families before networking', async () => {
  const h = fixture();
  for (const args of [[12345, token, 'ipwho.is', 4], [12345, token, 'claude.ai.evil.invalid', 4],
    [12345, '', 'claude.ai', 4], [12345, 'secret', 'claude.ai', 4], [0, token, 'claude.ai', 4],
    [12345, token, 'claude.ai', undefined], [12345, token, 'claude.ai', 0]]) {
    await assert.rejects(h.queryDestinationIP(...args), { message: errorText });
  }
  assert.equal(h.requests.length, 0); assert.equal(h.tunnels.length, 0); assert.equal(h.agents.length, 0);
});

test('destination checker rejects redirects, non-plain responses and compressed bodies without following them', async () => {
  for (const options of [{ statusCode: 302, headers: { location: 'https://untrusted.invalid/' } },
    { statusCode: 403 }, { headers: { 'content-type': 'text/html' } },
    { headers: { 'content-encoding': 'gzip' } }, { headers: { 'content-length': '16385' } }]) {
    const h = fixture(options);
    await assert.rejects(h.queryDestinationIP(12345, token, 'claude.ai', 4), { message: errorText });
    assert.equal(h.requests.length, 1); h.assertClosed();
  }
});

test('destination checker bounds streamed and parsed bodies to 16 KiB', async () => {
  const h = fixture({ chunks: [Buffer.from(trace()), Buffer.alloc(16384, 120)] });
  await assert.rejects(h.queryDestinationIP(12345, token, 'claude.ai', 4), { message: errorText }); h.assertClosed();
  assert.throws(() => parseDestinationTrace(trace() + 'x'.repeat(16384), 'claude.ai', 4), { message: errorText });
});

test('destination deadline closes an unfinished CONNECT and ignores its late completion', async () => {
  const h = fixture({ holdTunnel: true }); let settled = false;
  const query = h.queryDestinationIP(12345, token, 'claude.ai', 4); query.catch(() => { settled = true; });
  await h.advance(3999); assert.equal(settled, false);
  await h.advance(1); await assert.rejects(query, { message: errorText }); h.assertClosed();
  h.tunnels[0].resolve(h.tunnels[0].raw); await turn();
  assert.equal(h.tlsCalls.length, 0); h.assertClosed();
});

test('destination deadline closes a TLS handshake and ignores late success or private errors', async () => {
  const h = fixture({ holdTLS: true }), query = h.queryDestinationIP(12345, token, 'claude.ai', 4);
  query.catch(() => {}); await turn(); assert.equal(h.tlsCalls.length, 1);
  await h.advance(4000); await assert.rejects(query, { message: errorText }); h.assertClosed();
  h.tlsCalls[0].secure.emit('secureConnect'); h.tlsCalls[0].secure.emit('error', Error('private account detail'));
  await turn(); assert.equal(h.responses.length, 0); h.assertClosed();
});

test('destination deadline aborts an incomplete response and ignores late trace data', async () => {
  const h = fixture({ holdResponse: true }), query = h.queryDestinationIP(12345, token, 'claude.ai', 4);
  query.catch(() => {}); await turn(); assert.equal(h.responses.length, 1);
  await h.advance(4000); await assert.rejects(query, { message: errorText }); h.assertClosed();
  h.responses[0].emit('data', Buffer.from(trace())); h.responses[0].emit('end');
  h.responses[0].emit('error', Error('private response detail')); h.assertClosed();
});

test('destination checker closes all resources on transport, TLS, premature-close and malformed-trace errors', async () => {
  for (const options of [{ tunnelError: true }, { tlsError: true }, { abortResponse: true }, { closeResponse: true },
    { body: trace() + 'ip=203.0.113.22\n' }]) {
    const h = fixture(options);
    await assert.rejects(h.queryDestinationIP(12345, token, 'claude.ai', 4), { message: errorText }); h.assertClosed();
  }
});
