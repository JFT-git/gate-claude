'use strict';
const https = require('node:https');
const tls = require('node:tls');
const net = require('node:net');
const { connectTunnel } = require('./relay.cjs');

const destinationHosts = new Set(['claude.ai', 'api.anthropic.com']);
const destinationError = 'Не удалось проверить маршрут Claude. Соединение закрыто.';
const jsonError = 'Проверка внешнего IP не завершилась. Соединение закрыто.';
const traceLimit = 16384;
const jsonServices = new Set(['ipwho.is', 'api64.ipify.org', 'api.ipify.org', 'api6.ipify.org', 'ipinfo.io', 'ipapi.co']);
const isEDNSHost = value => typeof value === 'string' && /^[a-f0-9]{32}\.edns\.ip-api\.com$/.test(value);
const services = new Set([...jsonServices, 'edns.ip-api.com', ...destinationHosts]);
const codes = new Set(['TIMEOUT', 'CONNECT', 'TLS', 'HTTP_STATUS', 'HEADERS', 'SIZE', 'BODY', 'ABORTED', 'RESPONSE', 'REQUEST', 'INVALID_ARGUMENT']);
const phases = new Set(['arguments', 'connect', 'tls', 'request', 'headers', 'body', 'response']);
class NetworkCheckError extends Error {
  constructor({ code, service, phase, httpStatus, kind } = {}) {
    super(kind === 'json' ? jsonError : kind === 'unknown-service' ? 'Неизвестный сервис проверки IP.' : destinationError);
    Object.defineProperty(this, 'name', { value: 'NetworkCheckError', configurable: true });
    this.code = codes.has(code) ? code : 'REQUEST';
    this.service = services.has(service) ? service : 'unknown';
    this.phase = phases.has(phase) ? phase : 'request';
    if (Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599) this.httpStatus = httpStatus;
  }
}
const checkError = (code, service, phase, kind, httpStatus) => new NetworkCheckError({ code, service, phase, kind, httpStatus });
const destroy = value => { try { value?.destroy?.(); } catch { /* Cleanup never exposes transport error details. */ } };

// This endpoint reports the egress seen by the actual Claude destination. Keep
// country policy in the controller: a valid RU response must reach its kill switch.
function parseDestinationTrace(body, hostname, family) {
  try {
    if (!destinationHosts.has(hostname) || ![4, 6].includes(family) || typeof body !== 'string' ||
        Buffer.byteLength(body) > traceLimit || /[^\x20-\x7e\r\n]/.test(body) || /\r(?!\n)/.test(body)) throw Error('trace');
    const fields = new Map();
    for (const line of body.split(/\r?\n/)) {
      if (!line) continue;
      const split = line.indexOf('=');
      if (split < 1 || !/^[a-z_]+$/.test(line.slice(0, split))) throw Error('trace');
      const key = line.slice(0, split), value = line.slice(split + 1);
      if (['h', 'ip', 'loc'].includes(key)) {
        if (fields.has(key)) throw Error('duplicate');
        fields.set(key, value);
      }
    }
    const ip = fields.get('ip'), country = fields.get('loc');
    if (fields.get('h') !== hostname || typeof ip !== 'string' || ip.includes('%') || !net.isIP(ip) ||
        !/^[A-Z]{2}$/.test(country || '')) throw Error('trace');
    // A remote proxy can choose a different family for each destination. Its
    // authenticated result is pinned independently; family is only a caller hint.
    if (net.isIPv6(ip) && new URL('https://[' + ip + ']').hostname.slice(1, -1).toLowerCase().startsWith('::ffff:')) throw Error('mapped');
    return { ip, country_code: country, hostname };
  } catch { throw checkError('BODY', hostname, 'body'); }
}

function queryDestinationIP(relayPort, checkToken, hostname, family) {
  if (!Number.isInteger(relayPort) || relayPort < 1 || relayPort > 65535 || !/^[a-f0-9]{64}$/.test(checkToken) ||
      !destinationHosts.has(hostname) || ![4, 6].includes(family)) return Promise.reject(checkError('INVALID_ARGUMENT', hostname, 'arguments'));
  let raw, secure, request, response, finished = false, phase = 'request', agent;
  // Neither HTTP connections nor TLS sessions are shared with previous checks or
  // the user's Claude session. The control token is used only by CONNECT.
  try { agent = new https.Agent({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 }); }
  catch { return Promise.reject(checkError('REQUEST', hostname, phase)); }
  return new Promise((resolve, reject) => {
    const finish = (error, result) => {
      if (finished) return;
      finished = true; clearTimeout(timer);
      for (const stream of [response, request, secure, raw, agent]) destroy(stream);
      if (error) reject(error instanceof NetworkCheckError ? error : checkError('REQUEST', hostname, phase)); else resolve(result);
    };
    const fail = (code, failurePhase = phase, status) => finish(checkError(code, hostname, failurePhase, undefined, status));
    const timer = setTimeout(() => fail('TIMEOUT'), 4000);
    agent.createConnection = (_options, callback) => {
      phase = 'connect';
      let completed = false;
      const complete = (error, stream) => {
        if (!completed) {
          completed = true;
          try { callback(error, stream); } catch { fail('REQUEST', 'request'); }
        }
      };
      let tunnel;
      try { tunnel = connectTunnel(relayPort, hostname, 443, checkToken, socket => {
        raw = socket;
        if (finished) destroy(socket);
      }); } catch { const error = checkError('CONNECT', hostname, 'connect'); complete(error); finish(error); return; }
      Promise.resolve(tunnel).then(socket => {
        raw = socket;
        if (finished) { destroy(socket); return; }
        phase = 'tls';
        try {
          secure = tls.connect({ socket, servername: hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
          secure.once('secureConnect', () => { if (!finished) { phase = 'response'; complete(null, secure); } });
          secure.once('error', () => { if (!finished) { const error = checkError('TLS', hostname, 'tls'); complete(error); finish(error); } });
        } catch { const error = checkError('TLS', hostname, 'tls'); complete(error); finish(error); }
      }).catch(() => { if (!finished) { const error = checkError('CONNECT', hostname, 'connect'); complete(error); finish(error); } });
      return undefined;
    };
    try {
      request = https.request({ hostname, path: '/cdn-cgi/trace', method: 'GET', port: 443, agent,
        maxHeaderSize: 8192, headers: { Accept: 'text/plain', 'Accept-Encoding': 'identity',
          'Cache-Control': 'no-store, max-age=0', Pragma: 'no-cache', Connection: 'close', 'User-Agent': 'gate-claude/network-check' } }, incoming => {
        response = incoming;
        if (finished) { destroy(incoming); return; }
        phase = 'headers';
        try {
          incoming.once('aborted', () => fail('ABORTED', 'response'));
          incoming.once('error', () => fail('RESPONSE', 'response'));
          incoming.once('close', () => { if (!incoming.complete) fail('RESPONSE', 'response'); });
          const encoding = incoming.headers['content-encoding'];
          if (incoming.statusCode !== 200) { fail('HTTP_STATUS', 'headers', incoming.statusCode); return; }
          if (!/^text\/plain(?:\s*;.*)?$/i.test(incoming.headers['content-type'] || '') || (encoding && encoding !== 'identity')) { fail('HEADERS'); return; }
          if (Number(incoming.headers['content-length'] || 0) > traceLimit) { fail('SIZE'); return; }
          phase = 'body';
          let size = 0; const chunks = [];
          incoming.on('data', chunk => {
            if (finished) return;
            try {
              if (!Buffer.isBuffer(chunk)) throw Error();
              size += chunk.length;
              if (size > traceLimit) { fail('SIZE'); return; }
              chunks.push(chunk);
            } catch { fail('BODY', 'body'); }
          });
          incoming.once('end', () => {
            if (finished) return;
            try { finish(null, parseDestinationTrace(Buffer.concat(chunks, size).toString('utf8'), hostname, family)); }
            catch { fail('BODY', 'body'); }
          });
        } catch { fail('HEADERS', 'headers'); }
      });
      request.once('error', error => finish(error instanceof NetworkCheckError ? error : checkError('REQUEST', hostname, phase))); request.end();
    } catch { fail('REQUEST', 'request'); }
  });
}

async function queryJSON(relayPort, hostname, path, timeout = 4000, checkToken = '') {
  if (!jsonServices.has(hostname) && !isEDNSHost(hostname) || isEDNSHost(hostname) && path !== '/json') throw checkError('INVALID_ARGUMENT', hostname, 'arguments', 'unknown-service');
  const service = isEDNSHost(hostname) ? 'edns.ip-api.com' : hostname;
  let raw, secure, request, response, finished = false, phase = 'request', agent;
  try { agent = new https.Agent({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 }); }
  catch { throw checkError('REQUEST', service, phase, 'json'); }
  return new Promise((resolve, reject) => {
    const finish = (error, result) => {
      if (finished) return;
      finished = true; clearTimeout(timer);
      for (const stream of [response, request, secure, raw, agent]) destroy(stream);
      if (error) reject(error instanceof NetworkCheckError ? error : checkError('REQUEST', service, phase, 'json'));
      else resolve(result);
    };
    const fail = (code, failurePhase = phase, status) => finish(checkError(code, service, failurePhase, 'json', status));
    const timer = setTimeout(() => fail('TIMEOUT'), timeout);
    agent.createConnection = (_options, callback) => {
      phase = 'connect'; let completed = false;
      const complete = (error, stream) => {
        if (!completed) { completed = true; try { callback(error, stream); } catch { fail('REQUEST', 'request'); } }
      };
      let tunnel;
      try { tunnel = connectTunnel(relayPort, hostname, 443, checkToken, socket => { raw = socket; if (finished) destroy(socket); }); }
      catch { const error = checkError('CONNECT', service, 'connect', 'json'); complete(error); finish(error); return; }
      Promise.resolve(tunnel).then(socket => {
        raw = socket;
        if (finished) { destroy(socket); return; }
        phase = 'tls';
        try {
          secure = tls.connect({ socket, servername: hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
          secure.once('secureConnect', () => { if (!finished) { phase = 'response'; complete(null, secure); } });
          secure.once('error', () => { if (!finished) { const error = checkError('TLS', service, 'tls', 'json'); complete(error); finish(error); } });
        } catch { const error = checkError('TLS', service, 'tls', 'json'); complete(error); finish(error); }
      }).catch(() => { if (!finished) { const error = checkError('CONNECT', service, 'connect', 'json'); complete(error); finish(error); } });
      return undefined;
    };
    try {
      request = https.request({ hostname, path, method: 'GET', port: 443, agent, maxHeaderSize: 8192,
        headers: { Accept: 'application/json', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store, max-age=0', Pragma: 'no-cache', Connection: 'close', 'User-Agent': 'gate-claude/network-check' } }, incoming => {
        response = incoming;
        if (finished) { destroy(incoming); return; }
        phase = 'headers';
        try {
          if (incoming.statusCode !== 200) { fail('HTTP_STATUS', 'headers', incoming.statusCode); return; }
          phase = 'body'; let buffer = Buffer.alloc(0);
          incoming.on('data', chunk => {
            if (finished) return;
            try {
              if (!Buffer.isBuffer(chunk)) throw Error('body');
              buffer = Buffer.concat([buffer, chunk]);
              if (buffer.length > 32768) fail('SIZE', 'body');
            } catch { fail('BODY', 'body'); }
          });
          incoming.once('end', () => {
            if (finished) return;
            try { finish(null, JSON.parse(buffer.toString('utf8'))); } catch { fail('BODY', 'body'); }
          });
          incoming.once('aborted', () => fail('ABORTED', 'response'));
          incoming.once('error', () => fail('RESPONSE', 'response'));
          incoming.once('close', () => { if (!incoming.complete) fail('RESPONSE', 'response'); });
        } catch { fail('HEADERS', 'headers'); }
      });
      request.once('error', error => finish(error instanceof NetworkCheckError ? error : checkError('REQUEST', service, phase, 'json'))); request.end();
    } catch { fail('REQUEST', 'request'); }
  });
}

const geoProviders = Object.freeze([
  Object.freeze({ hostname: 'ipwho.is', path: '/?fields=success,ip,country_code,connection' }),
  Object.freeze({ hostname: 'ipinfo.io', path: '/json' }),
  Object.freeze({ hostname: 'ipapi.co', path: '/json/' })
]);
function canonical(value, service) {
  try {
    if (typeof value !== 'string' || !net.isIP(value)) throw Error('ip');
    if (net.isIPv4(value)) return value;
    const ip = new URL('https://[' + value + ']').hostname.slice(1, -1).toLowerCase();
    if (ip.startsWith('::ffff:')) throw Error('mapped');
    return ip;
  } catch { throw checkError('BODY', service, 'body', 'json'); }
}
function optionalText(value, limit = 160) {
  if (typeof value !== 'string') return '';
  const text = value.trim();
  return text.length > 0 && text.length <= limit && !/[\x00-\x1f\x7f]/.test(text) ? text : '';
}
function normalizeGeo(provider, raw) {
  const hostname = provider.hostname;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || raw.success === false) throw checkError('BODY', hostname, 'body', 'json');
  const ip = canonical(raw.ip, hostname), country = raw.country_code || raw.country;
  if (typeof country !== 'string' || !/^[A-Z]{2}$/.test(country)) throw checkError('BODY', hostname, 'body', 'json');
  let asn = '', organization = '';
  if (hostname === 'ipwho.is') {
    if (Number.isSafeInteger(raw.connection?.asn) && raw.connection.asn > 0 && raw.connection.asn <= 4294967295) asn = 'AS' + raw.connection.asn;
    organization = optionalText(raw.connection?.org || raw.connection?.isp);
  } else if (hostname === 'ipinfo.io') {
    const text = optionalText(raw.org), match = /^AS(\d{1,10})\s+(.+)$/.exec(text);
    if (match && Number(match[1]) <= 4294967295) { asn = 'AS' + match[1]; organization = optionalText(match[2]); }
    else organization = text;
  } else if (hostname === 'ipapi.co') {
    if (/^AS\d{1,10}$/.test(raw.asn || '') && Number(raw.asn.slice(2)) <= 4294967295) asn = raw.asn;
    organization = optionalText(raw.org);
  }
  return { success: true, ip, country_code: country, asn, organization };
}
function normalizePublic(provider, raw) { return { ip: canonical(raw?.ip, provider.hostname) }; }
function queryConsensus(providers, relayPort, checkToken, normalize, identity, request = queryJSON) {
  return new Promise((resolve, reject) => {
    let completed = 0, firstError, settled = false;
    const values = [];
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error); else resolve(value);
    };
    for (const provider of providers) {
      request(relayPort, provider.hostname, provider.path, 4000, checkToken).then(raw => {
        if (settled) return;
        let value;
        try { value = normalize(provider, raw); }
        catch (error) { firstError ||= error; return; }
        values.push({ provider, value });
        const matching = values.filter(item => identity(item.value) === identity(value));
        if (matching.length >= 2) {
          if (matching.length !== values.length) { finish(checkError('BODY', provider.hostname, 'body', 'json')); return; }
          finish(null, { ...matching[0].value, providers: matching.map(item => item.provider.hostname) });
          return;
        }
      }).catch(error => { firstError ||= error; }).finally(() => {
        completed++;
        if (settled || completed !== providers.length) return;
        if (!values.length) { finish(firstError || checkError('RESPONSE', providers[0].hostname, 'response', 'json')); return; }
        const identities = new Set(values.map(item => identity(item.value)));
        if (identities.size !== 1) { finish(checkError('BODY', values[0].provider.hostname, 'body', 'json')); return; }
        finish(null, { ...values[0].value, providers: values.map(item => item.provider.hostname) });
      });
    }
  });
}
function parseDNSProbe(raw) {
  const service = 'edns.ip-api.com', ip = canonical(raw?.dns?.ip, service), geo = optionalText(raw?.dns?.geo);
  if (!geo) throw checkError('BODY', service, 'body', 'json');
  return { ip, geo };
}
async function initialIP(port, token) { return queryConsensus(geoProviders, port, token, normalizeGeo, value => value.ip + '|' + value.country_code); }
async function currentIP(port, token, family) {
  const first = family === 4 ? 'api.ipify.org' : family === 6 ? 'api6.ipify.org' : 'api64.ipify.org';
  const providers = [{ hostname: first, path: '/?format=json' }, ...geoProviders.slice(1)];
  return queryConsensus(providers, port, token, normalizePublic, value => value.ip);
}
async function dnsProbe(port, token) {
  const hostname = require('node:crypto').randomBytes(16).toString('hex') + '.edns.ip-api.com';
  return parseDNSProbe(await queryJSON(port, hostname, '/json', 4000, token));
}

module.exports = {
  queryJSON,
  queryConsensus,
  normalizeGeo,
  parseDNSProbe,
  dnsProbe,
  NetworkCheckError,
  queryDestinationIP,
  parseDestinationTrace,
  initialIP,
  currentIP
};
