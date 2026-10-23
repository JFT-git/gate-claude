'use strict';
const https = require('node:https');
const tls = require('node:tls');
const net = require('node:net');
const { connectTunnel } = require('./relay.cjs');

const destinationHosts = new Set(['claude.ai', 'api.anthropic.com']);
const destinationError = 'Не удалось проверить маршрут Claude. Соединение закрыто.';
const jsonError = 'Проверка внешнего IP не завершилась. Соединение закрыто.';
const traceLimit = 16384;
const services = new Set(['ipwho.is', 'api64.ipify.org', 'api.ipify.org', 'api6.ipify.org', ...destinationHosts]);
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
  if (!['ipwho.is', 'api64.ipify.org', 'api.ipify.org', 'api6.ipify.org'].includes(hostname)) throw checkError('INVALID_ARGUMENT', hostname, 'arguments', 'unknown-service');
  let raw, secure, request, response, finished = false, phase = 'request', agent;
  try { agent = new https.Agent({ keepAlive: false, maxSockets: 1 }); }
  catch { throw checkError('REQUEST', hostname, phase, 'json'); }
  return new Promise((resolve, reject) => {
    const finish = (error, result) => {
      if (finished) return;
      finished = true; clearTimeout(timer);
      for (const stream of [response, request, secure, raw, agent]) destroy(stream);
      if (error) reject(error instanceof NetworkCheckError ? error : checkError('REQUEST', hostname, phase, 'json'));
      else resolve(result);
    };
    const fail = (code, failurePhase = phase, status) => finish(checkError(code, hostname, failurePhase, 'json', status));
    const timer = setTimeout(() => fail('TIMEOUT'), timeout);
    agent.createConnection = (_options, callback) => {
      phase = 'connect'; let completed = false;
      const complete = (error, stream) => {
        if (!completed) { completed = true; try { callback(error, stream); } catch { fail('REQUEST', 'request'); } }
      };
      let tunnel;
      try { tunnel = connectTunnel(relayPort, hostname, 443, checkToken, socket => { raw = socket; if (finished) destroy(socket); }); }
      catch { const error = checkError('CONNECT', hostname, 'connect', 'json'); complete(error); finish(error); return; }
      Promise.resolve(tunnel).then(socket => {
        raw = socket;
        if (finished) { destroy(socket); return; }
        phase = 'tls';
        try {
          secure = tls.connect({ socket, servername: hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
          secure.once('secureConnect', () => { if (!finished) { phase = 'response'; complete(null, secure); } });
          secure.once('error', () => { if (!finished) { const error = checkError('TLS', hostname, 'tls', 'json'); complete(error); finish(error); } });
        } catch { const error = checkError('TLS', hostname, 'tls', 'json'); complete(error); finish(error); }
      }).catch(() => { if (!finished) { const error = checkError('CONNECT', hostname, 'connect', 'json'); complete(error); finish(error); } });
      return undefined;
    };
    try {
      request = https.request({ hostname, path, method: 'GET', port: 443, agent,
        headers: { Accept: 'application/json', 'User-Agent': 'gate-claude/0.5.0' } }, incoming => {
        response = incoming;
        if (finished) { destroy(incoming); return; }
        phase = 'headers';
        try {
          if (incoming.statusCode !== 200) { fail('HTTP_STATUS', 'headers', incoming.statusCode); return; }
          phase = 'body'; let buffer = Buffer.alloc(0);
          incoming.on('data', chunk => {
            if (finished) return;
            try {
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
      request.once('error', error => finish(error instanceof NetworkCheckError ? error : checkError('REQUEST', hostname, phase, 'json'))); request.end();
    } catch { fail('REQUEST', 'request'); }
  });
}

module.exports = {
  queryJSON,
  NetworkCheckError,
  queryDestinationIP,
  parseDestinationTrace,
  initialIP: (port, token) => queryJSON(port, 'ipwho.is', '/', 12000, token),
  currentIP: (port, token, family) => queryJSON(port, family === 4 ? 'api.ipify.org' : family === 6 ? 'api6.ipify.org' : 'api64.ipify.org', '/?format=json', 4000, token)
};
