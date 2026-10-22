'use strict';
const https = require('node:https');
const tls = require('node:tls');
const net = require('node:net');
const { connectTunnel } = require('./relay.cjs');

const destinationHosts = new Set(['claude.ai', 'api.anthropic.com']);
const destinationError = 'Не удалось проверить маршрут Claude. Соединение закрыто.';
const traceLimit = 16384;

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
  } catch { throw Error(destinationError); }
}

function queryDestinationIP(relayPort, checkToken, hostname, family) {
  if (!Number.isInteger(relayPort) || relayPort < 1 || relayPort > 65535 || !/^[a-f0-9]{64}$/.test(checkToken) ||
      !destinationHosts.has(hostname) || ![4, 6].includes(family)) return Promise.reject(Error(destinationError));
  let raw, secure, request, response, finished = false;
  // Neither HTTP connections nor TLS sessions are shared with previous checks or
  // the user's Claude session. The control token is used only by CONNECT.
  const agent = new https.Agent({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 });
  return new Promise((resolve, reject) => {
    const finish = (error, result) => {
      if (finished) return;
      finished = true; clearTimeout(timer);
      response?.destroy(); request?.destroy(); secure?.destroy(); raw?.destroy(); agent.destroy();
      if (error) reject(Error(destinationError)); else resolve(result);
    };
    const timer = setTimeout(() => finish(Error('timeout')), 4000);
    agent.createConnection = (_options, callback) => {
      let completed = false;
      const complete = (error, stream) => { if (!completed) { completed = true; callback(error, stream); } };
      connectTunnel(relayPort, hostname, 443, checkToken, socket => {
        raw = socket;
        if (finished) socket.destroy();
      }).then(socket => {
        raw = socket;
        if (finished) { socket.destroy(); return; }
        secure = tls.connect({ socket, servername: hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
        secure.once('secureConnect', () => { if (!finished) complete(null, secure); });
        secure.once('error', error => { if (!finished) complete(error); });
      }).catch(error => { if (!finished) complete(error); });
      return undefined;
    };
    try {
      request = https.request({ hostname, path: '/cdn-cgi/trace', method: 'GET', port: 443, agent,
        maxHeaderSize: 8192, headers: { Accept: 'text/plain', 'Accept-Encoding': 'identity',
          'Cache-Control': 'no-store, max-age=0', Pragma: 'no-cache', Connection: 'close', 'User-Agent': 'gate-claude/network-check' } }, incoming => {
        response = incoming;
        if (finished) { incoming.destroy(); return; }
        incoming.once('aborted', () => finish(Error('aborted')));
        incoming.once('error', finish);
        incoming.once('close', () => { if (!incoming.complete) finish(Error('truncated')); });
        const encoding = incoming.headers['content-encoding'];
        if (incoming.statusCode !== 200 || !/^text\/plain(?:\s*;.*)?$/i.test(incoming.headers['content-type'] || '') ||
            (encoding && encoding !== 'identity') || Number(incoming.headers['content-length'] || 0) > traceLimit) {
          finish(Error('HTTP')); return;
        }
        let size = 0; const chunks = [];
        incoming.on('data', chunk => {
          if (finished) return;
          size += chunk.length;
          if (size > traceLimit) { finish(Error('size')); return; }
          chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finished) return;
          try { finish(null, parseDestinationTrace(Buffer.concat(chunks, size).toString('utf8'), hostname, family)); }
          catch { finish(Error('trace')); }
        });
      });
      request.once('error', finish); request.end();
    } catch { finish(Error('request')); }
  });
}

async function queryJSON(relayPort, hostname, path, timeout = 4000, checkToken = '') {
  if (!['ipwho.is', 'api64.ipify.org', 'api.ipify.org', 'api6.ipify.org'].includes(hostname)) throw Error('Неизвестный сервис проверки IP.');
  let raw, secure, request, finished = false;
  const agent = new https.Agent({ keepAlive: false, maxSockets: 1 });
  agent.createConnection = (_options, callback) => {
    connectTunnel(relayPort, hostname, 443, checkToken, socket => { raw = socket; }).then(socket => {
      raw = socket;
      if (finished) { socket.destroy(); return; }
      secure = tls.connect({ socket, servername: hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
      let completed = false;
      const complete = (error, stream) => { if (!completed) { completed = true; callback(error, stream); } };
      secure.once('secureConnect', () => complete(null, secure));
      secure.once('error', error => complete(error));
    }).catch(error => callback(error));
  };
  return new Promise((resolve, reject) => {
    const finish = (error, result) => {
      if (finished) return;
      finished = true; clearTimeout(timer);
      request?.destroy(); secure?.destroy(); raw?.destroy(); agent.destroy();
      if (error) reject(Error('Проверка внешнего IP не завершилась. Соединение закрыто.'));
      else resolve(result);
    };
    const timer = setTimeout(() => finish(Error('timeout')), timeout);
    request = https.request({ hostname, path, method: 'GET', port: 443, agent,
      headers: { Accept: 'application/json', 'User-Agent': 'gate-claude/0.5.0' } }, response => {
      if (response.statusCode !== 200) { finish(Error('HTTP')); return; }
      let buffer = Buffer.alloc(0);
      response.on('data', chunk => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length > 32768) finish(Error('size'));
      });
      response.once('end', () => {
        try { finish(null, JSON.parse(buffer.toString('utf8'))); } catch { finish(Error('JSON')); }
      });
      response.once('error', finish);
    });
    request.once('error', finish); request.end();
  });
}

module.exports = {
  queryJSON,
  queryDestinationIP,
  parseDestinationTrace,
  initialIP: (port, token) => queryJSON(port, 'ipwho.is', '/', 12000, token),
  currentIP: (port, token, family) => queryJSON(port, family === 4 ? 'api.ipify.org' : family === 6 ? 'api6.ipify.org' : 'api64.ipify.org', '/?format=json', 4000, token)
};
