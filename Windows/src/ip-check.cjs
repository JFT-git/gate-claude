'use strict';
const https = require('node:https');
const tls = require('node:tls');
const { connectTunnel } = require('./relay.cjs');

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
  initialIP: (port, token) => queryJSON(port, 'ipwho.is', '/', 12000, token),
  currentIP: (port, token, family) => queryJSON(port, family === 4 ? 'api.ipify.org' : family === 6 ? 'api6.ipify.org' : 'api64.ipify.org', '/?format=json', 4000, token)
};
