'use strict';
const net = require('node:net');
const { EventEmitter, once } = require('node:events');
const { randomBytes, timingSafeEqual } = require('node:crypto');
const securityError = message => Object.assign(Error(message), { guardSecurity: true });

class SocketReader {
  constructor(socket) {
    this.socket = socket; this.buffer = Buffer.alloc(0); this.waiting = null;
    this.onData = chunk => { this.buffer = Buffer.concat([this.buffer, chunk]); this.flush(); };
    this.onError = error => { this.error = error; this.flush(); };
    this.onEnd = () => this.onError(Error('Соединение SOCKS5 закрыто при настройке.'));
    socket.on('data', this.onData).on('error', this.onError).on('end', this.onEnd).on('close', this.onEnd);
  }
  flush() {
    if (!this.waiting) return;
    const { length, resolve, reject } = this.waiting;
    if (this.error) { this.waiting = null; reject(this.error); }
    else if (this.buffer.length >= length) {
      const result = this.buffer.subarray(0, length); this.buffer = this.buffer.subarray(length);
      this.waiting = null; resolve(result);
    }
  }
  read(length) { return new Promise((resolve, reject) => { this.waiting = { length, resolve, reject }; this.flush(); }); }
  release() {
    this.socket.pause();
    this.socket.off('data', this.onData).off('error', this.onError).off('end', this.onEnd).off('close', this.onEnd);
    if (this.buffer.length) this.socket.unshift(this.buffer);
  }
}

async function connectSOCKS(proxy, host, port, onSocket = () => {}) {
  const socket = net.createConnection({ host: proxy.host, port: proxy.port });
  onSocket(socket);
  socket.setTimeout(8000, () => socket.destroy(Error('Тайм-аут SOCKS5.')));
  const reader = new SocketReader(socket);
  try {
    await new Promise((resolve, reject) => {
      const connected = () => { cleanup(); resolve(); }, failed = error => { cleanup(); reject(error); };
      const closed = () => failed(Error('Соединение с SOCKS5 закрыто.'));
      const cleanup = () => socket.off('connect', connected).off('error', failed).off('close', closed);
      socket.once('connect', connected).once('error', failed).once('close', closed);
    });
    socket.write(proxy.username ? Buffer.from([5, 2, 0, 2]) : Buffer.from([5, 1, 0]));
    const greeting = await reader.read(2);
    if (greeting[0] !== 5 || ![0, 2].includes(greeting[1])) throw securityError('SOCKS5 не принял способ авторизации.');
    if (greeting[1] === 2) {
      if (!proxy.username) throw securityError('SOCKS5 требует логин и пароль.');
      const username = Buffer.from(proxy.username), password = Buffer.from(proxy.password || '');
      socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]));
      const auth = await reader.read(2);
      if (auth[0] !== 1 || auth[1] !== 0) throw securityError('SOCKS5 отверг логин или пароль.');
    }
    // ATYP=domain keeps target DNS resolution on the SOCKS server.
    const domain = Buffer.from(host);
    if (!domain.length || domain.length > 255) throw Error('Неверное имя назначения.');
    const targetPort = Buffer.alloc(2); targetPort.writeUInt16BE(port);
    socket.write(Buffer.concat([Buffer.from([5, 1, 0, 3, domain.length]), domain, targetPort]));
    const result = await reader.read(4);
    if (result[0] !== 5 || result[2] !== 0) throw Error('Некорректный ответ SOCKS5.');
    if (result[1] !== 0) {
      const error = Error('SOCKS5 отказал в подключении к назначению: ' + result[1]);
      error.targetRefused = result[1] >= 1 && result[1] <= 8; throw error;
    }
    let addressLength;
    if (result[3] === 1) addressLength = 4;
    else if (result[3] === 4) addressLength = 16;
    else if (result[3] === 3) addressLength = (await reader.read(1))[0];
    else throw Error('Неизвестный ответ SOCKS5.');
    await reader.read(addressLength + 2);
    socket.setTimeout(0); reader.release();
    return socket;
  } catch (error) { reader.release(); socket.destroy(); throw error; }
}

function authority(text) {
  const match = /^(?:\[([0-9a-fA-F:]+)\]|([a-zA-Z0-9._-]+)):(\d{1,5})$/.exec(text);
  if (!match) throw Error('Некорректный CONNECT.');
  const host = (match[1] || match[2]).toLowerCase(), port = Number(match[3]);
  if (!host || port < 1 || port > 65535 || (match[1] && !net.isIPv6(host))) throw Error('Неверное назначение CONNECT.');
  return { host, port };
}

// Parse one request before opening its selected upstream. Ordinary HTTP is one
// framed request per TCP connection; pipelining and upgrades cannot become an
// unparsed second request or carry proxy credentials through this adapter.
function proxyRequest(headers) {
  if (/[^\x09\x0a\x0d\x20-\x7e]/.test(headers) || !headers.endsWith('\r\n\r\n')) throw Error('Неверные заголовки прокси.');
  const lines = headers.slice(0, -4).split('\r\n'), requestLine = lines.shift();
  const fields = lines.map(line => {
    const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*([\x09\x20-\x7e]*)$/.exec(line);
    if (!match) throw Error('Неверные заголовки прокси.');
    return { name: match[1].toLowerCase(), value: match[2].trim() };
  });
  const connect = /^CONNECT ([^\s]+) HTTP\/1\.[01]$/.exec(requestLine);
  if (connect) return { kind: 'connect', ...authority(connect[1]), fields };
  const request = /^([A-Z]{1,32}) ([^\s]+) HTTP\/1\.([01])$/.exec(requestLine);
  if (!request) throw Error('Неверный запрос HTTP-прокси.');
  const [, method, target, minor] = request;
  if (/[^\x21-\x7e]|[\\#]/.test(target) || /%(?![0-9a-f]{2})|%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(target)) throw Error('Неверный HTTP URI.');
  const uri = /^http:\/\/(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9._-]+)(?::([1-9]\d{0,4}))?([/?][^#]*)?$/i.exec(target);
  if (!uri) throw Error('HTTP-прокси требует абсолютный http URI без авторизации.');
  const host = (uri[1].startsWith('[') ? uri[1].slice(1, -1) : uri[1]).toLowerCase(), port = uri[2] ? Number(uri[2]) : 80;
  if (port > 65535 || (uri[1].startsWith('[') && !net.isIPv6(host))) throw Error('Неверное назначение HTTP.');
  const hostHeader = (net.isIPv6(host) ? '[' + host + ']' : host) + (port === 80 ? '' : ':' + port);
  const hostFields = fields.filter(field => field.name === 'host');
  if (hostFields.length > 1 || (hostFields.length === 1 && hostFields[0].value.toLowerCase() !== hostHeader && hostFields[0].value.toLowerCase() !== hostHeader + (port === 80 ? ':80' : ''))) throw Error('Неоднозначный Host.');
  const lengths = fields.filter(field => field.name === 'content-length'), encodings = fields.filter(field => field.name === 'transfer-encoding');
  if (lengths.length > 1 || encodings.length > 1 || (lengths.length && encodings.length) || fields.some(field => field.name === 'trailer')) throw Error('Неоднозначная длина HTTP.');
  if (lengths.length && !/^(?:0|[1-9]\d{0,18})$/.test(lengths[0].value)) throw Error('Неверная длина HTTP.');
  if (encodings.length && (minor !== '1' || encodings[0].value.toLowerCase() !== 'chunked')) throw Error('Неподдерживаемое кодирование HTTP.');
  const connectionNames = new Set();
  for (const field of fields.filter(field => field.name === 'connection')) {
    for (const value of field.value.split(',')) {
      const token = value.trim().toLowerCase(); if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(token)) throw Error('Неверный Connection.');
      if (['host', 'content-length', 'transfer-encoding'].includes(token)) throw Error('Неоднозначное оформление HTTP.');
      connectionNames.add(token);
    }
  }
  const stripped = new Set(['host', 'proxy-authorization', 'proxy-authenticate', 'proxy-connection', 'connection', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade', ...connectionNames]);
  const path = uri[3] ? (uri[3].startsWith('?') ? '/' + uri[3] : uri[3]) : '/';
  const outgoing = [method + ' ' + path + ' HTTP/1.' + minor, 'Host: ' + hostHeader];
  for (const field of fields) if (!stripped.has(field.name)) outgoing.push(field.name + ': ' + field.value);
  // Transfer coding is reconstructed only after a strict single-coding check.
  if (encodings.length) outgoing.push('Transfer-Encoding: chunked');
  outgoing.push('Connection: close', '', '');
  return { kind: 'http', host, port, fields, header: Buffer.from(outgoing.join('\r\n'), 'latin1'), body: requestBody(encodings.length ? null : BigInt(lengths[0]?.value || '0')) };
}
function requestBody(length) {
  let state = length === null ? 'size' : 'fixed', remaining = length, line = '';
  const body = { complete: length === 0n, consume(bytes) {
    let offset = 0;
    while (offset < bytes.length) {
      if (body.complete) throw Error('HTTP pipelining запрещён.');
      if (state === 'fixed' || state === 'data') {
        const count = remaining > BigInt(bytes.length - offset) ? bytes.length - offset : Number(remaining);
        remaining -= BigInt(count); offset += count;
        if (remaining === 0n) { if (state === 'fixed') body.complete = true; else { state = 'data-crlf'; line = ''; } }
        continue;
      }
      line += String.fromCharCode(bytes[offset++]);
      if (line.length > 128) throw Error('Неверная граница HTTP.');
      if (state === 'size') {
        if (!line.endsWith('\r\n')) { if (line.endsWith('\n') || (line.includes('\r') && !line.endsWith('\r'))) throw Error('Неверная граница HTTP.'); continue; }
        if (!/^[0-9a-fA-F]{1,16}\r\n$/.test(line)) throw Error('Неверная граница HTTP.');
        remaining = BigInt('0x' + line.slice(0, -2)); line = ''; state = remaining === 0n ? 'last-crlf' : 'data';
      } else {
        if (line.length === 1 && line !== '\r') throw Error('HTTP trailers запрещены.');
        if (line.length === 2) {
          if (line !== '\r\n') throw Error('Неверная граница HTTP.');
          if (state === 'last-crlf') body.complete = true; else state = 'size';
          line = '';
        }
      }
    }
    return body.complete;
  } };
  return body;
}

async function connectCurrentNetwork(host, port, onSocket = () => {}) {
  const socket = net.createConnection({ host, port }); onSocket(socket);
  socket.setTimeout(8000, () => socket.destroy(Error('Тайм-аут подключения через текущую сеть.')));
  try {
    await new Promise((resolve, reject) => {
      const connected = () => { cleanup(); resolve(); }, failed = error => { cleanup(); reject(error); };
      const closed = () => failed(Error('Соединение закрыто при подключении.'));
      const cleanup = () => socket.off('connect', connected).off('error', failed).off('close', closed);
      socket.once('connect', connected).once('error', failed).once('close', closed);
    });
    socket.setTimeout(0); socket.pause(); return socket;
  } catch (error) { socket.destroy(); error.targetRefused = true; throw error; }
}

class SOCKSRelay extends EventEmitter {
  constructor(proxy, mode = 'socks5') {
    super();
    if (!['socks5', 'network'].includes(mode) || (mode === 'socks5' && !proxy?.host)) throw Error('Не задан режим подключения.');
    this.mode = mode; this.proxy = proxy; this.sockets = new Set(); this.controlSockets = new Set();
    this.checkToken = randomBytes(32).toString('hex'); this.unlocked = false; this.closed = false;
  }
  async start() {
    this.server = net.createServer({ allowHalfOpen: true }, socket => this.accept(socket));
    this.server.maxConnections = 128;
    this.server.on('error', () => { if (!this.closed) this.emit('fatal', 'Локальный шлюз остановился.'); });
    this.server.listen({ host: '127.0.0.1', port: 0 });
    await once(this.server, 'listening');
    this.port = this.server.address().port;
    return this.port;
  }
  track(socket, control = false) {
    this.sockets.add(socket); if (control) this.controlSockets.add(socket);
    socket.once('close', () => { this.sockets.delete(socket); this.controlSockets.delete(socket); }); socket.on('error', () => {}); return socket;
  }
  accept(client) {
    this.track(client); let bytes = Buffer.alloc(0), processing = false;
    client.setTimeout(10000, () => client.destroy());
    const onData = async chunk => {
      if (processing) return;
      bytes = Buffer.concat([bytes, chunk]);
      const end = bytes.indexOf('\r\n\r\n');
      if (end < 0) { if (bytes.length > 16384) client.destroy(); return; }
      if (end > 16384) { client.destroy(); return; }
      processing = true; client.off('data', onData);
      let upstream, pending, request, head = bytes.subarray(end + 4);
      const pendingLimit = () => request?.kind === 'http' ? 1024 * 1024 : 65536;
      const cancel = () => { pending?.destroy(); client.destroy(); };
      const collect = data => {
        try {
          if (request?.kind === 'http') request.body.consume(data);
          head = Buffer.concat([head, data]); if (head.length > pendingLimit()) cancel();
        } catch { cancel(); }
      };
      // Keep reading FIN while DNS/SOCKS is pending. Pausing here hides cancellation
      // and can otherwise create an upstream connection after the client has gone.
      client.on('data', collect).once('end', cancel).once('close', cancel).once('error', cancel);
      const release = () => { client.off('data', collect).off('end', cancel).off('close', cancel).off('error', cancel); };
      try {
        request = proxyRequest(bytes.subarray(0, end + 4).toString('latin1'));
        if (head.length > pendingLimit()) throw Error('Слишком большой буфер запроса.');
        const { host, port } = request;
        if (request.kind === 'http') request.body.consume(head);
        const credentials = request.fields.filter(field => field.name === 'proxy-authorization');
        const token = credentials.length === 1 && /^Bearer ([a-f0-9]{64})$/i.exec(credentials[0].value);
        const control = request.kind === 'connect' && token && timingSafeEqual(Buffer.from(token[1]), Buffer.from(this.checkToken)) &&
          port === 443 && ['ipwho.is', 'api64.ipify.org', 'api.ipify.org', 'api6.ipify.org'].includes(host);
        if (control) this.controlSockets.add(client);
        const allowed = () => !this.closed && !client.destroyed && (this.unlocked || control);
        if (!allowed()) {
          client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
        }
        const opened = socket => { pending = this.track(socket, Boolean(control)); if (!allowed()) socket.destroy(); };
        try { upstream = this.mode === 'network' ? await connectCurrentNetwork(host, port, opened) : await connectSOCKS(this.proxy, host, port, opened); }
        catch (error) {
          if (allowed() && !error.targetRefused) {
            if (error.guardSecurity) this.emit('fatal', error.message);
            else if (!control) this.emit('revalidate', 'Временный обрыв SOCKS5. Проверяем закреплённый IP.');
          }
          throw error;
        }
        if (!allowed()) { upstream.destroy(); return; }
        client.pause(); release(); client.setTimeout(0);
        // A single established TCP reset retires this tunnel, not the whole session.
        const close = () => { client.destroy(); upstream.destroy(); };
        client.once('close', close);
        upstream.once('close', () => {
          // Keep a clean HTTP response's buffered writes alive until client.end
          // flushes them. A reset or incomplete upstream still retires both sides.
          if (request.kind === 'http' && upstream.readableEnded) { if (!client.writableEnded) client.end(); }
          else close();
        });
        client.on('error', close); upstream.on('error', close);
        if (request.kind === 'connect') {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (head.length) upstream.write(head);
          client.pipe(upstream); upstream.pipe(client); client.resume(); upstream.resume();
        } else {
          let blocked = !upstream.write(request.header);
          if (head.length && !upstream.write(head)) blocked = true;
          const forward = data => {
            try {
              request.body.consume(data);
              if (!upstream.write(data)) { blocked = true; client.pause(); }
              if (request.body.complete) upstream.end();
            } catch { close(); }
          };
          client.on('data', forward).once('end', () => { if (request.body.complete) upstream.end(); else close(); });
          upstream.on('drain', () => { blocked = false; if (allowed()) client.resume(); });
          upstream.pipe(client); upstream.resume();
          if (request.body.complete) upstream.end();
          if (!blocked) client.resume();
        }
        this.emit('tunnel', { host, port });
      } catch { pending?.destroy(); if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); }
      finally { release(); }
    };
    client.on('data', onData);
  }
  unlock() { if (this.closed) throw Error('Шлюз закрыт.'); this.unlocked = true; }
  resume() { this.unlock(); }
  pause() {
    if (this.closed) return;
    this.unlocked = false;
    for (const socket of this.sockets) if (!this.controlSockets.has(socket)) socket.destroy();
  }
  close() {
    this.closed = true; this.unlocked = false;
    for (const socket of this.sockets) socket.destroy(); this.sockets.clear(); this.controlSockets.clear();
    this.server?.close(); this.proxy = null;
  }
}
class NetworkRelay extends SOCKSRelay { constructor() { super(null, 'network'); } }

async function connectTunnel(port, host, targetPort = 443, checkToken = '', onSocket = () => {}) {
  const socket = net.createConnection({ host: '127.0.0.1', port });
  socket.setTimeout(8000, () => socket.destroy(Error('Тайм-аут локального шлюза.')));
  socket.on('error', () => {});
  onSocket(socket);
  await new Promise((resolve, reject) => {
    const connected = () => { cleanup(); resolve(); }, failed = error => { cleanup(); reject(error); };
    const closed = () => failed(Error('Подключение к шлюзу отменено.'));
    const cleanup = () => socket.off('connect', connected).off('error', failed).off('close', closed);
    socket.once('connect', connected).once('error', failed).once('close', closed);
    if (socket.destroyed) closed();
  });
  const destination = (net.isIPv6(host) ? '[' + host + ']' : host) + ':' + targetPort;
  const authorization = /^[a-f0-9]{64}$/.test(checkToken) ? 'Proxy-Authorization: Bearer ' + checkToken + '\r\n' : '';
  socket.write(`CONNECT ${destination} HTTP/1.1\r\nHost: ${destination}\r\n${authorization}\r\n`);
  let buffer = Buffer.alloc(0);
  await new Promise((resolve, reject) => {
    const onError = e => { cleanup(); reject(e); }, onEnd = () => onError(Error('Шлюз закрыл соединение.'));
    const onData = data => {
      buffer = Buffer.concat([buffer, data]);
      if (buffer.length > 16384) return onError(Error('Слишком большой ответ шлюза.'));
      const end = buffer.indexOf('\r\n\r\n'); if (end < 0) return;
      if (!/^HTTP\/1\.1 200 /.test(buffer.toString('ascii'))) return onError(Error('Шлюз отказал в подключении.'));
      socket.pause(); cleanup();
      if (buffer.length > end + 4) socket.unshift(buffer.subarray(end + 4));
      resolve();
    };
    const cleanup = () => socket.off('data', onData).off('error', onError).off('end', onEnd).off('close', onEnd);
    socket.on('data', onData).once('error', onError).once('end', onEnd).once('close', onEnd);
  }).catch(error => { socket.destroy(); throw error; });
  socket.setTimeout(0); return socket;
}

module.exports = { SOCKSRelay, NetworkRelay, connectSOCKS, connectCurrentNetwork, connectTunnel, SocketReader, authority };
