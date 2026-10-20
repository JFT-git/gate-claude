'use strict';
const net = require('node:net');
const { EventEmitter, once } = require('node:events');

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
    if (greeting[0] !== 5 || ![0, 2].includes(greeting[1])) throw Error('SOCKS5 не принял способ авторизации.');
    if (greeting[1] === 2) {
      if (!proxy.username) throw Error('SOCKS5 требует логин и пароль.');
      const username = Buffer.from(proxy.username), password = Buffer.from(proxy.password || '');
      socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]));
      const auth = await reader.read(2);
      if (auth[0] !== 1 || auth[1] !== 0) throw Error('SOCKS5 отверг логин или пароль.');
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

class SOCKSRelay extends EventEmitter {
  constructor(proxy) { super(); this.proxy = proxy; this.sockets = new Set(); this.unlocked = false; this.closed = false; }
  async start() {
    this.server = net.createServer(socket => this.accept(socket));
    this.server.maxConnections = 128;
    this.server.on('error', () => { if (!this.closed) this.emit('fatal', 'Локальный шлюз остановился.'); });
    this.server.listen({ host: '127.0.0.1', port: 0 });
    await once(this.server, 'listening');
    this.port = this.server.address().port;
    return this.port;
  }
  track(socket) { this.sockets.add(socket); socket.once('close', () => this.sockets.delete(socket)); socket.on('error', () => {}); return socket; }
  accept(client) {
    this.track(client); let bytes = Buffer.alloc(0), processing = false;
    client.setTimeout(10000, () => client.destroy());
    const onData = async chunk => {
      if (processing) return;
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length > 16384) { client.destroy(); return; }
      const end = bytes.indexOf('\r\n\r\n'); if (end < 0) return;
      processing = true; client.pause(); client.off('data', onData);
      let upstream;
      try {
        const match = /^CONNECT ([^\s]+) HTTP\/1\.[01]\r\n/.exec(bytes.subarray(0, end + 4).toString('ascii'));
        if (!match) throw Error('Поддерживается только HTTPS CONNECT.');
        const { host, port } = authority(match[1]);
        if (this.closed || (!this.unlocked && !(port === 443 && ['ipwho.is', 'api64.ipify.org'].includes(host)))) {
          client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
        }
        try { upstream = await connectSOCKS(this.proxy, host, port, socket => this.track(socket)); }
        catch (error) { if (!this.closed && !error.targetRefused) this.emit('fatal', error.message); throw error; }
        if (this.closed || client.destroyed) { upstream.destroy(); return; }
        client.setTimeout(0);
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        const head = bytes.subarray(end + 4); if (head.length) upstream.write(head);
        // A single established TCP reset retires this tunnel, not the whole session.
        const close = () => { client.destroy(); upstream.destroy(); };
        client.once('close', close); upstream.once('close', close);
        client.on('error', close); upstream.on('error', close);
        client.pipe(upstream); upstream.pipe(client); client.resume(); upstream.resume();
        this.emit('tunnel', { host, port });
      } catch { if (upstream) upstream.destroy(); if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); }
    };
    client.on('data', onData);
  }
  unlock() { if (this.closed) throw Error('Шлюз закрыт.'); this.unlocked = true; }
  close() {
    this.closed = true; this.unlocked = false;
    for (const socket of this.sockets) socket.destroy(); this.sockets.clear();
    this.server?.close(); this.proxy = null;
  }
}

async function connectTunnel(port, host, targetPort = 443) {
  const socket = net.createConnection({ host: '127.0.0.1', port });
  socket.setTimeout(8000, () => socket.destroy(Error('Тайм-аут локального шлюза.')));
  socket.on('error', () => {});
  await once(socket, 'connect');
  socket.write(`CONNECT ${host}:${targetPort} HTTP/1.1\r\nHost: ${host}:${targetPort}\r\n\r\n`);
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
    const cleanup = () => socket.off('data', onData).off('error', onError).off('end', onEnd);
    socket.on('data', onData).once('error', onError).once('end', onEnd);
  }).catch(error => { socket.destroy(); throw error; });
  socket.setTimeout(0); return socket;
}

module.exports = { SOCKSRelay, connectSOCKS, connectTunnel, SocketReader, authority };
