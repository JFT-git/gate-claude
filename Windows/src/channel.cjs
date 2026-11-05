'use strict';
const { EventEmitter, once } = require('node:events');
const net = require('node:net');
const crypto = require('node:crypto');
const path = require('node:path');
const os = require('node:os');
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

class Channel extends EventEmitter {
  constructor() {
    super(); this.token = crypto.randomBytes(32).toString('hex');
    const id = 'gate-claude-' + crypto.randomBytes(16).toString('hex');
    this.path = process.platform === 'win32' ? '\\\\.\\pipe\\' + id : path.join(os.tmpdir(), id + '.sock');
    this.pending = new Map(); this.nextID = 0; this.closed = false;
  }
  async listen() {
    this.server = net.createServer(socket => {
      if (this.socket || this.closed) { socket.destroy(); return; }
      let buffer = Buffer.alloc(0), authenticated = false;
      const timer = setTimeout(() => socket.destroy(), 5000);
      socket.on('error', () => {});
      socket.on('data', chunk => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length > 8 * 1024 * 1024) { socket.destroy(); return; }
        let delimiter;
        while ((delimiter = buffer.indexOf(0)) >= 0) {
          const packet = buffer.subarray(0, delimiter); buffer = buffer.subarray(delimiter + 1);
          let message;
          try { message = JSON.parse(packet.toString('utf8')); } catch { socket.destroy(); return; }
          if (!record(message)) { socket.destroy(); return; }
          if (!authenticated) {
            const params = message.params;
            if (message.method !== 'ProxyGuard.hello' || !record(params) || typeof params.token !== 'string' ||
                !/^[a-f0-9]{64}$/.test(params.token)) { socket.destroy(); return; }
            const token = Buffer.from(params.token);
            if (token.length !== this.token.length ||
                !crypto.timingSafeEqual(token, Buffer.from(this.token)) || this.socket) { socket.destroy(); return; }
            authenticated = true; clearTimeout(timer); this.socket = socket; this.emit('connected');
          } else if (message.id && this.pending.has(message.id)) {
            const entry = this.pending.get(message.id); this.pending.delete(message.id); clearTimeout(entry.timer);
            if (message.error) entry.reject(Error(message.error.message || 'CDP error')); else entry.resolve(message.result || {});
          } else if (message.method) this.emit('event', message.method, message.params || {}, message.sessionId || '');
        }
      });
      socket.once('close', () => {
        clearTimeout(timer);
        if (authenticated && !this.closed) { this.rejectAll(); this.emit('fatal', 'Диагностический канал Claude закрыт.'); }
      });
    });
    this.server.on('error', () => { if (!this.closed) this.emit('fatal', 'Не удалось открыть канал диагностики.'); });
    this.server.listen({ path: this.path, readableAll: false, writableAll: false });
    await once(this.server, 'listening');
  }
  connected(timeout = 30000) {
    if (this.socket) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { cleanup(); reject(Error('Claude не открыл канал диагностики.')); }, timeout);
      const success = () => { cleanup(); resolve(); }, failure = reason => { cleanup(); reject(Error(reason)); };
      const cleanup = () => { clearTimeout(timer); this.off('connected', success).off('fatal', failure); };
      this.once('connected', success).once('fatal', failure);
    });
  }
  setFrozen(frozen) {
    const next = frozen === true;
    if (next === this.frozen) return;
    this.frozen = next;
    const now = performance.now();
    for (const [id, entry] of this.pending) {
      clearTimeout(entry.timer);
      if (next) entry.remaining = Math.max(0, entry.remaining - (now - entry.started));
      else {
        entry.started = now;
        entry.timer = this.commandTimeout(id, entry.method, entry.remaining);
      }
    }
    this.emit('freeze', next);
  }
  commandTimeout(id, method, delay) {
    return setTimeout(() => {
      const entry = this.pending.get(id);
      if (!entry || this.frozen) return;
      this.pending.delete(id); entry.reject(Error('CDP timeout: ' + method));
    }, delay);
  }
  command(method, params = {}, sessionId) {
    if (this.closed || !this.socket) return Promise.reject(Error('Канал диагностики закрыт.'));
    const id = ++this.nextID;
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, method, remaining: 6000, started: performance.now(), timer: null };
      this.pending.set(id, entry);
      if (!this.frozen) entry.timer = this.commandTimeout(id, method, entry.remaining);
      this.socket.write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0', error => {
        if (error) { clearTimeout(entry.timer); this.pending.delete(id); reject(error); }
      });
    });
  }
  rejectAll() { for (const item of this.pending.values()) { clearTimeout(item.timer); item.reject(Error('Канал остановлен.')); } this.pending.clear(); }
  close() { this.closed = true; this.rejectAll(); this.socket?.destroy(); this.server?.close(); this.emit('fatal', 'Канал остановлен.'); }
}
module.exports = { Channel };
