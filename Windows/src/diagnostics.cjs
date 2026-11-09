'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { body, diagnostic, secretKey } = require('./sanitize.cjs');
const { zipEntry, zipEnd } = require('./portable-zip.cjs');

const LOG_NAMES = Object.freeze(['events.previous.jsonl', 'events.jsonl', 'guard.previous.log', 'guard.log']);
const MAX_FILE_BYTES = 512 * 1024;
const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;
const README = `Claude Proxy Guard — диагностический архив

В архиве только технические события Guard, состояние сессии и службы.
IP-адреса, пароли, токены, cookies, трафик, содержимое Profile, CodeState,
settings.json и ip-memory.json не включаются. Перед отправкой архива можно
просмотреть все JSON/JSONL/LOG/TXT файлы обычным текстовым редактором.

events.jsonl — пользовательские и технические события с UTC-временем.
guard.log — ошибки main process и жизненный цикл приложения.
session.json — обезличенный снимок текущей сессии.
service.json — разрешённые поля состояния службы Windows.
manifest.json — версии приложения и операционной системы.
Файлы .previous — предыдущий ограниченный сегмент ротации журнала.
`;

function safeText(value) {
  const allowedHosts = new Set(['claude.ai', 'api.anthropic.com', 'ipwho.is', 'ipinfo.io', 'ipapi.co', 'api.ipify.org', 'edns.ip-api.com']);
  const text = String(value || '').replace(/\b(Win32Exception):(\d{1,5}):/g, '$1-$2-');
  return diagnostic(body(text))
    .replace(/[a-z]:\\Users\\[^\\\r\n]+/gi, '[профиль пользователя]')
    .replace(/\/(?:Users|home)\/[^/\r\n]+/g, '[профиль пользователя]')
    .replace(/\\\\[^\s\\]+\\[^\s\\]+/g, '[сетевой путь]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email скрыт]')
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, '[GUID скрыт]')
    .replace(/\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi, '[MAC скрыт]')
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi, host => allowedHosts.has(host.toLowerCase()) ? host : '[host скрыт]');
}
function safeFields(details) {
  const result = {};
  if (!details || typeof details !== 'object' || Array.isArray(details)) return result;
  for (const [key, value] of Object.entries(details).slice(0, 32)) {
    if (!/^[a-z][a-zA-Z0-9_]{0,63}$/.test(key) || secretKey(key)) continue;
    if (typeof value === 'boolean' || value === null) result[key] = value;
    else if (typeof value === 'number' && Number.isFinite(value)) result[key] = Math.max(-86400000, Math.min(86400000, Math.round(value)));
    else if (typeof value === 'string') result[key] = safeText(value).slice(0, 500);
  }
  return result;
}
function safeJSON(value) { return Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8'); }
function createZip(entries) {
  const names = Object.keys(entries).sort(); let offset = 0, expanded = 0;
  if (!names.length || names.length > 16) throw Error('Некорректный набор диагностических файлов.');
  const local = [], central = [], files = [];
  for (const name of names) {
    const data = entries[name];
    if (!Buffer.isBuffer(data) || data.length > MAX_FILE_BYTES) throw Error('Диагностический файл превышает ограничение размера.');
    expanded += data.length; if (expanded > MAX_BUNDLE_BYTES) throw Error('Диагностический архив превышает ограничение размера.');
    const entry = zipEntry(name, data, offset); offset += entry.size;
    local.push(...entry.local); central.push(entry.central); files.push(entry.file);
  }
  const directory = Buffer.concat(central), bytes = Buffer.concat([...local, directory, zipEnd(names.length, directory.length, offset)]);
  if (bytes.length > MAX_BUNDLE_BYTES) throw Error('Диагностический архив превышает ограничение размера.');
  return { bytes, files };
}
function sessionSnapshot(controller) {
  const value = controller.snapshot(), metrics = value.metrics || {}, dns = metrics.dns || {};
  const destinations = {};
  for (const host of ['claude.ai', 'api.anthropic.com']) {
    const item = metrics.destinations?.[host];
    if (item) destinations[host] = { state: safeText(item.state), latencyMs: Number.isFinite(item.latencyMs) ? item.latencyMs : null };
  }
  return {
    state: safeText(value.state), message: safeText(value.message), blocked: value.blocked === true,
    processFrozen: value.processFrozen === true, processState: safeText(value.processState), secondsRemaining: value.secondsRemaining,
    windowsApprovalPending: value.windowsApprovalPending === true, savedIPPresent: Boolean(value.savedIP), exitIPPresent: Boolean(value.exitIP),
    ipMemoryError: safeText(value.ipMemoryError), country: safeText(value.country), profile: value.profile ? {
      timezone: safeText(value.profile.timezone), language: safeText(value.profile.language), locale: safeText(value.profile.locale)
    } : null,
    runtime: {
      pid: Number.isSafeInteger(controller.runtimePID) ? controller.runtimePID : null,
      version: safeText(controller.runtime?.version), hostLive: controller.liveHost(),
      relayOpen: Boolean(controller.relay && !controller.relay.closed), relayUnlocked: controller.relay?.unlocked === true,
      fenceInstalled: controller.fence?.installed === true, fenceClosed: controller.fence?.closed === true
    },
    metrics: {
      sources: Array.isArray(metrics.sources) ? metrics.sources.slice(0, 16).map(safeText) : [],
      organization: safeText(metrics.organization), asn: safeText(metrics.asn), destinations,
      dns: { state: safeText(dns.state), organization: safeText(dns.organization) },
      dnsProtection: safeText(metrics.dnsProtection), webRTC: safeText(metrics.webRTC), quic: safeText(metrics.quic)
    }
  };
}
class DiagnosticStore {
  constructor(root, options = {}) {
    this.root = root; this.directory = path.join(root, 'logs'); this.maxFileBytes = options.maxFileBytes || MAX_FILE_BYTES;
    this.queue = []; this.queuedBytes = 0; this.flushing = null; this.scheduled = null;
    this.sequence = 0; this.dropped = 0; this.failures = 0; this.session = require('node:crypto').randomUUID();
  }
  ensure() {
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    const info = fs.lstatSync(this.directory);
    if (!info.isDirectory() || info.isSymbolicLink()) throw Error('Папка журналов не прошла проверку пути.');
    const root = fs.realpathSync(this.root), directory = fs.realpathSync(this.directory);
    if (directory.toLowerCase() !== path.join(root, 'logs').toLowerCase()) throw Error('Папка журналов не прошла проверку пути.');
    return this.directory;
  }
  base(type) {
    return { date: new Date().toISOString(), sequence: ++this.sequence, monotonicMS: Math.round(performance.now()), session: this.session,
      droppedEvents: this.dropped, writeFailures: this.failures, type };
  }
  append(name, line) {
    if (!['events.jsonl', 'guard.log'].includes(name)) return;
    const bytes = Buffer.byteLength(line + '\n', 'utf8');
    if (bytes > Math.min(16384, this.maxFileBytes)) { this.dropped++; return; }
    while (this.queue.length >= 256 || this.queuedBytes + bytes > 256 * 1024) {
      const dropped = this.queue.shift(); if (!dropped) break;
      this.queuedBytes -= dropped.bytes; this.dropped++;
    }
    this.queue.push({ name, line, bytes }); this.queuedBytes += bytes;
    if (!this.scheduled) {
      this.scheduled = setImmediate(() => { this.scheduled = null; void this.flush(); });
      this.scheduled.unref?.();
    }
  }
  async write({ name, line, bytes }) {
    try {
      const file = path.join(this.ensure(), name), previous = path.join(this.directory, name.replace(/(?:\.jsonl|\.log)$/, '.previous$&'));
      let size = 0;
      try { const info = await fs.promises.lstat(file); if (!info.isFile() || info.isSymbolicLink()) return; size = info.size; }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (size + bytes > this.maxFileBytes && size > 0) {
        try { const info = await fs.promises.lstat(previous); if (!info.isFile() || info.isSymbolicLink()) return; await fs.promises.unlink(previous); }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
        await fs.promises.rename(file, previous);
      }
      await fs.promises.appendFile(file, line + '\n', { mode: 0o600 });
    } catch { this.failures++; }
  }
  writeSync({ name, line, bytes }) {
    try {
      const file = path.join(this.ensure(), name), previous = path.join(this.directory, name.replace(/(?:\.jsonl|\.log)$/, '.previous$&'));
      let size = 0;
      try { const info = fs.lstatSync(file); if (!info.isFile() || info.isSymbolicLink()) return; size = info.size; } catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (size + bytes > this.maxFileBytes && size > 0) {
        try { const info = fs.lstatSync(previous); if (!info.isFile() || info.isSymbolicLink()) return; fs.unlinkSync(previous); } catch (error) { if (error.code !== 'ENOENT') throw error; }
        fs.renameSync(file, previous);
      }
      fs.appendFileSync(file, line + '\n', { mode: 0o600 });
    } catch { this.failures++; }
  }
  flush() {
    if (this.scheduled) { clearImmediate(this.scheduled); this.scheduled = null; }
    if (!this.flushing) this.flushing = (async () => {
      while (this.queue.length) {
        const item = this.queue.shift(); this.queuedBytes -= item.bytes;
        await this.write(item);
      }
    })().finally(() => { this.flushing = null; });
    return this.flushing;
  }
  flushSync() {
    if (this.scheduled) { clearImmediate(this.scheduled); this.scheduled = null; }
    while (this.queue.length) { const item = this.queue.shift(); this.queuedBytes -= item.bytes; this.writeSync(item); }
  }
  event(type, details) {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(type)) return;
    this.append('events.jsonl', JSON.stringify({ ...this.base(type), ...safeFields(details) }));
  }
  error(stage, error) {
    if (!/^[a-z][a-z0-9_:.-]{0,63}$/.test(stage)) return;
    const name = typeof error?.name === 'string' && /^[A-Za-z]{1,64}$/.test(error.name) ? error.name : 'Error';
    const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : null;
    this.append('guard.log', JSON.stringify({ ...this.base('error'), stage, name, code, message: safeText(error?.message || error) }));
  }
  async read(name) {
    try {
      if (!LOG_NAMES.includes(name)) return Buffer.alloc(0);
      const file = path.join(this.ensure(), name), info = await fs.promises.lstat(file);
      if (!info.isFile() || info.isSymbolicLink() || info.size > this.maxFileBytes) return Buffer.alloc(0);
      const data = await fs.promises.readFile(file);
      if (data.length && data[data.length - 1] !== 10) { const end = data.lastIndexOf(10); return end < 0 ? Buffer.alloc(0) : data.subarray(0, end + 1); }
      return data;
    } catch { return Buffer.alloc(0); }
  }
  async bundle({ manifest, session, service }) {
    await this.flush();
    const entries = {
      'README.txt': Buffer.from(README, 'utf8'),
      'manifest.json': safeJSON({ ...manifest, diagnostics: { droppedEvents: this.dropped, writeFailures: this.failures } }),
      'session.json': safeJSON(session), 'service.json': safeJSON(service)
    };
    for (const name of LOG_NAMES) { const data = await this.read(name); if (data.length) entries[name] = data; }
    return createZip(entries);
  }
}
module.exports = { DiagnosticStore, createZip, safeText, safeFields, sessionSnapshot };
