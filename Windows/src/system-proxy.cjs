'use strict';
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { createHash } = require('node:crypto');
const net = require('node:net');
const path = require('node:path');

const runFile = promisify(execFile);
const SETTINGS_KEY = 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const LIMIT = 65536;
const MESSAGE = 'Не удалось безопасно определить прокси Windows. Выберите явный SOCKS5-прокси в Guard.';
const NAMES = ['ProxyEnable', 'ProxyServer', 'AutoConfigURL'];
const nameByLowerCase = new Map(NAMES.map(name => [name.toLowerCase(), name]));
class SystemProxyError extends Error {
  constructor(code = 'INVALID_SETTINGS') {
    super(MESSAGE);
    this.code = ['READ_FAILED', 'INVALID_SETTINGS', 'UNSUPPORTED_PAC'].includes(code) ? code : 'INVALID_SETTINGS';
  }
}

function endpoint(value) {
  if (typeof value !== 'string' || !value.length || value.length > 1024 || /[\x00-\x20\x7f/@?#\\]/.test(value)) throw new SystemProxyError();
  const match = /^(?:\[([0-9a-fA-F:.]+)\]|([a-zA-Z0-9.-]+)):([1-9]\d{0,4})$/.exec(value);
  if (!match) throw new SystemProxyError();
  const host = (match[1] || match[2]).toLowerCase(), port = Number(match[3]);
  if (port > 65535) throw new SystemProxyError();
  if (match[1]) {
    if (!net.isIPv6(host)) throw new SystemProxyError();
  } else if (!net.isIPv4(host)) {
    // Do not let a numeric shorthand, octal IPv4 or integer address become an
    // OS-dependent DNS/IP interpretation. Ordinary DNS labels are ASCII only.
    if (/^[0-9.]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host) || host.length > 253 ||
        !host.replace(/\.$/, '').split('.').every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) throw new SystemProxyError();
  }
  return { host, port };
}

function parseProxyServer(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\x00-\x1f\x7f]/.test(value)) throw new SystemProxyError();
  const text = value.trim();
  if (!text || text.includes('://') || text.includes('@')) throw new SystemProxyError();
  if (!text.includes('=')) return Object.freeze({ kind: 'http', ...endpoint(text) });
  const entries = new Map();
  for (const part of text.split(';')) {
    const match = /^ *(https|http|socks) *= *([^=;]+?) *$/i.exec(part);
    if (!match) throw new SystemProxyError();
    const protocol = match[1].toLowerCase();
    if (entries.has(protocol)) throw new SystemProxyError();
    entries.set(protocol, endpoint(match[2]));
  }
  for (const protocol of ['https', 'http', 'socks']) {
    if (entries.has(protocol)) return Object.freeze({ kind: protocol === 'socks' ? 'socks5' : 'http', ...entries.get(protocol) });
  }
  throw new SystemProxyError();
}

function descriptor(controls) {
  // Only the digest escapes. This includes disabled values so a configuration
  // change invalidates a sample without disclosing registry strings or PAC URLs.
  const fingerprint = createHash('sha256').update(JSON.stringify(NAMES.map(name => [name, controls[name] || null]))).digest('hex');
  const pac = controls.AutoConfigURL;
  if (pac && (pac.type !== 'REG_SZ' || pac.value.trim() !== '')) throw new SystemProxyError('UNSUPPORTED_PAC');
  const enabled = controls.ProxyEnable;
  let useProxy = false;
  if (enabled) {
    if (enabled.type !== 'REG_DWORD' || !/^0x[0-9a-f]{1,8}$/i.test(enabled.value)) throw new SystemProxyError();
    const number = Number.parseInt(enabled.value.slice(2), 16);
    if (number !== 0 && number !== 1) throw new SystemProxyError();
    useProxy = number === 1;
  }
  if (!useProxy) return Object.freeze({ kind: 'direct', host: '', port: 0, fingerprint });
  const server = controls.ProxyServer;
  if (!server || server.type !== 'REG_SZ') throw new SystemProxyError();
  return Object.freeze({ ...parseProxyServer(server.value), fingerprint });
}

function parseRegistryOutput(stdout) {
  if (typeof stdout !== 'string' || Buffer.byteLength(stdout, 'utf8') > LIMIT || /\x00/.test(stdout)) throw new SystemProxyError();
  const lines = stdout.replace(/^\uFEFF/, '').split(/\r?\n/);
  const controls = Object.create(null);
  let currentKey = '', sawKey = false;
  for (const line of lines) {
    if (!line.trim()) continue;
    if (line.includes('\r')) throw new SystemProxyError();
    if (/^HKEY_/i.test(line)) {
      const key = line.toLowerCase(), expected = SETTINGS_KEY.toLowerCase();
      if (key !== expected && !key.startsWith(expected + '\\')) throw new SystemProxyError();
      if (!sawKey && key !== expected) throw new SystemProxyError();
      if (key === expected && sawKey) throw new SystemProxyError();
      sawKey = true; currentKey = key; continue;
    }
    if (!sawKey || currentKey !== SETTINGS_KEY.toLowerCase()) throw new SystemProxyError();
    const row = /^[ \t]+(.+?)[ \t]+(REG_[A-Z0-9_]+)(?:[ \t]+(.*))?$/.exec(line);
    if (!row) throw new SystemProxyError();
    const name = nameByLowerCase.get(row[1].toLowerCase());
    if (!name) continue;
    if (Object.hasOwn(controls, name)) throw new SystemProxyError();
    const value = row[3] || '';
    if (/[\x00-\x1f\x7f]/.test(value) || value.length > 4096) throw new SystemProxyError();
    controls[name] = { type: row[2], value };
  }
  if (!sawKey) throw new SystemProxyError();
  return descriptor(controls);
}

async function readSystemProxy({ platform = process.platform, execute = runFile, systemRoot = process.env.SystemRoot || 'C:\\Windows' } = {}) {
  if (platform !== 'win32') return descriptor(Object.create(null));
  try {
    if (typeof systemRoot !== 'string' || !/^[a-z]:\\/i.test(systemRoot) || /[\x00-\x1f<>"|?*]/.test(systemRoot)) throw new SystemProxyError();
    const executable = path.win32.join(systemRoot, 'System32', 'reg.exe');
    const result = await execute(executable, ['query', SETTINGS_KEY], { windowsHide: true, timeout: 2000, maxBuffer: LIMIT, encoding: 'utf8' });
    return parseRegistryOutput(result?.stdout);
  } catch (error) {
    if (error instanceof SystemProxyError) throw error;
    // Never propagate reg.exe output, command lines, paths, URLs or exception bodies.
    throw new SystemProxyError('READ_FAILED');
  }
}

module.exports = { readSystemProxy, parseRegistryOutput, parseProxyServer, SystemProxyError };
