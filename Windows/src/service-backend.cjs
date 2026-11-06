'use strict';
const path = require('node:path');
const { promisify } = require('node:util');
const { ownerHandle } = require('./fence-launch.cjs');

const SERVICE_VERSION = '1.0.0';
const STATUS_STATES = Object.freeze(['not_installed', 'running', 'stopped', 'update_required', 'error']);
const STATUS_KEYS = 'actions,available,code,schema,sessionRoutingSupported,state,version';
const RECEIPT_KEYS = 'code,elevated,operation,state,version';
class ServiceBackendError extends Error {
  constructor(code) { super('Системная служба Guard не подтвердила запрошенное действие.'); this.code = code; }
}
function decodeJSON(stdout) {
  if (typeof stdout !== 'string' || stdout.length > 8192) throw new ServiceBackendError('SERVICE_RESPONSE_INVALID');
  try {
    const value = JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
    if (!value || Array.isArray(value) || typeof value !== 'object') throw Error();
    return value;
  } catch { throw new ServiceBackendError('SERVICE_RESPONSE_INVALID'); }
}
function exactKeys(value, keys) {
  if (Object.keys(value).sort().join(',') !== keys) throw new ServiceBackendError('SERVICE_RESPONSE_INVALID');
}
function parseStatus(stdout) {
  const value = decodeJSON(stdout); exactKeys(value, STATUS_KEYS);
  if (value.schema !== 1 || value.available !== true || !STATUS_STATES.includes(value.state) ||
      value.sessionRoutingSupported !== (value.state === 'running') ||
      value.version !== null && value.version !== SERVICE_VERSION ||
      value.code !== null && !/^[A-Z][A-Z0-9_]{0,63}$/.test(value.code) || !Array.isArray(value.actions)) {
    throw new ServiceBackendError('SERVICE_STATUS_INVALID');
  }
  return value;
}
function parseReceipt(stdout, operation) {
  const value = decodeJSON(stdout); exactKeys(value, RECEIPT_KEYS);
  if (value.version !== 1 || value.operation !== operation || !Number.isInteger(value.code) || value.code < 0 || value.code > 65535 ||
      typeof value.elevated !== 'boolean' || !['running', 'not_installed', 'error'].includes(value.state) ||
      value.code === 0 && value.state === 'error' || value.code !== 0 && value.state !== 'error') {
    throw new ServiceBackendError('SERVICE_RECEIPT_INVALID');
  }
  if (value.code !== 0) throw new ServiceBackendError('SERVICE_OPERATION_REJECTED');
  return value;
}
function parseLaunchReceipt(stdout) {
  const value = decodeJSON(stdout);
  exactKeys(value, 'code,launched,version');
  if (value.version !== 1 || value.launched !== true || value.code !== 0) throw new ServiceBackendError('SERVICE_LAUNCH_REJECTED');
  return value;
}
function ready(status) { return status.state === 'running' && status.sessionRoutingSupported === true && status.version === SERVICE_VERSION; }

class NativeServiceBackend {
  constructor(options = {}) {
    this.helperPath = options.helperPath || path.join(process.resourcesPath || path.resolve(__dirname, '..'), 'GuardService.exe');
    this.ownerWindow = options.ownerWindow || (() => null);
    this.exec = options.exec || promisify(require('node:child_process').execFile);
    this.queue = Promise.resolve();
  }
  validateHelper() {
    if (!path.isAbsolute(this.helperPath || '') || /[\0\r\n\t]/.test(this.helperPath)) throw new ServiceBackendError('SERVICE_HELPER_INVALID');
  }
  async call(args, timeout) {
    this.validateHelper();
    try {
      const result = await this.exec(this.helperPath, args, { windowsHide: true, timeout, maxBuffer: 8192, shell: false });
      return result.stdout;
    } catch (error) {
      if (error && typeof error.stdout === 'string' && error.stdout.trim().length > 0 && error.stdout.length <= 8192) return error.stdout;
      throw new ServiceBackendError('SERVICE_NATIVE_REQUEST_FAILED');
    }
  }
  owner() {
    try { return ownerHandle(this.ownerWindow()); }
    catch { throw new ServiceBackendError('SERVICE_OWNER_INVALID'); }
  }
  serialize(operation) {
    const result = this.queue.then(operation, operation);
    this.queue = result.then(() => {}, () => {});
    return result;
  }
  async getStatus() { return parseStatus(await this.call(['--status'], 10000)); }
  install() { return this.serialize(() => this.requestInstall()); }
  update() { return this.serialize(() => this.requestInstall()); }
  async requestInstall() { return parseReceipt(await this.call(['--request-install', '--owner', this.owner()], 0), 'install'); }
  start() { return this.serialize(async () => { await this.call(['--start'], 20000); }); }
  stop() { return this.serialize(async () => { await this.call(['--stop'], 20000); }); }
  uninstall() {
    return this.serialize(async () => parseReceipt(await this.call(['--request-uninstall', '--owner', this.owner()], 0), 'uninstall'));
  }
  async ensureReadyUnlocked() {
    let status = await this.getStatus();
    if (ready(status)) return status;
    if (status.state === 'stopped') await this.call(['--start'], 20000);
    else if (['not_installed', 'update_required', 'error'].includes(status.state)) await this.requestInstall();
    else throw new ServiceBackendError('SERVICE_NOT_READY');
    status = await this.getStatus();
    if (!ready(status)) throw new ServiceBackendError('SERVICE_READBACK_FAILED');
    return status;
  }
  ensureReady() { return this.serialize(() => this.ensureReadyUnlocked()); }
  launchFence(request) {
    return this.serialize(async () => {
      if (!request || typeof request.root !== 'string' || request.root.length > 240 || !/^[A-Za-z]:\\/.test(request.root) ||
          /[\0\r\n\t]/.test(request.root) || !/^gate-network-fence-[a-f0-9]{32}$/.test(request.pipeName || '') ||
          !/^[a-f0-9]{64}$/.test(request.token || '')) throw new ServiceBackendError('SERVICE_LAUNCH_INVALID');
      await this.ensureReadyUnlocked();
      const root = Buffer.from(request.root, 'utf8').toString('base64');
      parseLaunchReceipt(await this.call(['--launch', '--root', root, '--pipe', request.pipeName, '--token', request.token], 15000));
    });
  }
}
module.exports = { NativeServiceBackend, ServiceBackendError, SERVICE_VERSION, parseStatus, parseReceipt, parseLaunchReceipt, ready };
