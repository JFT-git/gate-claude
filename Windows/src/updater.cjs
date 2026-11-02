'use strict';
const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');
const semver = require('semver');
const yaml = require('js-yaml');

const PUBLIC_KEY_SPKI_BASE64 = 'MCowBQYDK2VwAyEAdgEyOH5iBelfAXj9Zmkjl1E80AlijGQEs6ffKmmKJow=';
const METADATA_NAME = 'latest.yml';
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const MAX_METADATA_BYTES = 128 * 1024;
const PUBLIC_KEY = crypto.createPublicKey({ key: Buffer.from(PUBLIC_KEY_SPKI_BASE64, 'base64'), format: 'der', type: 'spki' });

class UpdateError extends Error {
  constructor(code, message) { super(message); this.code = code; this.publicMessage = message; }
}

function validSHA512(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 64 && bytes.toString('base64') === value;
}

function verifyDetachedMetadata(metadata, signature, publicKey = PUBLIC_KEY) {
  const bytes = Buffer.isBuffer(metadata) ? metadata : Buffer.from(String(metadata), 'utf8');
  if (!bytes.length || bytes.length > MAX_METADATA_BYTES || typeof signature !== 'string') throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.');
  const encoded = signature.trim();
  if (!/^[A-Za-z0-9+/]{86}==$/.test(encoded)) throw new UpdateError('SIGNATURE_INVALID', 'Подпись метаданных обновления не подтверждена.');
  const signatureBytes = Buffer.from(encoded, 'base64');
  if (signatureBytes.length !== 64 || signatureBytes.toString('base64') !== encoded || !crypto.verify(null, bytes, publicKey, signatureBytes)) {
    throw new UpdateError('SIGNATURE_INVALID', 'Подпись метаданных обновления не подтверждена.');
  }
  let value;
  try { value = yaml.load(bytes.toString('utf8')); }
  catch { throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.');
  return value;
}

function signedFileInfo(metadata, currentVersion) {
  if (typeof metadata.version !== 'string' || semver.valid(metadata.version) !== metadata.version || semver.prerelease(metadata.version) || !semver.gt(metadata.version, currentVersion)) {
    throw new UpdateError('VERSION_REFUSED', 'Обновление не является более новой стабильной версией.');
  }
  if (!Array.isArray(metadata.files) || metadata.files.length !== 1) throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.');
  const file = metadata.files[0], expectedName = `ClaudeProxyGuard-Windows-${metadata.version}-x64-Setup.exe`;
  if (!file || file.url !== expectedName || !validSHA512(file.sha512) || !Number.isSafeInteger(file.size) || file.size < 1024 * 1024 || file.size > 2 * 1024 * 1024 * 1024 ||
      file.blockMapSize !== undefined && (!Number.isSafeInteger(file.blockMapSize) || file.blockMapSize < 1 || file.blockMapSize > file.size)) {
    throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.');
  }
  if (metadata.path !== undefined && metadata.path !== file.url || metadata.sha512 !== undefined && metadata.sha512 !== file.sha512) {
    throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.');
  }
  return Object.freeze({ url: file.url, sha512: file.sha512, size: file.size, ...(file.blockMapSize === undefined ? {} : { blockMapSize: file.blockMapSize }) });
}

function bindUpdateInfo(info, metadata, currentVersion) {
  if (!info || info.version !== metadata.version || !Array.isArray(info.files) || info.files.length !== 1) {
    throw new UpdateError('METADATA_CHANGED', 'Метаданные обновления изменились. Повторите проверку.');
  }
  const file = signedFileInfo(metadata, currentVersion), original = info.files[0];
  for (const key of ['url', 'sha512', 'size', 'blockMapSize']) {
    if (original?.[key] !== file[key]) throw new UpdateError('METADATA_CHANGED', 'Метаданные обновления изменились. Повторите проверку.');
  }
  if (info.path !== undefined && info.path !== file.url || info.sha512 !== undefined && info.sha512 !== file.sha512) {
    throw new UpdateError('METADATA_CHANGED', 'Метаданные обновления изменились. Повторите проверку.');
  }
  return Object.freeze({ ...info, version: metadata.version, files: Object.freeze([file]), ...(metadata.path === undefined ? {} : { path: metadata.path }), ...(metadata.sha512 === undefined ? {} : { sha512: metadata.sha512 }) });
}

function sanitizeUpdaterError(error) {
  if (error instanceof UpdateError || typeof error?.publicMessage === 'string' && /^[A-Z_]+$/.test(error.code || '')) return { code: error.code, message: error.publicMessage };
  const status = Number(error?.statusCode), code = String(error?.code || '');
  if (status === 429 || status === 403) return { code: 'RATE_LIMIT', message: 'GitHub временно ограничил проверку обновлений. Guard продолжит работу; повторите позже.' };
  if (['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENETDOWN', 'ENETUNREACH', 'EHOSTUNREACH', 'ERR_INTERNET_DISCONNECTED', 'HTTP_ERROR_429'].includes(code)) {
    return { code: 'OFFLINE', message: 'Не удалось связаться с GitHub. Guard продолжит работу; проверка обновления не влияет на защищённую сессию.' };
  }
  return { code: 'UPDATE_FAILED', message: 'Проверка или загрузка обновления не завершилась. Guard продолжит работу; повторите позже.' };
}

class WindowsUpdater extends EventEmitter {
  constructor(options) {
    super();
    this.updater = options.autoUpdater;
    this.currentVersion = options.currentVersion;
    this.quiesce = options.quiesce;
    this.metadataReader = options.metadataReader || this.readMetadata.bind(this);
    this.publicKey = options.publicKey || PUBLIC_KEY;
    this.supported = options.platform === 'win32' && options.isPackaged === true && options.configurationPresent === true && !options.portable;
    this.reason = this.supported ? '' : options.portable || options.isPackaged === true && options.configurationPresent !== true ? 'portable' : 'unavailable';
    this.value = { state: 'idle', supported: this.supported, reason: this.reason, version: null, progress: null, error: null, errorCode: null, checkedAt: null };
    this.updater.autoDownload = false;
    this.updater.autoInstallOnAppQuit = false;
    this.updater.autoRunAppAfterInstall = true;
    this.updater.allowPrerelease = false;
    this.updater.allowDowngrade = false;
    this.updater.disableDifferentialDownload = false;
    this.updater.disableWebInstaller = true;
    this.updater.logger = null;
    this.updater.on('download-progress', value => {
      if (this.value.state !== 'downloading') return;
      const progress = value && Number.isFinite(value.percent) ? Math.max(0, Math.min(100, Math.round(value.percent * 10) / 10)) : 0;
      this.assign({ progress });
    });
  }
  snapshot() { return { ...this.value }; }
  get installing() { return this.value.state === 'installing'; }
  assign(value) { this.value = { ...this.value, ...value }; this.emit('state', this.snapshot()); return this.snapshot(); }
  fail(error) { const safe = sanitizeUpdaterError(error); return this.assign({ state: 'error', progress: null, error: safe.message, errorCode: safe.code }); }
  start() {
    if (!this.supported || this.timer) return;
    void this.check();
    this.timer = setInterval(() => { void this.check(); }, CHECK_INTERVAL_MS);
    this.timer.unref?.();
  }
  dispose() { if (this.timer) clearInterval(this.timer); this.timer = null; }
  check() {
    if (!this.supported || this.installing) return Promise.resolve(this.snapshot());
    if (this.checkPromise) return this.checkPromise;
    if (this.downloadPromise) return this.downloadPromise.then(() => this.snapshot(), () => this.snapshot());
    this.checkPromise = this.performCheck().catch(error => this.fail(error)).finally(() => { this.checkPromise = null; });
    return this.checkPromise;
  }
  async performCheck() {
    this.assign({ state: 'checking', error: null, errorCode: null, progress: null });
    const result = await this.updater.checkForUpdates();
    this.value = { ...this.value, checkedAt: new Date().toISOString() };
    if (!result?.isUpdateAvailable) return this.assign({ state: 'idle', version: null, progress: null });
    const bound = await this.verifyAndBind();
    const available = this.assign({ state: 'available', version: bound.version, progress: 0, error: null, errorCode: null });
    this.downloadPromise = this.performDownload().catch(error => this.fail(error)).finally(() => { this.downloadPromise = null; });
    return available;
  }
  async verifyAndBind() {
    const result = this.updater.updateInfoAndProvider;
    if (!result?.provider || !result.info) throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.');
    const files = result.provider.resolveFiles(result.info);
    if (!Array.isArray(files) || files.length !== 1 || !(files[0].url instanceof URL) || files[0].url.protocol !== 'https:') throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.');
    const metadataURL = new URL(METADATA_NAME, files[0].url), signatureURL = new URL(METADATA_NAME + '.sig', files[0].url);
    const { metadata, signature } = await this.metadataReader(metadataURL, signatureURL, result.provider);
    const signed = verifyDetachedMetadata(metadata, signature, this.publicKey);
    const bound = bindUpdateInfo(result.info, signed, this.currentVersion);
    result.info = bound;
    return bound;
  }
  async readMetadata(metadataURL, signatureURL, provider) {
    if (!this.updater.httpExecutor) throw new UpdateError('UPDATE_UNAVAILABLE', 'Служба обновления недоступна.');
    const request = async url => {
      const value = await this.updater.httpExecutor.request(provider.createRequestOptions(url, { accept: '*/*' }));
      if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_METADATA_BYTES) throw new UpdateError('METADATA_INVALID', 'Метаданные обновления повреждены.');
      return value;
    };
    return { metadata: await request(metadataURL), signature: await request(signatureURL) };
  }
  async performDownload() {
    if (!this.updater.updateInfoAndProvider?.info || this.value.state !== 'available') throw new UpdateError('DOWNLOAD_REFUSED', 'Загрузка без подтверждённых метаданных запрещена.');
    this.assign({ state: 'downloading', progress: 0 });
    await this.updater.downloadUpdate();
    return this.assign({ state: 'downloaded', progress: 100, error: null, errorCode: null });
  }
  install(confirmed) {
    if (!this.supported || this.value.state !== 'downloaded' || confirmed !== true) return Promise.resolve(this.snapshot());
    if (this.installPromise) return this.installPromise;
    this.installPromise = this.performInstall().catch(error => this.fail(error)).finally(() => { this.installPromise = null; });
    return this.installPromise;
  }
  async performInstall() {
    this.assign({ state: 'installing', error: null, errorCode: null });
    if (typeof this.quiesce !== 'function' || await this.quiesce() !== true) throw new UpdateError('SHUTDOWN_PENDING', 'Дождитесь завершения операций Guard перед установкой обновления.');
    this.updater.quitAndInstall(false, true);
    return this.snapshot();
  }
}

module.exports = { WindowsUpdater, UpdateError, verifyDetachedMetadata, bindUpdateInfo, sanitizeUpdaterError, PUBLIC_KEY_SPKI_BASE64, CHECK_INTERVAL_MS };
