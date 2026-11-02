'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const crypto = require('node:crypto');
const yaml = require('js-yaml');
const { WindowsUpdater, verifyDetachedMetadata, sanitizeUpdaterError, PUBLIC_KEY_SPKI_BASE64 } = require('../src/updater.cjs');

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const sha512 = Buffer.alloc(64, 7).toString('base64');
const metadataFor = (version = '0.7.0') => ({ version, files: [{ url: `ClaudeProxyGuard-Windows-${version}-x64-Setup.exe`, sha512, size: 100000000, blockMapSize: 100000 }], path: `ClaudeProxyGuard-Windows-${version}-x64-Setup.exe`, sha512, releaseDate: '2026-11-02T00:00:00.000Z' });

function fixture(options = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const metadata = options.metadata || metadataFor(options.version);
  const metadataText = options.metadataText === undefined ? yaml.dump(metadata) : options.metadataText;
  let signedText = metadataText;
  const info = { ...metadata, files: metadata.files.map(file => ({ ...file })), ...(options.info || {}) };
  class FakeUpdater extends EventEmitter {
    constructor() { super(); this.downloads = 0; this.installs = 0; this.provider = { resolveFiles: value => value.files.map(file => ({ url: new URL(file.url, `https://github.com/JFT-git/gate-claude/releases/download/v${value.version}/`) })) }; }
    checkForUpdates() {
      this.checks = (this.checks || 0) + 1;
      if (options.checkError) return Promise.reject(options.checkError);
      if (options.checkPending) return options.checkPending.promise;
      this.updateInfoAndProvider = { info, provider: this.provider };
      return Promise.resolve({ isUpdateAvailable: options.available !== false, updateInfo: info });
    }
    downloadUpdate() {
      this.downloads++;
      if (options.downloadPending) return options.downloadPending.promise;
      this.emit('download-progress', { percent: 50 });
      return Promise.resolve(['C:\\fixture\\Setup.exe']);
    }
    quitAndInstall() { this.installs++; }
  }
  const autoUpdater = new FakeUpdater();
  const quiesce = options.quiesce || (async () => true);
  const updater = new WindowsUpdater({ autoUpdater, currentVersion: '0.6.16', platform: 'win32', isPackaged: true, configurationPresent: true,
    portable: options.portable, publicKey, quiesce, metadataReader: async () => ({ metadata: metadataText, signature: crypto.sign(null, Buffer.from(signedText), privateKey).toString('base64') }) });
  return { updater, autoUpdater, info, metadata, privateKey, publicKey, setMetadataText: value => { signedText = value; } };
}

test('signed stable metadata binds all installer fields and downloads in the background', async () => {
  const f = fixture(); const states = []; f.updater.on('state', value => states.push(value.state));
  const result = await f.updater.check();
  assert.equal(result.state, 'available');
  await f.updater.downloadPromise;
  assert.equal(f.updater.snapshot().state, 'downloaded'); assert.equal(f.updater.snapshot().progress, 100);
  assert.equal(f.autoUpdater.downloads, 1); assert.equal(f.autoUpdater.autoInstallOnAppQuit, false);
  assert.equal(f.autoUpdater.disableDifferentialDownload, false); assert.equal(f.autoUpdater.allowPrerelease, false); assert.equal(f.autoUpdater.allowDowngrade, false);
  assert.ok(Object.isFrozen(f.autoUpdater.updateInfoAndProvider.info)); assert.ok(Object.isFrozen(f.autoUpdater.updateInfoAndProvider.info.files[0]));
  assert.deepEqual(states, ['checking', 'available', 'downloading', 'downloading', 'downloaded']);
});

test('signature mismatch and signed corrupt metadata refuse download', async () => {
  const mismatch = fixture(); mismatch.setMetadataText(yaml.dump(metadataFor('9.9.9')));
  await mismatch.updater.check(); assert.equal(mismatch.updater.snapshot().errorCode, 'SIGNATURE_INVALID'); assert.equal(mismatch.autoUpdater.downloads, 0);
  const corrupt = fixture({ metadataText: 'files: [' }); await corrupt.updater.check();
  assert.equal(corrupt.updater.snapshot().errorCode, 'METADATA_INVALID'); assert.equal(corrupt.autoUpdater.downloads, 0);
  assert.throws(() => verifyDetachedMetadata('version: 0.7.0', 'not-a-signature'), /подпись/i);
});

test('downgrade and prerelease metadata are refused even if the release check returns them', async () => {
  for (const version of ['0.6.15', '0.7.0-beta.1']) {
    const f = fixture({ version }); await f.updater.check();
    assert.equal(f.updater.snapshot().errorCode, 'VERSION_REFUSED'); assert.equal(f.autoUpdater.downloads, 0);
  }
});

test('changed unsigned UpdateInfo cannot race the separately signed metadata', async () => {
  const f = fixture({ info: { files: [{ ...metadataFor().files[0], sha512: Buffer.alloc(64, 8).toString('base64') }] } });
  await f.updater.check(); assert.equal(f.updater.snapshot().errorCode, 'METADATA_CHANGED'); assert.equal(f.autoUpdater.downloads, 0);
});

test('offline and rate-limit errors are sanitized and do not escape into Guard', async () => {
  for (const [error, code] of [[Object.assign(Error('secret host token'), { code: 'ENOTFOUND' }), 'OFFLINE'], [Object.assign(Error('private URL'), { statusCode: 429 }), 'RATE_LIMIT']]) {
    const f = fixture({ checkError: error }); const state = await f.updater.check();
    assert.equal(state.state, 'error'); assert.equal(state.errorCode, code); assert.doesNotMatch(state.error, /secret|private/);
  }
  assert.equal(sanitizeUpdaterError(Error('raw')).code, 'UPDATE_FAILED');
});

test('portable ZIP refuses all updater actions and never accesses release metadata', async () => {
  const f = fixture({ portable: true });
  assert.equal(f.updater.snapshot().supported, false); assert.equal(f.updater.snapshot().reason, 'portable');
  assert.equal((await f.updater.check()).state, 'idle'); assert.equal((await f.updater.install(true)).state, 'idle');
  assert.equal(f.autoUpdater.checks || 0, 0); assert.equal(f.autoUpdater.downloads, 0); assert.equal(f.autoUpdater.installs, 0);
});

test('duplicate checks, downloads and installs share one underlying action', async () => {
  const checkPending = deferred(), downloadPending = deferred(), shutdown = deferred();
  const f = fixture({ checkPending, downloadPending, quiesce: () => shutdown.promise });
  const first = f.updater.check(), second = f.updater.check(); assert.equal(first, second); assert.equal(f.autoUpdater.checks, 1);
  f.autoUpdater.updateInfoAndProvider = { info: f.info, provider: f.autoUpdater.provider }; checkPending.resolve({ isUpdateAvailable: true, updateInfo: f.info });
  await first; assert.equal(f.autoUpdater.downloads, 1); const duplicateDownload = f.updater.check(); assert.equal(f.autoUpdater.checks, 1); assert.equal(f.autoUpdater.downloads, 1);
  downloadPending.resolve([]); await Promise.all([duplicateDownload, f.updater.downloadPromise]); assert.equal(f.updater.snapshot().state, 'downloaded');
  const installing = f.updater.install(true); await f.updater.install(true); assert.equal(f.updater.snapshot().state, 'installing'); assert.equal(f.autoUpdater.installs, 0);
  shutdown.resolve(true); await installing; assert.equal(f.autoUpdater.installs, 1);
});

test('install requires downloaded state, explicit confirmation and successful quiesce', async () => {
  let calls = 0; const f = fixture({ quiesce: async () => { calls++; return false; } });
  await f.updater.install(true); assert.equal(calls, 0); assert.equal(f.autoUpdater.installs, 0);
  await f.updater.check(); await f.updater.downloadPromise; await f.updater.install(false); assert.equal(calls, 0);
  await f.updater.install(true); assert.equal(calls, 1); assert.equal(f.autoUpdater.installs, 0); assert.equal(f.updater.snapshot().errorCode, 'SHUTDOWN_PENDING');
});

test('no newer stable release returns to idle without a download', async () => {
  const f = fixture({ available: false }); const state = await f.updater.check();
  assert.equal(state.state, 'idle'); assert.ok(state.checkedAt); assert.equal(f.autoUpdater.downloads, 0);
});

test('the approved Ed25519 SPKI key remains pinned', () => {
  assert.equal(PUBLIC_KEY_SPKI_BASE64, 'MCowBQYDK2VwAyEAdgEyOH5iBelfAXj9Zmkjl1E80AlijGQEs6ffKmmKJow=');
});
