'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { readRouteFingerprint, RouteReadError } = require('../src/route-reader.cjs');

const secret = 'PRIVATE subprocess body C:\\private\\helper.exe';
const helper = 'C:\\owned\\resources\\GuardHost.exe';
function rejected(code) {
  return error => {
    assert.ok(error instanceof RouteReadError);
    assert.equal(error.code, code);
    assert.equal(error.message, 'Не удалось прочитать таблицу маршрутов Windows. Трафик остаётся закрытым.');
    assert.deepEqual(Object.keys(error), ['code']);
    assert.equal(JSON.stringify(error).includes(secret), false);
    return true;
  };
}

test('route reader invokes only the fixed native query with the existing deadline and output cap', async () => {
  const routes = ['7|192.0.2.1|42|0.0.0.0/0', '9|fe80::1|10|::/0'];
  let calls = 0;
  const result = await readRouteFingerprint(helper, { execute: async (file, args, options) => {
    calls++;
    assert.equal(file, helper); assert.deepEqual(args, ['--route-fingerprint']);
    assert.deepEqual(options, { windowsHide: true, timeout: 4000, maxBuffer: 65536, encoding: 'utf8' });
    return { stdout: '\r\n' + JSON.stringify(routes, null, 2) + '\r\n', stderr: secret };
  } });
  assert.equal(result, JSON.stringify(routes)); assert.equal(calls, 1);
  assert.equal(await readRouteFingerprint(helper, { execute: async () => ({ stdout: '[]' }) }), '[]');
});

for (const [name, metadata, expected] of [
  ['deadline termination', { killed: true, signal: 'SIGTERM', code: null }, 'TIMEOUT'],
  ['timeout status', { code: 'ETIMEDOUT' }, 'TIMEOUT'],
  ['missing helper', { code: 'ENOENT' }, 'ENOENT'],
  ['access denied', { code: 'EACCES' }, 'EACCES'],
  ['operation denied', { code: 'EPERM' }, 'EACCES'],
  ['unsupported native query', { code: 64 }, 'EXIT_NONZERO'],
  ['native API failure', { code: 1 }, 'EXIT_NONZERO'],
  ['unknown native failure', { code: 'UNTRUSTED_' + secret }, 'EXIT_NONZERO'],
  ['buffer overflow despite a killed child', { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', killed: true }, 'INVALID_SNAPSHOT']
]) {
  test('route reader classifies ' + name + ' without disclosing subprocess details', async () => {
    const failure = Object.assign(Error(secret), metadata, { stdout: secret, stderr: secret, path: helper });
    await assert.rejects(readRouteFingerprint(helper, { execute: async () => { throw failure; } }), rejected(expected));
  });
}

test('malformed, non-array, invalid-entry and oversized native snapshots fail closed', async () => {
  for (const stdout of ['', secret, '{}', 'null', '[1]', '[null]', JSON.stringify(['x'.repeat(257)]),
    ' '.repeat(65537), JSON.stringify(Array(300).fill('я'.repeat(128))), Buffer.from('[]')]) {
    await assert.rejects(readRouteFingerprint(helper, { execute: async () => ({ stdout }) }), rejected('INVALID_SNAPSHOT'));
  }
  await assert.rejects(readRouteFingerprint(helper, { execute: async () => undefined }), rejected('INVALID_SNAPSHOT'));
});

function controllerRoute(read) {
  const filename = path.resolve(__dirname, '../src/controller.cjs'), localRequire = createRequire(filename);
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
    module, process: { platform: 'win32' },
    require: name => name === './route-reader.cjs' ? { readRouteFingerprint: read, RouteReadError } : localRequire(name)
  }, { filename });
  return module.exports.GuardController.prototype.routeFingerprint;
}

test('controller logs only changed safe categories and allows a new occurrence after recovery', async () => {
  const logs = [], target = { resources: 'owned-resources', epoch: 7, log: (...args) => logs.push(args) };
  let code = 'TIMEOUT';
  const route = controllerRoute(async file => {
    assert.equal(file, path.join(target.resources, 'GuardHost.exe'));
    if (code) throw new RouteReadError(code);
    return '[]';
  });
  await assert.rejects(route.call(target), rejected('TIMEOUT'));
  await assert.rejects(route.call(target), rejected('TIMEOUT'));
  code = 'ENOENT'; await assert.rejects(route.call(target), rejected('ENOENT'));
  code = null; assert.equal(await route.call(target), '[]'); assert.equal(target.routeErrorCode, null);
  code = 'ENOENT'; await assert.rejects(route.call(target), rejected('ENOENT'));
  assert.deepEqual(logs, [
    ['Проверка маршрутов Windows: TIMEOUT.', 'warning'],
    ['Проверка маршрутов Windows: ENOENT.', 'warning'],
    ['Проверка маршрутов Windows: ENOENT.', 'warning']
  ]);
});

test('a cancelled route query cannot log into or reset diagnostics for a later epoch', async () => {
  const logs = [], target = { resources: 'owned-resources', epoch: 1, routeErrorCode: 'ENOENT', log: value => logs.push(value) };
  let finish;
  const route = controllerRoute(() => new Promise((resolve, reject) => { finish = { resolve, reject }; }));
  const failed = route.call(target); target.epoch++;
  finish.reject(new RouteReadError('TIMEOUT')); await assert.rejects(failed, rejected('TIMEOUT'));
  const successful = route.call(target); target.epoch++;
  finish.resolve('[]'); assert.equal(await successful, '[]');
  assert.equal(target.routeErrorCode, 'ENOENT'); assert.deepEqual(logs, []);
});

async function smoke(routeFailure) {
  let calls = 0, receipt, complete;
  const finished = new Promise(resolve => { complete = resolve; });
  const app = {
    isPackaged: true, setName() {}, setAppUserModelId() {}, requestSingleInstanceLock: () => true,
    getPath: () => 'owned-smoke-data', getVersion: () => '0.6.0', whenReady: () => Promise.resolve(),
    on() {}, exit: code => complete(code)
  };
  class Controller {
    on() {}
    async routeFingerprint() {
      calls++;
      if (routeFailure) { this.routeErrorCode = routeFailure; throw new RouteReadError(routeFailure); }
      return '[]';
    }
  }
  class Window {
    constructor() {
      this.webContents = {
        on() {}, setWindowOpenHandler() {},
        session: { setPermissionRequestHandler() {}, setPermissionCheckHandler() {} },
        executeJavaScript: async () => ({ ready: 'true', api: 'function', discoveryDone: 'true', connectionModes: ['network', 'socks5'] })
      };
    }
    async loadFile() {}
  }
  const mocks = {
    electron: { app, BrowserWindow: Window, ipcMain: { handle() {} }, dialog: { showErrorBox() {} }, powerMonitor: { on() {} } },
    'node:fs': { writeFileSync: (_file, value) => { receipt = JSON.parse(value); } },
    './controller.cjs': { GuardController: Controller }, './discovery.cjs': {}, './runtime.cjs': {}, './policy.cjs': {},
    './sanitize.cjs': { diagnostic: value => value }, './deep-link.cjs': { takeDeepLinkFromArgv: () => ({ hadLink: false }) },
    './protocol-registration.cjs': { ensureGuardProtocolRegistration: async () => ({ skipped: true }) }
  };
  const filename = path.resolve(__dirname, '../src/main.cjs'), localRequire = createRequire(filename);
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
    __dirname: path.dirname(filename), require: name => mocks[name] || localRequire(name),
    process: { platform: 'win32', resourcesPath: 'owned-package-resources', argv: ['app', '--smoke-test'], env: { GATE_SMOKE_OUT: 'owned-receipt' }, on() {} }
  }, { filename });
  return { code: await finished, calls, receipt };
}

test('Windows packaged smoke requires a successful native route probe', { timeout: 1000 }, async () => {
  const result = await smoke(null);
  assert.equal(result.calls, 1); assert.equal(result.code, 0);
  assert.equal(result.receipt.nativeRoutesVerified, true); assert.equal(result.receipt.result, 'PASS');
});

test('Windows packaged smoke fails even with a ready UI when its native route helper fails', { timeout: 1000 }, async () => {
  const result = await smoke('TIMEOUT');
  assert.equal(result.calls, 1); assert.equal(result.code, 1);
  assert.equal(result.receipt.nativeRoutesVerified, false); assert.equal(result.receipt.result, 'FAIL');
  assert.equal(result.receipt.routeErrorCode, 'TIMEOUT');
});
