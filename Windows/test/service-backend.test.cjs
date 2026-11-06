'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { NativeServiceBackend, ServiceBackendError, parseStatus, parseReceipt, parseLaunchReceipt } = require('../src/service-backend.cjs');

const validRoot = 'C:\\Users\\fixture\\AppData\\Roaming\\Claude Proxy Guard\\Guard\\Cache\\Runtime-' + 'a'.repeat(24);
const launchRequest = () => ({ root: validRoot, pipeName: 'gate-network-fence-' + 'b'.repeat(32), token: 'c'.repeat(64) });
const status = (state, routing = state === 'running') => JSON.stringify({ schema: 1, available: true, state, code: null,
  version: state === 'not_installed' ? null : '1.0.0', actions: [], sessionRoutingSupported: routing });
const receipt = (operation = 'install', elevated = true) => JSON.stringify({ version: 1, operation, code: 0, elevated, state: operation === 'uninstall' ? 'not_installed' : 'running' });
function fixture(initial = 'running') {
  let state = initial, releaseInstall;
  const calls = [];
  const backend = new NativeServiceBackend({ helperPath: process.execPath, ownerWindow: () => null, exec: async (exe, args, options) => {
    calls.push({ exe, args: args.slice(), options });
    if (args[0] === '--status') return { stdout: status(state), stderr: '' };
    if (args[0] === '--request-install') {
      if (releaseInstall) await releaseInstall;
      state = 'running'; return { stdout: receipt('install'), stderr: '' };
    }
    if (args[0] === '--request-uninstall') { state = 'not_installed'; return { stdout: receipt('uninstall'), stderr: '' }; }
    if (args[0] === '--start') { state = 'running'; return { stdout: '', stderr: '' }; }
    if (args[0] === '--stop') { state = 'stopped'; return { stdout: '', stderr: '' }; }
    if (args[0] === '--launch') return { stdout: '{"version":1,"launched":true,"code":0}', stderr: '' };
    throw Error('unexpected operation');
  } });
  return { backend, calls, holdInstall() { releaseInstall = new Promise(resolve => { this.release = resolve; }); } };
}

test('native status is authoritative and rejects incompatible routing claims and extra fields', () => {
  assert.equal(parseStatus(status('running')).sessionRoutingSupported, true);
  assert.equal(parseStatus(status('not_installed')).sessionRoutingSupported, false);
  for (const value of [
    { ...JSON.parse(status('stopped')), sessionRoutingSupported: true },
    { ...JSON.parse(status('running')), version: '0.0.0' },
    { ...JSON.parse(status('running')), extra: 'private' },
    { ...JSON.parse(status('running')), state: 'imaginary' }
  ]) assert.throws(() => parseStatus(JSON.stringify(value)), ServiceBackendError);
});

test('operation and launch receipts are exact, bounded and operation-specific', () => {
  assert.equal(parseReceipt(receipt(), 'install').code, 0);
  assert.throws(() => parseReceipt(receipt('uninstall'), 'install'), ServiceBackendError);
  assert.throws(() => parseReceipt('{"version":1,"operation":"install","code":2,"elevated":true,"state":"error"}', 'install'), ServiceBackendError);
  assert.throws(() => parseLaunchReceipt('{"version":1,"launched":false,"code":5}'), ServiceBackendError);
  assert.throws(() => parseLaunchReceipt('{"version":1,"launched":true,"code":0,"args":"arbitrary"}'), ServiceBackendError);
});

test('two concurrent launches share one installation and never repeat UAC when current', async () => {
  const h = fixture('not_installed'); h.holdInstall();
  const first = h.backend.launchFence(launchRequest()), second = h.backend.launchFence(launchRequest());
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(h.calls.filter(call => call.args[0] === '--request-install').length, 1);
  assert.equal(h.calls.filter(call => call.args[0] === '--launch').length, 0);
  h.release(); await Promise.all([first, second]);
  assert.equal(h.calls.filter(call => call.args[0] === '--request-install').length, 1);
  assert.equal(h.calls.filter(call => call.args[0] === '--launch').length, 2);
  assert.equal(h.calls.find(call => call.args[0] === '--request-install').options.timeout, 0);
});

test('a current running service launches without install or elevation', async () => {
  const h = fixture(); await h.backend.launchFence(launchRequest());
  assert.deepEqual(h.calls.map(call => call.args[0]), ['--status', '--launch']);
  const call = h.calls[1];
  assert.deepEqual(call.args.slice(0, 2), ['--launch', '--root']);
  assert.equal(Buffer.from(call.args[2], 'base64').toString('utf8'), validRoot);
  assert.deepEqual(call.args.slice(3), ['--pipe', launchRequest().pipeName, '--token', launchRequest().token]);
  assert.equal(call.options.shell, false); assert.equal(call.options.windowsHide, true);
});

test('stopped service is started without an elevation request and read back', async () => {
  const h = fixture('stopped'); const result = await h.backend.ensureReady();
  assert.equal(result.state, 'running');
  assert.deepEqual(h.calls.map(call => call.args[0]), ['--status', '--start', '--status']);
});

test('update and uninstall use only fixed native requester operations', async () => {
  const h = fixture('update_required'); await h.backend.update(); await h.backend.uninstall();
  const operations = h.calls.filter(call => call.args[0] !== '--status');
  assert.deepEqual(operations.map(call => call.args[0]), ['--request-install', '--request-uninstall']);
  for (const call of operations) assert.deepEqual(call.args.slice(1), ['--owner', '0']);
});

test('invalid launch requests fail before status, installation or a privileged pipe request', async () => {
  const h = fixture('not_installed');
  for (const patch of [{ root: '\\\\server\\share\\Runtime-' + 'a'.repeat(24) }, { root: validRoot + '\n' }, { pipeName: 'other' }, { token: 'bad' }]) {
    await assert.rejects(h.backend.launchFence({ ...launchRequest(), ...patch }), error => error.code === 'SERVICE_LAUNCH_INVALID');
  }
  assert.equal(h.calls.length, 0);
});

test('read-back failures and native diagnostics do not authorize launch or leak secrets', async () => {
  const backend = new NativeServiceBackend({ helperPath: process.execPath, exec: async (_exe, args) => {
    if (args[0] === '--status') return { stdout: status('running') };
    const error = Error('private account and token'); error.stdout = '';
    throw error;
  } });
  await assert.rejects(backend.launchFence(launchRequest()), error => error instanceof ServiceBackendError && !error.message.includes('private'));
});

test('NetworkFence pin in native service matches the cross-build pin exactly', () => {
  const pins = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../packaging/windows/cross-build-pins.json'), 'utf8'));
  const native = fs.readFileSync(path.resolve(__dirname, '../native/GuardService.cs'), 'utf8');
  assert.ok(native.includes('NetworkFenceSHA256 = "' + pins.sha256['NetworkFence.exe'] + '"'));
  assert.match(pins.sha256['GuardService.exe'], /^[a-f0-9]{64}$/);
  assert.ok(native.includes('FileName = GuardService.ProtectedFence'));
  assert.ok(native.includes('if (stopping || activeBrokers >= 16'));
  assert.ok(native.includes('if (activeBrokers != 0)'));
  assert.ok(native.includes('class ManagementLock'));
  assert.ok(native.includes('Global\\ClaudeProxyGuard.Management.v1'));
  assert.ok(native.includes('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100001;;;AU)'));
  assert.ok(!native.includes('O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100001;;;AU)'));
  assert.ok(native.includes('RequireNoProtectedBroker();'));
  assert.ok(native.includes('FileSystemRights.ReadAndExecute'));
  assert.ok(native.includes('D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;AU)'));
  assert.ok(native.includes('pipe.RunAsClient'));
  assert.ok(native.includes('ProfileList\\'));
  assert.ok(!native.includes('FileName = root') && !native.includes('FileName = args'));
});
