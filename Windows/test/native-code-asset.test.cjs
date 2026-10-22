'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const vm = require('node:vm');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const { once } = require('node:events');
const { NetworkRelay } = require('../src/relay.cjs');
const production = require('../src/native-code-asset.cjs');
const implementation = fs.readFileSync(path.join(__dirname, '../src/native-code-asset.cjs'), 'utf8');
const fixturePath = path.join(__dirname, 'helpers/native-code-asset-tls');
const cert = fs.readFileSync(path.join(fixturePath, 'cert.txt')), key = fs.readFileSync(path.join(fixturePath, 'key.txt'));
const body = Buffer.from('Synthetic pinned native Code asset bytes.\0\xff', 'latin1');
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const denied = { code: 'ERR_GUARD_CODE_ASSET' };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function load({ trust = true, filesystem = fs, cryptography = crypto } = {}) {
  // Only this VM substitutes the body size/digest and trusts our synthetic CA.
  // The host, URL path, TLS verification and production API are unchanged.
  const module = { exports: {} }, tlsCalls = [];
  const localRequire = name => {
    if (name === './code-preparation.cjs') return { SOURCE_POLICY: { compressedSize: body.length, compressedSHA256: sha256(body) } };
    if (name === './raw-fs.cjs') return filesystem;
    if (name === 'node:crypto') return cryptography;
    if (name === 'node:tls') return { connect: options => { tlsCalls.push(options); return tls.connect({ ...options, ...(trust ? { ca: cert } : {}) }); } };
    if (name.startsWith('./')) return require('../src/' + name.slice(2));
    return require(name);
  };
  vm.runInNewContext(implementation, { require: localRequire, module, exports: module.exports, Buffer, setTimeout, clearTimeout, setInterval, clearInterval }, { filename: 'native-code-asset.cjs' });
  return { api: module.exports, tlsCalls };
}
async function directory(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gate-native-asset-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true })); return root;
}
async function fixture(t, handler) {
  const sockets = new Set(), requests = [], connects = [], tlsNames = [];
  function track(socket) { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); }
  const origin = https.createServer({ key, cert }, (request, response) => { requests.push({ url: request.url, headers: request.headers }); handler(request, response); });
  origin.on('connection', track); origin.on('secureConnection', socket => tlsNames.push(socket.servername)); origin.listen(0, '127.0.0.1'); await once(origin, 'listening');
  const proxy = net.createServer(client => {
    track(client); let pending = Buffer.alloc(0);
    const consume = chunk => {
      pending = Buffer.concat([pending, chunk]); const end = pending.indexOf('\r\n\r\n'); if (end < 0) return;
      client.off('data', consume); connects.push(pending.subarray(0, end + 4).toString());
      assert.equal(pending.length, end + 4); assert.match(connects.at(-1), /^CONNECT downloads\.claude\.ai:443 HTTP\/1\.1\r\n/);
      const upstream = net.connect(origin.address().port, '127.0.0.1'); track(upstream);
      upstream.once('connect', () => { client.write('HTTP/1.1 200 Connection Established\r\n\r\n'); client.pipe(upstream); upstream.pipe(client); });
      client.once('close', () => upstream.destroy()); upstream.once('close', () => client.destroy());
    }; client.on('data', consume);
  }); proxy.listen(0, '127.0.0.1'); await once(proxy, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await Promise.all([new Promise(resolve => proxy.close(resolve)), new Promise(resolve => origin.close(resolve))]); });
  return { port: proxy.address().port, requests, connects, tlsNames, sockets, closeTraffic() { for (const socket of sockets) socket.destroy(); } };
}
function sendBody(_request, response) { response.writeHead(200, { 'Content-Length': String(body.length) }); response.end(body); }
async function waitFor(predicate) { const end = Date.now() + 2000; while (!predicate()) { if (Date.now() > end) throw Error('Fixture did not reach its expected phase.'); await delay(5); } }
function contents(root) { const assets = path.join(root, 'CodeAssets'); return fs.existsSync(assets) ? fs.readdirSync(assets) : []; }

test('production source policy pins one official HTTPS release and exposes no URL/CA override', async t => {
  assert.equal(production.ASSET.hostname, 'downloads.claude.ai'); assert.equal(production.ASSET.pathname, '/claude-code-releases/2.1.304/win32-x64/claude.exe.zst'); assert.equal(production.ASSET.bytes, 104965652); assert.equal(production.ASSET.sha256, 'aed62990b91e94efb35482fd7068cc616c6c2414084c6aa32148ca2a359e4e81'); assert.ok(Object.isFrozen(production.ASSET));
  const root = await directory(t); await assert.rejects(production.ensureNativeCodeAsset(root, 1234, { active: () => true, url: 'https://other.invalid' }), denied); assert.deepEqual(fs.readdirSync(root), []);
});
test('TLS download uses only ordinary relay CONNECT, fixed SNI/path and identity bytes, then revalidates its private cache', async t => {
  const root = await directory(t), f = await fixture(t, sendBody), h = load(), result = await h.api.ensureNativeCodeAsset(root, f.port, { active: () => true });
  assert.equal(result.path, path.join(root, 'CodeAssets', sha256(body), 'win32-x64.zst')); assert.ok(fs.readFileSync(result.path).equals(body)); assert.equal(fs.statSync(result.path).nlink, 1);
  assert.equal(f.connects.length, 1); assert.ok(!/authorization|cookie/i.test(f.connects[0])); assert.equal(f.requests[0].url, production.ASSET.pathname); assert.equal(f.requests[0].headers['accept-encoding'], 'identity'); assert.equal(f.requests[0].headers.authorization, undefined); assert.deepEqual(f.tlsNames, ['downloads.claude.ai']);
  assert.equal(h.tlsCalls[0].rejectUnauthorized, true); assert.equal(h.tlsCalls[0].minVersion, 'TLSv1.2'); assert.ok(h.tlsCalls[0].socket); assert.equal(h.tlsCalls[0].host, undefined);
  const reused = await h.api.ensureNativeCodeAsset(root, f.port, { active: () => true }); assert.equal(reused.path, result.path); assert.equal(f.connects.length, 1); assert.deepEqual(contents(root), [sha256(body)]);
  fs.writeFileSync(result.path, Buffer.alloc(body.length)); await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, { active: () => true }), denied); assert.equal(f.connects.length, 1); assert.ok(fs.readFileSync(result.path).equals(Buffer.alloc(body.length)));
});
test('normal certificate verification rejects an untrusted origin and never falls back to direct TLS', async t => {
  const root = await directory(t), f = await fixture(t, sendBody), h = load({ trust: false }); await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, { active: () => true }), denied);
  assert.equal(f.connects.length, 1); assert.equal(f.requests.length, 0); assert.equal(h.tlsCalls.length, 1); assert.deepEqual(contents(root), [sha256(body)]); assert.deepEqual(fs.readdirSync(path.join(root, 'CodeAssets', sha256(body))), []);
});
for (const mode of ['redirect', 'length', 'encoding', 'checksum', 'truncated', 'chunked', 'overrun']) test('asset rejects ' + mode + ' responses without publishing or retaining a partial body', async t => {
  const root = await directory(t), f = await fixture(t, (_request, response) => {
    if (mode === 'redirect') { response.writeHead(302, { Location: 'https://other.invalid/private', 'Content-Length': '0' }); response.end(); return; }
    if (mode === 'chunked') { response.writeHead(200, { 'Transfer-Encoding': 'chunked' }); response.end(body); return; }
    response.writeHead(200, { 'Content-Length': String(body.length + (mode === 'length' ? 1 : 0)), ...(mode === 'encoding' ? { 'Content-Encoding': 'gzip' } : {}) });
    if (mode === 'truncated') { response.write(body.subarray(0, 4)); setImmediate(() => response.destroy()); } else response.end(mode === 'checksum' ? Buffer.alloc(body.length) : mode === 'overrun' ? Buffer.concat([body, Buffer.from('unexpected bytes')]) : body);
  }), h = load();
  await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, { active: () => true }), denied); assert.equal(f.connects.length, 1); assert.deepEqual(contents(root), [sha256(body)]); assert.deepEqual(fs.readdirSync(path.join(root, 'CodeAssets', sha256(body))), []);
});
for (const mode of ['signal', 'inactive', 'relay-close']) test(mode + ' cancels a held download and removes its owned staging file', async t => {
  const root = await directory(t), f = await fixture(t, (_request, response) => { response.writeHead(200, { 'Content-Length': String(body.length) }); response.write(body.subarray(0, 3)); }), h = load(), controller = new AbortController(); let active = true;
  const pending = h.api.ensureNativeCodeAsset(root, f.port, { active: () => active, signal: controller.signal }); const rejected = assert.rejects(pending, denied); await waitFor(() => f.requests.length === 1);
  if (mode === 'signal') controller.abort(); else if (mode === 'inactive') active = false; else f.closeTraffic();
  await rejected; assert.deepEqual(contents(root), [sha256(body)]); assert.deepEqual(fs.readdirSync(path.join(root, 'CodeAssets', sha256(body))), []);
});
test('locked or paused actual Guard relay denies asset traffic without a control exception', async t => {
  const root = await directory(t), relay = new NetworkRelay(), h = load(); await relay.start(); relay.pinIPFamily(4); t.after(() => relay.close());
  for (const paused of [false, true]) { if (paused) { relay.unlock(); relay.pause(); } await assert.rejects(h.api.ensureNativeCodeAsset(root, relay.port, { active: () => true }), denied); }
  assert.equal(h.tlsCalls.length, 0); assert.equal(relay.controlSockets.size, 0);
});
test('inactive/pre-aborted starts and invalid ports create no cache or tunnel', async t => {
  const root = await directory(t), f = await fixture(t, sendBody), h = load(), controller = new AbortController(); controller.abort();
  for (const options of [{ active: () => false }, { active: () => true, signal: controller.signal }]) await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, options), denied);
  for (const port of [0, 65536, '1234', 1.5]) await assert.rejects(h.api.ensureNativeCodeAsset(root, port, { active: () => true }), denied);
  assert.deepEqual(fs.readdirSync(root), []); assert.equal(f.connects.length, 0);
});
test('cache hardlinks and substituted parent directories are refused without replacement', async t => {
  const root = await directory(t), f = await fixture(t, sendBody), h = load(), result = await h.api.ensureNativeCodeAsset(root, f.port, { active: () => true });
  const extra = path.join(root, 'hardlink'); fs.linkSync(result.path, extra); await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, { active: () => true }), denied); fs.unlinkSync(extra);
  fs.renameSync(path.join(root, 'CodeAssets'), path.join(root, 'SavedAssets')); fs.symlinkSync(path.join(root, 'SavedAssets'), path.join(root, 'CodeAssets'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, { active: () => true }), denied); assert.equal(f.connects.length, 1); fs.unlinkSync(path.join(root, 'CodeAssets'));
});
test('a pre-existing staging name is preserved and cannot be removed on a failed open', async t => {
  const root = await directory(t), assets = path.join(root, 'CodeAssets'), nonce = Buffer.alloc(16, 7), candidate = path.join(assets, 'Preparing-' + nonce.toString('hex') + '.zst'); fs.mkdirSync(assets); fs.writeFileSync(candidate, 'other-owned-operation');
  const f = await fixture(t, sendBody), h = load({ cryptography: { ...crypto, randomBytes: () => nonce } });
  await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, { active: () => true }), denied); assert.equal(fs.readFileSync(candidate, 'utf8'), 'other-owned-operation'); assert.equal(f.connects.length, 0);
});
test('cancellation after verified transfer still prevents publication', async t => {
  const root = await directory(t), f = await fixture(t, sendBody); let active = true;
  const h = load({ filesystem: { promises: { ...fs.promises, open: async (...args) => {
    const handle = await fs.promises.open(...args); if (args[1] === 'wx') { const sync = handle.sync.bind(handle); handle.sync = async () => { await sync(); active = false; }; } return handle;
  } } } });
  await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, { active: () => active }), denied); assert.deepEqual(contents(root), [sha256(body)]); assert.deepEqual(fs.readdirSync(path.join(root, 'CodeAssets', sha256(body))), []);
});
test('atomic publication never replaces a concurrent cache leaf', async t => {
  const root = await directory(t), f = await fixture(t, sendBody), h = load({ filesystem: { promises: { ...fs.promises, link: async (source, destination) => { await fs.promises.writeFile(destination, 'concurrent-owner', { flag: 'wx' }); return fs.promises.link(source, destination); } } } });
  await assert.rejects(h.api.ensureNativeCodeAsset(root, f.port, { active: () => true }), denied); assert.equal(fs.readFileSync(path.join(root, 'CodeAssets', sha256(body), 'win32-x64.zst'), 'utf8'), 'concurrent-owner'); assert.deepEqual(contents(root), [sha256(body)]);
});
