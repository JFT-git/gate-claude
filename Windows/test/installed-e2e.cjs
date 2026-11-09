'use strict';
// Run explicitly on Windows against an official local Claude, using a fresh profile.
// Local TLS fixtures and certificate trust below exist only in this test.
// The production external IP checker and Windows network fence are not substituted.
// Per-destination route results and system-proxy selection are synthetic test-only seams.
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const https = require('node:https');
const tls = require('node:tls');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { SocketReader } = require('../src/relay.cjs');
const { prepareRuntime, powershell } = require('../src/runtime.cjs');

const argv = process.argv.slice(2), argument = name => argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined;
let source = argument('--claude'); const work = path.resolve(argument('--work'));
const connectionMode = argv.includes('--network') ? 'network' : 'socks5';
const certPath = path.resolve(argument('--cert')), keyPath = path.resolve(argument('--key'));
const hostPath = path.resolve(argument('--host'));
const fencePath = argument('--fence') ? path.resolve(argument('--fence')) : null;
const servicePath = argument('--service') ? path.resolve(argument('--service')) : null;
const codeEnabled = argv.includes('--code');
const codeHostPath = argument('--code-host') ? path.resolve(argument('--code-host')) : null;
const codeToolsDir = argument('--code-tools-dir') ? path.resolve(argument('--code-tools-dir')) : null;
const ipHosts = ['ipwho.is', 'ipinfo.io', 'ipapi.co', 'api64.ipify.org', 'api.ipify.org', 'api6.ipify.org'];
const persistenceMarker = crypto.randomBytes(24).toString('hex');
const persistenceCookie = '__Host-guard_fixture_persist';
const fixtureDeepLink = 'claude://claude.ai/magic-link#guard-fixture-id:synthetic-token';
let observed = '203.0.113.7', failNextCurrentIP = false, holdCurrentIP = false;
const heldIPResponses = [], activeStreams = new Set();
const childProcess = require('node:child_process');
const nativeSpawn = childProcess.spawn;
childProcess.spawn = (file, args, options) => {
  const child = nativeSpawn(file, args, options);
  if (args.includes('--prepare-state')) {
    let stdout = '', stderr = '';
    const end = child.stdin.end.bind(child.stdin);
    child.stdin.end = bytes => {
      try { observations.preparePacket = JSON.parse(bytes.subarray(4).toString('utf8')); } catch { observations.preparePacket = { invalid: true }; }
      return end(bytes);
    };
    child.stdout.on('data', chunk => { stdout = (stdout + chunk).slice(-4096); });
    child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4096); });
    child.once('close', code => { observations.prepareState = { code, stdout, stderr }; });
  }
  return child;
};
const { GuardController } = require('../src/controller.cjs');
const { NativeServiceBackend } = require('../src/service-backend.cjs');
const fixtureNetworkProxy = Object.freeze({ kind: 'direct', host: '', port: 0,
  fingerprint: crypto.createHash('sha256').update('gate-claude/installed-e2e/direct-proxy/v1').digest('hex') });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(check, label, timeout = 30000) {
  const started = Date.now();
  while (Date.now() - started < timeout) { const result = await check(); if (result) return result; await sleep(80); }
  throw Error('Timeout: ' + label);
}
async function fixtureCookieDisk(profile) {
  const { DatabaseSync } = require('node:sqlite'), files = [], rows = [];
  async function walk(directory) {
    for (const item of await fs.readdir(directory, { withFileTypes: true })) {
      const file = path.join(directory, item.name);
      if (item.isDirectory()) await walk(file); else if (item.isFile() && item.name === 'Cookies') files.push(file);
    }
  }
  await walk(profile);
  for (const file of files) {
    // Chromium holds an exclusive SQLite lock. Inspect only a temporary byte
    // snapshot of this test's own DB; never write to the live browser store.
    const snapshot=path.join(work,'CookieInspection-'+crypto.randomUUID());await fs.mkdir(snapshot);
    try {
      const copy=path.join(snapshot,'Cookies');await fs.copyFile(file,copy);
      for(const suffix of ['-wal','-journal'])try{await fs.copyFile(file+suffix,copy+suffix)}catch(error){if(error.code!=='ENOENT')throw error}
      const db = new DatabaseSync(copy);
      try { rows.push(...db.prepare('SELECT host_key AS host,name,is_secure AS secure,is_httponly AS httpOnly,is_persistent AS persistent,CAST(expires_utc AS TEXT) AS expiry,length(encrypted_value) AS encryptedLength,substr(hex(encrypted_value),1,6) AS scheme,length(value) AS plaintextLength FROM cookies WHERE name=?').all(persistenceCookie)); }
      finally { db.close(); }
    } finally { await fs.rm(snapshot,{recursive:true,force:true}); }
  }
  return { databaseCount: files.length, rows };
}
const sockets = new Set(), observations = {}, proof = { platform: process.platform, test: 'official Windows Claude, separate profile, local TLS fixture', observedIPSource: 'controlled test-only provider; no physical WAN change' };
function fixtureNetworkChecks(controller) {
  controller.networkProxyConfiguration = async () => fixtureNetworkProxy;
  if (connectionMode === 'network') controller.usesLocalPin = () => false;
  controller.requestDestinationIP = async (epoch, hostname, port, token) => {
    assert.equal(epoch, controller.epoch, 'Destination fixture belongs to the active controller epoch');
    assert.ok(['claude.ai', 'api.anthropic.com'].includes(hostname), 'Only the two production destination checks are substituted');
    assert.equal(port, controller.relay.port); assert.equal(token, controller.relay.checkToken);
    (observations.destinationChecks ||= {})[hostname] = (observations.destinationChecks?.[hostname] || 0) + 1;
    // Read the same mutable test provider as production initialIP/currentIP. The
    // synthetic address switch therefore exercises every destination policy too,
    // without ever contacting a real Claude account or public trace endpoint.
    return { ip: observed, country_code: 'NL', hostname };
  };
  return controller;
}
function newGuardController(root, resources) {
  const controller = new GuardController(root, resources);
  if (servicePath) {
    const backend = new NativeServiceBackend({ helperPath: servicePath, ownerWindow: () => null });
    controller.nativeServiceBackend = backend;
    controller.fenceServiceLaunch = request => {
      observations.serviceLaunches = (observations.serviceLaunches || 0) + 1;
      return backend.launchFence(request);
    };
  }
  return fixtureNetworkChecks(controller);
}
function instrumentAsset() {
  if (observations.assetInstrumented) return;
  observations.assetInstrumented = true;
  const request = https.request;
  https.request = (...args) => {
    const options = args[0] || {};
    const result = request(...args);
    if (options.hostname === 'downloads.claude.ai') {
      result.on('error', error => (observations.assetErrors ||= []).push({ phase: 'request', code: error.code || 'ERROR' }));
      result.on('response', response => {
        (observations.assetResponses ||= []).push({ status: response.statusCode, length: response.headers['content-length'], encoding: response.headers['content-encoding'], transfer: response.headers['transfer-encoding'] });
        const digest = crypto.createHash('sha256'); let bytes = 0;
        response.on('data', chunk => { bytes += chunk.length; digest.update(chunk); });
        response.on('end', () => (observations.assetBodies ||= []).push({ event: 'end', bytes, sha256: digest.digest('hex') }));
        response.on('aborted', () => (observations.assetBodies ||= []).push({ event: 'aborted', bytes }));
        response.on('close', () => (observations.assetBodies ||= []).push({ event: 'close', bytes }));
      });
    }
    return result;
  };
  const connect = tls.connect;
  tls.connect = (...args) => {
    const options = args[0] || {};
    const result = connect(...args);
    if (options.servername === 'downloads.claude.ai') result.on('error', error => (observations.assetErrors ||= []).push({ phase: 'tls', code: error.code || 'ERROR' }));
    return result;
  };
}
const track = socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); return socket; };
const html = `<!doctype html><html><body><h1>Guard Windows fixture</h1><script>
const profile=()=>({timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,locale:Intl.DateTimeFormat().resolvedOptions().locale});
window.__guardFixture={profiles:[]};
window.addEventListener('message',event=>{if(event.origin==='https://challenges.cloudflare.com'&&event.data.guardFixture)window.__guardFixture.profiles.push(event.data)});
(async()=>{
const current=profile();const response=await fetch('/__guard_test__/capture',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer fixture-secret-do-not-export'},body:JSON.stringify({...current,account:{language:'ru-RU'},content:{locale:'ru',quotedTimezone:'Europe/Moscow',message:'Пример русского текста'}})}).then(r=>r.json());
window.__guardFixture.result={profile:current,response};
for(let i=0;i<8;i++){const f=document.createElement('iframe');f.src='https://challenges.cloudflare.com/frame?i='+i;document.body.append(f);const deadline=Date.now()+5000;while(window.__guardFixture.profiles.length<=i&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,30));f.remove()}
window.__guardFixture.iframeDone=true;
const socket=new WebSocket('wss://claude.ai/__guard_test__/ws');socket.onopen=()=>socket.send('guard-ws-request');socket.onmessage=event=>window.__guardFixture.ws=event.data;
fetch('/__guard_test__/stream').then(async r=>{const reader=r.body.getReader();window.__guardFixture.stream=true;while(!(await reader.read()).done){}}).catch(()=>{});
})();
</script></body></html>`;
const frame = '<script>parent.postMessage({guardFixture:true,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,locale:Intl.DateTimeFormat().resolvedOptions().locale},"https://claude.ai")</script>';

async function main() {
  assert.equal(process.platform, 'win32');
  if (process.env.GUARD_TLS_DEBUG === '1') {
    const originalConnect = tls.connect;
    tls.connect = (...args) => {
      const result = originalConnect(...args);
      result.on('error', error => console.error('TLS_FIXTURE_ERROR', error.code || '', error.message || error));
      return result;
    };
  }
  await fs.mkdir(work, { recursive: true });
  if (codeEnabled) instrumentAsset();
  const execution = JSON.parse(await powershell("[pscustomobject]@{elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);interactive=((Get-Process -Id $PID).SessionId -gt 0)}|ConvertTo-Json -Compress"));
  proof.executionContext = { elevated: execution.elevated === true, interactive: execution.interactive === true,
    standardUserRuntimeCovered: execution.elevated !== true,
    limitation: execution.elevated === true ? 'Interactive elevated fixture; standard-user runtime token is not covered by this run.' : 'Runtime inherits the invoking test token.' };
  if (source === 'auto') {
    const found = await require('../src/discovery.cjs').discoverClaude();
    assert.equal(found.status, 'found'); assert.ok(['msix', 'legacy'].includes(found.kind));
    if (found.kind === 'msix') assert.ok(found.path.toLowerCase().includes('\\windowsapps\\'));
    source = found.path; proof.automaticDiscoveryKind = found.kind;
  }
  proof.connectionMode = connectionMode;
  const cert = await fs.readFile(certPath), key = await fs.readFile(keyPath);
  const tlsServer = https.createServer({ cert, key }, (req, res) => {
    const hostname = req.headers.host?.split(':')[0];
    if (ipHosts.includes(hostname)) {
      (observations.ipChecks ||= {})[hostname] = (observations.ipChecks?.[hostname] || 0) + 1;
      if (hostname !== 'ipwho.is' && failNextCurrentIP) {
        failNextCurrentIP = false; holdCurrentIP = true; observations.http500 = (observations.http500 || 0) + 1;
        res.writeHead(500, { 'Content-Length': 0 }); res.end(); return;
      }
      const respond = () => {
        if (res.destroyed) return;
        const response = JSON.stringify(hostname === 'ipwho.is' ? { success: true, country_code: 'NL', ip: observed } : { ip: observed });
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(response) }); res.end(response);
      };
      if (hostname !== 'ipwho.is' && holdCurrentIP) heldIPResponses.push(respond); else respond();
      return;
    }
    if (req.url.startsWith('/__guard_test__/stream')) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', Connection: 'keep-alive', 'Cache-Control': 'no-cache' });
      res.write('data: {"marker":"guard-sse-open"}\n\n'); observations.streamOpen = true;
      activeStreams.add(res); observations.streamsOpened = (observations.streamsOpened || 0) + 1;
      const timer = setInterval(() => res.write(': heartbeat\n\n'), 200);
      res.once('close', () => { clearInterval(timer); activeStreams.delete(res); observations.streamClosed = true; }); return;
    }
    let body = ''; req.on('data', data => { body += data.toString(); });
    req.on('end', () => {
      if (req.url === '/__guard_test__/persist') {
        const cookiePresent = String(req.headers.cookie || '').split(';').some(value => value.trim() === persistenceCookie + '=' + persistenceMarker);
        const response = JSON.stringify({ marker: 'guard-persistence-fixture', cookiePresent });
        const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(response), 'Cache-Control': 'no-store' };
        // The read endpoint never recreates the marker after the runtime restart.
        if (req.method === 'POST') headers['Set-Cookie'] = persistenceCookie + '=' + persistenceMarker + '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=86400';
        res.writeHead(200, headers); res.end(response); return;
      }
      if (req.url.startsWith('/__guard_test__/revalidation')) {
        (observations.revalidationRequests ||= []).push(req.url);
        const result = JSON.stringify({ marker: 'guard-revalidation-response' });
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(result) }); res.end(result); return;
      }
      if (req.url.startsWith('/__guard_test__/capture')) {
        observations.received = { path: req.url, language: req.headers['accept-language'], body: JSON.parse(body) };
        const result = JSON.stringify({ marker: 'guard-response-ok', received: JSON.parse(body) });
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(result) }); res.end(result); return;
      }
      if (req.url === '/magic-link') observations.magicFixtureRequests = (observations.magicFixtureRequests || 0) + 1;
      const frameRequest = req.headers.host?.split(':')[0] === 'challenges.cloudflare.com';
      if (frameRequest) (observations.frameRequests ||= []).push(req.url);
      const result = frameRequest ? frame : html;
      res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(result) }); res.end(result);
    });
  });
  tlsServer.on('connection', track);
  tlsServer.on('upgrade', (req, socket) => {
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
    const data = Buffer.from('guard-ws-response'); socket.write(Buffer.concat([Buffer.from([0x81, data.length]), data]));
  });
  tlsServer.listen(0, '127.0.0.1'); await once(tlsServer, 'listening');
  const originalConnection = net.createConnection;
  if (connectionMode === 'network') {
    // Test-scoped destination mapping, without changing hosts or shipping a route override.
    net.createConnection = function (options, ...args) {
      if (options && typeof options === 'object' && options.host && !['127.0.0.1', '::1'].includes(options.host)) {
        if (['claude.ai', 'challenges.cloudflare.com', ...ipHosts].includes(options.host) && options.port === 443) {
          const mapped = { ...options, host: '127.0.0.1', port: tlsServer.address().port };
          if (mapped.lookup) mapped.lookup = (name, lookupOptions, callback) => callback(null, '127.0.0.1', 4);
          return originalConnection.call(this, mapped, ...args);
        }
        if (codeEnabled && options.host === 'downloads.claude.ai' && options.port === 443) return originalConnection.call(this, options, ...args);
        const socket = new net.Socket(); queueMicrotask(() => socket.destroy(Object.assign(Error('Fixture denies external destinations'), { code: 'ECONNREFUSED' }))); return socket;
      }
      return originalConnection.call(this, options, ...args);
    };
  }
  const socks = net.createServer(async socket => {
    track(socket); const reader = new SocketReader(socket);
    try {
      const greeting = await reader.read(2); await reader.read(greeting[1]); socket.write(Buffer.from([5, 0]));
      const request = await reader.read(5); assert.equal(request[3], 3);
      const host = (await reader.read(request[4])).toString(), port = (await reader.read(2)).readUInt16BE();
      if (!['claude.ai', 'challenges.cloudflare.com', ...ipHosts, ...(codeEnabled ? ['downloads.claude.ai'] : [])].includes(host) || port !== 443) {
        (observations.deniedTargets ||= []).push({ host, port });
        socket.write(Buffer.from([5, 2, 0, 1, 0, 0, 0, 0, 0, 0])); reader.release(); socket.end(); return;
      }
      const codeDownload = codeEnabled && host === 'downloads.claude.ai';
      const upstream = track(net.connect(codeDownload ? port : tlsServer.address().port, codeDownload ? host : '127.0.0.1')); await once(upstream, 'connect');
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])); reader.release();
      socket.once('close', () => upstream.destroy()); upstream.once('close', () => socket.destroy());
      socket.pipe(upstream); upstream.pipe(socket); socket.resume();
    } catch { reader.release(); socket.destroy(); }
  });
  socks.listen(0, '127.0.0.1'); await once(socks, 'listening');
  const resources = path.join(path.dirname(work), path.basename(work) + '-resources'); await fs.mkdir(resources, { recursive: true });
  await fs.copyFile(hostPath, path.join(resources, 'GuardHost.exe'));
  if (fencePath) await fs.copyFile(fencePath, path.join(resources, 'NetworkFence.exe'));
  await fs.access(path.join(resources, 'NetworkFence.exe')); // Never bypass the production fence for this test.
  if (codeEnabled) {
    await fs.copyFile(codeHostPath, path.join(resources, 'CodeHost.exe'));
    await fs.copyFile(path.join(codeToolsDir, 'code-tools-policy.json'), path.join(resources, 'code-tools-policy.json'));
    await fs.cp(path.join(codeToolsDir, 'CodeTools'), path.join(resources, 'CodeTools'), { recursive: true });
  }
  const originalBoot = await fs.readFile(path.resolve(__dirname, '..', '..', 'Resources', 'RuntimeBootstrap.cjs'), 'utf8');
  const fingerprint = new crypto.X509Certificate(cert).fingerprint256;
  const fixtureBoot = originalBoot + `
// TEST ONLY: pin one fixture certificate, never alter the OS trust store.
const testFingerprint=${JSON.stringify(fingerprint)};
function pinFixture(s){s.setCertificateVerifyProc((r,cb)=>{if(!['claude.ai','challenges.cloudflare.com'].includes(r.hostname))return cb(-3);try{cb(new(require('node:crypto').X509Certificate)(r.certificate.data).fingerprint256===testFingerprint?0:-2)}catch{cb(-2)}})}
app.on('session-created',pinFixture);app.whenReady().then(()=>pinFixture(electron.session.defaultSession));
electron.shell.openExternal=async()=>{};
app.setAsDefaultProtocolClient=()=>false;
const fixtureDeepLink=${JSON.stringify(fixtureDeepLink)};
const testDeepLink={count:0,privateProfileArgument:false,workingDirectoryCorrect:false};
const observeDeepLink=(_event,args,cwd)=>{
 if(!Array.isArray(args)||!args.includes(fixtureDeepLink))return;
 testDeepLink.count++;
 testDeepLink.privateProfileArgument=args.length===3&&args[0]===process.execPath&&args[1]==='--user-data-dir='+cfg.userData&&args[2]===fixtureDeepLink;
 testDeepLink.workingDirectoryCorrect=typeof cwd==='string'&&path.resolve(cwd).toLowerCase()===path.dirname(process.execPath).toLowerCase();
};
app.on('second-instance',observeDeepLink);
let testWindowsDone=0;const productionCommand=command;
command=async m=>{
 if(m.method==='ProxyGuard.testDeepLinkStatus'){
  emit({id:m.id,result:{...testDeepLink,vendorListenerPresent:app.listeners('second-instance').some(handler=>handler!==observeDeepLink)}});return;
 }
 if(m.method==='ProxyGuard.testWindowLifecycle'){
  for(const delay of [1,75]){const w=new electron.BrowserWindow({show:false});w.loadURL('https://claude.ai/__guard_test__/aux').catch(()=>{});setTimeout(()=>{if(!w.isDestroyed())w.destroy();testWindowsDone++},delay)}
  emit({id:m.id,result:{}});return;
 }
 if(m.method==='ProxyGuard.testWindowStatus'){emit({id:m.id,result:{completed:testWindowsDone}});return}
 if(m.method==='ProxyGuard.testFlushProfile'){
  const target=sessions.get(m.params.targetSession);if(!target||target.child)throw Error('root target required');
  const storage=target.wc.session;await storage.cookies.flushStore();storage.flushStorageData();
  const cookies=await storage.cookies.get({url:'https://claude.ai',name:${JSON.stringify(persistenceCookie)}});
  const cookie=cookies[0],own=path.resolve(cfg.userData).toLowerCase();
  const same=p=>typeof p==='string'&&path.resolve(p).toLowerCase()===own;
  const storagePath=storage.getStoragePath();const storageOwn=typeof storagePath==='string'&&(same(storagePath)||path.resolve(storagePath).toLowerCase().startsWith(own+path.sep));
  emit({id:m.id,result:{electronVersion:process.versions.electron,flushed:true,cookieCount:cookies.length,cookiePersistent:cookies.length===1&&cookie.httpOnly&&cookie.secure&&!cookie.session&&cookie.expirationDate>Date.now()/1000+300,
   cookieValueMatches:cookie?.value===m.params.expectedValue,userDataOwn:same(app.getPath('userData')),sessionDataOwn:same(app.getPath('sessionData')),sessionStorageOwn:storageOwn}});return;
 }
 if(m.method==='ProxyGuard.testSharedLocale'){
  const target=sessions.get(m.params.targetSession);if(!target||target.child)throw Error('root target required');const dbg=target.wc.debugger;
  await dbg.sendCommand('Emulation.setLocaleOverride',{locale:''});const info=await dbg.sendCommand('Target.getTargetInfo');
  const first=await dbg.sendCommand('Target.attachToTarget',{targetId:info.targetInfo.targetId,flatten:true});
  await dbg.sendCommand('Emulation.setLocaleOverride',{locale:cfg.language.replaceAll('-','_')},first.sessionId);let conflict;
  try{await dbg.sendCommand('Emulation.setLocaleOverride',{locale:cfg.language.replaceAll('-','_')})}catch(e){conflict=e.message}
  if(!conflict?.includes('Another locale override is already in effect'))throw Error('native conflict absent');
  const inherited=await ensureRendererLocale(target.wc);const second=await dbg.sendCommand('Target.attachToTarget',{targetId:info.targetInfo.targetId,flatten:true});
  emit({id:m.id,result:{conflict,inherited,firstSession:first.sessionId,secondSession:second.sessionId}});return;
 }
 return productionCommand(m);
};
`;
  await fs.writeFile(path.join(resources, 'RuntimeBootstrap.cjs'), fixtureBoot);
  const root = path.join(work, 'Cache'), runtime = await prepareRuntime(source, root, path.join(resources, 'RuntimeBootstrap.cjs'));
  proof.sourceVersion = runtime.version; proof.sourceSignature = runtime.signature;
  let controller;
  try {
    controller = newGuardController(root, resources); controller.on('log', e => console.log(e.kind + ': ' + e.message));
    const states = []; controller.on('state', state => {
      states.push(state.state);
      const event = { at: Date.now(), state: state.state, processState: state.processState, frozen: state.processFrozen, message: state.message, activeStreams: activeStreams.size, revision: controller.revalidationRevision || 0 };
      (observations.timeline ||= []).push(event);
      fsSync.appendFileSync(path.join(work, 'timeline.jsonl'), JSON.stringify(event) + '\n');
    });
    const captures = new Map(); controller.on('record', r => captures.set(r.id, r));
    const input = { mode: connectionMode, host: '127.0.0.1', port: socks.address().port, timezone: 'Europe/Amsterdam', language: 'en-US', interval: codeEnabled ? 30 : 2, captureBodies: true, claudePath: source, codeEnabled };
    await controller.start(input);
    await until(() => controller.state === 'running' || (controller.state === 'blocked' && Promise.reject(Error(controller.message))), 'renderer profile', 45000);
    assert.equal(controller.fence?.installed, true, 'Production WFP protection must be installed before runtime launch');
    assert.equal(controller.fence.proof?.persistent, true);
    proof.networkFence = { ...controller.fence.proof, installedBeforeRuntime: true };
    if (servicePath) {
      const status = await controller.nativeServiceBackend.getStatus();
      proof.serviceRouting = { backend: 'NativeServiceBackend', state: status.state, sessionRoutingSupported: status.sessionRoutingSupported,
        launchRequests: observations.serviceLaunches, perSessionElevation: false };
      assert.equal(status.state, 'running'); assert.equal(status.sessionRoutingSupported, true);
    }
    if (codeEnabled) {
      assert.equal(controller.fence.codeProof?.filters, 10);
      const prepared = JSON.parse(observations.prepareState.stdout);
      assert.equal(prepared.prepared, true); assert.equal(prepared.sid, controller.fence.codeProof.sid);
      proof.codeStatePreparation = { prepared: true, entries: prepared.entries };
      proof.codeFenceSession = { ...controller.fence.codeProof, running: true };
      observations.codeStatePreparation = proof.codeStatePreparation;
      observations.codeFenceSession = proof.codeFenceSession;
    }
    proof.internet = 'production WFP fence permits private runtime images to use only the Guard relay';
    const channel = controller.channel;
    let sid;
    const result = await until(async () => {
      if (controller.state === 'blocked') throw Error(controller.message);
      for (const [candidate, item] of controller.inspector.sessions) {
        if (!item.verified || !candidate.startsWith('guard-')) continue;
        try {
          const value = (await channel.command('Runtime.evaluate', { expression: 'window.__guardFixture?.result', returnByValue: true }, candidate)).result?.value;
          if (value) { sid = candidate; return value; }
        } catch (error) { if (!/context|target closed|session/i.test(error.message)) throw error; }
      }
      return false;
    }, 'capture');
    proof.rendererProfile = result.profile;
    const evaluate = async expr => (await channel.command('Runtime.evaluate', { expression: expr, returnByValue: true }, sid)).result?.value;
    assert.equal(result.response.marker, 'guard-response-ok'); assert.equal(result.profile.timezone, 'Europe/Amsterdam'); assert.equal(result.profile.locale, 'en-US');
    proof.rendererResult = result;
    await until(async () => await evaluate('window.__guardFixture?.iframeDone'), 'iframe churn', 60000);
    const profiles = await evaluate('window.__guardFixture.profiles'); assert.equal(profiles.length, 8);
    for (const p of profiles) { assert.equal(p.timezone, 'Europe/Amsterdam'); assert.equal(p.language, 'en-US'); assert.equal(p.locale, 'en-US'); }
    proof.iframeProfiles = profiles.length;
    await channel.command('ProxyGuard.testWindowLifecycle');
    await until(async () => (await channel.command('ProxyGuard.testWindowStatus')).completed === 2, 'auxiliary close');
    assert.equal(controller.state, 'running'); proof.auxiliaryWindowsClosed = 2;
    proof.sharedLocale = await channel.command('ProxyGuard.testSharedLocale', { targetSession: sid }); assert.equal(proof.sharedLocale.inherited, true);
    await until(() => [...captures.values()].some(r => r.received.includes('guard-response-ok')), 'response interception');
    proof.capturedHTTP = [...captures.values()].find(r => r.received.includes('guard-response-ok'));
    assert.ok(!JSON.stringify(proof.capturedHTTP).includes('fixture-secret-do-not-export'));
    await until(() => [...captures.values()].some(r => r.kind === 'WebSocket' && r.received.includes('guard-ws-response') && r.sent.includes('guard-ws-request')), 'WebSocket interception');
    proof.webSocketCaptured = true;
    await until(() => observations.streamOpen, 'live SSE stream');
    assert.equal(observations.received.language, 'en-US'); proof.serverReceived = observations.received;
    assert.equal(observations.received.body.account.language, 'ru-RU');
    assert.equal(observations.received.body.content.locale, 'ru');
    assert.equal(observations.received.body.content.quotedTimezone, 'Europe/Moscow');
    assert.equal(controller.state, 'running');
    assert.equal(result.profile.language, 'en-US');
    proof.contentLocaleAllowed = { russianAccountLanguage: true, russianContentLocale: true, quotedTimezone: true,
      contentReachedFixtureUnchanged: true, actualAcceptLanguage: 'en-US', actualRendererStillVerified: true };
    const beforeMagicPID = controller.runtimePID;
    const delivered = await controller.deliverDeepLink(fixtureDeepLink);
    assert.deepEqual(delivered, { accepted: true, delivered: true });
    const deepLink = await until(async () => {
      const status = await channel.command('ProxyGuard.testDeepLinkStatus'); return status.count === 1 && status;
    }, 'synthetic callback delivered through production adapter');
    for (const field of ['vendorListenerPresent', 'privateProfileArgument', 'workingDirectoryCorrect']) assert.equal(deepLink[field], true, field);
    await until(() => observations.magicFixtureRequests >= 1, 'vendor magic-link handler navigated controlled fixture');
    await until(async () => {
      if (controller.state === 'blocked') throw Error(controller.message);
      for (const [candidate, item] of controller.inspector.sessions) {
        if (!item.verified || !candidate.startsWith('guard-')) continue;
        try {
          const value = (await channel.command('Runtime.evaluate', { expression: 'location.pathname==="/magic-link"&&Boolean(window.__guardFixture?.result)', returnByValue: true }, candidate)).result?.value;
          if (value) { sid = candidate; return true; }
        } catch (error) { if (!/context|target closed|session/i.test(error.message)) throw error; }
      }
      return false;
    }, 'magic-link fixture renderer verified');
    await until(async () => await evaluate('window.__guardFixture?.iframeDone'), 'magic-link iframe churn', 60000);
    await until(() => activeStreams.size > 0, 'magic-link fixture live SSE');
    const pid = controller.runtimePID;
    assert.ok(pid > 0); assert.equal(pid, beforeMagicPID); assert.equal(controller.state, 'running');
    proof.magicLinkDelivery = { syntheticCallbackDelivered: true, vendorListenerPresent: true, observerCount: deepLink.count,
      sameRuntimePID: true, privateProfileArgument: true, workingDirectoryCorrect: true, vendorNavigatedFixture: true };
    const statesBefore = states.length;
    failNextCurrentIP = true;
    if (codeEnabled) void controller.revalidate();
    await until(() => observations.http500 === 1 && controller.processState === 'frozen', 'HTTP 500 freezes the verified runtime', 10000);
    assert.equal(controller.relay.unlocked, false); assert.equal(controller.policy.blocked, false);
    assert.equal(controller.runtimePID, pid); process.kill(pid, 0);
    await until(() => activeStreams.size === 0, 'SSE closed while frozen');
    assert.equal(observations.revalidationRequests?.length || 0, 0, 'Frozen app request reached destination');
    assert.equal(controller.state, 'rechecking'); process.kill(pid, 0);
    holdCurrentIP = false; for (const respond of heldIPResponses.splice(0)) respond();
    await until(() => controller.state === 'running', 'same IP thaws and resumes application traffic', 15000);
    assert.equal(controller.runtimePID, pid); assert.equal(controller.processFrozen, false); process.kill(pid, 0);
    const resumedFetch = (await channel.command('Runtime.evaluate', {
      expression: `(async()=>await fetch('/__guard_test__/revalidation?stage=resumed',{cache:'no-store'}).then(r=>r.json()))()`,
      awaitPromise: true, returnByValue: true
    }, sid)).result?.value;
    assert.equal(resumedFetch?.marker, 'guard-revalidation-response');
    assert.deepEqual(observations.revalidationRequests, ['/__guard_test__/revalidation?stage=resumed']);
    await evaluate(`fetch('/__guard_test__/stream?after-revalidation=1').then(async r=>{const reader=r.body.getReader();while(!(await reader.read()).done){}}).catch(()=>{});true`);
    await until(() => activeStreams.size > 0 && observations.streamsOpened >= 2, 'SSE resumed after IP confirmation');
    proof.revalidation = { injectedHTTP500: observations.http500, recheckingObserved: states.slice(statesBefore).includes('rechecking'),
      nativeFreezeAcknowledged: true, appTrafficBlockedWhilePaused: true, processSurvived: true, samePID: true, resumedHTTP: true, resumedStream: true };
    assert.equal(proof.revalidation.recheckingObserved, true);
    const firstProfile = controller.runtime.profile, firstExecutable = controller.runtime.executable, firstFence = controller.fence;
    const profileKeyHash=async()=>{try{const state=JSON.parse(await fs.readFile(path.join(firstProfile,'Local State'),'utf8')),value=state.os_crypt?.encrypted_key;return typeof value==='string'?crypto.createHash('sha256').update(value).digest('hex'):null}catch{return null}};
    observations.profilePathsBeforeWrite=await channel.command('ProxyGuard.testFlushProfile',{targetSession:sid});
    for(const field of ['userDataOwn','sessionDataOwn','sessionStorageOwn'])assert.equal(observations.profilePathsBeforeWrite[field],true,field+' must use only the fixture profile');
    const writePersistence = (await channel.command('Runtime.evaluate', {
      expression: `(async()=>{
        const key='guard-fixture-persistence-v1',value=${JSON.stringify(persistenceMarker)};
        localStorage.setItem(key,value);
        await new Promise((resolve,reject)=>{
          const open=indexedDB.open('guard-fixture-persistence',1);
          open.onupgradeneeded=()=>open.result.createObjectStore('markers');open.onerror=()=>reject(open.error);
          open.onsuccess=()=>{const db=open.result;const tx=db.transaction('markers','readwrite',{durability:'strict'});
            tx.objectStore('markers').put(value,'marker');tx.oncomplete=()=>{db.close();resolve()};tx.onabort=()=>{db.close();reject(tx.error)}};
        });
        await fetch('/__guard_test__/persist',{method:'POST',cache:'no-store'}).then(r=>{if(!r.ok)throw Error('fixture cookie rejected')});
        return {localStorageWritten:localStorage.getItem(key)===value,indexedDBCommitted:true,httpOnlyInvisible:!document.cookie.split(';').some(x=>x.trim().startsWith(${JSON.stringify(persistenceCookie + '=')}))};
      })()`, awaitPromise: true, returnByValue: true
    }, sid)).result?.value;
    assert.deepEqual(writePersistence, { localStorageWritten: true, indexedDBCommitted: true, httpOnlyInvisible: true });
    const flush = await channel.command('ProxyGuard.testFlushProfile', { targetSession: sid, expectedValue: persistenceMarker });
    observations.persistenceBeforeKill=flush;
    assert.equal(flush.flushed, true); assert.equal(flush.cookiePersistent, true);assert.equal(flush.cookieValueMatches,true);
    const baselineCookie=(await channel.command('Runtime.evaluate',{expression:`fetch('/__guard_test__/persist',{cache:'no-store'}).then(r=>r.json()).then(v=>v.cookiePresent)`,awaitPromise:true,returnByValue:true},sid)).result?.value;
    observations.cookieSentBeforeKill=baselineCookie===true;assert.equal(baselineCookie,true);
    const profileKeyPresence=async()=>{try{const value=JSON.parse(await fs.readFile(path.join(firstProfile,'Local State'),'utf8')).os_crypt||{};return {legacyKey:typeof value.encrypted_key==='string',appBoundKey:typeof value.app_bound_encrypted_key==='string'}}catch{return {legacyKey:false,appBoundKey:false}}};
    const firstKeyHash=await profileKeyHash();observations.ownEncryptionKeyPresentBefore=firstKeyHash!==null;
    observations.ownKeyPresenceBefore=await profileKeyPresence();observations.fixtureCookieDiskBefore=await fixtureCookieDisk(firstProfile).catch(error=>{if(error.code==='EBUSY')return {locked:true};throw error});
    // Round trips follow Chromium's explicit storage flush and committed IndexedDB
    // transaction. Persistence must survive the real freeze, bounded graceful close
    // and forced Job cleanup rather than a test-only orderly profile shutdown.
    assert.equal(await evaluate(`localStorage.getItem('guard-fixture-persistence-v1')===${JSON.stringify(persistenceMarker)}`), true);
    await sleep(argv.includes('--settle-key')?15000:350);
    observations.ownKeyPresenceAfterSettling=await profileKeyPresence();observations.ownEncryptionKeyPresentAfterSettling=(await profileKeyHash())!==null;
    const port = controller.relay.port, changedAt = Date.now();
    observed = '203.0.113.8';
    if (codeEnabled) void controller.revalidate();
    await until(() => controller.processState === 'frozen', 'IP mismatch freezes before timeout', 10000);
    assert.equal(controller.runtimePID, pid); process.kill(pid, 0);
    await until(() => controller.state === 'blocked', 'IP freeze timeout closes Claude', 35000);
    await until(() => activeStreams.size === 0, 'SSE closed');
    await until(() => { try { process.kill(pid, 0); return false; } catch { return true; } }, 'runtime terminated');
    const refusal = net.connect(port, '127.0.0.1'); const refused = await new Promise(resolve => { refusal.once('connect', () => resolve(false)); refusal.once('error', () => resolve(true)); }); refusal.destroy();
    assert.equal(refused, true); controller.stop(); await assert.rejects(controller.start(input));
    if (process.env.GUARD_RESET_PROBE === '1') {
      const snapshot = controller.resetIP();
      proof.resetProbe = { stateAfterReset: snapshot.state, memoryAfterReset: snapshot.savedIP };
      await controller.start(input);
      await until(() => controller.state === 'running' || (controller.state === 'blocked' && Promise.reject(Error(controller.message))), 'reset allows a different external IP', 45000);
      proof.resetProbe.allowedDifferentIP = true;
      controller.stop();
    }
    const closeMilliseconds = Date.now() - changedAt;
    assert.ok(closeMilliseconds >= 19000 && closeMilliseconds < 35000, 'Freeze timeout must be bounded and must not be immediate');
    proof.killSwitch = { milliseconds: closeMilliseconds, freezeObservedBeforeClose: true, processGone: true, streamClosed: true, relayRefusesNewConnections: refused, blockedUntilRestart: true };
    // Teardown is asynchronous: do not race a new broker against the old global
    // WFP mutex or accept abandoned persistent filters as successful cleanup.
    await until(() => firstFence.closed && firstFence.installed === false, 'old WFP broker acknowledged filter removal', 20000);
    observations.fixtureCookieDiskStopped=await fixtureCookieDisk(firstProfile).catch(error=>{if(error.code==='EBUSY')return {locked:true};throw error});
    observed = process.env.GUARD_RESET_PROBE === '1' ? '203.0.113.8' : '203.0.113.7';
    controller = newGuardController(root, resources);
    controller.on('log', event => console.log('restart ' + event.kind + ': ' + event.message));
    assert.equal(controller.policy.pinned, null); assert.equal(controller.policy.blocked, false);
    await controller.start(input);
    await until(() => controller.state === 'running' || (controller.state === 'blocked' && Promise.reject(Error(controller.message))), 'restarted renderer profile', 45000);
    assert.equal(controller.runtime.profile, firstProfile);
    observations.sameRuntimeExecutable=controller.runtime.executable===firstExecutable;assert.equal(observations.sameRuntimeExecutable,true);
    assert.equal(controller.fence?.installed, true); assert.equal(controller.fence.proof?.persistent, true);
    let restartedSession;
    await until(async () => {
      if (controller.state === 'blocked') throw Error(controller.message);
      for (const [candidate, item] of controller.inspector.sessions) {
        if (!item.verified || !candidate.startsWith('guard-')) continue;
        try {
          const value = (await controller.channel.command('Runtime.evaluate', { expression: 'Boolean(window.__guardFixture?.result)', returnByValue: true }, candidate)).result?.value;
          if (value) { restartedSession = candidate; return true; }
        } catch (error) { if (!/context|target closed|session/i.test(error.message)) throw error; }
      }
      return false;
    }, 'restarted fixture origin');
    observations.persistenceAfterRestart=await controller.channel.command('ProxyGuard.testFlushProfile',{targetSession:restartedSession,expectedValue:persistenceMarker});
    const secondKeyHash=await profileKeyHash();observations.ownEncryptionKeyPresentAfter=secondKeyHash!==null;observations.ownEncryptionKeyUnchanged=firstKeyHash!==null&&secondKeyHash===firstKeyHash;
    observations.ownKeyPresenceAfter=await profileKeyPresence();observations.fixtureCookieDiskAfter=await fixtureCookieDisk(firstProfile).catch(error=>{if(error.code==='EBUSY')return {locked:true};throw error});
    const persisted = (await controller.channel.command('Runtime.evaluate', {
      expression: `(async()=>{
        const value=${JSON.stringify(persistenceMarker)};
        const saved=await new Promise((resolve,reject)=>{
          const open=indexedDB.open('guard-fixture-persistence',1);open.onerror=()=>reject(open.error);
          open.onsuccess=()=>{const db=open.result;if(!db.objectStoreNames.contains('markers')){db.close();resolve(null);return}
            const tx=db.transaction('markers','readonly');const get=tx.objectStore('markers').get('marker');
            get.onsuccess=()=>{const result=get.result;db.close();resolve(result)};get.onerror=()=>{db.close();reject(get.error)}};
        });
        const cookie=await fetch('/__guard_test__/persist',{cache:'no-store'}).then(r=>r.json());
        return {localStorage:localStorage.getItem('guard-fixture-persistence-v1')===value,indexedDB:saved===value,httpOnlyCookie:cookie.cookiePresent===true,
          httpOnlyInvisible:!document.cookie.split(';').some(x=>x.trim().startsWith(${JSON.stringify(persistenceCookie + '=')}))};
      })()`, awaitPromise: true, returnByValue: true
    }, restartedSession)).result?.value;
    assert.deepEqual(persisted, { localStorage: true, indexedDB: true, httpOnlyCookie: true, httpOnlyInvisible: true });
    const restartedPID = controller.runtimePID, restartedFence = controller.fence;
    assert.ok(restartedPID > 0); assert.equal(controller.state, 'running');
    controller.stop();
    await until(() => { try { process.kill(restartedPID, 0); return false; } catch { return true; } }, 'restarted runtime terminated');
    await until(() => restartedFence.closed && restartedFence.installed === false, 'restarted WFP broker acknowledged filter removal', 20000);
    proof.profilePersistence = { samePrivateProfile: true, freshGuardPolicy: true, previousFenceRemovedBeforeRestart: true,
      localStorage: persisted.localStorage, indexedDB: persisted.indexedDB, persistentHttpOnlyCookie: persisted.httpOnlyCookie,
      httpOnlyInvisibleToJavaScript: persisted.httpOnlyInvisible, secondFenceInstalled: true, secondGuardCleanlyStopped: true };
    assert.ok(observations.ipChecks?.['ipwho.is'] >= 1);
    assert.ok(ipHosts.filter(host => host !== 'ipwho.is').reduce((total, host) => total + (observations.ipChecks?.[host] || 0), 0) >= 4);
    proof.ipChecksThroughLocalTLS = true;
    for (const hostname of ['claude.ai', 'api.anthropic.com']) assert.ok(observations.destinationChecks?.[hostname] >= 2, 'Each destination is checked for the initial session and restart');
    proof.destinationRouteChecks = { source: 'controlled test-only per-host results; no WAN destination trace',
      sameSyntheticIPProvider: true, counts: { ...observations.destinationChecks }, capturedProxy: 'fixed test-only direct route' };
    proof.profileDiagnostics={electronVersion:flush.electronVersion,sameRuntimeExecutable:observations.sameRuntimeExecutable,
      keysBefore:observations.ownKeyPresenceBefore,keysAfterSettling:observations.ownKeyPresenceAfterSettling,keysAfterRestart:observations.ownKeyPresenceAfter,
      beforeKillDBLocked:observations.fixtureCookieDiskBefore.locked===true,persistedFixtureRowsBeforeReload:observations.fixtureCookieDiskStopped.rows.length,
      encryptedFixtureScheme:observations.fixtureCookieDiskStopped.rows[0]?.scheme,diagnosticSettleBeforeIPChange:argv.includes('--settle-key')};
    if (servicePath) proof.serviceRouting.launchRequests = observations.serviceLaunches;
    if (codeEnabled) proof.codeFenceSession.closeCleanup = true;
    proof.result = 'PASS'; await fs.writeFile(path.join(work, 'proof.json'), JSON.stringify(proof, null, 2));
    console.log('PASS: installed Windows Claude, production WFP, locale, interception, same-PID revalidation, IP kill and persistent private profile');
  } catch (error) {
    if (controller?.inspector) {
      const records = [...controller.inspector.records.values()].map(r => ({url:r.url,status:r.status,note:r.note}));
      await fs.writeFile(path.join(work, 'runtime-failure.json'), JSON.stringify({ records, profile:controller.verified, observations }, null, 2));
    }
    throw error;
  } finally {
    controller?.stop();
    net.createConnection = originalConnection;
    for (const socket of sockets) socket.destroy(); tlsServer.close(); socks.close();
  }
}
main().catch(async error => {
  console.error(error.stack || error); await fs.mkdir(work, { recursive: true });
  fsSync.writeFileSync(path.join(work, 'failure.json'), JSON.stringify({ error: String(error), observations }, null, 2)); process.exitCode = 1;
  for (const socket of sockets) socket.destroy();
  // Bound a failed native test even if an external Electron fixture did not exit.
  setTimeout(() => process.exit(1), 1000).unref();
});
