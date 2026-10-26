'use strict';
// Real Electron API, temporary profile, no windows/accounts or HTTP requests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { app, session } = require('electron');
app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'guard-proxy-policy-')));
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-component-update');
const proxyURL = 'http://127.0.0.1:41234';
require('../../src/runtime-network-guard.cjs').installNetworkGuard({proxyURL});
setTimeout(() => app.exit(2), 15000).unref();
app.whenReady().then(async () => {
  const good = {mode: 'fixed_servers', proxyRules: proxyURL, proxyBypassRules: '<-loopback>', pacScript: undefined};
  const bad = {mode: 'direct', proxyRules: 'direct://', proxyBypassRules: '*', pacScript: 'https://example.invalid/proxy.pac'};
  for (const name of Object.keys(good)) {
    const target = session.fromPartition('guard-proxy-' + name);
    let reads = 0;
    const options = {...good}; Object.defineProperty(options, name, {get() { return ++reads === 1 ? good[name] : bad[name]; }});
    await target.setProxy(options);
    assert.equal(await target.resolveProxy('https://example.invalid'), 'PROXY 127.0.0.1:41234', name);
    assert.equal(reads, 1, name);
  }
  console.log(JSON.stringify({status: 'PASS', electron: process.versions.electron, cases: 4, proxy: 'PROXY 127.0.0.1:41234', networkRequests: 0}));
  app.exit(0);
}).catch(error => { console.error(error); app.exit(1); });
