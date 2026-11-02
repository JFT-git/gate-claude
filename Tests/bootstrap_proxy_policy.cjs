'use strict';
// Exercise the shared/macOS policy against real Electron Session APIs. All
// partitions/profile data are temporary; resolveProxy performs no HTTP request.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const electron = require('electron');
const { app, session } = electron;
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-shared-proxy-'));
app.setPath('userData', profile);
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-component-update');
const proxyURL = 'http://127.0.0.1:41234';
const source = fs.readFileSync(path.join(__dirname, '..', 'Resources', 'RuntimeBootstrap.cjs'), 'utf8');
const start = source.indexOf('function installNetworkHardening() {');
const end = source.indexOf('\ninstallNetworkHardening();', start);
assert.ok(start >= 0 && end > start, 'shared policy anchors');
// Keep the exact production function body; pipe/CDP setup is irrelevant to this
// native Session boundary and would require a synthetic parent inspector.
const install = Function('require', 'electron', 'app', 'cfg', source.slice(start, end) + '\nreturn installNetworkHardening;')
  (require, electron, app, { proxyURL });
install();
setTimeout(() => app.exit(2), 15000).unref();
app.whenReady().then(async () => {
  const good = { mode: 'fixed_servers', proxyRules: proxyURL, proxyBypassRules: '<-loopback>', pacScript: undefined };
  const bad = { mode: 'direct', proxyRules: 'direct://', proxyBypassRules: '*', pacScript: 'https://example.invalid/proxy.pac' };
  const observations = [];
  for (const name of Object.keys(good)) {
    const target = session.fromPartition('guard-shared-proxy-' + name);
    let reads = 0;
    const options = { ...good };
    Object.defineProperty(options, name, { get() { return ++reads === 1 ? good[name] : bad[name]; } });
    await target.setProxy(options);
    const result = await target.resolveProxy('https://example.invalid');
    observations.push({ name, reads, result });
    if (!process.argv.includes('--expect-vulnerable')) {
      assert.equal(result, 'PROXY 127.0.0.1:41234', name);
      assert.equal(reads, 1, name);
    }
  }
  console.log(JSON.stringify({ status: process.argv.includes('--expect-vulnerable') ? 'OBSERVED' : 'PASS', electron: process.versions.electron, cases: observations, networkRequests: 0 }));
  app.exit(0);
}).catch(error => { console.error(error); app.exit(1); });
