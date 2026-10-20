'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

// Each case gets a fresh process: deny hooks must never affect the test runner.
const setup = `
const assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const Module=require('node:module'),oldLoad=Module._load;
const app=new EventEmitter(),calls=[];
app.isReady=()=>false;
app.commandLine={appendSwitch:(...a)=>calls.push(a),removeSwitch:()=>{},appendArgument:()=>{}};
app.relaunch=()=>{},app.setLoginItemSettings=()=>{},app.setAsDefaultProtocolClient=()=>true;
const session={setProxy:async o=>{calls.push(['sessionProxy',o]);},resolveHost:()=>{}};
const updater=new EventEmitter();for(const n of ['quitAndInstall','setFeedURL','checkForUpdates'])updater[n]=()=>{};
const electron={app,session:{defaultSession:session},net:{resolveHost:()=>{},request:()=>{calls.push(['chromiumRequest']);return 1;}},
 shell:Object.fromEntries(['openExternal','openPath','showItemInFolder','trashItem'].map(n=>[n,()=>{}])),
 utilityProcess:{fork:()=>{}},autoUpdater:updater};
Module._load=function(name,...a){return name==='electron'?electron:oldLoad.call(this,name,...a);};
const {installNetworkGuard}=require(${JSON.stringify(path.resolve(__dirname, '../src/runtime-network-guard.cjs'))});
const cfg={proxyURL:'http://127.0.0.1:41234'};
function denied(fn){assert.throws(fn,e=>e.code==='ERR_GUARD_NETWORK_DENIED');}
`;
function run(body) {
  const script = setup + '\n(async()=>{' + body + '\n})().catch(e=>{console.error(e);process.exitCode=1;});';
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-runtime-network-'));
  const fixture = path.join(directory, 'fixture.cjs');
  try {
    fs.chmodSync(directory, 0o700);
    fs.writeFileSync(fixture, script, { encoding: 'utf8', mode: 0o600 });
    return execFileSync(process.execPath, [fixture], { encoding: 'utf8', timeout: 15000, env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

test('runtime guard rejects malformed relay configs and makes its configuration immutable', () => {
  run(`for(const proxyURL of ['', 'socks5://127.0.0.1:1','http://localhost:1','http://user:pass@127.0.0.1:1','http://127.0.0.1:1/path','http://127.0.0.1:1/?pac=1','https://127.0.0.1:1'])assert.throws(()=>installNetworkGuard({proxyURL}));
    const result=installNetworkGuard(cfg);assert.equal(result.installed,true);assert.equal(installNetworkGuard(cfg),result);
    assert.throws(()=>installNetworkGuard({...cfg,proxyURL:'http://127.0.0.1:41235'}));`);
});

test('runtime guard denies TCP, TLS, UDP and native HTTP including prototype and retained references', () => {
  run(`const net=require('node:net'),tls=require('node:tls'),udp=require('node:dgram');
    const socket=new net.Socket(),datagram=udp.createSocket('udp4');
    const retainedConnection=net.createConnection;
    installNetworkGuard(cfg);
    for(const host of ['127.0.0.1','192.0.2.3','::1','2001:db8::1','example.invalid']){
      denied(()=>net.connect({host,port:443}));denied(()=>net.createConnection(443,host));denied(()=>socket.connect({host,port:443}));
      denied(()=>tls.connect({host,port:443}));denied(()=>retainedConnection({host,port:443}));
    }
    denied(()=>new net.Server().listen(0));
    denied(()=>udp.createSocket('udp4'));denied(()=>datagram.send('x',443,'127.0.0.1'));denied(()=>datagram.connect(443,'::1'));
    for(const name of ['node:http','node:https']){denied(()=>require(name).request('https://example.invalid/'));denied(()=>require(name).get('https://example.invalid/'));}
    denied(()=>require('node:http2').connect('https://example.invalid'));
    await assert.rejects(fetch('https://example.invalid'),e=>e.code==='ERR_GUARD_NETWORK_DENIED');
    datagram.close();socket.destroy();`);
});

test('runtime guard denies callback and promise DNS including resolver instances', () => {
  run(`const dns=require('node:dns'),resolver=new dns.Resolver(),asyncResolver=new dns.promises.Resolver();installNetworkGuard(cfg);
    for(const object of [dns,dns.promises,resolver,asyncResolver])for(const name of ['resolve','resolve4','resolve6','reverse'])if(typeof object[name]==='function')denied(()=>object[name]('example.invalid',()=>{}));
    denied(()=>dns.lookup('example.invalid',()=>{}));denied(()=>dns.promises.lookup('example.invalid'));denied(()=>dns.lookupService('127.0.0.1',443,()=>{}));`);
});

test('runtime guard denies native children, workers, native addon loading and low-level bindings', () => {
  run(`const child=require('node:child_process'),existingChild=new child.ChildProcess();installNetworkGuard(cfg);
    for(const name of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])denied(()=>child[name]('fixture-must-never-run'));
    denied(()=>existingChild.spawn({file:'fixture-must-never-run',args:[]}));
    denied(()=>new(require('node:worker_threads').Worker)('fixture-must-never-run'));
    denied(()=>require('node:inspector').open(0,'0.0.0.0'));denied(()=>require('node:inspector/promises').open(0,'0.0.0.0'));
    denied(()=>electron.utilityProcess.fork('fixture-must-never-run'));
    denied(()=>process.dlopen({},'fixture-must-never-load.node'));
    for(const name of ['tcp_wrap','udp_wrap','cares_wrap','spawn_sync','process_wrap','pipe_wrap','tls_wrap'])denied(()=>process.binding(name));`);
});

test('runtime guard prevents desktop escape and immutable proxy or WebRTC policy downgrade', () => {
  run(`installNetworkGuard(cfg);
    for(const name of ['openExternal','openPath','showItemInFolder','trashItem'])denied(()=>electron.shell[name]('https://example.invalid'));
    denied(()=>app.relaunch());denied(()=>app.setLoginItemSettings({openAtLogin:true}));assert.equal(app.setAsDefaultProtocolClient('claude'),false);
    denied(()=>updater.quitAndInstall());denied(()=>updater.setFeedURL('https://example.invalid'));
    let updates=0;updater.on('update-not-available',()=>updates++);updater.checkForUpdates();assert.equal(updates,1);
    app.emit('session-created',session);await session.setProxy({mode:'fixed_servers',proxyRules:cfg.proxyURL,proxyBypassRules:'<-loopback>'});
    for(const options of [{mode:'direct'},{mode:'system'},{mode:'pac_script',pacScript:'https://example.invalid'},{mode:'fixed_servers',proxyRules:cfg.proxyURL,proxyBypassRules:'*'}])await assert.rejects(session.setProxy(options),e=>e.code==='ERR_GUARD_NETWORK_DENIED');
    denied(()=>session.resolveHost('example.invalid'));denied(()=>electron.net.resolveHost('example.invalid'));
    assert.deepEqual(calls.find(v=>v[0]==='host-resolver-rules'),['host-resolver-rules','MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']);
    for(const [name,value]of [['proxy-server','direct://'],['proxy-bypass-list','*'],['force-webrtc-ip-handling-policy','default'],['enable-quic',''],['proxy-pac-url','https://example.invalid'],['host-resolver-rules','MAP * 192.0.2.1']])denied(()=>app.commandLine.appendSwitch(name,value));
    denied(()=>app.commandLine.removeSwitch('proxy-server'));denied(()=>app.commandLine.appendArgument('--no-proxy-server'));
    const contents={session,setWebRTCIPHandlingPolicy:value=>calls.push(['webrtc',value])};app.emit('web-contents-created',{},contents);
    assert.deepEqual(calls.find(v=>v[0]==='webrtc'),['webrtc','disable_non_proxied_udp']);denied(()=>contents.setWebRTCIPHandlingPolicy('default'));
    assert.equal(electron.net.request(),1);`);
});

test('runtime guard denies arbitrary IPC and resists replacement of patched native APIs', () => {
  run(`const net=require('node:net');installNetworkGuard(cfg);
    for(const address of ['\\\\.\\pipe\\another-app','/tmp/another-app.sock',{path:'\\\\.\\pipe\\another-app'},{fd:1},{}])denied(()=>net.connect(address));
    net.connect=()=>{throw Error('replacement executed');};denied(()=>net.connect(443,'example.invalid'));
    net.Socket.prototype.connect=()=>{throw Error('replacement executed');};denied(()=>new net.Socket().connect(443,'example.invalid'));
    process.binding=()=>{throw Error('replacement executed');};denied(()=>process.binding('tcp_wrap'));`);
});

test('runtime guard accepts only its own randomized diagnostic pipe configuration', () => {
  run(`assert.throws(()=>installNetworkGuard({...cfg,channelPipe:'\\\\.\\pipe\\other'}));
    const pipe='\\\\\\\\.\\\\pipe\\\\gate-claude-'+'a'.repeat(32);
    const result=installNetworkGuard({...cfg,channelPipe:pipe});assert.equal(result.channelPipe,pipe);
    const net=require('node:net');for(const address of [{path:pipe,port:443},{path:pipe,host:'example.invalid'},{path:pipe,fd:1}])denied(()=>net.connect(address));`);
});
