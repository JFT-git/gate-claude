'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const { randomBytes } = require('node:crypto');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

test('changing path getters cannot redirect real diagnostic IPC to another server', { timeout: 15000 }, async t => {
  const directory = await fs.mkdtemp(path.join(process.platform === 'darwin' ? '/tmp' : os.tmpdir(), 'gipc-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const pipe = '\\\\.\\pipe\\gate-claude-' + randomBytes(16).toString('hex');
  const own = process.platform === 'win32' ? pipe : path.join(directory, pipe);
  const foreign = process.platform === 'win32' ? '\\\\.\\pipe\\foreign-' + randomBytes(16).toString('hex') : path.join(directory, 'other.sock');
  const received = {own: [], foreign: []};
  for (const [kind, address] of [['own', own], ['foreign', foreign]]) {
    const server = net.createServer(socket => {
      let message = '';
      socket.on('data', data => message += data.toString());
      socket.on('end', () => { received[kind].push(message); socket.end(); });
    });
    t.after(() => new Promise(resolve => server.close(resolve)));
    server.listen(address); await once(server, 'listening');
  }
  const guard = path.resolve(__dirname, '../src/runtime-network-guard.cjs');
  const source = `
    const assert=require('node:assert/strict'),Module=require('node:module'),{EventEmitter}=require('node:events');
    const app=new EventEmitter();app.isReady=()=>false;app.commandLine={appendSwitch(){},removeSwitch(){},appendArgument(){}};
    const load=Module._load;Module._load=function(name,...args){return name==='electron'?{app}:load.call(this,name,...args);};
    const net=require('node:net'),pipe=${JSON.stringify(pipe)},foreign=${JSON.stringify(foreign)};
    require(${JSON.stringify(guard)}).installNetworkGuard({proxyURL:'http://127.0.0.1:41234',channelPipe:pipe});
    (async()=>{
      for(let index=0;index<3;index++){
        let reads=0;const options={get path(){return ++reads<=(index===0?1:2)?pipe:foreign;}};
        await new Promise((resolve,reject)=>{
          const connected=function(){this.end('method-'+index);};
          const socket=index===0?new net.Socket().connect(options,connected):index===1?net.connect(options,connected):net.createConnection(options,connected);
          socket.once('error',reject);socket.once('close',resolve);
        });
      }
    })().catch(error=>{console.error(error);process.exitCode=1;});
  `;
  const fixture = path.join(directory, 'fixture.cjs'); await fs.writeFile(fixture, source, {mode: 0o600});
  const child = spawn(process.execPath, [fixture], {cwd: directory, env: {...process.env, ELECTRON_RUN_AS_NODE: '1'}, stdio: ['ignore', 'ignore', 'pipe']});
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let errors = ''; child.stderr.on('data', data => errors += data.toString());
  const [code] = await once(child, 'exit'); assert.equal(code, 0, errors);
  assert.deepEqual(received.foreign, []);
  assert.deepEqual(received.own.sort(), ['method-0', 'method-1', 'method-2']);
});
