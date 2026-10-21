'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),net=require('node:net'),dgram=require('node:dgram');
const {execFile}=require('node:child_process'),run=require('node:util').promisify(execFile);
test('original image deny blocks loopback TCP, IPv6 and UDP; removal restores connectivity', {skip:process.platform!=='win32'||process.env.GATE_ORIGINAL_FENCE_TEST!=='1',timeout:90000},async t=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'gate-original-fence-')),image=path.join(root,'Claude.exe');await fs.copyFile(process.execPath,image);
 const source=path.resolve(__dirname,'../native/OriginalClaudeFence.cs');
 const counts={tcp4:0,tcp6:0,udp:0};const sockets=new Set();
 async function listen(host,key){const s=net.createServer(c=>{counts[key]++;sockets.add(c);c.on('error',()=>{});c.on('close',()=>sockets.delete(c));c.end()});await new Promise((r,j)=>{s.once('error',j);s.listen(0,host,r)});t.after(()=>{for(const c of sockets)c.destroy();s.close()});return s.address().port}
 const tcp4=await listen('127.0.0.1','tcp4'),tcp6=await listen('::1','tcp6'),u=dgram.createSocket('udp4');u.on('message',()=>counts.udp++);await new Promise(r=>u.bind(0,'127.0.0.1',r));t.after(()=>u.close());const ports={tcp4,tcp6,udp:u.address().port};
 const quote=s=>"'"+s.replaceAll("'","''")+"'";
 async function policy(mode){const ps=`$ErrorActionPreference='Stop';Add-Type -Path ${quote(source)};[OriginalClaudeFence]::Apply([string[]]@(${quote(image)}),${quote(mode)})`;return run('powershell.exe',['-NoProfile','-EncodedCommand',Buffer.from(ps,'utf16le').toString('base64')],{timeout:20000,windowsHide:true})}
 const probe=`const net=require('net'),d=require('dgram'),p=JSON.parse(process.argv[1]);async function tcp(h,p){return new Promise(r=>{const s=net.connect(p,h);let done=false;function end(v){if(done)return;done=true;s.destroy();r(v)}s.on('error',()=>end(false));s.on('connect',()=>end(true));s.setTimeout(600,()=>end(false))})};(async()=>{const a=await tcp('127.0.0.1',p.tcp4),b=await tcp('::1',p.tcp6);const u=d.createSocket('udp4');u.on('error',()=>{});for(let i=0;i<3;i++)u.send('probe',p.udp,'127.0.0.1',()=>{});await new Promise(r=>setTimeout(r,200));u.close();console.log(JSON.stringify({tcp4:a,tcp6:b}))})();`;
 async function invoke(){return JSON.parse((await run(image,['-e',probe,JSON.stringify(ports)],{timeout:10000,windowsHide:true})).stdout)}
 let installed=false;
 try{
  assert.deepEqual(await invoke(),{tcp4:true,tcp6:true});assert.ok(counts.udp>0);for(const k of Object.keys(counts))counts[k]=0;
  installed=true;await policy('Install');await policy('Verify');assert.deepEqual(await invoke(),{tcp4:false,tcp6:false});assert.deepEqual(counts,{tcp4:0,tcp6:0,udp:0});
  await policy('Install');assert.deepEqual(await invoke(),{tcp4:false,tcp6:false});assert.deepEqual(counts,{tcp4:0,tcp6:0,udp:0});
  await policy('Remove');installed=false;assert.deepEqual(await invoke(),{tcp4:true,tcp6:true});assert.ok(counts.udp>0);
 }finally{if(installed)await policy('Remove');await fs.rm(root,{recursive:true,force:true})}
});
