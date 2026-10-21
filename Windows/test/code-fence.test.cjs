'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),net=require('node:net'),dgram=require('node:dgram');
const {spawn,execFile}=require('node:child_process'),run=require('node:util').promisify(execFile);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const quote=s=>"'"+s.replaceAll("'","''")+"'";
// No external endpoints or account data. Independent loopback receivers prove
// which attempted packets reached a destination, not merely a client error.
test('zero-capability package fence follows native sockets to PowerShell and protects the relay port',{
 skip:process.platform!=='win32'||process.env.GATE_CODE_FENCE_TEST!=='1',timeout:120000
},async t=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'gate-code-fence-')),profile='gate-probe-'+require('node:crypto').randomBytes(16).toString('hex');
 const image=path.join(root,'canary.exe'),foreignImage=path.join(root,'foreign.exe'),launcher=path.join(root,'CodeFenceProbe.exe'),result=path.join(root,'result.json');
 const counts={relay:0,other4:0,other6:0,udp4:0,udp6:0,dns:0};let heldAccepted=0,heldBytes=0;const live=new Set(),servers=[];let child,timer;
 const events=[];let stderr='',probeError=null;
 async function listener(host,key){const s=net.createServer(c=>{live.add(c);c.on('error',()=>{});c.on('close',()=>live.delete(c));c.once('data',data=>{if(key==='relay'&&data.toString().startsWith('CONNECT keep.fixture.invalid:443 ')){heldAccepted++;c.write('HTTP/1.1 200 Connection Established\r\n\r\n');c.on('data',b=>{heldBytes+=b.length;c.write('ack')});return}if(data.toString().startsWith('ERRORfixture:'))probeError=data.toString().slice(13,96);counts[key]++;if(key==='relay'&&data.toString().startsWith('CONNECT fixture.invalid:443 '))c.end('HTTP/1.1 200 Connection Established\r\n\r\nfixture');else c.end('fixture')})});await new Promise((r,j)=>{s.once('error',j);s.listen({host,port:0,exclusive:true},r)});servers.push(s);return s}
 async function udp(type,host,key){const s=dgram.createSocket(type);s.on('message',()=>counts[key]++);await new Promise((r,j)=>{s.once('error',j);s.bind(0,host,r)});servers.push(s);return s.address().port}
 async function ps(script){return run('powershell.exe',['-NoLogo','-NoProfile','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{timeout:25000,windowsHide:true,maxBuffer:131072}).catch(()=>{throw new Error('fixture-powershell-failed')})}
 async function waitFor(predicate,timeout=15000){const start=Date.now();while(Date.now()-start<timeout){const item=predicate();if(item)return item;const error=events.find(x=>x.event==='error');if(error)throw new Error('native-stage:'+error.stage+':'+error.type+':'+error.win32);await sleep(30)}throw new Error('fixture-wait-timeout')}
 async function fixtureResult(){try{return JSON.parse(await fs.readFile(result,'utf8'))}catch{return null}}
 async function bindProbe(host,port){const code=`const n=require('net'),s=n.createServer();s.once('error',e=>{console.log(JSON.stringify({bound:false,code:e.code}));process.exit(0)});s.listen({host:process.argv[1],port:+process.argv[2],exclusive:true},()=>{console.log(JSON.stringify({bound:true}));s.close()});setTimeout(()=>process.exit(2),1500).unref()`;return JSON.parse((await run(foreignImage,['-e',code,host,String(port)],{timeout:4000,windowsHide:true})).stdout)}
 let created=false;
 try{
  await fs.copyFile(process.execPath,foreignImage);
  const native=path.resolve(__dirname,'../native/CodeNetworkFence.cs'),fixture=path.resolve(__dirname,'helpers/CodeFenceProbe.cs');
  const csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
  await run(csc,['/nologo','/target:exe','/platform:x64','/out:'+launcher,fixture,native],{timeout:15000,windowsHide:true});
  await run(csc,['/nologo','/target:exe','/platform:x64','/out:'+image,path.resolve(__dirname,'helpers/CodeSocketCanary.cs')],{timeout:15000,windowsHide:true});
  const createdEvent=JSON.parse((await run(launcher,['create','--name',profile],{timeout:15000,windowsHide:true})).stdout);created=true;assert.equal(createdEvent.capabilityCount,0);const sid=createdEvent.sid;
  // ACL only this fresh fixture; no system or user's existing profile is changed.
  await ps(`$ErrorActionPreference='Stop';$p=${quote(root)};$s=[System.Security.Principal.SecurityIdentifier]::new(${quote(sid)});$acl=Get-Acl -LiteralPath $p;$r=[System.Security.AccessControl.FileSystemAccessRule]::new($s,'Modify','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($r);Set-Acl -LiteralPath $p -AclObject $acl`);
  const relay=await listener('127.0.0.1','relay'),relayPort=relay.address().port;
  const other4=(await listener('127.0.0.1','other4')).address().port,other6=(await listener('::1','other6')).address().port;
  const ports={relay:relayPort,other4,other6,udp4:await udp('udp4','127.0.0.1','udp4'),udp6:await udp('udp6','::1','udp6'),dns:await udp('udp4','127.0.0.1','dns')};
  // Uncontained positive baseline proves the exact image and receivers function.
  const canaryArgs=[result,...Object.values(ports).map(String)];
  await run(image,[...canaryArgs,'baseline'],{timeout:10000,windowsHide:true});const baseline=JSON.parse(await fs.readFile(result,'utf8')).node;await fs.rm(result);
  assert.equal(baseline.relay,true,'baseline CONNECT');assert.equal(baseline.other4,true,'baseline TCP4');assert.equal(baseline.other6,true,'baseline TCP6');assert.equal(baseline.mapped,true,'baseline mapped IPv6');assert.ok(counts.udp4>0&&counts.udp6>0&&counts.dns>0);Object.keys(counts).forEach(k=>counts[k]=0);
  child=spawn(launcher,['launch','--name',profile,'--workdir',root,'--relay-image',process.execPath,'--relay-port',String(relayPort),'--heartbeat-ms','15000','--',image,...canaryArgs,'confined'],{windowsHide:true,stdio:['pipe','pipe','pipe']});
  child.stdin.on('error',()=>{});let pending='';child.stdout.on('data',b=>{pending+=b;let i;while((i=pending.indexOf('\n'))>=0){const line=pending.slice(0,i);pending=pending.slice(i+1);try{events.push(JSON.parse(line))}catch{}}});child.stderr.on('data',b=>stderr=(stderr+b).slice(-8192));timer=setInterval(()=>{if(!child.stdin.destroyed)child.stdin.write('ping\n')},500);
  await waitFor(()=>events.find(x=>x.event==='started'));
  let answer;const start=Date.now();while(Date.now()-start<20000){answer=await fixtureResult();if(answer)break;if(events.some(x=>x.event==='stopped'))break;const error=events.find(x=>x.event==='error');if(error)throw new Error('native-stage:'+error.stage+':'+error.type+':'+error.win32);await sleep(40)}let probeStage=null;try{probeStage=await fs.readFile(result+'.stage','utf8')}catch{}if(!answer)t.diagnostic(JSON.stringify({probeStage,events:events.map(x=>({event:x.event,stage:x.stage,exitCode:x.exitCode,reason:x.reason})),probeError,counts}));assert.ok(answer,'confined fixture returned a result');
  assert.deepEqual(answer.node,{relay:true,other4:false,other6:false,mapped:false});assert.deepEqual(answer.powershell,{relay:true,other4:false,other6:false});
  assert.deepEqual(counts,{relay:2,other4:0,other6:0,udp4:0,udp6:0,dns:0});
  const token=events.find(x=>x.event==='token');assert.equal(token.isAppContainer,true);assert.equal(token.sid,sid);assert.equal(token.capabilityCount,0);assert.equal(token.jobAssigned,true);
  const descendant=events.flatMap(x=>x.event==='job'?x.processes:[]);assert.ok(descendant.some(x=>x.pid!==token.pid&&x.imageKind==='powershell'),'a live PowerShell descendant was observed');for(const p of descendant){assert.equal(p.isAppContainer,true);assert.equal(p.sid,sid);assert.equal(p.capabilityCount,0)}
  assert.equal(answer.held,true);assert.equal(heldAccepted,1);await waitFor(()=>heldBytes>=12); // Two acknowledged roundtrips before a third tick.
  // Seal cuts a live stream and denies reconnect while both images stay alive.
  child.stdin.write('seal\n');await waitFor(()=>events.find(x=>x.event==='sealed'));const foreignOwner=JSON.parse((await run(launcher,['foreign-owner-probe',profile,String(relayPort),process.execPath],{timeout:8000,windowsHide:true})).stdout);assert.deepEqual(foreignOwner,{event:'foreign-owner',previousOwnerRejected:true,retireRejected:true,sealRejected:true,launchCleanupRejected:true,originalPolicyVerified:true});await fs.writeFile(result+'.seal','1');let sealed;const sealStart=Date.now();while(Date.now()-sealStart<4000){try{sealed=JSON.parse(await fs.readFile(result+'.sealed','utf8'));break}catch{}await sleep(40)}assert.deepEqual(sealed,{relay:false,heldClosed:true,childAlive:true});await sleep(150);const before=heldBytes;await sleep(250);assert.equal(heldBytes,before);
  for(const s of live)s.destroy();await new Promise(r=>relay.close(r));for(const h of ['127.0.0.1','0.0.0.0','::1','::'])assert.equal((await bindProbe(h,relayPort)).bound,false,'foreign relay rebind '+h);
  child.stdin.write('stop\n');await waitFor(()=>events.find(x=>x.event==='stopped'));await new Promise((r,j)=>{if(child.exitCode!==null)return r();child.once('exit',r);setTimeout(()=>j(new Error('launcher-exit-timeout')),5000).unref()});
  assert.equal(child.exitCode,0);assert.equal(stderr,'');assert.equal(events.some(x=>x.policyRetained||x.loopbackRemovalFailed),false);
  assert.equal((await bindProbe('127.0.0.1',relayPort)).bound,true,'retired policy releases the port');
 }finally{
  clearInterval(timer);if(child&&child.exitCode===null){child.stdin.end('stop\n');await Promise.race([new Promise(r=>child.once('exit',r)),sleep(8000)]);if(child.exitCode===null)throw new Error('owned launcher cleanup did not complete')}
  for(const s of live)s.destroy();for(const s of servers){try{s.close()}catch{}}
  if(events.some(x=>x.policyRetained||x.loopbackRemovalFailed)){await fs.writeFile(path.join(root,'recovery.json'),JSON.stringify({profile,relayPort:events.find(x=>x.event==='policy')?.relayPort,policyRetained:true}));throw new Error('owned-policy-cleanup-unconfirmed')}
  if(created)await run(launcher,['delete','--name',profile],{timeout:15000,windowsHide:true});await fs.rm(root,{recursive:true,force:true});
 }
});
