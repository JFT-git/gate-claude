'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {spawn,execFile}=require('node:child_process'),run=require('node:util').promisify(execFile);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const quote=value=>"'"+value.replaceAll("'","''")+"'";
// Opt-in from an elevated test runner. Only the fresh task, runtime and package
// generated below are touched. The actual controller is Interactive/Limited.
test('production fence authenticates a Limited controller, drains before retire, retains deny on EOF, and preserves legacy protocol',{
 skip:process.platform!=='win32'||process.env.GATE_NATIVE_FENCE_SESSION_TEST!=='1',timeout:120000
},async t=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'gate-native-session-'));
 const native=path.resolve(__dirname,'../native'),helper=path.join(root,'SessionProbe.exe'),broker=path.join(root,'NetworkFence.exe');
 const csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
 async function ps(script){return run('powershell.exe',['-NoLogo','-NoProfile','-EncodedCommand',Buffer.from("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"+script,'utf16le').toString('base64')],{timeout:25000,windowsHide:true,maxBuffer:131072});}
 const admin=await ps("[Console]::Write((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))");
 assert.equal(admin.stdout,'True','fixture requires an elevated parent runner');
 await run(csc,['/nologo','/target:exe','/platform:x64','/out:'+broker,...['NetworkFence.cs','CodeFenceSession.cs','CodeNetworkFence.cs'].map(file=>path.join(native,file))],{timeout:15000,windowsHide:true});
 await run(csc,['/nologo','/target:exe','/platform:x64','/r:System.Web.Extensions.dll','/out:'+helper,path.join(__dirname,'helpers/NativeFenceSessionProbe.cs'),path.join(native,'CodeNetworkFence.cs')],{timeout:15000,windowsHide:true});
 let allPassed=false;const receipts=[];
 try {
  for(const entry of [{mode:'code',folder:'code'},{mode:'wrong-image',folder:'wrong-image'},{mode:'legacy',folder:'wrong-image'},{mode:'eof',folder:'eof'},{mode:'legacy',folder:'eof'}]){
   const {mode,folder}=entry;
   // Legacy recovery deliberately reuses only the EOF fixture's inert image root
   // so the production four-part protocol also removes its retained image rules.
   const id=crypto.randomBytes(16).toString('hex'),task='gate-native-session-'+id,caseRoot=path.join(root,folder),runtime=path.join(caseRoot,'Runtime-111111111111111111111111');
   await fs.mkdir(runtime,{recursive:true});await fs.copyFile(helper,path.join(runtime,'Claude.exe'));await fs.writeFile(path.join(runtime,'guard-manifest.json'),'{}');
   await fs.rm(path.join(caseRoot,'ready.json'),{force:true});await fs.rm(path.join(caseRoot,'proof.json'),{force:true});
   const config={root:caseRoot,mode,pipeName:'gate-network-fence-'+id,token:crypto.randomBytes(32).toString('hex'),containerName:'gate-code-'+crypto.randomBytes(12).toString('hex'),jobName:'Global\\gate-code-job-'+id};
   const configPath=path.join(caseRoot,'config.json');await fs.writeFile(configPath,JSON.stringify(config));let child,registered=false,exited;
   async function readResult(name){try{return JSON.parse(await fs.readFile(path.join(caseRoot,name),'utf8'))}catch(error){if(error.code==='ENOENT')return null;throw error}}
   async function waitFile(name){for(let i=0;i<800;i++){const data=await readResult(name);if(data)return data;await sleep(50)}throw new Error('native-fence-fixture-timeout-'+name)}
   try {
    await ps(`if(Get-ScheduledTask -TaskName ${quote(task)} -ErrorAction SilentlyContinue){throw 'OwnTaskCollision'};$a=New-ScheduledTaskAction -Execute ${quote(helper)} -Argument ${quote('"'+configPath+'"')};$p=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited;$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 1);$settings.Priority=4;Register-ScheduledTask -TaskName ${quote(task)} -Action $a -Principal $p -Settings $settings|Out-Null;Start-ScheduledTask -TaskName ${quote(task)}`);registered=true;
    const ready=await waitFile('ready.json');assert.equal(ready.standardUser,true);assert.equal(ready.interactiveSession,true);
    child=spawn(broker,['--pipe',config.pipeName,'--token',config.token],{windowsHide:true,stdio:'ignore'});exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>resolve({code,signal}))});
    const proof=await waitFile('proof.json');assert.equal(proof.pass,true,JSON.stringify(proof));assert.equal(proof.loopbackRestoredExactly,true);
    if(mode==='wrong-image'){assert.equal(proof.controllerImageMismatchDenied,true);assert.equal(proof.noJobOnRejectedController,true)}else if(mode==='eof')assert.equal(proof.jobKilledAfterEof,true);else assert.equal(proof.removed,true);
    if(mode==='code'||mode==='eof'){assert.equal(proof.limitedAssignSucceeded,true);if(mode==='code')assert.equal(proof.jobDrainedBeforeRemoved,true);assert.equal(proof.codeProofExact,true);assert.equal(proof.setAttributesDenied,true);assert.equal(proof.terminateDenied,true);assert.equal(proof.writeDaclDenied,true);assert.equal(proof.writeOwnerDenied,true)}else if(mode==='legacy')assert.equal(Object.hasOwn(proof.installed,'code'),false);
    const result=await Promise.race([exited,sleep(5000).then(()=>{throw new Error('native-broker-exit-timeout')})]);
    // A disconnected Windows pipe may report ERROR_BROKEN_PIPE instead of a
    // zero-byte read. Both enter the production abort cleanup; prove its state.
    if(mode==='eof')assert.ok(result.code===0||result.code===1);else assert.equal(result.code,mode==='wrong-image'?1:0);
    if(mode==='eof'){
     const cleanup=JSON.parse((await run(helper,['--cleanup-eof',configPath],{timeout:10000,windowsHide:true})).stdout);
     assert.deepEqual(cleanup,{verifiedSealedFilters:8,jobAbsent:true,exemptionAbsent:true,exactKeysDeleted:8});proof.stickyDenyVerified=true;proof.exactFixtureCleanup=cleanup;
    }
    receipts.push({mode,folder,proof});
   } finally {
    if(registered)await ps(`$t=Get-ScheduledTask -TaskName ${quote(task)} -ErrorAction SilentlyContinue;if($t){if($t.State-eq'Running'){Stop-ScheduledTask -TaskName ${quote(task)}};Unregister-ScheduledTask -TaskName ${quote(task)} -Confirm:$false}`);
    if(child&&child.exitCode===null){await Promise.race([exited,sleep(9000)]);if(child.exitCode===null){child.kill();await exited}}
   }
  }
  allPassed=true;if(process.env.GATE_NATIVE_FENCE_SESSION_RECEIPT)await fs.writeFile(process.env.GATE_NATIVE_FENCE_SESSION_RECEIPT,JSON.stringify({result:'PASS',cases:receipts},null,2));
 } finally {
  // Failed security fixtures retain their exact configuration for investigation;
  // they never use a global delete/reset to remove sticky deny policy.
  if(allPassed)await fs.rm(root,{recursive:true,force:true});else t.diagnostic('isolated native-fence fixture retained for inspection');
 }
});
