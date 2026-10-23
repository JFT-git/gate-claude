'use strict';
// Exercises the real HTML/CSS/renderer with test-only IPC. No engine, service,
// vendor profile, network requests or elevation is started by this harness.
const {app,BrowserWindow,ipcMain,nativeTheme}=require('electron');const fs=require('node:fs');const path=require('node:path');const assert=require('node:assert/strict');const os=require('node:os');
const out=path.resolve(process.env.GATE_UI_TEST_OUT||path.join(os.tmpdir(),'gate-ui-smoke'));
const userData=fs.mkdtempSync(path.join(os.tmpdir(),'gate-ui-fixture-'));app.setPath('userData',userData);
const calls={},checks=[];let win,heldStart,holdStart=false,failRestart=false;
let service={schema:1,available:false,state:'unavailable',actions:[]};
const state=phase=>({state:phase,message:'Тест интерфейса · '+phase});
const settings={mode:'network',claudeSource:'auto',interval:5,timezone:'Europe/Amsterdam',language:'en-US',captureBodies:false,codeEnabled:false};
ipcMain.handle('fixture:call',async(_event,name)=>{
 calls[name]=(calls[name]||0)+1;
 if(name==='init')return{version:'0.6.9 · UI fixture',settings,state:state('idle'),protocol:{skipped:true},logs:[],records:[]};
 if(name==='serviceStatus')return service;
 if(name==='serviceOperation')throw Error('No real service exists in this fixture');
 if(name==='find')return{status:'found',path:'C:\\Fixture\\Claude.exe',message:'Тестовый путь; Claude не запускается'};
 if(name==='start'){if(holdStart)return new Promise(resolve=>heldStart=resolve);return state('running');}
 if(name==='stop')return state('blocked');
 if(name==='restart'){if(failRestart)throw Error('private-token-must-not-render');return{};}
 return{};
});
const js=source=>win.webContents.executeJavaScript(source,true);
const wait=async predicate=>{for(let n=0;n<120;n++){if(await js(predicate))return;await new Promise(r=>setTimeout(r,25));}throw Error('Timed out: '+predicate);};
const check=async(name,fn)=>{await fn();checks.push({name,status:'PASS'});};
const emit=async event=>{win.webContents.send('fixture:event',event);await new Promise(r=>setTimeout(r,30));};
const lumRatio=colors=>{const luminance=rgb=>rgb.match(/[\d.]+/g).slice(0,3).map(Number).map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((sum,v,i)=>sum+v*[.2126,.7152,.0722][i],0);const values=colors.map(luminance).sort((a,b)=>a-b);return (values[1]+.05)/(values[0]+.05);};
const buttons=()=>js(`Object.fromEntries(['start','stop','restart'].map(id=>[id,{disabled:document.getElementById(id).disabled,rect:document.getElementById(id).getBoundingClientRect().toJSON()}]))`);
app.whenReady().then(async()=>{
 try{
 fs.mkdirSync(out,{recursive:true});win=new BrowserWindow({width:1240,height:900,show:false,webPreferences:{preload:path.join(__dirname,'../test/helpers/ui-preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true}});
 win.webContents.session.webRequest.onBeforeRequest((details,callback)=>callback({cancel:!details.url.startsWith('file:')&&!details.url.startsWith('data:')}));
 const consoleErrors=[];win.webContents.on('console-message',(_event,details)=>{if(details.level==='error')consoleErrors.push(details.message);});
 await win.loadFile(path.join(__dirname,'../src/ui/index.html'));await wait(`document.body.dataset.ready==='true'&&document.body.dataset.discoveryDone==='true'&&document.getElementById('serviceState').dataset.state==='unavailable'`);
 await check('unavailable service never presents install or running success',async()=>{assert.equal(await js(`document.getElementById('serviceActions').hidden`),true);assert.match(await js(`document.getElementById('serviceMessage').textContent`),/недоступна/);});
 await check('three main buttons share one row and equal dimensions',async()=>{const b=await buttons();for(const id of ['stop','restart'])for(const key of ['y','width','height'])assert.ok(Math.abs(b.start.rect[key]-b[id].rect[key])<1,`${id}:${key}`);assert.equal(b.start.disabled,false);assert.equal(b.stop.disabled,true);});
 await check('no external scripts, styles, images or privileged renderer APIs',async()=>{assert.equal(await js(`typeof require`),'undefined');assert.equal(await js(`typeof window.guard.serviceStatus`),'function');assert.equal(await js(`Array.from(document.querySelectorAll('[src],[href]')).filter(e=>/^https?:/.test(e.getAttribute('src')||e.getAttribute('href'))).length`),0);});
 await new Promise(r=>setTimeout(r,220));
 await check('primary action text contrast at rest exceeds WCAG AA',async()=>{const colors=await js(`(()=>{const c=getComputedStyle(document.getElementById('start'));return[c.color,c.backgroundColor]})()`);assert.ok(lumRatio(colors)>=4.5,colors.join(' / '));});
 nativeTheme.themeSource='light';await new Promise(r=>setTimeout(r,150));
 await check('light theme keeps input text and button labels readable',async()=>{const field=await js(`(()=>{const c=getComputedStyle(document.getElementById('timezone'));return[c.color,c.backgroundColor]})()`);assert.ok(lumRatio(field)>=4.5,'input: '+field.join(' / '));const btn=await js(`(()=>{const c=getComputedStyle(document.getElementById('restart'));return[c.color,c.backgroundColor]})()`);assert.ok(lumRatio(btn)>=4.5,'button: '+btn.join(' / '));});
 nativeTheme.themeSource='dark';await new Promise(r=>setTimeout(r,150));
 fs.writeFileSync(path.join(out,'windows-ui-idle.png'),(await win.webContents.capturePage()).toPNG());
 await check('pending startup suppresses duplicate requests and permits stop',async()=>{holdStart=true;await js(`document.getElementById('start').click();document.getElementById('start').click()`);await wait(`document.getElementById('start').disabled&&!document.getElementById('stop').disabled`);assert.equal(calls.start,1);await js(`document.getElementById('stop').click()`);await wait(`document.body.dataset.state==='blocked'`);heldStart(state('blocked'));await new Promise(r=>setTimeout(r,60));assert.equal(calls.stop,1);holdStart=false;});
 await check('blocked session requires Guard restart',async()=>{const b=await buttons();assert.equal(b.start.disabled,true);assert.equal(b.restart.disabled,false);});
 await emit({type:'state',data:{...state('starting'),windowsApprovalPending:true}});
 await check('pending Windows approval prevents repeat restart',async()=>{assert.equal((await buttons()).restart.disabled,true);assert.equal(await js(`document.getElementById('approvalHint').hidden`),false);});
 await emit({type:'state',data:{...state('running'),profile:{timezone:'Europe/Amsterdam',language:'en-US',locale:'en-US'}}});
 await check('authoritative profile and running controls display',async()=>{assert.match(await js(`document.getElementById('profile').textContent`),/Amsterdam.*en-US/);assert.equal((await buttons()).stop.disabled,false);});
 await js(`document.getElementById('restart').click()`);
 await check('restart during active session requires inline confirmation before IPC',async()=>{assert.equal(calls.restart||0,0);assert.equal(await js(`document.getElementById('errorBanner').hidden`),true);assert.equal(await js(`document.getElementById('restartConfirm').hidden`),false);assert.equal(await js(`document.activeElement.id`),'restartConfirmYes');});
 await emit({type:'state',data:{...state('running'),profile:{timezone:'Europe/Amsterdam',language:'en-US',locale:'en-US'}}});
 await emit({type:'state',data:{...state('running'),profile:{timezone:'Europe/Amsterdam',language:'en-US',locale:'en-US'}}});
 await check('repeated state events keep confirmation visible and focused',async()=>{assert.equal(await js(`document.getElementById('restartConfirm').hidden`),false);assert.equal(await js(`document.activeElement.id`),'restartConfirmYes');});
 await emit({type:'state',data:state('blocked')});
 await check('transition to blocked hides confirmation and returns focus',async()=>{assert.equal(await js(`document.getElementById('restartConfirm').hidden`),true);assert.equal(await js(`document.activeElement.id`),'restart');});
 await js(`document.getElementById('dismissError').click()`);
 await emit({type:'state',data:{...state('running'),profile:{timezone:'Europe/Amsterdam',language:'en-US',locale:'en-US'}}});
 await js(`document.getElementById('restart').click()`);
 failRestart=true;await js(`document.getElementById('restartConfirmYes').click()`);await wait(`!document.getElementById('errorBanner').hidden`);
 await check('IPC failure is visible, sanitized and unlocks controls',async()=>{assert.equal(await js(`document.body.innerText.includes('private-token')`),false);assert.equal((await buttons()).restart.disabled,false);assert.match(await js(`document.getElementById('lastOperation').textContent`),/нет подтверждения/);});
 await check('error opens logs with focus',async()=>{await js(`document.getElementById('errorLogs').click()`);assert.equal(await js(`document.activeElement.id`),'logs');});
 await check('keyboard tabs support End/Home and ARIA state',async()=>{await js(`document.getElementById('logsTab').dispatchEvent(new KeyboardEvent('keydown',{key:'End',bubbles:true}))`);assert.equal(await js(`document.activeElement.id`),'trafficTab');assert.equal(await js(`document.getElementById('trafficTab').getAttribute('aria-selected')`),'true');await js(`document.getElementById('trafficTab').dispatchEvent(new KeyboardEvent('keydown',{key:'Home',bubbles:true}))`);assert.equal(await js(`document.activeElement.id`),'logsTab');});
 await emit({type:'log',data:{date:new Date().toISOString(),kind:'event',message:'<img src=x onerror=alert(1)> fixture'}});
 await check('diagnostic content is escaped',async()=>{assert.equal(await js(`document.getElementById('logs').querySelectorAll('img').length`),0);assert.match(await js(`document.getElementById('logs').textContent`),/<img/);});
 for(const phase of ['not_installed','installing','running','stopped','error','update_required']){service={schema:1,available:true,state:phase,actions:phase==='not_installed'?['install']:[]};await emit({type:'service',data:service});await check('fixture-only service state: '+phase,async()=>assert.equal(await js(`document.getElementById('serviceState').dataset.state`),phase));}
 service={schema:1,available:false,state:'unavailable',actions:[]};await emit({type:'service',data:service});await emit({type:'state',data:state('idle')});await js(`document.getElementById('dismissError').click()`);
 win.setSize(640,850);await new Promise(r=>setTimeout(r,60));
 await check('640px window retains inline equal controls',async()=>{const b=await buttons();assert.ok(Math.abs(b.start.rect.y-b.restart.rect.y)<1);assert.ok(Math.abs(b.start.rect.width-b.restart.rect.width)<1);assert.equal(await js(`document.documentElement.scrollWidth<=window.innerWidth`),true);});
 win.webContents.setZoomFactor(2);await new Promise(r=>setTimeout(r,80));
 await check('200 percent zoom stacks controls without text overflow',async()=>{assert.equal(await js(`document.documentElement.scrollWidth<=window.innerWidth`),true);const b=await buttons();assert.ok(b.restart.rect.y>b.start.rect.y+10,'buttons must stack at 200 percent zoom');assert.ok(Math.abs(b.start.rect.width-b.restart.rect.width)<2,'stacked buttons share width');const leak=await js(`(()=>{const btn=document.getElementById('restart').getBoundingClientRect();const span=document.getElementById('restart').querySelector('span').getBoundingClientRect();return span.left>=btn.left-1&&span.right<=btn.right+1&&span.top>=btn.top-1&&span.bottom<=btn.bottom+1})()`);assert.ok(leak,'label stays inside button bounds');});
 await js(`document.getElementById('sessionActions').scrollIntoView({block:'center'})`);
 fs.writeFileSync(path.join(out,'windows-ui-200-percent.png'),(await win.webContents.capturePage()).toPNG());
 assert.deepEqual(consoleErrors,[]);
 fs.writeFileSync(path.join(out,'ui-validation.json'),JSON.stringify({schema:1,mode:'REAL_RENDERER_TEST_ONLY_IPC',engineTests:'NOT_RUN_BY_THIS_HARNESS',platform:process.platform,electron:process.versions.electron,checks},null,2)+'\n');
 console.log(JSON.stringify({status:'PASS',checks:checks.length,out}));win.destroy();app.exit(0);
 }catch(error){fs.mkdirSync(out,{recursive:true});fs.writeFileSync(path.join(out,'ui-failure.txt'),error.stack);console.error(error.stack);win?.destroy();app.exit(1);}
});
app.on('will-quit',()=>fs.rmSync(userData,{recursive:true,force:true}));
