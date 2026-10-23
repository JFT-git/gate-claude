'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const {ServiceIntegration,STATES,validateStatus}=require('../src/service-integration.cjs');
const {controls,service}=require('../src/ui/view-model.js');
const snapshot=(state,actions=[])=>({schema:1,available:true,state,version:'1.0.0',actions});
test('production has no service and cannot report installation success',async()=>{
 const api=new ServiceIntegration();assert.equal((await api.status()).available,false);
 for(const op of ['install','start','stop','update','uninstall'])assert.equal((await api.invoke(op)).code,'SERVICE_API_UNAVAILABLE');
 assert.deepEqual(service(await api.status()).actions,[]);
});
test('six authoritative states are represented without enabling session routing',()=>{
 for(const state of STATES){const value=validateStatus(snapshot(state));assert.equal(value.state,state);assert.equal(value.sessionRoutingSupported,false);assert.notEqual(service(value).key,'unavailable');}
});
test('malformed or unknown capabilities never reach backend operations',async()=>{
 for(const value of [snapshot('imaginary'),snapshot('running',['shell']),snapshot('running',['stop','stop']),{...snapshot('running'),version:'secret'}])assert.throws(()=>validateStatus(value));
 let calls=0;const api=new ServiceIntegration({getStatus:()=>snapshot('running',[]),stop:()=>calls++});
 assert.equal((await api.invoke('stop')).code,'SERVICE_ACTION_UNAVAILABLE');assert.equal((await api.invoke('shell')).code,'SERVICE_ACTION_INVALID');assert.equal(calls,0);
});
test('operations read back backend status and suppress duplicate requests',async()=>{
 let release,calls=0;const api=new ServiceIntegration({getStatus:()=>snapshot('not_installed',['install']),install:()=>{calls++;return new Promise(resolve=>release=resolve);}});
 const first=api.invoke('install');await new Promise(setImmediate);
 assert.equal((await api.invoke('install')).code,'SERVICE_BUSY');release();
 assert.equal((await first).state,'not_installed');assert.equal(calls,1);assert.equal(api.pending,false);
});
test('backend errors are not exposed and locks recover after failure',async()=>{
 const api=new ServiceIntegration({getStatus:()=>snapshot('stopped',['start']),start:()=>{throw Error('private token');}});
 const result=await api.invoke('start');assert.equal(result.code,'SERVICE_OPERATION_FAILED');assert.ok(!JSON.stringify(result).includes('private token'));assert.equal(api.pending,false);
 const bad=new ServiceIntegration({getStatus:()=>{throw Error('private path');}});assert.equal((await bad.status()).code,'SERVICE_STATUS_FAILED');
});
test('status capabilities are immutable copies',()=>{const original=snapshot('stopped',['start']);const copy=validateStatus(original);original.actions.push('uninstall');assert.deepEqual(copy.actions,['start']);assert.ok(Object.isFrozen(copy.actions));});
test('session controls preserve stop during startup and require restart after blocking',()=>{
 assert.equal(controls({state:'idle'},[],false).start,false);
 const starting=controls({state:'idle'},['start']);assert.equal(starting.start,false);assert.equal(starting.stop,true);assert.equal(starting.restart,false);
 for(const phase of ['checking','starting','running','rechecking']){const c=controls({state:phase});assert.equal(c.start,false);assert.equal(c.stop,true);assert.equal(c.settings,false);}
 const blocked=controls({state:'blocked'});assert.equal(blocked.start,false);assert.equal(blocked.restart,true);assert.equal(blocked.primary,'restart');
 assert.equal(controls({state:'starting',windowsApprovalPending:true}).restart,false);
 for(const pending of ['start','stop','restart'])assert.equal(controls({state:'idle'},[pending]).restart,false);
});
