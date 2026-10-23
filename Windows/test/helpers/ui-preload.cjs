'use strict';
// Test-only bridge. This directory is excluded from the packaged application.
const {contextBridge,ipcRenderer}=require('electron');
const api={};for(const name of ['init','find','choose','start','stop','restart','serviceStatus','serviceOperation','protocolSettings','protocolCheck','codeWorkspace','export'])api[name]=(...args)=>ipcRenderer.invoke('fixture:call',name,args);
api.subscribe=callback=>{const listener=(_event,event)=>callback(event);ipcRenderer.on('fixture:event',listener);return()=>ipcRenderer.removeListener('fixture:event',listener);};
contextBridge.exposeInMainWorld('guard',api);
