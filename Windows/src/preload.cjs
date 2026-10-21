'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('guard', Object.freeze({
  init: () => ipcRenderer.invoke('guard:init'),
  choose: () => ipcRenderer.invoke('guard:choose'),
  codeWorkspace: () => ipcRenderer.invoke('guard:codeWorkspace'),
  find: () => ipcRenderer.invoke('guard:find'),
  protocolSettings: () => ipcRenderer.invoke('guard:protocolSettings'),
  protocolCheck: () => ipcRenderer.invoke('guard:protocolCheck'),
  start: settings => ipcRenderer.invoke('guard:start', settings),
  stop: () => ipcRenderer.invoke('guard:stop'),
  restart: () => ipcRenderer.invoke('guard:restart'),
  export: () => ipcRenderer.invoke('guard:export'),
  subscribe: callback => { const listener = (_event, value) => callback(value); ipcRenderer.on('guard:event', listener); return () => ipcRenderer.off('guard:event', listener); }
}));
