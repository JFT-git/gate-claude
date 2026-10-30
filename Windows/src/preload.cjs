'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('guard', Object.freeze({
  init: () => ipcRenderer.invoke('guard:init'),
  choose: () => ipcRenderer.invoke('guard:choose'),
  codeWorkspace: () => ipcRenderer.invoke('guard:codeWorkspace'),
  find: () => ipcRenderer.invoke('guard:find'),
  serviceStatus: () => ipcRenderer.invoke('guard:serviceStatus'),
  serviceOperation: action => ipcRenderer.invoke('guard:serviceOperation', action),
  protocolSettings: () => ipcRenderer.invoke('guard:protocolSettings'),
  protocolCheck: () => ipcRenderer.invoke('guard:protocolCheck'),
  start: settings => ipcRenderer.invoke('guard:start', settings),
  stop: () => ipcRenderer.invoke('guard:stop'),
  resetIP: () => ipcRenderer.invoke('guard:resetIP'),
  restart: () => ipcRenderer.invoke('guard:restart'),
  export: () => ipcRenderer.invoke('guard:export'),
  subscribe: callback => { const listener = (_event, value) => callback(value); ipcRenderer.on('guard:event', listener); return () => ipcRenderer.off('guard:event', listener); }
}));
