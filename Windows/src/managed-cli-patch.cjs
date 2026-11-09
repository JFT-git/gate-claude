"use strict";
const crypto = require('node:crypto');
const LEGACY = {
  desktopVersion: '1.44121.2', codeVersion: '2.1.304',
  sdkFile: '.vite/build/index.chunk-C9oYxKD_.js', sdkBytes: 1473093, sdkSHA256: '537dd37ac39a90e93abab47fa66c326216fc2bc9cc801d7fe511cc89c7df988b',
  mainFile: '.vite/build/index.chunk-BHbE7U4N.js', mainBytes: 6036846, mainSHA256: 'dfe50aee8e72e608a3cc7b73b8f4e528bc486d403470d49e2dc353d9163a83be',
  sessionsFile: '.vite/build/index.chunk-CpLncQKd.js', sessionsBytes: 63070, sessionsSHA256: 'fc411409057ed2d5fff86ce104e933a49403c29b1a96235dc25d2fe38ee80477',
  scratchFile: '.vite/build/index.chunk-yN5MKp7Y.js', scratchBytes: 3217, scratchSHA256: 'cbac1b8c0b4a05393296569b8f8a2ec65d2f334a958a441573de9d87d4549b8a',
  spawn: 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=(0,w.spawn)(t,n,{cwd:r,stdio:["pipe","pipe","pipe"],signal:a,env:i,windowsHide:!0}),',
  settings: 'this.options.managedSettings&&T.push("--managed-settings",this.options.managedSettings);',
  query: 'exports.query=qEe',
  pluginRun: 'let n=await jp(i,e,{timeout:r,env:{...process.env,PATH:a,...t.env,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1"},cwd:t.cwd,ignoreExitCode:!0})',
  hostPreseed: 'async getHostPreseedInPlacePath(){if(!Ir()||this.skipPreseedThisProcess)return null;let e=this.getHostTarget();return iSn(e.platform,e.binaryName)}',
  managedPreseed: 'async getHostPreseedInPlacePath(){let e=this.getHostTarget();if(e.platform!=="win32-x64"||this.targetVersion!=="2.1.304"||this.expectedChecksumForTarget(e)!=="aed62990b91e94efb35482fd7068cc616c6c2414084c6aa32148ca2a359e4e81")throw Error("Unsupported Claude Code version; protected launch is unavailable.");return __gateCli.resolveManagedCliPath(this.getBinaryPathForTarget(e,this.targetVersion))}',
  sessionsFactory: 'function he(e,t){let n={...t};'
};
const V4 = {
  desktopVersion: '4.23118.0', codeVersion: '2.1.317',
  sdkFile: '.vite/build/index.chunk-C-c5uMKU.js', sdkBytes: 300459, sdkSHA256: 'a9f13d9927d7c6079febe749d2caf22032444f7529d4ed06bbcdad8050eca4a4',
  mainFile: '.vite/build/index.chunk-CUXoxsyW.js', mainBytes: 7189806, mainSHA256: '8a49065ed8437a1e4d91c972524044ad58c73eebcac521729a9bc9d9472fab32',
  sessionsFile: '.vite/build/index.chunk-Ch26xtGc.js', sessionsBytes: 115434, sessionsSHA256: 'd8b5f3dd24bd8f11cc461462b7225c26f544a4a2ff9b57857712173c671ded05',
  scratchFile: '.vite/build/index.chunk-BotcpFp4.js', scratchBytes: 4299, scratchSHA256: 'b373b0e32c3f2d04639f12dddf7e86743750d67b250d51b8a980852541d5bf95',
  spawn: 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=(0,g.spawn)(t,n,{cwd:r,stdio:["pipe","pipe","pipe"],signal:a,env:i,windowsHide:!0});',
  settings: 'this.options.managedSettings&&j.push(...Mp("--managed-settings",this.options.managedSettings));',
  query: 'exports.query=og',
  pluginRun: null,
  hostPreseed: 'async getHostPreseedInPlacePath(){if(!ti()||this.skipPreseedThisProcess)return null;let e=this.getHostTarget();return zvi(e.platform,e.binaryName)}',
  managedPreseed: 'async getHostPreseedInPlacePath(){let e=this.getHostTarget();if(e.platform!=="win32-x64"||this.targetVersion!=="2.1.317"||this.expectedChecksumForTarget(e)!=="a33aa5518497dda9dca73d465d77da3fb56de5373350ff734ec20e88464efa17")throw Error("Unsupported Claude Code version; protected launch is unavailable.");return __gateCli.resolveManagedCliPath(this.getBinaryPathForTarget(e,this.targetVersion))}',
  sessionsFactory: 'return Mn(y,{'
};
const PROFILES = [LEGACY, V4];
const PREFIX = '"use strict";const __gateCli=require("./proxy-guard-managed-cli.cjs");\n';
const failure = () => Error('Unsupported Claude Code SDK; protected launch is unavailable.');
const mainFailure = () => Error('Unsupported Claude Code main module; protected launch is unavailable.');
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
function profileFor(bytes, kind) {
  const error = kind === 'main' ? mainFailure : failure;
  if (!Buffer.isBuffer(bytes)) throw error();
  const sha256 = digest(bytes), suffix = kind === 'main' ? 'mainSHA256' : kind === 'sessions' ? 'sessionsSHA256' : 'sdkSHA256', bytesKey = kind === 'main' ? 'mainBytes' : kind === 'sessions' ? 'sessionsBytes' : 'sdkBytes';
  const profile = PROFILES.find(candidate => bytes.length === candidate[bytesKey] && sha256 === candidate[suffix]);
  if (!profile && kind === 'main') throw error();
  return profile;
}
function patchManagedCliSDK(bytes) {
  const profile = profileFor(bytes, 'sdk');
  if (!profile) throw failure();
  const source = bytes.toString('utf8');
  if ([profile.spawn, profile.settings, profile.query].some(anchor => source.split(anchor).length !== 2) || source.includes('__gateCli')) throw failure();
  const spawnReplacement = profile === LEGACY
    ? 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=__gateCli.spawnManaged(e);'
    : 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=__gateCli.spawnManaged(e);';
  const settingsReplacement = profile === LEGACY
    ? 'T.push("--managed-settings",__gateCli.mergeManagedSettings(this.options.managedSettings));'
    : 'j.push(...Mp("--managed-settings",__gateCli.mergeManagedSettings(this.options.managedSettings)));';
  const changed = source.replace(profile.spawn, spawnReplacement).replace(profile.settings, settingsReplacement);
  return Buffer.from(PREFIX + changed);
}
function findManagedCliSDK(archive) {
  if (!archive || typeof archive.read !== 'function' || !archive.header?.files) throw failure();
  const candidates = [];
  function walk(files, prefix = '') {
    for (const [name, entry] of Object.entries(files)) {
      if (!name || name === '.' || name === '..' || /[\\/]/.test(name) || !entry || typeof entry !== 'object') throw failure();
      const filename = prefix + name;
      if (entry.files) { if (!entry.link && !entry.unpacked) walk(entry.files, filename + '/'); continue; }
      if (!/^\.vite\/build\/index\.chunk-[A-Za-z0-9_-]+\.js$/.test(filename) || entry.link || entry.unpacked) continue;
      const source = archive.read(filename), profile = profileFor(source, 'sdk');
      if (profile && entry.size === profile.sdkBytes) candidates.push({ filename, source, sha256: profile.sdkSHA256 });
    }
  }
  walk(archive.header.files);
  if (candidates.length !== 1) throw failure();
  patchManagedCliSDK(candidates[0].source);
  return candidates[0];
}
function archiveEntry(archive, filename) {
  let entry = archive.header;
  for (const component of filename.split('/')) {
    entry = entry.files?.[component];
    if (!entry || entry.link || entry.unpacked) return null;
  }
  return entry.files ? null : entry;
}
function findProfileEntry(archive, kind, error) {
  const fileKey = kind === 'main' ? 'mainFile' : kind === 'sessions' ? 'sessionsFile' : 'scratchFile';
  const bytesKey = kind === 'main' ? 'mainBytes' : kind === 'sessions' ? 'sessionsBytes' : 'scratchBytes';
  const candidates = [];
  for (const profile of PROFILES) {
    const filename = profile[fileKey], entry = archiveEntry(archive, filename);
    if (!entry || entry.size !== profile[bytesKey]) continue;
    const source = archive.read(filename);
    if (kind === 'scratch') {
      if (digest(source) === profile.scratchSHA256) candidates.push({ filename, source, sha256: profile.scratchSHA256 });
      continue;
    }
    const patch = kind === 'main' ? patchManagedCliMain : patchManagedCliSessions;
    try { patch(source); candidates.push({ filename, source, sha256: digest(source) }); } catch {}
  }
  if (candidates.length !== 1) throw error();
  return candidates[0];
}
function patchManagedCliMain(bytes) {
  const profile = profileFor(bytes, 'main');
  if (!profile) throw mainFailure();
  const source = bytes.toString('utf8'), anchors = [profile.pluginRun, profile.hostPreseed].filter(Boolean);
  if (anchors.some(anchor => source.split(anchor).length !== 2) || source.includes('__gateCli')) throw mainFailure();
  let changed = source;
  if (profile.pluginRun) changed = changed.replace(profile.pluginRun, 'let n=await __gateCli.runManagedCommand(i,e,{timeout:r,env:{...process.env,PATH:a,...t.env,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1"},cwd:t.cwd})');
  changed = changed.replace(profile.hostPreseed, profile.managedPreseed);
  return Buffer.from(PREFIX + changed);
}
function findManagedCliMain(archive) {
  if (!archive || typeof archive.read !== 'function' || !archive.header?.files) throw mainFailure();
  return findProfileEntry(archive, 'main', mainFailure);
}
function patchManagedCliSessions(bytes) {
  const profile = profileFor(bytes, 'sessions');
  if (!profile) throw failure();
  const source = bytes.toString('utf8');
  if (source.split(profile.sessionsFactory).length !== 2 || source.includes('__gateCli')) throw failure();
  const replacement = profile === LEGACY
    ? 'function he(e,t){t=__gateCli.configureLocalSessions(t);let n={...t};'
    : 'return Mn(__gateCli.configureLocalSessions(y),{';
  return Buffer.from(PREFIX + source.replace(profile.sessionsFactory, replacement));
}
function findManagedCliSessions(archive) {
  if (!archive || typeof archive.read !== 'function' || !archive.header?.files) throw failure();
  return findProfileEntry(archive, 'sessions', failure);
}
function findManagedCliScratch(archive) {
  if (!archive || typeof archive.read !== 'function' || !archive.header?.files) throw failure();
  return findProfileEntry(archive, 'scratch', failure);
}
module.exports = { patchManagedCliSDK, findManagedCliSDK, SDK_SHA256: LEGACY.sdkSHA256, SDK_BYTES: LEGACY.sdkBytes,
  patchManagedCliMain, findManagedCliMain, MAIN_FILE: LEGACY.mainFile, MAIN_SHA256: LEGACY.mainSHA256, MAIN_BYTES: LEGACY.mainBytes,
  patchManagedCliSessions, findManagedCliSessions, SESSIONS_FILE: LEGACY.sessionsFile, SESSIONS_SHA256: LEGACY.sessionsSHA256, SESSIONS_BYTES: LEGACY.sessionsBytes,
  findManagedCliScratch, SCRATCH_FILE: LEGACY.scratchFile, SCRATCH_SHA256: LEGACY.scratchSHA256, SCRATCH_BYTES: LEGACY.scratchBytes,
  V4_DESKTOP_VERSION: V4.desktopVersion, V4_CODE_VERSION: V4.codeVersion, V4_MAIN_FILE: V4.mainFile, V4_MAIN_SHA256: V4.mainSHA256, V4_MAIN_BYTES: V4.mainBytes,
  V4_SDK_SHA256: V4.sdkSHA256, V4_SDK_BYTES: V4.sdkBytes, V4_SESSIONS_FILE: V4.sessionsFile, V4_SESSIONS_BYTES: V4.sessionsBytes,
  V4_SCRATCH_FILE: V4.scratchFile, V4_SCRATCH_BYTES: V4.scratchBytes };
