"use strict";
const crypto = require('node:crypto');
const SDK_SHA256 = '06001ed9af5a0fb09056c10568bf2597845a7f3974a3087b8ad632ab215d60bd';
const SDK_BYTES = 1261535;
const MAIN_FILE = '.vite/build/index.chunk-7dsQFims.js';
const MAIN_SHA256 = '403a7d93388a723d2c0688cea83861ecfbe7e08caa63c6701bcd49684100c348';
const MAIN_BYTES = 7058603;
const SPAWN = 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=(0,h.spawn)(t,n,{cwd:r,stdio:["pipe","pipe","pipe"],signal:a,env:i,windowsHide:!0});';
const SETTINGS = 'managedSettings:l?O(l):void 0';
const EXPORT = 'exports.query=Ske';
const PREFIX = '"use strict";const __gateCli=require("./proxy-guard-managed-cli.cjs");\n';
// This is the Code marketplace's native CLI call, after the vendor's binary
// identity and host-auth checks. Generic Yf/Zf and child_process stay blocked.
const PLUGIN_RUN = 'Yf(i,e,{timeout:r,env:{...t.env,...o.env,PATH:s,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1"},cwd:t.cwd,stdin:t.stdin,ignoreExitCode:!0})';
const PLUGIN_AUTH = 'let o=await dAa({tag:"plugin_cli",versionIdentity:a});';
const failure = () => Error('Unsupported Claude Code SDK; protected launch is unavailable.');
const mainFailure = () => Error('Unsupported Claude Code main module; protected launch is unavailable.');
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
function patchManagedCliSDK(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== SDK_BYTES || digest(bytes) !== SDK_SHA256) throw failure();
  const source = bytes.toString('utf8');
  if ([SPAWN, SETTINGS, EXPORT].some(anchor => source.split(anchor).length !== 2) || source.includes('__gateCli')) throw failure();
  const changed = source.replace(SPAWN, 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=__gateCli.spawnManaged(e);')
    .replace(SETTINGS, 'managedSettings:O(__gateCli.mergeManagedSettings(l))');
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
      if (!/^\.vite\/build\/index\.chunk-[A-Za-z0-9_-]+\.js$/.test(filename) || entry.link || entry.unpacked || entry.size !== SDK_BYTES) continue;
      const source = archive.read(filename);
      if (Buffer.isBuffer(source) && digest(source) === SDK_SHA256) candidates.push({ filename, source, sha256: SDK_SHA256 });
    }
  }
  walk(archive.header.files);
  if (candidates.length !== 1) throw failure();
  patchManagedCliSDK(candidates[0].source); // Validate every exact anchor before returning a candidate.
  return candidates[0];
}
function patchManagedCliMain(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== MAIN_BYTES || digest(bytes) !== MAIN_SHA256) throw mainFailure();
  const source = bytes.toString('utf8');
  if ([PLUGIN_RUN, PLUGIN_AUTH, 'async function hAa(e,t={})'].some(anchor => source.split(anchor).length !== 2) || source.includes('__gateCli')) throw mainFailure();
  return Buffer.from(PREFIX + source.replace(PLUGIN_RUN, PLUGIN_RUN.replace('Yf(', '__gateCli.runManagedCommand(')));
}
function findManagedCliMain(archive) {
  if (!archive || typeof archive.read !== 'function' || !archive.header?.files) throw mainFailure();
  let entry = archive.header;
  for (const component of MAIN_FILE.split('/')) {
    entry = entry.files?.[component];
    if (!entry || entry.link || entry.unpacked) throw mainFailure();
  }
  if (entry.files || entry.size !== MAIN_BYTES) throw mainFailure();
  const source = archive.read(MAIN_FILE);
  patchManagedCliMain(source); // Validate the original, never a previously patched runtime copy.
  return { filename: MAIN_FILE, source, sha256: MAIN_SHA256 };
}
module.exports = { patchManagedCliSDK, findManagedCliSDK, SDK_SHA256, SDK_BYTES,
  patchManagedCliMain, findManagedCliMain, MAIN_FILE, MAIN_SHA256, MAIN_BYTES };
