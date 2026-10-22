"use strict";
const crypto = require('node:crypto');
const SDK_SHA256 = '06001ed9af5a0fb09056c10568bf2597845a7f3974a3087b8ad632ab215d60bd';
const SDK_BYTES = 1261535;
const MAIN_FILE = '.vite/build/index.chunk-7dsQFims.js';
const MAIN_SHA256 = '403a7d93388a723d2c0688cea83861ecfbe7e08caa63c6701bcd49684100c348';
const MAIN_BYTES = 7058603;
const SESSIONS_FILE = '.vite/build/index.chunk-CFHSNuch.js';
const SESSIONS_SHA256 = 'a64cdcffa713797bc736cd2f7ac35425259779435f52116ca96c41322bcc130f';
const SESSIONS_BYTES = 96497;
const SESSIONS_FACTORY = 'function Kt(e,t){let n={...t};';
const SPAWN = 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=(0,h.spawn)(t,n,{cwd:r,stdio:["pipe","pipe","pipe"],signal:a,env:i,windowsHide:!0});';
const SETTINGS = 'managedSettings:l?O(l):void 0';
const EXPORT = 'exports.query=Ske';
const PREFIX = '"use strict";const __gateCli=require("./proxy-guard-managed-cli.cjs");\n';
// This is the Code marketplace's native CLI call, after the vendor's binary
// identity and host-auth checks. Generic Yf/Zf and child_process stay blocked.
const PLUGIN_RUN = 'Yf(i,e,{timeout:r,env:{...t.env,...o.env,PATH:s,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1"},cwd:t.cwd,stdin:t.stdin,ignoreExitCode:!0})';
const PLUGIN_AUTH = 'let o=await dAa({tag:"plugin_cli",versionIdentity:a});';
const HOST_PRESEED = 'async getHostPreseedInPlacePath(){if(!pi()||this.skipPreseedThisProcess)return null;let e=this.getHostTarget();return BHr(e.platform,e.binaryName)}';
// Reuse the vendor's prepared-binary branch so a fresh Profile never has to
// install a second CLI before the SDK can reach the protected transport. Its
// ordinary version identity and host-only behavior remain intact. A complete
// checksum check precedes the vendor path, whose folder uses only 12 hex chars.
const MANAGED_PRESEED = 'async getHostPreseedInPlacePath(){let e=this.getHostTarget();if(e.platform!=="win32-x64"||this.targetVersion!=="2.1.304"||this.expectedChecksumForTarget(e)!=="aed62990b91e94efb35482fd7068cc616c6c2414084c6aa32148ca2a359e4e81")throw Error("Unsupported Claude Code version; protected launch is unavailable.");return __gateCli.resolveManagedCliPath(this.getBinaryPathForTarget(e,this.targetVersion))}';
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
  if ([PLUGIN_RUN, PLUGIN_AUTH, HOST_PRESEED, 'async function hAa(e,t={})'].some(anchor => source.split(anchor).length !== 2) || source.includes('__gateCli')) throw mainFailure();
  return Buffer.from(PREFIX + source.replace(PLUGIN_RUN, PLUGIN_RUN.replace('Yf(', '__gateCli.runManagedCommand(')).replace(HOST_PRESEED, MANAGED_PRESEED));
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
function patchManagedCliSessions(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== SESSIONS_BYTES || digest(bytes) !== SESSIONS_SHA256) throw failure();
  const source = bytes.toString('utf8');
  if (source.split(SESSIONS_FACTORY).length !== 2 || source.includes('__gateCli')) throw failure();
  return Buffer.from(PREFIX + source.replace(SESSIONS_FACTORY, 'function Kt(e,t){t=__gateCli.configureLocalSessions(t);let n={...t};'));
}
function findManagedCliSessions(archive) {
  if (!archive || typeof archive.read !== 'function' || !archive.header?.files) throw failure();
  let entry = archive.header;
  for (const component of SESSIONS_FILE.split('/')) {
    entry = entry.files?.[component];
    if (!entry || entry.link || entry.unpacked) throw failure();
  }
  if (entry.files || entry.size !== SESSIONS_BYTES) throw failure();
  const source = archive.read(SESSIONS_FILE);
  patchManagedCliSessions(source);
  return { filename: SESSIONS_FILE, source, sha256: SESSIONS_SHA256 };
}
module.exports = { patchManagedCliSDK, findManagedCliSDK, SDK_SHA256, SDK_BYTES,
  patchManagedCliMain, findManagedCliMain, MAIN_FILE, MAIN_SHA256, MAIN_BYTES,
  patchManagedCliSessions, findManagedCliSessions, SESSIONS_FILE, SESSIONS_SHA256, SESSIONS_BYTES };
