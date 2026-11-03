"use strict";
const crypto = require('node:crypto');
const SDK_SHA256 = '537dd37ac39a90e93abab47fa66c326216fc2bc9cc801d7fe511cc89c7df988b';
const SDK_BYTES = 1473093;
const MAIN_FILE = '.vite/build/index.chunk-BHbE7U4N.js';
const MAIN_SHA256 = 'dfe50aee8e72e608a3cc7b73b8f4e528bc486d403470d49e2dc353d9163a83be';
const MAIN_BYTES = 6036846;
const SESSIONS_FILE = '.vite/build/index.chunk-CpLncQKd.js';
const SESSIONS_SHA256 = 'fc411409057ed2d5fff86ce104e933a49403c29b1a96235dc25d2fe38ee80477';
const SESSIONS_BYTES = 63070;
const SESSIONS_FACTORY = 'function he(e,t){let n={...t};';
const SCRATCH_FILE = '.vite/build/index.chunk-yN5MKp7Y.js';
const SCRATCH_SHA256 = 'cbac1b8c0b4a05393296569b8f8a2ec65d2f334a958a441573de9d87d4549b8a';
const SCRATCH_BYTES = 3217;
const SPAWN = 'spawnLocalProcess(e){let{command:t,args:n,cwd:r,env:i,signal:a}=e,o=(0,w.spawn)(t,n,{cwd:r,stdio:["pipe","pipe","pipe"],signal:a,env:i,windowsHide:!0}),';
const SETTINGS = 'this.options.managedSettings&&T.push("--managed-settings",this.options.managedSettings);';
const EXPORT = 'exports.query=qEe';
const PREFIX = '"use strict";const __gateCli=require("./proxy-guard-managed-cli.cjs");\n';
// HostCLIRunner resolves the pinned binary before invoking the marketplace CLI.
const PLUGIN_RUN = 'let n=await jp(i,e,{timeout:r,env:{...process.env,PATH:a,...t.env,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1"},cwd:t.cwd,ignoreExitCode:!0})';
const HOST_PRESEED = 'async getHostPreseedInPlacePath(){if(!Ir()||this.skipPreseedThisProcess)return null;let e=this.getHostTarget();return iSn(e.platform,e.binaryName)}';
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
    .replace(SETTINGS, 'T.push("--managed-settings",__gateCli.mergeManagedSettings(this.options.managedSettings));');
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
  if ([PLUGIN_RUN, HOST_PRESEED].some(anchor => source.split(anchor).length !== 2) || source.includes('__gateCli')) throw mainFailure();
  return Buffer.from(PREFIX + source.replace(PLUGIN_RUN, 'let n=await __gateCli.runManagedCommand(i,e,{timeout:r,env:{...process.env,PATH:a,...t.env,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:"1"},cwd:t.cwd})').replace(HOST_PRESEED, MANAGED_PRESEED));
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
  return Buffer.from(PREFIX + source.replace(SESSIONS_FACTORY, 'function he(e,t){t=__gateCli.configureLocalSessions(t);let n={...t};'));
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
function findManagedCliScratch(archive) {
  if (!archive || typeof archive.read !== 'function' || !archive.header?.files) throw failure();
  let entry = archive.header;
  for (const component of SCRATCH_FILE.split('/')) {
    entry = entry.files?.[component];
    if (!entry || entry.link || entry.unpacked) throw failure();
  }
  if (entry.files || entry.size !== SCRATCH_BYTES) throw failure();
  const source = archive.read(SCRATCH_FILE);
  if (!Buffer.isBuffer(source) || source.length !== SCRATCH_BYTES || digest(source) !== SCRATCH_SHA256) throw failure();
  return { filename: SCRATCH_FILE, source, sha256: SCRATCH_SHA256 };
}
module.exports = { patchManagedCliSDK, findManagedCliSDK, SDK_SHA256, SDK_BYTES,
  patchManagedCliMain, findManagedCliMain, MAIN_FILE, MAIN_SHA256, MAIN_BYTES,
  patchManagedCliSessions, findManagedCliSessions, SESSIONS_FILE, SESSIONS_SHA256, SESSIONS_BYTES,
  findManagedCliScratch, SCRATCH_FILE, SCRATCH_SHA256, SCRATCH_BYTES };
