'use strict';
// Release-time only. Inputs are the private trees already extracted from the
// official, checksum-verified assets and the pinned Guard PowerShell bootstrap.
// This script never executes an installer, compiler or generated launcher.
const fs = require('node:fs').promises;
const path = require('node:path');
const crypto = require('node:crypto');
const { SOURCE_POLICY, safeFilesystem, validatePolicy } = require('../src/code-tools.cjs');
const { LIMITS, sha256, manifestSHA256, validateName, validateFiles, zipEntry, zipEnd } = require('../src/portable-zip.cjs');
const bad = () => Error('Portable tool release preparation failed');
// PortableGit's official post-install copies these from the build machine or
// generates mount state. Never distribute host-specific data with the tools.
const GIT_MACHINE_FILES = new Set(['etc/hosts', 'etc/networks', 'etc/protocols', 'etc/services', 'etc/mtab']);
async function collectFiles(root, safe) {
  await safe.inspect(root, true); const files = []; let total = 0;
  async function visit(directory, prefix) {
    for (const name of (await safe.fs.readdir(directory)).sort()) {
      const relative = prefix ? prefix + '/' + name : name, file = path.join(directory, name), stat = await safe.fs.lstat(file);
      validateName(relative);
      if (stat.isDirectory()) { await safe.inspect(file, true); await visit(file, relative); }
      else { const bytes = await safe.read(file, LIMITS.file); if (bytes.length !== stat.size) throw bad(); files.push({ path: relative, absolute: file, size: bytes.length, sha256: sha256(bytes) }); total += bytes.length; if (files.length > LIMITS.entries || total > LIMITS.expanded) throw bad(); }
    }
  }
  await visit(root, ''); return files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
async function buildZip(destination, files, safe) {
  const handle = await safe.fs.open(destination, 'wx', 0o600), central = [], manifest = [], digest = crypto.createHash('sha256'); let offset = 0;
  async function write(bytes) { await handle.writeFile(bytes); digest.update(bytes); offset += bytes.length; if (offset > LIMITS.archive) throw bad(); }
  try {
    for (const file of files) {
      const bytes = await safe.read(file.absolute, file.size); if (bytes.length !== file.size || sha256(bytes) !== file.sha256) throw bad();
      const entry = zipEntry(file.path, bytes, offset); manifest.push(entry.file); central.push(entry.central); for (const piece of entry.local) await write(piece);
    }
    validateFiles(manifest); const centralOffset = offset; for (const bytes of central) await write(bytes);
    await write(zipEnd(manifest.length, offset - centralOffset, centralOffset)); await handle.sync();
    return { files: manifest, archiveSHA256: digest.digest('hex'), archiveSize: offset, expandedSize: manifest.reduce((size, file) => size + file.size, 0) };
  } finally { await handle.close(); }
}
async function powerShellFiles(files, bootstrapRoot, source, safe) {
  const apphost = files.find(file => file.path === 'pwsh.exe'); if (!apphost) throw bad();
  // Authenticate the official distribution independently of our bootstrap.
  // Accept the former byte-identical legacy alias in private source staging.
  if (!files.some(file => file.path === 'powershell.exe')) files.push({ ...apphost, path: 'powershell.exe' });
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  if (manifestSHA256(files.map(({ path, size, sha256 }) => ({ path, size, sha256 }))) !== source.sourceTreeSHA256) throw bad();
  const bootstrap = await collectFiles(bootstrapRoot, safe);
  if (bootstrap.map(file => file.path).join(',') !== 'Guard.PowerShell.ps1,Guard.PowerShell.pssc,GuardPowerShell.exe' || manifestSHA256(bootstrap.map(({ path, size, sha256 }) => ({ path, size, sha256 }))) !== source.bootstrapSHA256) throw bad();
  const launcher = bootstrap.find(file => file.path === 'GuardPowerShell.exe');
  // The official .NET apphost embeds pwsh.dll and retains its original bytes.
  // Both public entry points run the same pinned configuration-file launcher.
  return [...files.filter(file => !['pwsh.exe', 'powershell.exe'].includes(file.path)),
    { ...apphost, path: 'GuardPwsh.exe' }, { ...launcher, path: 'pwsh.exe' }, { ...launcher, path: 'powershell.exe' },
    ...bootstrap.filter(file => file.path !== 'GuardPowerShell.exe')].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
async function buildCodeTools(inputs, testdeps = {}) {
  const safe = safeFilesystem(testdeps.fs || fs), policy = testdeps.sourcePolicy || SOURCE_POLICY; let created = false;
  const keys = ['gitRoot', 'powerShellRoot', 'powerShellBootstrap', 'gitAsset', 'powerShellAsset', 'output'];
  try {
    if (!inputs || Object.keys(inputs).sort().join(',') !== keys.sort().join(',')) throw bad();
    for (const key of keys) if (typeof inputs[key] !== 'string' || !path.isAbsolute(inputs[key])) throw bad();
    await safe.inspect(path.dirname(inputs.output), true);
    const prepared = [];
    for (const id of ['git', 'powershell']) {
      const source = policy[id], root = inputs[id === 'git' ? 'gitRoot' : 'powerShellRoot'], assetPath = inputs[id === 'git' ? 'gitAsset' : 'powerShellAsset'];
      const asset = await safe.read(assetPath, source.sourceSize); if (asset.length !== source.sourceSize || sha256(asset) !== source.sourceSHA256) throw bad();
      let files = (await collectFiles(root, safe)).filter(file => id !== 'git' || !GIT_MACHINE_FILES.has(file.path));
      if (id === 'powershell') files = await powerShellFiles(files, inputs.powerShellBootstrap, source, safe);
      // Authenticate every file before creating any output; never briefly write
      // an archive containing an added local profile, test fixture or secret.
      if (manifestSHA256(files.map(({ path, size, sha256 }) => ({ path, size, sha256 }))) !== source.treeSHA256) throw bad();
      for (const [name, expected] of Object.entries(source.anchors)) {
        const file = files.find(entry => entry.path === name); if (!file || file.sha256 !== expected) throw bad();
      }
      prepared.push({ source, files });
    }
    // Refuse existing output, including empty directories and junctions.
    await safe.fs.mkdir(inputs.output, { mode: 0o700 }); created = true; await safe.inspect(inputs.output, true);
    const result = { schemaVersion: 1, platform: 'win32-x64', tools: [] };
    for (const { source, files } of prepared) {
      const archive = await buildZip(path.join(inputs.output, source.archiveName), files, safe);
      result.tools.push({ id: source.id, version: source.version, archiveName: source.archiveName, ...archive, source: { name: source.sourceName, size: source.sourceSize, sha256: source.sourceSHA256 } });
    }
    validatePolicy(result, policy); const bytes = Buffer.from(JSON.stringify(result, null, 2) + '\n');
    await safe.fs.writeFile(path.join(inputs.output, 'code-tools-policy.json'), bytes, { flag: 'wx', mode: 0o600 });
    return { policy: result, policySHA256: sha256(bytes) };
  } catch {
    if (created) { try { await safe.fs.rm(inputs.output, { recursive: true, force: true }); } catch {} }
    throw bad();
  }
}
function parseArguments(argv) {
  const mapping = { '--git-root': 'gitRoot', '--powershell-root': 'powerShellRoot', '--powershell-bootstrap': 'powerShellBootstrap', '--git-asset': 'gitAsset', '--powershell-asset': 'powerShellAsset', '--output': 'output' }, result = {};
  if (argv.length !== 12) throw bad();
  for (let index = 0; index < argv.length; index += 2) { const key = mapping[argv[index]]; if (!key || key in result || !path.isAbsolute(argv[index + 1])) throw bad(); result[key] = argv[index + 1]; }
  return result;
}
if (require.main === module) {
  Promise.resolve().then(() => buildCodeTools(parseArguments(process.argv.slice(2)))).then(result => {
    console.log(JSON.stringify({ ok: true, policySHA256: result.policySHA256, tools: result.policy.tools.map(tool => ({ name: tool.archiveName, sha256: tool.archiveSHA256, archiveSize: tool.archiveSize, expandedSize: tool.expandedSize, files: tool.files.length })), runtimeSmokeRequired: true }));
  }).catch(() => { console.error(JSON.stringify({ ok: false, error: 'portable-tools-build-failed' })); process.exitCode = 1; });
}
module.exports = { buildCodeTools, collectFiles, parseArguments };
