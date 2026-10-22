'use strict';
const rawFS = require('./raw-fs.cjs');
const path = require('node:path');
const crypto = require('node:crypto');
const { LIMITS, manifestSHA256, validateFiles, parsePortableZip, inflateEntryAsync } = require('./portable-zip.cjs');
const { sha256 } = require('./async-bytes.cjs');
// This is source provenance, not permission to execute a downloaded installer.
// Release preparation repacks the verified, already extracted official trees.
// Tree hashes cover canonical path/size/SHA256 records: the official Git SFX
// after its own post-install, excluding five generated machine files, and the
// official PowerShell ZIP with its apphost preserved as GuardPwsh.exe and the
// separately pinned Guard launcher, configuration and session prelude.
const SOURCE_POLICY = Object.freeze({
  git: Object.freeze({ id: 'git', version: '2.56.0.windows.2', archiveName: 'GateCodeTools-Git-2.56.0.zip', sourceName: 'PortableGit-2.56.0.2-64-bit.7z.exe', sourceSize: 60027568, sourceSHA256: '075e158ef8e1f0ab80b347e245405d3eca735c2dc88fd8e032e137d0ca61f61b', treeSHA256: '3c7a6d240b765b765a41c34c5bb58bd0904aced00bb5e5966674a7fd1378a504', anchors: Object.freeze({ 'cmd/git.exe': '54bda91c773c6bba2b970424423cfcb80552d92dc6967d766f98931fe1251a54', 'bin/bash.exe': '6cc575e9112efe6253b6a6999c12aa0240cb3f511aeda3480ae026edc0dc5280', 'usr/bin/bash.exe': '5490d0da5e7cf9d92068cc48fcc590f2bcf8564add8ff91c3b5fe541eb2d72e3' }) }),
  powershell: Object.freeze({ id: 'powershell', version: '7.6.7', archiveName: 'GateCodeTools-PowerShell-7.6.7.zip', sourceName: 'PowerShell-7.6.7-win-x64.zip', sourceSize: 106364316, sourceSHA256: 'd2f952ebdbf24386cb8923553aa58e41a846db35a6155ea04c58142a4b16dbb7', sourceTreeSHA256: '4c58e89bfb72e99280b5077193eff0c9828729aa4818ce3ecab5d8332b61b41a', bootstrapSHA256: 'bb28c9361cb153f21caa06b3c423076308d7900c4256c45c8a508d740cd3f1f4', treeSHA256: 'e89cb434541a1e322e92781a10f4373805d221f56360bff1908cddf0cb230b11', anchors: Object.freeze({ 'Guard.PowerShell.ps1': 'c74113ce8f57ddeff9934ca5b128aba18f9f8ff96b56291f0ce5a6defdf9108b', 'Guard.PowerShell.pssc': 'de9cb67beb914e77629f88d6a03fead4747a8cb305d0e19a826e526d0c4490f6', 'GuardPwsh.exe': 'fa2c8bb1e35cdd62ad15cd06a1d8f2c5961e9725a9bfa1e7cfd2c322f49e9619', 'powershell.exe': 'eba66fbca8327dfaccd43d17f570c7d604424c81a8ecd6395e6627dd2f77d9b4', 'pwsh.exe': 'eba66fbca8327dfaccd43d17f570c7d604424c81a8ecd6395e6627dd2f77d9b4' }) })
});
const MAX_POLICY_BYTES = 8 * 1024 * 1024;
const fail = () => Error('Не удалось безопасно подготовить Git и PowerShell. Проверьте комплект переносимых инструментов Guard.');
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys.split(',').sort().join(',');
function validatePolicy(policy, sourcePolicy = SOURCE_POLICY) {
  if (!exactKeys(policy, 'schemaVersion,platform,tools') || policy.schemaVersion !== 1 || policy.platform !== 'win32-x64' || !Array.isArray(policy.tools) || policy.tools.length !== 2) throw fail();
  for (let index = 0; index < 2; index++) {
    const tool = policy.tools[index], source = sourcePolicy[index === 0 ? 'git' : 'powershell'];
    if (!exactKeys(tool, 'id,version,archiveName,archiveSHA256,archiveSize,expandedSize,source,files') || tool.id !== source.id || tool.version !== source.version || tool.archiveName !== source.archiveName || !/^[a-f0-9]{64}$/.test(tool.archiveSHA256) || !Number.isSafeInteger(tool.archiveSize) || tool.archiveSize < 22 || tool.archiveSize > LIMITS.archive || !Number.isSafeInteger(tool.expandedSize) || validateFiles(tool.files) !== tool.expandedSize) throw fail();
    if (!exactKeys(tool.source, 'name,size,sha256') || tool.source.name !== source.sourceName || tool.source.size !== source.sourceSize || tool.source.sha256 !== source.sourceSHA256) throw fail();
    if (manifestSHA256(tool.files) !== source.treeSHA256) throw fail();
    for (const [name, digest] of Object.entries(source.anchors)) if (tool.files.find(file => file.path === name)?.sha256 !== digest) throw fail();
  }
  return policy;
}
function samePath(a, b) { const first = path.resolve(a), second = path.resolve(b); return process.platform === 'win32' ? first.toLowerCase() === second.toLowerCase() : first === second; }
function safeFilesystem(fs = rawFS.promises) {
  async function inspect(file, directory, maximum = Infinity) {
    if (typeof file !== 'string' || !path.isAbsolute(file) || process.platform === 'win32' && !/^[a-z]:[\\/]/i.test(file)) throw fail();
    const absolute = path.resolve(file), root = path.parse(absolute).root; let current = root;
    for (const part of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, part); const stat = await fs.lstat(current);
      if (stat.isSymbolicLink() || stat.attributes !== undefined && (stat.attributes & 1024) || !samePath(await fs.realpath(current), current)) throw fail();
      if (current !== absolute && !stat.isDirectory()) throw fail();
      if (current === absolute && (directory ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1 || stat.size < 0 || stat.size > maximum)) throw fail();
    }
    return absolute;
  }
  async function directory(file) {
    await inspect(path.dirname(file), true);
    try { await fs.mkdir(file, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    return inspect(file, true);
  }
  async function read(file, maximum) {
    await inspect(file, false, maximum);
    // Recheck the open file too, so a substituted hardlink cannot supply bytes
    // between the path inspection and read. Native preparation later pins ACLs.
    const handle = await fs.open(file, 'r');
    try {
      const stat = await handle.stat(), named = await fs.lstat(file);
      if (!stat.isFile() || stat.nlink !== 1 || !Number.isSafeInteger(stat.size) || stat.size < 0 || stat.size > maximum || named.isSymbolicLink() || named.dev !== stat.dev || named.ino !== stat.ino || !samePath(await fs.realpath(file), file)) throw fail();
      const bytes = Buffer.alloc(stat.size); let offset = 0;
      while (offset < bytes.length) { const result = await handle.read(bytes, offset, bytes.length - offset, offset); if (!result.bytesRead) throw fail(); offset += result.bytesRead; }
      const extra = await handle.read(Buffer.alloc(1), 0, 1, offset), after = await handle.stat();
      if (extra.bytesRead || after.size !== stat.size || after.nlink !== 1 || after.dev !== stat.dev || after.ino !== stat.ino) throw fail();
      return bytes;
    }
    finally { await handle.close(); }
  }
  return { fs, inspect, directory, read };
}
async function systemPathEntries(environment, safe) {
  const names = Object.keys(environment).filter(name => name.toLowerCase() === 'systemroot');
  if (names.length !== 1) throw fail();
  const root = environment[names[0]];
  if (typeof root !== 'string' || /[;\x00-\x1f"%]/.test(root) || !path.isAbsolute(root) || !samePath(root, path.normalize(root)) || path.normalize(root) !== root || process.platform === 'win32' && !/^[a-z]:\\[^\\]/i.test(root)) throw fail();
  for (const name of Object.keys(environment).filter(name => name.toLowerCase() === 'windir')) if (!samePath(environment[name], root)) throw fail();
  await safe.inspect(root, true); const system32 = path.join(root, 'System32'); await safe.inspect(system32, true);
  return [system32, root];
}
async function verifyTree(root, files, safe) {
  const expectedFiles = new Map(files.map(file => [file.path, file])), expectedDirectories = new Set();
  for (const file of files) { const parts = file.path.split('/'); parts.pop(); while (parts.length) { expectedDirectories.add(parts.join('/')); parts.pop(); } }
  await safe.inspect(root, true); const seenFiles = new Set(), seenDirectories = new Set();
  async function visit(directory, relative) {
    for (const name of await safe.fs.readdir(directory)) {
      const entry = relative ? relative + '/' + name : name, absolute = path.join(directory, name);
      if (expectedDirectories.has(entry)) { await safe.inspect(absolute, true); seenDirectories.add(entry); await visit(absolute, entry); }
      else {
        const expected = expectedFiles.get(entry); if (!expected) throw fail();
        const bytes = await safe.read(absolute, expected.size);
        if (bytes.length !== expected.size || await sha256(bytes) !== expected.sha256) throw fail(); seenFiles.add(entry);
      }
    }
  }
  await visit(root, ''); if (seenFiles.size !== files.length || seenDirectories.size !== expectedDirectories.size) throw fail();
}
// `resources` is the trusted Guard package directory, never a download folder.
// Its build-generated policy pins every sidecar byte and every extracted file.
// `archives` contains absolute gitArchive/powerShellArchive paths selected by the
// controller. This module performs no downloads, subprocesses, ACL or PATH edits.
async function prepareCodeTools(guardRoot, resources, archives, testdeps = {}) {
  const safe = safeFilesystem(testdeps.fs), sourcePolicy = testdeps.sourcePolicy || SOURCE_POLICY;
  const randomBytes = testdeps.randomBytes || crypto.randomBytes; let staging;
  try {
    if ((testdeps.platform || process.platform) !== 'win32' || (testdeps.arch || process.arch) !== 'x64' || !exactKeys(archives, 'gitArchive,powerShellArchive')) throw fail();
    await safe.inspect(guardRoot, true); await safe.inspect(resources, true);
    const systemPaths = await systemPathEntries(testdeps.environment || process.env, safe);
    const policyBytes = await safe.read(path.join(resources, 'code-tools-policy.json'), MAX_POLICY_BYTES), policy = validatePolicy(JSON.parse(policyBytes.toString('utf8')), sourcePolicy);
    const parsed = [];
    // Authenticate and preflight both archives before creating any output.
    for (let index = 0; index < 2; index++) {
      const tool = policy.tools[index], archivePath = archives[index === 0 ? 'gitArchive' : 'powerShellArchive'];
      if (!samePath(archivePath, path.join(resources, 'CodeTools', tool.archiveName))) throw fail();
      const archive = await safe.read(archivePath, tool.archiveSize);
      if (archive.length !== tool.archiveSize || await sha256(archive) !== tool.archiveSHA256) throw fail();
      parsed.push(parsePortableZip(archive, tool.files));
    }
    const toolsRoot = await safe.directory(path.join(guardRoot, 'CodeTools')), toolRoots = [];
    for (let index = 0; index < 2; index++) {
      const tool = policy.tools[index], target = path.join(toolsRoot, (index === 0 ? 'Git-' : 'PowerShell-') + tool.archiveSHA256);
      let exists = false; try { await safe.fs.lstat(target); exists = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (exists) await verifyTree(target, tool.files, safe);
      else {
        const nonce = randomBytes(16).toString('hex'); if (!/^[a-f0-9]{32}$/.test(nonce)) throw fail();
        const candidate = path.join(toolsRoot, 'Preparing-' + nonce); await safe.fs.mkdir(candidate, { mode: 0o700 }); staging = candidate; await safe.inspect(staging, true);
        const createdDirectories = new Set([staging]);
        for (const entry of parsed[index].entries) {
          const parts = entry.path.split('/'), leaf = parts.pop(); let directory = staging;
          for (const part of parts) {
            directory = path.join(directory, part);
            if (!createdDirectories.has(directory)) { await safe.directory(directory); createdDirectories.add(directory); }
          }
          // Check the complete parent chain before every file write, while
          // avoiding repeated mkdir calls for thousands of shared prefixes.
          await safe.inspect(directory, true);
          const bytes = await inflateEntryAsync(entry); await safe.fs.writeFile(path.join(directory, leaf), bytes, { flag: 'wx', mode: 0o600 });
        }
        await verifyTree(staging, tool.files, safe);
        // A concurrent installer fails closed; it cannot replace an existing tree.
        await safe.fs.rename(staging, target); staging = undefined; await verifyTree(target, tool.files, safe);
      }
      toolRoots.push(target);
    }
    const [gitRoot, powerShellRoot] = toolRoots, pathEntries = Object.freeze([path.join(gitRoot, 'cmd'), path.join(gitRoot, 'usr', 'bin'), powerShellRoot, ...systemPaths]);
    // MSYS Bash cannot initialize in the zero-capability AppContainer. Select
    // the CLI's supported PowerShell tool while keeping native Git available.
    return { toolRoots: Object.freeze(toolRoots), gitRoot, powerShellRoot, policySHA256: await sha256(policyBytes),
      gitExecutable: path.join(gitRoot, 'cmd', 'git.exe'), bashExecutable: path.join(gitRoot, 'bin', 'bash.exe'), powerShellExecutable: path.join(powerShellRoot, 'powershell.exe'),
      pathEntries,
      environment: Object.freeze({ PATH: pathEntries.join(';'), GIT_EXEC_PATH: path.join(gitRoot, 'ucrt64', 'libexec', 'git-core'), GIT_TEMPLATE_DIR: path.join(gitRoot, 'ucrt64', 'share', 'git-core', 'templates'), GIT_CONFIG_NOSYSTEM: '1',
        CLAUDE_CODE_USE_POWERSHELL_TOOL: '1', PSModulePath: path.join(powerShellRoot, 'Modules'), POWERSHELL_TELEMETRY_OPTOUT: '1', POWERSHELL_UPDATECHECK: 'Off' }) };
  } catch {
    if (staging) { try { await safe.fs.rm(staging, { recursive: true, force: true }); } catch {} }
    throw fail();
  }
}
module.exports = { SOURCE_POLICY, MAX_POLICY_BYTES, validatePolicy, prepareCodeTools, safeFilesystem, verifyTree, systemPathEntries };
