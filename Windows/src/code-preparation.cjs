"use strict";
const rawFS = require('./raw-fs.cjs').promises;
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const runFile = require('node:util').promisify(require('node:child_process').execFile);
const { parseArchive } = require('./asar.cjs');
const { findManagedCliSDK, SDK_SHA256 } = require('./managed-cli-patch.cjs');
const MAX_CLI_BYTES = 512 * 1024 * 1024;
const SOURCE_POLICY = Object.freeze({ desktopVersion: '3.1623.0', codeVersion: '2.1.304', platform: 'win32-x64',
  compressedSize: 104965652, compressedSHA256: 'aed62990b91e94efb35482fd7068cc616c6c2414084c6aa32148ca2a359e4e81',
  executableSize: 293227168, executableSHA256: '019e5174d5d954585edb1a946fe280e44a973050b4897034adf0e16306f85fdd',
  sdkSHA256: SDK_SHA256, mainFile: '.vite/build/index.chunk-7dsQFims.js', mainSHA256: '403a7d93388a723d2c0688cea83861ecfbe7e08caa63c6701bcd49684100c348' });
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const fail = () => Error('Не удалось безопасно подготовить Claude Code. Исходная версия или файлы не подтверждены.');
function validatePE(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 256 || bytes.length > MAX_CLI_BYTES || bytes.readUInt16LE(0) !== 0x5a4d) throw fail();
  const pe = bytes.readUInt32LE(0x3c);
  if (pe < 64 || pe + 26 > bytes.length || bytes.readUInt32LE(pe) !== 0x4550 || bytes.readUInt16LE(pe + 4) !== 0x8664 || bytes.readUInt16LE(pe + 6) < 1 || bytes.readUInt16LE(pe + 6) > 96 || bytes.readUInt16LE(pe + 24) !== 0x20b) throw fail();
  return bytes;
}
async function inspectSource(archiveBytes, policy) {
  const archive = parseArchive(archiveBytes), metadata = JSON.parse(archive.read('package.json').toString('utf8'));
  if (!['@ant/desktop', 'claude', 'Claude'].includes(metadata.name) || metadata.version !== policy.desktopVersion ||
      findManagedCliSDK(archive).sha256 !== policy.sdkSHA256 || hash(archive.read(policy.mainFile)) !== policy.mainSHA256) throw fail();
}
function samePath(a, b) { return process.platform === 'win32' ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase() : path.resolve(a) === path.resolve(b); }
async function prepareCodeFiles(runtime, sourcePath, guardRoot, resources, testdeps = {}, assets) {
  const fs = testdeps.fs || rawFS, run = testdeps.runFile || runFile, decompress = testdeps.decompress || zlib.zstdDecompressSync;
  // Dependency injection is for owned unit fixtures; production supplies no overrides.
  const policy = testdeps.sourcePolicy || SOURCE_POLICY, inspect = testdeps.inspectSource || inspectSource;
  const randomBytes = testdeps.randomBytes || crypto.randomBytes;
  let createdProfile = false, containerName, hostPath, staging;
  async function safePath(file, directory, maxSize = Infinity) {
    if (!path.isAbsolute(file)) throw fail();
    const absolute = path.resolve(file), root = path.parse(absolute).root;
    let current = root;
    for (const part of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, part); const stat = await fs.lstat(current);
      if (stat.isSymbolicLink() || (stat.attributes !== undefined && (stat.attributes & 1024)) || !samePath(await fs.realpath(current), current)) throw fail();
      if (current !== absolute && !stat.isDirectory()) throw fail();
      if (current === absolute && (directory ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1 || stat.size < 1 || stat.size > maxSize)) throw fail();
    }
    return absolute;
  }
  async function directory(file) {
    await safePath(path.dirname(file), true);
    try { await fs.mkdir(file, { recursive: false, mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    return safePath(file, true);
  }
  async function read(file, maxSize) { await safePath(file, false, maxSize); return fs.readFile(file); }
  async function deleteProfile() {
    if (!createdProfile) return; createdProfile = false;
    try { await run(hostPath, ['--delete-profile', containerName], { windowsHide: true, timeout: 15000, maxBuffer: 4096 }); } catch { throw fail(); }
  }
  try {
    if ((testdeps.platform || process.platform) !== 'win32' || (testdeps.arch || process.arch) !== 'x64' || runtime?.signature !== 'Valid' || runtime.version !== policy.desktopVersion || typeof decompress !== 'function') throw fail();
    if (!path.isAbsolute(sourcePath) || path.basename(sourcePath).toLowerCase() !== 'claude.exe' || !path.isAbsolute(guardRoot) || !path.isAbsolute(resources) || !path.isAbsolute(runtime.executable)) throw fail();
    await safePath(sourcePath, false); await safePath(runtime.executable, false); await safePath(guardRoot, true);
    const sourceDirectory = path.dirname(sourcePath), archivePath = path.join(sourceDirectory, 'resources', 'app.asar');
    await inspect(await read(archivePath, 128 * 1024 * 1024), policy); // Reject unsupported releases before a large decompression or filesystem writes.
    hostPath = await safePath(path.join(resources, 'CodeHost.exe'), false, 16 * 1024 * 1024);
    validatePE(await fs.readFile(hostPath));
    // Store packages omit the optional vendor preseed. Release preparation may
    // supply the same pinned bytes beside CodeHost; startup never downloads or
    // reads a writable Profile copy. Only absence permits the sidecar fallback.
    let compressedPath = path.join(sourceDirectory, 'resources', 'preseed', 'claude-code', policy.platform + '.zst');
    if (assets !== undefined) {
      const fixedAsset = path.join(guardRoot, 'CodeAssets', policy.compressedSHA256, policy.platform + '.zst');
      if (!assets || typeof assets !== 'object' || Array.isArray(assets) || Object.keys(assets).join(',') !== 'nativeAssetPath' ||
          typeof assets.nativeAssetPath !== 'string' || !samePath(assets.nativeAssetPath, fixedAsset)) throw fail();
      compressedPath = fixedAsset;
    } else {
      try { await fs.lstat(compressedPath); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        compressedPath = path.join(resources, 'NativeCode', policy.platform + '.zst');
      }
    }
    const compressed = await read(compressedPath, policy.compressedSize);
    if (compressed.length !== policy.compressedSize || hash(compressed) !== policy.compressedSHA256) throw fail();
    const executableBytes = validatePE(decompress(compressed, { maxOutputLength: MAX_CLI_BYTES })), executableSHA256 = hash(executableBytes);
    if (executableBytes.length !== policy.executableSize || executableSHA256 !== policy.executableSHA256) throw fail();
    const codeBin = await directory(path.join(guardRoot, 'CodeBin')), target = path.join(codeBin, executableSHA256), executable = path.join(target, 'claude.exe');
    const manifestPayload = { version: 1, desktopVersion: policy.desktopVersion, codeVersion: policy.codeVersion, compressedSHA256: policy.compressedSHA256, sdkSHA256: policy.sdkSHA256, mainSHA256: policy.mainSHA256, executableSHA256, executableSize: executableBytes.length };
    const manifest = { ...manifestPayload, manifestSHA256: hash(Buffer.from(JSON.stringify(manifestPayload))) }, manifestBytes = Buffer.from(JSON.stringify(manifest));
    let exists = false;
    try { await fs.lstat(target); exists = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (exists) {
      await safePath(target, true);
      const names = await fs.readdir(target); if (names.length !== 2 || !names.includes('claude.exe') || !names.includes('guard-code-manifest.json')) throw fail();
      const saved = await read(path.join(target, 'guard-code-manifest.json'), 16384), actual = validatePE(await read(executable, MAX_CLI_BYTES));
      if (!saved.equals(manifestBytes) || actual.length !== executableBytes.length || hash(actual) !== executableSHA256) throw fail();
    } else {
      staging = path.join(codeBin, 'Preparing-' + randomBytes(16).toString('hex'));
      await fs.mkdir(staging, { recursive: false, mode: 0o700 }); await safePath(staging, true);
      await fs.writeFile(path.join(staging, 'claude.exe'), executableBytes, { flag: 'wx', mode: 0o600 });
      await fs.writeFile(path.join(staging, 'guard-code-manifest.json'), manifestBytes, { flag: 'wx', mode: 0o600 });
      await fs.rename(staging, target); staging = undefined;
      await safePath(target, true); if (hash(await read(executable, MAX_CLI_BYTES)) !== executableSHA256) throw fail();
    }
    const stateRoot = await directory(path.join(guardRoot, 'CodeState')), workspaceRoot = await directory(path.join(stateRoot, 'Workspace'));
    containerName = 'gate-code-' + randomBytes(12).toString('hex');
    if (!/^gate-code-[a-f0-9]{24}$/.test(containerName)) throw fail();
    createdProfile = true;
    const result = await run(hostPath, ['--create-profile', containerName], { windowsHide: true, timeout: 15000, maxBuffer: 4096 });
    if (typeof result?.stdout !== 'string' || result.stdout.length > 2048) throw fail();
    const profile = JSON.parse(result.stdout.replace(/^\uFEFF/, '').trim()), containerSid = profile.sid;
    if (!/^S-1-15-2-(?:\d+-){6}\d+$/.test(containerSid || '')) throw fail();
    return { hostPath, stateRoot, workspaceRoot, runtimeExecutable: runtime.executable, containerName, containerSid,
      approved: [{ path: executable, sha256: executableSHA256, requestedPath: path.join(guardRoot, 'Profile', 'claude-code', policy.codeVersion, policy.compressedSHA256.slice(0, 12), 'claude.exe') }],
      cleanupProfile: deleteProfile };
  } catch {
    if (staging) { try { await fs.rm(staging, { recursive: true, force: true }); } catch {} }
    if (createdProfile) { try { await deleteProfile(); } catch {} }
    throw fail();
  }
}
module.exports = { prepareCodeFiles, SOURCE_POLICY, MAX_CLI_BYTES, validatePE };
