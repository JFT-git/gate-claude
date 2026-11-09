"use strict";
const rawFS = require('./raw-fs.cjs').promises;
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { promisify } = require('node:util');
const runFile = promisify(require('node:child_process').execFile);
const decompressZstd = typeof zlib.zstdDecompress === 'function' ? promisify(zlib.zstdDecompress) : undefined;
const { sha256: hash } = require('./async-bytes.cjs');
const { parseArchive } = require('./asar.cjs');
const { findManagedCliSDK, SDK_SHA256, V4_SDK_SHA256, V4_MAIN_FILE, V4_MAIN_SHA256 } = require('./managed-cli-patch.cjs');
const { createPreparationProgress } = require('./preparation-progress.cjs');
const MAX_CLI_BYTES = 512 * 1024 * 1024;
const SOURCE_POLICY = Object.freeze({ desktopVersion: '1.44121.2', codeVersion: '2.1.304', platform: 'win32-x64',
  compressedSize: 104965652, compressedSHA256: 'aed62990b91e94efb35482fd7068cc616c6c2414084c6aa32148ca2a359e4e81',
  executableSize: 293227168, executableSHA256: '019e5174d5d954585edb1a946fe280e44a973050b4897034adf0e16306f85fdd',
  sdkSHA256: SDK_SHA256, mainFile: '.vite/build/index.chunk-BHbE7U4N.js', mainSHA256: 'dfe50aee8e72e608a3cc7b73b8f4e528bc486d403470d49e2dc353d9163a83be' });
const SOURCE_POLICY_V4 = Object.freeze({ desktopVersion: '4.23118.0', codeVersion: '2.1.317', platform: 'win32-x64',
  compressedSize: 122895826, compressedSHA256: 'a33aa5518497dda9dca73d465d77da3fb56de5373350ff734ec20e88464efa17',
  executableSize: 338187936, executableSHA256: '26b01ec22df2c17ac7f5703aa547d36706e8d58412136ced0344a8ced4d86038',
  sdkSHA256: V4_SDK_SHA256, mainFile: V4_MAIN_FILE, mainSHA256: V4_MAIN_SHA256 });
const SOURCE_POLICIES = Object.freeze([SOURCE_POLICY, SOURCE_POLICY_V4]);
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
      findManagedCliSDK(archive).sha256 !== policy.sdkSHA256 || await hash(archive.read(policy.mainFile)) !== policy.mainSHA256) throw fail();
}
function samePath(a, b) { return process.platform === 'win32' ? path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase() : path.resolve(a) === path.resolve(b); }
// Keep the observer separate from fixture dependencies and the exact asset
// schema. `ready` means files/profile prepared; network authorization is later.
async function prepareCodeFiles(runtime, sourcePath, guardRoot, resources, testdeps = {}, assets, options = {}) {
  const fs = testdeps.fs || rawFS, run = testdeps.runFile || runFile, decompress = testdeps.decompress || decompressZstd;
  // Dependency injection is for owned unit fixtures; production supplies no overrides.
  const policy = testdeps.sourcePolicy || SOURCE_POLICIES.find(candidate => candidate.desktopVersion === runtime?.version) || SOURCE_POLICY, inspect = testdeps.inspectSource || inspectSource;
  const randomBytes = testdeps.randomBytes || crypto.randomBytes;
  const progress = createPreparationProgress(options);
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
    progress.begin('claude-code', 'source-verify', 1);
    await inspect(await read(archivePath, 128 * 1024 * 1024), policy); // Reject unsupported releases before a large decompression or filesystem writes.
    progress.complete(); progress.begin('claude-code', 'host-verify', 1);
    hostPath = await safePath(path.join(resources, 'CodeHost.exe'), false, 16 * 1024 * 1024);
    validatePE(await fs.readFile(hostPath));
    progress.complete();
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
    progress.begin('claude-code', 'asset-verify', 1);
    const compressed = await read(compressedPath, policy.compressedSize);
    if (compressed.length !== policy.compressedSize || await hash(compressed) !== policy.compressedSHA256) throw fail();
    progress.complete(); progress.begin('claude-code', 'decompress', 1);
    const executableBytes = validatePE(await decompress(compressed, { maxOutputLength: MAX_CLI_BYTES }));
    progress.complete(); progress.begin('claude-code', 'executable-verify', 1);
    const executableSHA256 = await hash(executableBytes);
    if (executableBytes.length !== policy.executableSize || executableSHA256 !== policy.executableSHA256) throw fail();
    progress.complete();
    const codeBin = await directory(path.join(guardRoot, 'CodeBin')), target = path.join(codeBin, executableSHA256), executable = path.join(target, 'claude.exe');
    const manifestPayload = { version: 1, desktopVersion: policy.desktopVersion, codeVersion: policy.codeVersion, compressedSHA256: policy.compressedSHA256, sdkSHA256: policy.sdkSHA256, mainSHA256: policy.mainSHA256, executableSHA256, executableSize: executableBytes.length };
    const manifest = { ...manifestPayload, manifestSHA256: await hash(Buffer.from(JSON.stringify(manifestPayload))) }, manifestBytes = Buffer.from(JSON.stringify(manifest));
    let exists = false;
    try { await fs.lstat(target); exists = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (exists) {
      progress.begin('claude-code', 'cache-verify', 2);
      await safePath(target, true);
      const names = await fs.readdir(target); if (names.length !== 2 || !names.includes('claude.exe') || !names.includes('guard-code-manifest.json')) throw fail();
      const saved = await read(path.join(target, 'guard-code-manifest.json'), 16384), actual = validatePE(await read(executable, MAX_CLI_BYTES));
      if (!saved.equals(manifestBytes) || actual.length !== executableBytes.length || await hash(actual) !== executableSHA256) throw fail();
      progress.complete();
    } else {
      progress.begin('claude-code', 'publish', 2);
      staging = path.join(codeBin, 'Preparing-' + randomBytes(16).toString('hex'));
      await fs.mkdir(staging, { recursive: false, mode: 0o700 }); await safePath(staging, true);
      await fs.writeFile(path.join(staging, 'claude.exe'), executableBytes, { flag: 'wx', mode: 0o600 });
      progress.update(1);
      await fs.writeFile(path.join(staging, 'guard-code-manifest.json'), manifestBytes, { flag: 'wx', mode: 0o600 });
      await fs.rename(staging, target); staging = undefined;
      progress.complete(); progress.begin('claude-code', 'target-verify', 1);
      await safePath(target, true); if (await hash(await read(executable, MAX_CLI_BYTES)) !== executableSHA256) throw fail();
      progress.complete();
    }
    const stateRoot = await directory(path.join(guardRoot, 'CodeState')), workspaceRoot = await directory(path.join(stateRoot, 'Workspace'));
    containerName = 'gate-code-' + randomBytes(12).toString('hex');
    if (!/^gate-code-[a-f0-9]{24}$/.test(containerName)) throw fail();
    createdProfile = true;
    progress.begin('claude-code', 'profile-create', 1);
    const result = await run(hostPath, ['--create-profile', containerName], { windowsHide: true, timeout: 15000, maxBuffer: 4096 });
    if (typeof result?.stdout !== 'string' || result.stdout.length > 2048) throw fail();
    const profile = JSON.parse(result.stdout.replace(/^\uFEFF/, '').trim()), containerSid = profile.sid;
    if (!/^S-1-15-2-(?:\d+-){6}\d+$/.test(containerSid || '')) throw fail();
    progress.complete(); progress.begin('claude-code', 'ready', 1); progress.complete();
    return { hostPath, stateRoot, workspaceRoot, runtimeExecutable: runtime.executable, containerName, containerSid,
      approved: [{ path: executable, sha256: executableSHA256, requestedPath: path.join(guardRoot, 'Profile', 'claude-code', policy.codeVersion, policy.compressedSHA256.slice(0, 12), 'claude.exe') }],
      cleanupProfile: deleteProfile };
  } catch {
    if (staging) { try { await fs.rm(staging, { recursive: true, force: true }); } catch {} }
    if (createdProfile) { try { await deleteProfile(); } catch {} }
    throw fail();
  }
}
module.exports = { prepareCodeFiles, SOURCE_POLICY, SOURCE_POLICY_V4, SOURCE_POLICIES, MAX_CLI_BYTES, validatePE };
