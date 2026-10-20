'use strict';
const fs = require('./raw-fs.cjs').promises;
const path = require('node:path');
const { promisify } = require('node:util');
const { execFile } = require('node:child_process');
const run = promisify(execFile);
const { parseArchive, addBootstrap, updatePEIntegrity, windowsBootstrap, hash } = require('./asar.cjs');
const { powershell, psQuote } = require('./windows.cjs');

async function discoverClaude() {
  return (await require('./discovery.cjs').discoverClaude()).path;
}

async function restrictRoot(root) {
  if (process.platform !== 'win32') return;
  const sid = await powershell('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value');
  if (!/^S-1-5-\d+(?:-\d+)+$/.test(sid)) throw Error('Не удалось проверить владельца папки Guard.');
  await run(path.join(process.env.SystemRoot, 'System32', 'icacls.exe'), [root, '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'], { windowsHide: true, timeout: 15000 });
}

async function prepareRuntime(sourcePath, root, bootstrapPath, onStatus = () => {}) {
  if (!path.isAbsolute(sourcePath) || path.basename(sourcePath).toLowerCase() !== 'claude.exe') throw Error('Выберите установленный claude.exe.');
  const source = await fs.realpath(sourcePath), sourceDirectory = path.dirname(source);
  const archivePath = path.join(sourceDirectory, 'resources', 'app.asar');
  const original = await fs.readFile(archivePath), parsed = parseArchive(original);
  const metadata = JSON.parse(parsed.read('package.json').toString('utf8'));
  if (!['@ant/desktop', 'claude', 'Claude'].includes(metadata.name)) throw Error('Выбранное приложение не является поддерживаемым Claude Desktop.');
  const base = await fs.readFile(bootstrapPath, 'utf8'), bootstrap = windowsBootstrap(base), executable = await fs.readFile(source);
  const fingerprint = hash(Buffer.concat([Buffer.from(parsed.digest), bootstrap, Buffer.from(hash(executable)), Buffer.from('gate-runtime-v4')]));
  const directory = path.join(root, 'Runtime-' + fingerprint.slice(0, 24)), destination = path.join(directory, path.basename(source));
  const profile = path.join(root, 'Profile');
  let signature = 'unavailable';
  if (process.platform === 'win32') {
    try { signature = await powershell('(Get-AuthenticodeSignature -LiteralPath ' + psQuote(source) + ').Status.ToString()'); }
    catch { throw Error('Не удалось проверить подпись исходного Claude.'); }
  }
  await fs.mkdir(root, { recursive: true, mode: 0o700 }); await restrictRoot(root);
  await fs.mkdir(profile, { recursive: true, mode: 0o700 });
  try {
    const manifest = JSON.parse(await fs.readFile(path.join(directory, 'guard-manifest.json'), 'utf8'));
    if (manifest.fingerprint === fingerprint && hash(await fs.readFile(destination)) === manifest.exeDigest &&
        parseArchive(await fs.readFile(path.join(directory, 'resources', 'app.asar'))).digest === manifest.asarDigest) {
      return { executable: destination, profile, version: String(metadata.version), signature };
    }
  } catch {}
  onStatus('Подготовка отдельной локальной копии Claude…');
  const staging = path.join(root, 'Preparing-' + require('node:crypto').randomUUID());
  try {
    await fs.cp(sourceDirectory, staging, { recursive: true, dereference: false, errorOnExist: true });
    const patched = addBootstrap(original, bootstrap), patchedExecutable = updatePEIntegrity(executable, patched.oldDigest, patched.digest);
    await fs.writeFile(path.join(staging, 'resources', 'app.asar'), patched.archive);
    await fs.writeFile(path.join(staging, path.basename(source)), patchedExecutable);
    const manifest = { fingerprint, asarDigest: patched.digest, exeDigest: hash(patchedExecutable), version: String(metadata.version) };
    await fs.writeFile(path.join(staging, 'guard-manifest.json'), JSON.stringify(manifest));
    await fs.rm(directory, { recursive: true, force: true }); await fs.rename(staging, directory);
    return { executable: destination, profile, version: String(metadata.version), signature };
  } catch (error) {
    await fs.rm(staging, { recursive: true, force: true });
    throw Error('Не удалось подготовить копию Claude: ' + String(error.message || error));
  }
}

module.exports = { powershell, psQuote, discoverClaude, prepareRuntime, restrictRoot };
