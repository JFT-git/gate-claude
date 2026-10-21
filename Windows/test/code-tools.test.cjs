'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { SOURCE_POLICY, prepareCodeTools, validatePolicy } = require('../src/code-tools.cjs');
const { sha256, manifestSHA256 } = require('../src/portable-zip.cjs');
const { buildCodeTools, parseArguments } = require('../scripts/prepare-code-tools.cjs');
const denied = /Не удалось безопасно подготовить/;
function manifest(entries) { return entries.map(([name, content]) => ({ path: name, size: Buffer.byteLength(content), sha256: sha256(Buffer.from(content)) })).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0); }
async function fixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gate-tools-'))); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const inputs = { gitRoot: path.join(root, 'GitSource'), powerShellRoot: path.join(root, 'PowerShellSource'), powerShellBootstrap: path.join(root, 'PowerShellBootstrap'), gitAsset: path.join(root, 'git-source.exe'), powerShellAsset: path.join(root, 'ps-source.zip'), output: path.join(root, 'Build') };
  const git = [['bin/bash.exe', 'fixture-bash-launcher'], ['cmd/git.exe', 'fixture-git'], ['ucrt64/libexec/git-core/git-remote-https.exe', 'fixture-git-https'], ['ucrt64/share/git-core/templates/description', 'fixture-template'], ['usr/bin/bash.exe', 'fixture-bash']], powershell = [['Modules/Example/Example.psd1', 'fixture-module'], ['pwsh.dll', 'fixture-dll'], ['pwsh.exe', 'fixture-apphost']];
  const bootstrap = [['Guard.PowerShell.ps1', 'fixture-prelude'], ['Guard.PowerShell.pssc', 'fixture-configuration'], ['GuardPowerShell.exe', 'fixture-launcher']];
  const packagedPowerShell = [...powershell.filter(([name]) => name !== 'pwsh.exe'), ['GuardPwsh.exe', 'fixture-apphost'], ['pwsh.exe', 'fixture-launcher'], ['powershell.exe', 'fixture-launcher'], ...bootstrap.filter(([name]) => name !== 'GuardPowerShell.exe')];
  for (const [source, entries] of [[inputs.gitRoot, git], [inputs.powerShellRoot, powershell], [inputs.powerShellBootstrap, bootstrap]]) for (const [name, content] of entries) { fs.mkdirSync(path.dirname(path.join(source, name)), { recursive: true }); fs.writeFileSync(path.join(source, name), content); }
  fs.writeFileSync(inputs.gitAsset, 'fixture-git-asset'); fs.writeFileSync(inputs.powerShellAsset, 'fixture-powershell-asset');
  const policy = {};
  for (const [id, entries, asset] of [['git', git, inputs.gitAsset], ['powershell', packagedPowerShell, inputs.powerShellAsset]]) {
    const bytes = fs.readFileSync(asset), original = SOURCE_POLICY[id]; policy[id] = { ...original, sourceSize: bytes.length, sourceSHA256: sha256(bytes), treeSHA256: manifestSHA256(manifest(entries)), anchors: Object.fromEntries(entries.filter(([name]) => /(?:^|\/)(?:git|bash|pwsh|powershell|GuardPwsh)\.exe$|^Guard\.PowerShell\./.test(name)).map(([name, content]) => [name, sha256(Buffer.from(content))])) };
  }
  policy.powershell.sourceTreeSHA256 = manifestSHA256(manifest([...powershell, ['powershell.exe', 'fixture-apphost']]));
  policy.powershell.bootstrapSHA256 = manifestSHA256(manifest(bootstrap));
  const built = await buildCodeTools(inputs, { sourcePolicy: policy }), resources = path.join(root, 'Resources'), guardRoot = path.join(root, 'Guard'), systemRoot = path.join(root, 'Windows');
  fs.mkdirSync(path.join(resources, 'CodeTools'), { recursive: true }); fs.mkdirSync(guardRoot); fs.mkdirSync(path.join(systemRoot, 'System32'), { recursive: true });
  fs.copyFileSync(path.join(inputs.output, 'code-tools-policy.json'), path.join(resources, 'code-tools-policy.json'));
  const archives = { gitArchive: path.join(resources, 'CodeTools', policy.git.archiveName), powerShellArchive: path.join(resources, 'CodeTools', policy.powershell.archiveName) };
  for (const archive of Object.values(archives)) fs.copyFileSync(path.join(inputs.output, path.basename(archive)), archive);
  const environment = { SystemRoot: systemRoot, WINDIR: systemRoot, PATH: 'must-never-inherit', USERPROFILE: 'must-never-copy' };
  const deps = { platform: 'win32', arch: 'x64', sourcePolicy: policy, environment };
  const writePolicy = value => fs.writeFileSync(path.join(resources, 'code-tools-policy.json'), JSON.stringify(value));
  return { root, inputs, built, resources, guardRoot, systemRoot, archives, deps, policy, writePolicy, prepare: overrides => prepareCodeTools(guardRoot, resources, archives, { ...deps, ...overrides }) };
}
test('official source policy pins both source assets, full normalized trees and executable anchors', () => {
  assert.ok(Object.isFrozen(SOURCE_POLICY));
  for (const source of Object.values(SOURCE_POLICY)) { assert.ok(Object.isFrozen(source)); assert.match(source.sourceSHA256, /^[a-f0-9]{64}$/); assert.match(source.treeSHA256, /^[a-f0-9]{64}$/); assert.ok(source.sourceSize > 1); }
  assert.match(SOURCE_POLICY.powershell.sourceTreeSHA256, /^[a-f0-9]{64}$/); assert.match(SOURCE_POLICY.powershell.bootstrapSHA256, /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(SOURCE_POLICY.powershell.anchors).sort(), ['Guard.PowerShell.ps1', 'Guard.PowerShell.pssc', 'GuardPwsh.exe', 'powershell.exe', 'pwsh.exe']);
  assert.equal(SOURCE_POLICY.powershell.anchors['pwsh.exe'], SOURCE_POLICY.powershell.anchors['powershell.exe']); assert.notEqual(SOURCE_POLICY.powershell.anchors['pwsh.exe'], SOURCE_POLICY.powershell.anchors['GuardPwsh.exe']);
});
test('prepares complete hash-addressed tools with only own tools and validated Windows directories on PATH', async t => {
  const f = await fixture(t), result = await f.prepare();
  assert.deepEqual(result.toolRoots, f.built.policy.tools.map((tool, i) => path.join(f.guardRoot, 'CodeTools', (i ? 'PowerShell-' : 'Git-') + tool.archiveSHA256)));
  assert.deepEqual(result.pathEntries, [path.join(result.gitRoot, 'cmd'), path.join(result.gitRoot, 'usr', 'bin'), result.powerShellRoot, path.join(f.systemRoot, 'System32'), f.systemRoot]);
  assert.equal(result.environment.PATH, result.pathEntries.join(';')); assert.ok(!result.environment.PATH.includes('must-never-inherit'));
  assert.equal(result.environment.GIT_EXEC_PATH, path.join(result.gitRoot, 'ucrt64', 'libexec', 'git-core')); assert.equal(result.environment.GIT_TEMPLATE_DIR, path.join(result.gitRoot, 'ucrt64', 'share', 'git-core', 'templates'));
  assert.equal(result.environment.PSModulePath, path.join(result.powerShellRoot, 'Modules')); assert.equal(result.environment.GIT_CONFIG_NOSYSTEM, '1'); assert.ok(Object.isFrozen(result.environment)); assert.ok(Object.isFrozen(result.pathEntries));
  assert.equal(result.environment.CLAUDE_CODE_USE_POWERSHELL_TOOL, '1'); assert.ok(!Object.hasOwn(result.environment, 'SHELL')); assert.ok(!Object.hasOwn(result.environment, 'CLAUDE_CODE_GIT_BASH_PATH'));
  assert.equal(fs.readFileSync(result.powerShellExecutable, 'utf8'), 'fixture-launcher'); assert.equal(fs.readFileSync(path.join(result.powerShellRoot, 'pwsh.exe'), 'utf8'), 'fixture-launcher'); assert.equal(fs.readFileSync(path.join(result.powerShellRoot, 'GuardPwsh.exe'), 'utf8'), 'fixture-apphost'); assert.equal(fs.readFileSync(result.gitExecutable, 'utf8'), 'fixture-git');
  const firstTime = fs.statSync(result.gitExecutable).mtimeMs, again = await f.prepare(); assert.equal(again.gitRoot, result.gitRoot); assert.equal(fs.statSync(result.gitExecutable).mtimeMs, firstTime);
});
test('both archives and full source policy must authenticate before creating CodeTools', async t => {
  const f = await fixture(t); const original = fs.readFileSync(f.archives.powerShellArchive); fs.writeFileSync(f.archives.powerShellArchive, Buffer.alloc(original.length));
  await assert.rejects(f.prepare(), denied); assert.ok(!fs.existsSync(path.join(f.guardRoot, 'CodeTools'))); fs.writeFileSync(f.archives.powerShellArchive, original);
  const altered = structuredClone(f.built.policy); altered.tools[0].files.find(file => file.path.endsWith('git-remote-https.exe')).sha256 = '1'.repeat(64); f.writePolicy(altered);
  await assert.rejects(f.prepare(), denied); assert.ok(!fs.existsSync(path.join(f.guardRoot, 'CodeTools')));
});
test('policy rejects unsupported source versions, omitted files, arbitrary fields and inconsistent source metadata', async t => {
  const f = await fixture(t);
  for (const change of [p => p.schemaVersion = 2, p => p.extra = true, p => p.tools.reverse(), p => p.tools[0].version = 'future', p => p.tools[0].source.sha256 = '0'.repeat(64), p => p.tools[0].files.pop(), p => p.tools[0].files[0].extra = true, p => p.tools[0].archiveName = '../other.zip']) {
    const altered = structuredClone(f.built.policy); change(altered); assert.throws(() => validatePolicy(altered, f.policy)); f.writePolicy(altered); await assert.rejects(f.prepare(), denied);
  }
  assert.ok(!fs.existsSync(path.join(f.guardRoot, 'CodeTools')));
});
test('wrong platform, malformed SystemRoot, mismatched WINDIR and arbitrary archive locations fail closed', async t => {
  const f = await fixture(t);
  for (const overrides of [{ platform: 'darwin' }, { arch: 'arm64' }, { environment: {} }, { environment: { SystemRoot: f.systemRoot + ';untrusted' } }, { environment: { SystemRoot: f.systemRoot, systemroot: f.systemRoot } }, { environment: { SystemRoot: f.systemRoot, WINDIR: path.join(f.root, 'Other') } }, { environment: { SystemRoot: path.join(f.root, 'missing') } }]) await assert.rejects(f.prepare(overrides), denied);
  const outside = path.join(f.root, f.policy.git.archiveName); fs.copyFileSync(f.archives.gitArchive, outside);
  await assert.rejects(prepareCodeTools(f.guardRoot, f.resources, { ...f.archives, gitArchive: outside }, f.deps), denied);
  assert.ok(!fs.existsSync(path.join(f.guardRoot, 'CodeTools')));
});
test('input hardlinks and symlinked output or Windows directories are never followed', async t => {
  const f = await fixture(t), link = path.join(f.root, 'archive-hardlink'); fs.linkSync(f.archives.gitArchive, link); await assert.rejects(f.prepare(), denied); fs.unlinkSync(link);
  const outside = path.join(f.root, 'Outside'); fs.mkdirSync(outside); fs.symlinkSync(outside, path.join(f.guardRoot, 'CodeTools'), process.platform === 'win32' ? 'junction' : 'dir'); await assert.rejects(f.prepare(), denied); assert.deepEqual(fs.readdirSync(outside), []); fs.unlinkSync(path.join(f.guardRoot, 'CodeTools'));
  const windowsLink = path.join(f.root, 'WindowsLink'); fs.symlinkSync(f.systemRoot, windowsLink, process.platform === 'win32' ? 'junction' : 'dir'); await assert.rejects(f.prepare({ environment: { SystemRoot: windowsLink } }), denied);
});
test('cached tools reject added, changed, missing, linked files and unexpected empty directories without replacement', async t => {
  const f = await fixture(t), first = await f.prepare(), target = first.gitExecutable, original = fs.readFileSync(target);
  fs.writeFileSync(target, 'tampered'); await assert.rejects(f.prepare(), denied); assert.equal(fs.readFileSync(target, 'utf8'), 'tampered'); fs.writeFileSync(target, original);
  const extra = path.join(first.gitRoot, 'user-secret.txt'); fs.writeFileSync(extra, 'private-fixture'); await assert.rejects(f.prepare(), denied); assert.ok(fs.existsSync(extra)); fs.unlinkSync(extra);
  fs.mkdirSync(extra); await assert.rejects(f.prepare(), denied); fs.rmdirSync(extra);
  const saved = path.join(f.root, 'saved'); fs.renameSync(target, saved); await assert.rejects(f.prepare(), denied); fs.renameSync(saved, target);
  fs.linkSync(target, saved); await assert.rejects(f.prepare(), denied); fs.unlinkSync(saved);
});
test('cached tools reject a substituted file symlink when the OS permits creating one', async t => {
  const f = await fixture(t), first = await f.prepare(), target = first.gitExecutable, saved = path.join(f.root, 'saved');
  fs.renameSync(target, saved);
  try { fs.symlinkSync(saved, target); }
  catch (error) { fs.renameSync(saved, target); if (process.platform === 'win32' && error.code === 'EPERM') { t.skip('This Windows token lacks the privilege to create file symlinks; hardlink and junction checks run separately.'); return; } throw error; }
  await assert.rejects(f.prepare(), denied); fs.unlinkSync(target); fs.renameSync(saved, target);
});
test('a staging-name collision preserves pre-existing files and never cleans another operation', async t => {
  const f = await fixture(t), nonce = Buffer.alloc(16, 7), collision = path.join(f.guardRoot, 'CodeTools', 'Preparing-' + nonce.toString('hex'));
  fs.mkdirSync(collision, { recursive: true }); fs.writeFileSync(path.join(collision, 'preserve.txt'), 'other-owned-operation');
  await assert.rejects(f.prepare({ randomBytes: () => nonce }), denied); assert.equal(fs.readFileSync(path.join(collision, 'preserve.txt'), 'utf8'), 'other-owned-operation');
});
test('bounded decompression failure removes only its own fresh incomplete staging directory', async t => {
  const f = await fixture(t), bytes = fs.readFileSync(f.archives.gitArchive), changed = structuredClone(f.built.policy), nameLength = bytes.readUInt16LE(26);
  bytes[30 + nameLength] ^= 255; fs.writeFileSync(f.archives.gitArchive, bytes); changed.tools[0].archiveSHA256 = sha256(bytes); f.writePolicy(changed);
  await assert.rejects(f.prepare(), error => denied.test(error.message) && !error.message.includes(f.root)); assert.deepEqual(fs.readdirSync(path.join(f.guardRoot, 'CodeTools')), []);
});
test('release builder is deterministic, preserves the official apphost, adds both pinned launchers and excludes generated machine files', async t => {
  const f = await fixture(t); fs.mkdirSync(path.join(f.inputs.gitRoot, 'etc')); fs.writeFileSync(path.join(f.inputs.gitRoot, 'etc', 'hosts'), 'private-machine-fixture');
  const output = path.join(f.root, 'BuildAgain'), again = await buildCodeTools({ ...f.inputs, output }, { sourcePolicy: f.policy }); assert.equal(again.policySHA256, f.built.policySHA256);
  for (const source of Object.values(f.policy)) assert.ok(fs.readFileSync(path.join(output, source.archiveName)).equals(fs.readFileSync(path.join(f.inputs.output, source.archiveName))));
  assert.ok(!JSON.stringify(again.policy).includes('etc/hosts')); assert.equal(again.policy.tools[1].files.find(file => file.path === 'powershell.exe').sha256, again.policy.tools[1].files.find(file => file.path === 'pwsh.exe').sha256);
  assert.equal(again.policy.tools[1].files.find(file => file.path === 'GuardPwsh.exe').sha256, sha256(Buffer.from('fixture-apphost')));
  assert.equal(again.policy.tools[1].files.find(file => file.path === 'Guard.PowerShell.pssc').sha256, sha256(Buffer.from('fixture-configuration')));
});
test('official PowerShell input and generated bootstrap authenticate separately before any archive is written', async t => {
  const f = await fixture(t), output = path.join(f.root, 'Rejected');
  for (const [file, content] of [[path.join(f.inputs.powerShellRoot, 'pwsh.exe'), 'fixture-apphost'], ...['Guard.PowerShell.ps1', 'Guard.PowerShell.pssc', 'GuardPowerShell.exe'].map(name => [path.join(f.inputs.powerShellBootstrap, name), fs.readFileSync(path.join(f.inputs.powerShellBootstrap, name))])]) {
    fs.writeFileSync(file, 'unverified'); await assert.rejects(buildCodeTools({ ...f.inputs, output }, { sourcePolicy: f.policy }), /preparation failed/); assert.ok(!fs.existsSync(output)); fs.writeFileSync(file, content);
  }
  const linked = path.join(f.root, 'launcher-link'); fs.linkSync(path.join(f.inputs.powerShellBootstrap, 'GuardPowerShell.exe'), linked); await assert.rejects(buildCodeTools({ ...f.inputs, output }, { sourcePolicy: f.policy }), /preparation failed/); assert.ok(!fs.existsSync(output)); fs.unlinkSync(linked);
  const extra = path.join(f.inputs.powerShellBootstrap, 'secret.txt'); fs.writeFileSync(extra, 'must-never-ship'); await assert.rejects(buildCodeTools({ ...f.inputs, output }, { sourcePolicy: f.policy }), /preparation failed/); assert.ok(!fs.existsSync(output));
});
test('cached PowerShell launcher, official apphost, configuration and prelude are all immutable', async t => {
  const f = await fixture(t), prepared = await f.prepare();
  for (const name of ['GuardPwsh.exe', 'pwsh.exe', 'powershell.exe', 'Guard.PowerShell.pssc', 'Guard.PowerShell.ps1']) {
    const file = path.join(prepared.powerShellRoot, name), original = fs.readFileSync(file); fs.writeFileSync(file, 'unverified'); await assert.rejects(f.prepare(), denied); assert.equal(fs.readFileSync(file, 'utf8'), 'unverified'); fs.writeFileSync(file, original);
  }
});
test('release builder rejects source contamination and unverified assets while preserving existing output', async t => {
  const f = await fixture(t), output = path.join(f.root, 'Rejected'); fs.writeFileSync(path.join(f.inputs.gitRoot, 'test-private.txt'), 'must-never-ship');
  await assert.rejects(buildCodeTools({ ...f.inputs, output }, { sourcePolicy: f.policy }), /preparation failed/); assert.ok(!fs.existsSync(output)); fs.unlinkSync(path.join(f.inputs.gitRoot, 'test-private.txt'));
  fs.writeFileSync(f.inputs.gitAsset, 'invalid'); await assert.rejects(buildCodeTools({ ...f.inputs, output }, { sourcePolicy: f.policy }), /preparation failed/); assert.ok(!fs.existsSync(output));
  await assert.rejects(buildCodeTools(f.inputs, { sourcePolicy: f.policy }), /preparation failed/); assert.ok(fs.existsSync(path.join(f.inputs.output, 'code-tools-policy.json')));
});
test('release command parser only accepts all fixed named inputs exactly once', () => {
  for (const argv of [[], ['--git-root', '../relative'], ['--bad', '/tmp', '--git-root', '/tmp', '--powershell-root', '/tmp', '--git-asset', '/tmp', '--output', '/tmp'], ['--git-root', '/tmp', '--git-root', '/tmp', '--powershell-root', '/tmp', '--git-asset', '/tmp', '--output', '/tmp']]) assert.throws(() => parseArguments(argv));
  const absolute = path.resolve(os.tmpdir(), 'fixture'); const args = ['--git-root', '--powershell-root', '--powershell-bootstrap', '--git-asset', '--powershell-asset', '--output'].flatMap(flag => [flag, absolute]); assert.equal(parseArguments(args).powerShellBootstrap, absolute);
  const duplicate = [...args]; duplicate[4] = '--powershell-root'; assert.throws(() => parseArguments(duplicate));
});
