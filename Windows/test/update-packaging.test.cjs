'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const cp = require('node:child_process');

const root = path.resolve(__dirname, '../..');

test('NSIS remains per-user x64 with preserved data, blockmaps and the existing AppId', () => {
  const config = require('../../packaging/windows/electron-builder.cjs');
  const inno = fs.readFileSync(path.join(root, 'packaging/windows/Guard.iss'), 'utf8');
  assert.equal(config.appId, 'local.proxyguard.gate-claude'); assert.match(inno, /AppId=local\.proxyguard\.gate-claude/);
  assert.equal(config.extraMetadata.name, 'Claude Proxy Guard');
  assert.match(inno, /DefaultDirName=\{localappdata\}\\Programs\\Claude Proxy Guard/);
  assert.equal(config.nsis.oneClick, true); assert.equal(config.nsis.perMachine, false); assert.equal(config.nsis.allowElevation, false);
  assert.equal(config.nsis.deleteAppDataOnUninstall, false); assert.equal(config.nsis.differentialPackage, true);
  assert.deepEqual(config.win.target, [{ target: 'nsis', arch: ['x64'] }]);
  assert.match(config.nsis.artifactName, /^ClaudeProxyGuard-Windows-\$\{version\}-x64-Setup\.\$\{ext\}$/);
});

test('Inno migration removes only an owned legacy uninstall entry and refuses a foreign directory', () => {
  const script = fs.readFileSync(path.join(root, 'packaging/windows/installer.nsh'), 'utf8');
  assert.match(script, /Uninstall\\local\.proxyguard\.gate-claude_is1/);
  assert.match(script, /!macro customInit[\s\S]*StrCmp \$0 "\$LOCALAPPDATA\\Programs\\Claude Proxy Guard\\" guardInnoMigrationValidated[\s\S]*Abort[\s\S]*!macroend/);
  assert.match(script, /MessageBox MB_ICONSTOP/); assert.match(script, /\n  Abort\n/);
  assert.match(script, /DeleteRegKey HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\local\.proxyguard\.gate-claude_is1"/);
  assert.doesNotMatch(script, /ExecWait.*unins000/i);
});

test('install and uninstall wait for the owned service request and preserve exit 2 and conditional HKCU cleanup', () => {
  const script = fs.readFileSync(path.join(root, 'packaging/windows/installer.nsh'), 'utf8');
  for (const value of ['GateClaudeOwner', 'gate-claude.protocol.v1', 'GateClaudeGuard.Url.claude', 'Software\\RegisteredApplications']) assert.ok(script.includes(value));
  assert.ok(script.includes('"$INSTDIR\\Claude Proxy Guard.exe"'));
  assert.match(script, /ExecWait '"\$INSTDIR\\resources\\GuardService\.exe" --request-install --owner 0' \$0/);
  assert.match(script, /ExecWait '"\$INSTDIR\\resources\\GuardService\.exe" --request-uninstall --owner 0' \$0/);
  assert.match(script, /StrCmp \$0 2 guardServiceExitTwo/); assert.match(script, /StrCmp \$0 2 guardServiceUninstallExitTwo/);
  const uninstall = script.match(/!macro customUnInstall([\s\S]*?)!macroend/)[1];
  assert.match(uninstall, /\$\{If\} \$\{isUpdated\}[\s\S]*?\$\{Else\}[\s\S]*?--request-uninstall --owner 0[\s\S]*?\$\{EndIf\}/);
  assert.doesNotMatch(script, /HKLM|WriteReg|CreateService|sc\.exe/i);
});

test('GuardService is a required packaged resource with an independent Windows csc pin', () => {
  const script = fs.readFileSync(path.join(root, 'Windows/scripts/package.cjs'), 'utf8');
  const pins = JSON.parse(fs.readFileSync(path.join(root, 'packaging/windows/cross-build-pins.json'), 'utf8'));
  assert.match(script, /resources', 'GuardService\.exe'/); assert.match(script, /native', 'GuardService\.cs'/);
  assert.match(script, /--service/); assert.match(script, /System\.ServiceProcess\.dll/);
  assert.match(pins.sha256['GuardService.exe'], /^[a-f0-9]{64}$/);
  assert.match(fs.readFileSync(path.join(root, 'packaging/windows/package.ps1'), 'utf8'), /SERVICE_REQUEST_ON_DEMAND/);
});

test('release packaging excludes electron-builder debug output', () => {
  const script = fs.readFileSync(path.join(root, 'packaging/windows/package.ps1'), 'utf8');
  assert.match(script, /Remove-Item -LiteralPath \(Join-Path \$ArtifactDir 'builder-debug\.yml'\)/);
});

test('metadata signer rejects a key that does not match the pinned release key', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-wrong-update-key-')); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const keyPath = path.join(directory, 'wrong-key.pem'), metadata = path.join(directory, 'latest.yml');
  fs.writeFileSync(keyPath, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 }); fs.writeFileSync(metadata, 'version: 0.7.0\n');
  const result = cp.spawnSync(process.execPath, [path.join(root, 'packaging/windows/sign-update-metadata.cjs'), metadata], { env: { ...process.env, GUARD_WINDOWS_UPDATE_PRIVATE_KEY: keyPath }, encoding: 'utf8' });
  assert.notEqual(result.status, 0); assert.match(result.stderr, /does not match/); assert.equal(fs.existsSync(metadata + '.sig'), false);
});
