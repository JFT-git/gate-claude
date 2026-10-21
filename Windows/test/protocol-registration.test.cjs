'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const windows = require('../src/windows.cjs');
const P = require('../src/protocol-registration.cjs');
const executable = "C:\\Own Guard O'Hare & Co\\Claude Proxy Guard.exe";
const app = { isPackaged: true, setAsDefaultProtocolClient() { assert.fail('Legacy scheme takeover must not be used'); } };
const successful = (changes = {}) => ({ capabilitiesRegistered: true, effectiveProgID: P.PROG_ID, effectiveExecutable: executable, progIDQuery: 0, executableQuery: 0, ...changes });
async function withPowerShell(reply, callback) {
  const original = windows.powershell, calls = [];
  windows.powershell = async (script, timeout) => { calls.push({ script, timeout }); if (reply instanceof Error) throw reply; return typeof reply === 'string' ? reply : JSON.stringify(reply); };
  try { return await callback(calls); } finally { windows.powershell = original; }
}
const ensure = options => P.ensureGuardProtocolRegistration(app, { platform: 'win32', execPath: executable, ...options });

test('a successful candidate registration does not claim the existing AppX default', async () => {
  await withPowerShell(successful({ effectiveProgID: 'AppX.Fixture.OfficialClaude', effectiveExecutable: 'C:\\Program Files\\WindowsApps\\Fixture\\claude.exe' }), async calls => {
    const result = await ensure();
    assert.equal(result.registered, true); assert.equal(result.capabilitiesRegistered, true);
    assert.equal(result.defaultConfirmed, false); assert.equal(result.selectionRequired, true);
    assert.equal(result.settingsURL, P.SETTINGS_URL); assert.equal(calls.length, 1); assert.equal(calls[0].timeout, 15000);
  });
});

test('effective default requires both the owned ProgID and the current normalized executable', async () => {
  await withPowerShell(successful({ effectiveProgID: P.PROG_ID.toUpperCase(), effectiveExecutable: executable.toUpperCase().replaceAll('\\', '/') }), async () => {
    const result = await ensure(); assert.equal(result.defaultConfirmed, true); assert.equal(result.selectionRequired, false);
  });
  for (const changes of [
    { effectiveProgID: 'AppX.Other' }, { effectiveExecutable: 'C:\\Previous Guard\\Guard.exe' },
    { effectiveExecutable: executable + ' --attacker' }, { progIDQuery: 1 }, { executableQuery: -2147467259 },
    { progIDQuery: '0' }, { executableQuery: undefined }, { effectiveProgID: undefined }, { effectiveExecutable: undefined }
  ]) await withPowerShell(successful(changes), async () => {
    const result = await ensure(); assert.equal(result.defaultConfirmed, false, JSON.stringify(changes)); assert.equal(result.selectionRequired, true);
  });
});

test('smoke tests, development executables and other platforms never invoke a registry writer', async () => {
  await withPowerShell(Error('Unexpected registry mutation'), async calls => {
    for (const options of [{ platform: 'darwin' }, { platform: 'linux' }, { smokeTest: true }]) {
      const result = await ensure(options); assert.equal(result.skipped, true); assert.equal(result.defaultConfirmed, false);
    }
    const result = await P.ensureGuardProtocolRegistration({ isPackaged: false }, { platform: 'win32', execPath: executable });
    assert.equal(result.skipped, true); assert.equal(calls.length, 0);
  });
});

test('invalid executable paths cannot enter the registry command or launch PowerShell', async () => {
  await withPowerShell(successful(), async calls => {
    for (const value of ['Guard.exe', '\\\\server\\share\\Guard.exe', 'C:Guard.exe', 'C:\\Own\\Guard.cmd', 'C:\\Own\\"Guard.exe', 'C:\\%TEMP%\\Guard.exe', 'C:\\Own\\Guard\n.exe', 'C:\\Own\\' + 'x'.repeat(32700) + '.exe', null]) {
      assert.throws(() => P.registrationScript(value), error => error.message === 'Недопустимый путь приложения Guard.');
      const result = await ensure({ execPath: value }); assert.equal(result.registrationFailed, true); assert.equal(result.defaultConfirmed, false);
    }
    assert.equal(calls.length, 0);
  });
});

test('registration failures and unconfirmed writer results expose only fixed status fields', async () => {
  const privateText = 'claude://claude.ai/magic-link#private-id:private-token';
  for (const reply of [Error(privateText), privateText, 'null', '[]', '{}', 'false', successful({ capabilitiesRegistered: false }), successful({ capabilitiesRegistered: 'true' })]) {
    await withPowerShell(reply, async () => {
      const result = await ensure(); assert.equal(result.registrationFailed, true); assert.equal(result.defaultConfirmed, false);
      assert.equal(result.selectionRequired, true); assert.equal(JSON.stringify(result).includes('private'), false);
      assert.deepEqual(Object.keys(result).sort(), ['capabilitiesRegistered', 'defaultConfirmed', 'registered', 'registrationFailed', 'selectionRequired', 'settingsURL'].sort());
    });
  }
});

test('the candidate command quotes its own executable and one opaque URL argument', () => {
  for (const value of [executable, "C:\\Odd '; Write-Output hostile; ' Path\\Guard.exe", 'C:\\Own Guard\\Guard.EXE']) {
    const script = P.registrationScript(value), assignment = /^\$command = '((?:''|[^'])*)'$/m.exec(script);
    assert.ok(assignment); assert.equal(assignment[1].replaceAll("''", "'"), '"' + value + '" "%1"');
  }
});

test('registry mutation targets are limited to the owned candidate and one RegisteredApplications value', () => {
  const script = P.registrationScript(executable), code = script.split('\n').filter(line => !line.trim().startsWith('#')).join('\n');
  const writes = [...code.matchAll(/^Put-OwnValue (.+)$/gm)].map(match => match[1]);
  const ownTargets = ['$ownBase ', '$progPath ', "($progPath + '\\DefaultIcon') ", "($progPath + '\\shell\\open\\command') ", '$capPath ', "($capPath + '\\URLAssociations') ", "'Software\\RegisteredApplications' "];
  assert.ok(writes.length > 0); for (const write of writes) assert.ok(ownTargets.some(prefix => write.startsWith(prefix)), write);
  assert.ok(code.includes("'Software\\Classes\\" + P.PROG_ID + "'"));
  assert.ok(code.includes("Put-OwnValue ($capPath + '\\URLAssociations') 'claude' '" + P.PROG_ID + "'"));
  assert.ok(code.includes('::CurrentUser.CreateSubKey('));
  assert.doesNotMatch(code, /UserChoice|HKEY_LOCAL_MACHINE|::LocalMachine|Remove-Item|Set-ItemProperty|Software\\Classes\\claude(?:\\|')/i);
  assert.match(code, /AssocQueryStringW\(0x1000, 2, 'claude'/); assert.match(code, /AssocQueryStringW\(0x1000, 20, 'claude'/);
});

test('Default Apps navigation remains a fixed Windows settings URI without caller input', async () => {
  assert.equal(P.SETTINGS_URL, 'ms-settings:defaultapps?registeredAppUser=Claude%20Proxy%20Guard');
  await withPowerShell(successful(), async () => {
    const result = await ensure({ settingsURL: 'https://attacker.test/?token=private' });
    assert.equal(result.settingsURL, P.SETTINGS_URL); assert.equal(JSON.stringify(result).includes('attacker'), false);
  });
});

test('Windows parses hostile filename characters as one literal command value without executing the registry script', { skip: process.platform !== 'win32' }, async () => {
  const value = "C:\\Odd '; Write-Output hostile; ' Path\\Guard.exe";
  const source = Buffer.from(P.registrationScript(value), 'utf8').toString('base64');
  const result = JSON.parse(await windows.powershell(`
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${source}'))
$tokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
$assignment=$tree.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.VariablePath.UserPath -eq 'command'},$true)
$nodes=@($assignment.Right.FindAll({param($node) $true},$true))
$literals=@($nodes|Where-Object{$_ -is [Management.Automation.Language.StringConstantExpressionAst]})
$unexpected=@($nodes|Where-Object{$_.GetType().Name -notin @('StatementBlockAst','PipelineAst','CommandExpressionAst','StringConstantExpressionAst')})
$literal=$literals[0]
$literalOnly=$literals.Count -eq 1 -and $unexpected.Count -eq 0 -and $literal.StringConstantType -eq [Management.Automation.Language.StringConstantType]::SingleQuoted
[ordered]@{parseErrors=@($parseErrors).Count;literalOnly=$literalOnly;literalCommand=$literal.Value}|ConvertTo-Json -Compress
`, 15000));
  assert.equal(result.parseErrors, 0); assert.equal(result.literalOnly, true); assert.equal(result.literalCommand, '"' + value + '" "%1"');
});
