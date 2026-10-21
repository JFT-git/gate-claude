'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// Opt in with an already verified portable tool tree. This never installs a shell,
// modifies a real profile, grants capabilities, or changes any ACL.
const root = process.env.GATE_POWERSHELL_BOOTSTRAP_ROOT;
test('portable PowerShell aliases preserve streams, arguments, exit codes and nested cwd', {
  skip: process.platform !== 'win32' || !root,
  timeout: 120000,
}, () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-powershell-test-'));
  const cwd = path.join(scratch, 'nested workspace');
  fs.mkdirSync(cwd);
  const env = {};
  for (const name of ['SystemRoot', 'WINDIR', 'SystemDrive', 'COMSPEC']) {
    if (process.env[name]) env[name] = process.env[name];
  }
  Object.assign(env, {
    PATHEXT: '.COM;.EXE;.BAT;.CMD',
    PATH: root + ';' + path.join(process.env.SystemRoot, 'System32'),
    HOME: scratch, USERPROFILE: scratch, TEMP: scratch, TMP: scratch,
    APPDATA: scratch, LOCALAPPDATA: scratch, PSModulePath: path.join(root, 'Modules'),
    POWERSHELL_TELEMETRY_OPTOUT: '1', POWERSHELL_UPDATECHECK: 'Off',
  });
  const run = (alias, args, input) => {
    const result = spawnSync(path.join(root, alias), ['-NoLogo', '-NoProfile', '-NonInteractive', ...args], {
      cwd, env, input, encoding: 'utf8', timeout: 20000, windowsHide: true,
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    return result;
  };
  try {
    for (const alias of ['powershell.exe', 'pwsh.exe']) {
      let result = run(alias, ['-Command', "Set-Content -LiteralPath './marker.txt' -Value 'workspace'; [Console]::WriteLine((Get-Content -LiteralPath './marker.txt')); [Console]::Error.WriteLine('stderr-marker'); exit 17"]);
      assert.equal(result.status, 17);
      assert.equal(result.stdout.trim(), 'workspace');
      assert.equal(result.stderr.trim(), 'stderr-marker');
      assert.equal(fs.readFileSync(path.join(cwd, 'marker.txt'), 'utf8').trim(), 'workspace');
      const script = path.join(cwd, 'arguments.ps1');
      fs.writeFileSync(script, '[Console]::WriteLine(($args | ConvertTo-Json -Compress -EscapeHandling EscapeNonAscii)); exit 19');
      const values = ['a b', 'quote"value', 'tail\\', '', 'Привет ☃'];
      result = run(alias, ['-File', script, ...values]);
      assert.equal(result.status, 19);
      assert.deepEqual(JSON.parse(result.stdout.trim()), values);
      assert.equal(result.stderr, '');
      result = run(alias, ['-Command', '-'], "[Console]::WriteLine('stdin-marker')\nexit 21\n");
      assert.equal(result.status, 21);
      assert.equal(result.stdout.trim(), 'stdin-marker');
      assert.equal(result.stderr, '');
      const nested = path.join(cwd, 'child directory');
      fs.mkdirSync(nested, { recursive: true });
      const marker = path.join(scratch, 'cli-cwd.txt');
      const psLiteral = value => "'" + value.replace(/'/g, "''") + "'";
      const markerScript = "Set-Location -LiteralPath './child directory';" +
        " $_ec = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } elseif ($?) { 0 } else { 1 };" +
        " (Get-Location).Path | Out-File -FilePath " + psLiteral(marker) + " -Encoding utf8 -NoNewline;" +
        " if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') { $host.SetShouldExit($_ec) } else { exit $_ec }";
      result = run(alias, ['-EncodedCommand', Buffer.from(markerScript, 'utf16le').toString('base64')]);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, '');
      assert.equal(fs.readFileSync(marker, 'utf8'), nested);
      const locationScript = "Push-Location './child directory'; " +
        "$s = Get-Location -Stack; if ($s.GetType().Name -ne 'PathInfoStack') { throw 'Stack type' }; Pop-Location; " +
        "$p = Get-Location -PSProvider FileSystem -PSDrive Guard; " +
        "if ($p.GetType().Name -ne 'PathInfo' -or $p.Path -ne $p.ProviderPath) { throw 'Path metadata' }; " +
        "if ((gl).Path -ne $p.Path -or (pwd).Path -ne $p.Path) { throw 'Alias metadata' }; " +
        "Set-Location Env:; if ((Get-Location).Provider.Name -ne 'Environment') { throw 'Other provider' }; " +
        "[Console]::WriteLine('location-parameters')";
      result = run(alias, ['-EncodedCommand', Buffer.from(locationScript, 'utf16le').toString('base64')]);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout.trim(), 'location-parameters');
      assert.equal(result.stderr, '');
      const command = "[Console]::WriteLine('encoded-marker'); exit 23";
      result = run(alias, ['-EncodedCommand', Buffer.from(command, 'utf16le').toString('base64')]);
      assert.equal(result.status, 23);
      assert.equal(result.stdout.trim(), 'encoded-marker');
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});
