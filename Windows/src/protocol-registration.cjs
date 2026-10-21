'use strict';
const path = require('node:path');
const windows = require('./windows.cjs');
const APP_NAME = 'Claude Proxy Guard';
const PROG_ID = 'GateClaudeGuard.Url.claude';
const SETTINGS_URL = 'ms-settings:defaultapps?registeredAppUser=' + encodeURIComponent(APP_NAME);
const CAPABILITIES_PATH = 'Software\\GateClaudeGuard\\Capabilities';
const OWNER = 'gate-claude.protocol.v1';
function canonicalExecutable(value) {
  if (typeof value !== 'string' || value.length > 32700 || !/^[a-z]:[\\/]/i.test(value) || /["%\x00-\x1f\x7f]/.test(value) || path.win32.extname(value).toLowerCase() !== '.exe') return '';
  return path.win32.normalize(value).toLowerCase();
}
function registrationScript(executable) {
  if (!canonicalExecutable(executable)) throw Error('Недопустимый путь приложения Guard.');
  const q = windows.psQuote;
  return `$ownBase = 'Software\\GateClaudeGuard'
$capPath = ${q(CAPABILITIES_PATH)}
$progPath = ${q('Software\\Classes\\' + PROG_ID)}
$appName = ${q(APP_NAME)}
$ownerMarker = ${q(OWNER)}
$command = ${q('"' + executable + '" "%1"')}
# Only our application-specific keys and our one RegisteredApplications value.
# A generic scheme class, UserChoice, hashes, package registration and HKLM are never modified.
foreach ($keyPath in @($ownBase, $progPath)) {
  $existing = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath)
  if ($null -ne $existing) {
    try { if ($existing.GetValue('GateClaudeOwner', '') -cne $ownerMarker) { throw 'Registration namespace conflict.' } }
    finally { $existing.Dispose() }
  }
}
$registeredApps = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\\RegisteredApplications')
if ($null -ne $registeredApps) {
  try {
    $previous = $registeredApps.GetValue($appName, $null)
    if ($null -ne $previous -and $previous -ine $capPath) { throw 'Registration name conflict.' }
  } finally { $registeredApps.Dispose() }
}
function Put-OwnValue([string]$keyPath, [string]$name, [string]$value) {
  $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($keyPath)
  if ($null -eq $key) { throw 'Registration key unavailable.' }
  try { $key.SetValue($name, $value, [Microsoft.Win32.RegistryValueKind]::String) }
  finally { $key.Dispose() }
}
Put-OwnValue $ownBase 'GateClaudeOwner' $ownerMarker
Put-OwnValue $progPath 'GateClaudeOwner' $ownerMarker
Put-OwnValue $progPath '' 'Claude Proxy Guard login link'
Put-OwnValue $progPath 'URL Protocol' ''
Put-OwnValue ($progPath + '\\DefaultIcon') '' ${q('"' + executable + '",0')}
Put-OwnValue ($progPath + '\\shell\\open\\command') '' $command
Put-OwnValue $capPath 'ApplicationName' $appName
Put-OwnValue $capPath 'ApplicationDescription' 'Open Claude login links in the active protected Guard session.'
Put-OwnValue $capPath 'ApplicationIcon' ${q('"' + executable + '",0')}
Put-OwnValue ($capPath + '\\URLAssociations') 'claude' ${q(PROG_ID)}
Put-OwnValue 'Software\\RegisteredApplications' $appName $capPath
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class GateProtocolAssociation {
  [DllImport("shlwapi.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
  public static extern int AssocQueryStringW(uint flags, uint kind, string association, string extra, StringBuilder result, ref uint length);
  [DllImport("shell32.dll")]
  public static extern void SHChangeNotify(uint change, uint flags, IntPtr first, IntPtr second);
}
'@
[GateProtocolAssociation]::SHChangeNotify(0x08000000, 0x1000, [IntPtr]::Zero, [IntPtr]::Zero)
$exeResult = [Text.StringBuilder]::new(32768); [uint32]$exeLength = 32768
$progResult = [Text.StringBuilder]::new(32768); [uint32]$progLength = 32768
$exeStatus = [GateProtocolAssociation]::AssocQueryStringW(0x1000, 2, 'claude', $null, $exeResult, [ref]$exeLength)
$progStatus = [GateProtocolAssociation]::AssocQueryStringW(0x1000, 20, 'claude', $null, $progResult, [ref]$progLength)
[ordered]@{capabilitiesRegistered=$true; effectiveProgID=$progResult.ToString(); effectiveExecutable=$exeResult.ToString(); progIDQuery=$progStatus; executableQuery=$exeStatus} | ConvertTo-Json -Compress`;
}
async function ensureGuardProtocolRegistration(app, { platform = process.platform, execPath = process.execPath, smokeTest = false } = {}) {
  const base = { registered: false, capabilitiesRegistered: false, defaultConfirmed: false, selectionRequired: false, settingsURL: SETTINGS_URL };
  if (platform !== 'win32' || smokeTest || app.isPackaged !== true) return { ...base, skipped: true };
  try {
    const script = registrationScript(execPath);
    const result = JSON.parse(await windows.powershell(script, 15000));
    if (result?.capabilitiesRegistered !== true) throw Error('Registration unconfirmed');
    const defaultConfirmed = result.progIDQuery === 0 && result.executableQuery === 0 && typeof result.effectiveProgID === 'string' && result.effectiveProgID.toLowerCase() === PROG_ID.toLowerCase() && canonicalExecutable(result.effectiveExecutable) === canonicalExecutable(execPath);
    return { ...base, registered: true, capabilitiesRegistered: true, defaultConfirmed, selectionRequired: !defaultConfirmed };
  } catch { return { ...base, selectionRequired: true, registrationFailed: true }; }
}
module.exports = { APP_NAME, PROG_ID, SETTINGS_URL, registrationScript, ensureGuardProtocolRegistration };
