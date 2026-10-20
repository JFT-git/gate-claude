'use strict';
const fs = require('./raw-fs.cjs').promises;
const path = require('node:path');
const { powershell } = require('./windows.cjs');
const win = path.win32;
const array = value => value == null ? [] : Array.isArray(value) ? value : [value];

// The package registry can be queried without traversing WindowsApps in Explorer.
const packageScript = `
$packages=@(Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.IsResourcePackage -and ($_.Name -match 'Claude|Anthropic' -or $_.Publisher -match 'Anthropic') } | Sort-Object Version -Descending | ForEach-Object {
 $p=$_; $executables=@()
 try { $m=Get-AppxPackageManifest -Package $p.PackageFullName; $executables=@($m.Package.Applications.Application | ForEach-Object { [string]$_.Executable }) } catch {}
 [pscustomobject]@{location=[string]$p.InstallLocation;version=$p.Version.ToString();executables=$executables}
})
$registry=@()
foreach($key in @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\claude.exe','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\claude.exe','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\claude.exe')) {
 if(Test-Path -LiteralPath $key) { $value=(Get-Item -LiteralPath $key).GetValue(''); if($value){$registry += [string]$value} }
}
@{packages=$packages;registry=$registry}|ConvertTo-Json -Compress -Depth 5
`;

function compareVersions(a, b) {
  const left = String(a || '').split('.').map(Number), right = String(b || '').split('.').map(Number);
  for (let i = 0; i < 4; i++) { const difference = (right[i] || 0) - (left[i] || 0); if (difference) return difference; }
  return 0;
}
function packageCandidates(packages) {
  const result = [], seen = new Set();
  for (const item of array(packages).sort((a, b) => compareVersions(a.version, b.version))) {
    const root = String(item.location || ''); if (!/^[a-z]:\\/i.test(root)) continue;
    for (const entry of [...array(item.executables), 'app\\Claude.exe', 'Claude.exe']) {
      if (typeof entry !== 'string' || win.isAbsolute(entry) || win.basename(entry).toLowerCase() !== 'claude.exe') continue;
      const filename = win.resolve(root, entry), relative = win.relative(root, filename);
      if (relative === '..' || relative.startsWith('..\\') || win.isAbsolute(relative) || seen.has(filename.toLowerCase())) continue;
      seen.add(filename.toLowerCase()); result.push({ path: filename, kind: 'msix', version: String(item.version || '') });
    }
  }
  return result;
}
async function readable(candidate) {
  const archive = win.join(win.dirname(candidate.path), 'resources', 'app.asar');
  for (const file of [candidate.path, archive]) {
    const handle = await fs.open(file, 'r');
    try { const stat = await handle.stat(); if (!stat.isFile() || stat.size < 16) throw Error('Not an installed runtime'); }
    finally { await handle.close(); }
  }
}
async function selectCandidate(candidates, check = readable) {
  let denied = false;
  for (const candidate of candidates) {
    try { await check(candidate); return { status: 'found', ...candidate, message: candidate.kind === 'msix' ? 'Claude найден в WindowsApps автоматически' : 'Claude найден автоматически' }; }
    catch (error) { if (['EACCES', 'EPERM'].includes(error.code)) denied = true; }
  }
  return { status: denied ? 'access-denied' : 'not-found', path: '', kind: '', version: '',
    message: denied ? 'Пакет Claude найден, но Windows запрещает чтение. Проверьте установку для текущего пользователя.' : 'Claude не найден. Установите его для текущего пользователя или выберите EXE.' };
}
async function discoverClaude() {
  if (process.platform !== 'win32') return { status: 'not-found', path: '', kind: '', message: 'Автопоиск Windows доступен в Windows.' };
  const local = process.env.LOCALAPPDATA || '', candidates = [];
  let queryFailed = false;
  try {
    const metadata = JSON.parse(await powershell(packageScript, 20000));
    candidates.push(...packageCandidates(metadata.packages));
    for (const item of array(metadata.registry)) {
      const filename = String(item).replace(/^"|"$/g, '');
      if (win.isAbsolute(filename) && win.basename(filename).toLowerCase() === 'claude.exe') candidates.push({ path: filename, kind: 'registry', version: '' });
    }
  } catch { queryFailed = true; }
  for (const base of [win.join(local, 'AnthropicClaude'), win.join(local, 'Claude'), win.join(local, 'Programs', 'Claude'), win.join(process.env.ProgramFiles || 'C:\\Program Files', 'Claude')]) {
    const versions = (await fs.readdir(base, { withFileTypes: true }).catch(() => [])).filter(x => x.isDirectory() && /^app-/i.test(x.name))
      .sort((a, b) => compareVersions(a.name.slice(4), b.name.slice(4)));
    for (const item of versions) candidates.push({ path: win.join(base, item.name, 'claude.exe'), kind: 'legacy', version: item.name.slice(4) });
    candidates.push({ path: win.join(base, 'claude.exe'), kind: 'legacy', version: '' });
  }
  const result = await selectCandidate(candidates);
  if (queryFailed && result.status === 'not-found') result.message = 'Не удалось прочитать список пакетов Windows. Нажмите «Найти» повторно или выберите EXE.';
  return result;
}
module.exports = { discoverClaude, packageCandidates, selectCandidate, compareVersions, packageScript };
