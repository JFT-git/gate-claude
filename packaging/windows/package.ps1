[CmdletBinding()]
param([Parameter(Mandatory)][string]$CodeToolsDir,[string]$InnoCompiler,[string]$ArtifactDir)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$repository=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$windows=Join-Path $repository 'Windows'
$CodeToolsDir=[IO.Path]::GetFullPath($CodeToolsDir)
if(!$ArtifactDir){$ArtifactDir=Join-Path $repository 'release'}
$ArtifactDir=[IO.Path]::GetFullPath($ArtifactDir)
$version=(Get-Content -Raw (Join-Path $windows 'package.json')|ConvertFrom-Json).version
if($version-notmatch'^\d+\.\d+\.\d+$'){throw 'Expected three-part product version'}
if(!(Test-Path -LiteralPath (Join-Path $CodeToolsDir 'code-tools-policy.json') -PathType Leaf)){throw 'Verified CodeTools sidecars are required'}
if(!$env:GUARD_WINDOWS_UPDATE_PRIVATE_KEY){throw 'GUARD_WINDOWS_UPDATE_PRIVATE_KEY must name the external Ed25519 private key PEM'}
$old=Get-Location
try {
 Set-Location $windows
 & npm.cmd ci --no-audit --no-fund
 if($LASTEXITCODE-ne0){throw 'npm ci failed'}
 & node scripts/package.cjs --platform win32 --arch x64 --code-tools-dir ([IO.Path]::GetFullPath($CodeToolsDir))
 if($LASTEXITCODE-ne0){throw 'Packaging failed'}
 $product=Join-Path $windows 'dist\Claude Proxy Guard-win32-x64'
 [void][IO.Directory]::CreateDirectory($ArtifactDir)
 $archive=Join-Path $ArtifactDir "ClaudeProxyGuard-Windows-$version-x64.zip"
 if(Test-Path -LiteralPath $archive){throw 'Artifact already exists; use a fresh output directory'}
 Compress-Archive -LiteralPath $product -DestinationPath $archive -CompressionLevel Optimal
 $installerProduct=Join-Path $windows 'dist\Claude Proxy Guard-win32-x64-nsis'
 if(Test-Path -LiteralPath $installerProduct){Remove-Item -LiteralPath $installerProduct -Recurse -Force}
 Copy-Item -LiteralPath $product -Destination $installerProduct -Recurse
 $updateConfig=@('provider: github','owner: JFT-git','repo: gate-claude','channel: latest','updaterCacheDirName: gate-claude-updater','')
 [IO.File]::WriteAllLines((Join-Path $installerProduct 'resources\app-update.yml'),$updateConfig,[Text.UTF8Encoding]::new($false))
 $env:GUARD_WINDOWS_ARTIFACT_DIR=$ArtifactDir
 try {
  & node (Join-Path $windows 'node_modules\electron-builder\cli.js') --prepackaged $installerProduct --win nsis --x64 --config (Join-Path $PSScriptRoot 'electron-builder.cjs') --publish never
  if($LASTEXITCODE-ne0){throw 'NSIS compilation failed'}
 }finally{Remove-Item Env:\GUARD_WINDOWS_ARTIFACT_DIR -ErrorAction SilentlyContinue}
 Remove-Item -LiteralPath (Join-Path $ArtifactDir 'builder-debug.yml') -ErrorAction SilentlyContinue
 $metadata=Join-Path $ArtifactDir 'latest.yml'
 & node (Join-Path $PSScriptRoot 'sign-update-metadata.cjs') $metadata
 if($LASTEXITCODE-ne0){throw 'Update metadata signing failed'}
 Get-ChildItem -LiteralPath $ArtifactDir -File|Where-Object {$_.Extension-in@('.zip','.exe','.blockmap','.yml','.sig')}|ForEach-Object {
  $digest=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  [IO.File]::WriteAllText(($_.FullName+'.sha256'),($digest+'  '+$_.Name+"`n"),[Text.UTF8Encoding]::new($false))
 }
 [ordered]@{version=$version;portable='BUILT_UPDATER_DISABLED';installer='BUILT_NOT_INSTALL_TESTED';updateMetadata='SIGNED';differentialBlockmap='BUILT';innoMigration='IMPLEMENTED_NOT_WINDOWS_RUN';installerElevates='SERVICE_REQUEST_ON_DEMAND';installsService='REQUEST_INSTALL_FAIL_CLOSED_NOT_WINDOWS_RUN';deleteAppDataOnUninstall=$false;runtimeTests='NOT_RUN_BY_PACKAGING';authenticode='NOT_CONFIGURED'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $ArtifactDir 'windows-build-status.json') -Encoding UTF8
}finally{Set-Location $old.Path}
