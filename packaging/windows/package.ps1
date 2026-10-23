[CmdletBinding()]
param([Parameter(Mandatory)][string]$CodeToolsDir,[string]$InnoCompiler,[string]$ArtifactDir)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$repository=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$windows=Join-Path $repository 'Windows'
$CodeToolsDir=[IO.Path]::GetFullPath($CodeToolsDir)
if($InnoCompiler){$InnoCompiler=[IO.Path]::GetFullPath($InnoCompiler)}
if(!$ArtifactDir){$ArtifactDir=Join-Path $repository 'release'}
$ArtifactDir=[IO.Path]::GetFullPath($ArtifactDir)
$version=(Get-Content -Raw (Join-Path $windows 'package.json')|ConvertFrom-Json).version
if($version-notmatch'^\d+\.\d+\.\d+$'){throw 'Expected three-part product version'}
if(!(Test-Path -LiteralPath (Join-Path $CodeToolsDir 'code-tools-policy.json') -PathType Leaf)){throw 'Verified CodeTools sidecars are required'}
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
 $installer='NOT_BUILT'
 if($InnoCompiler){
  if(!(Test-Path -LiteralPath $InnoCompiler -PathType Leaf)){throw 'Inno compiler not found'}
  & $InnoCompiler ('/DAppVersion='+$version) ('/DSourceDir='+$product) ('/DArtifactDir='+$ArtifactDir) (Join-Path $PSScriptRoot 'Guard.iss')
  if($LASTEXITCODE-ne0){throw 'Installer compilation failed'}
  $installer='BUILT_NOT_INSTALL_TESTED'
 }
 Get-ChildItem -LiteralPath $ArtifactDir -File|Where-Object {$_.Extension-in@('.zip','.exe')}|ForEach-Object {
  $digest=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  [IO.File]::WriteAllText(($_.FullName+'.sha256'),($digest+'  '+$_.Name+"`n"),[Text.UTF8Encoding]::new($false))
 }
 [ordered]@{version=$version;portable='BUILT';installer=$installer;installerElevates=$false;installsService=$false;runtimeTests='NOT_RUN_BY_PACKAGING';authenticode='NOT_CONFIGURED'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $ArtifactDir 'windows-build-status.json') -Encoding UTF8
}finally{Set-Location $old.Path}
