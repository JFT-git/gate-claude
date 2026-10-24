param([string]$Destination = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'AppContainerProbe.cs'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Stock .NET Framework x64 compiler not found.' }
[void](New-Item -ItemType Directory -Path $Destination -Force)
$output = Join-Path $Destination 'AppContainerProbe.exe'
& $compiler /nologo /target:exe /platform:x64 /optimize+ ("/out:" + $output) $source
if ($LASTEXITCODE -ne 0) { throw 'AppContainerProbe compilation failed.' }
@{ result = 'BUILT'; file = 'AppContainerProbe.exe'; sha256 = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant() } | ConvertTo-Json -Compress
