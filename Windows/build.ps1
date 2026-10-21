param([switch]$SkipTests, [string]$CodeToolsDir)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-Location $PSScriptRoot

& npm.cmd ci --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
if ($CodeToolsDir) { & npm.cmd run build -- --code-tools-dir $CodeToolsDir } else { & npm.cmd run build }
if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }

$product = Join-Path $PSScriptRoot 'dist\Claude Proxy Guard-win32-x64'
$env:GATE_HOST = Join-Path $product 'resources\GuardHost.exe'
if (-not $SkipTests) {
    & npm.cmd test
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    $smoke = Join-Path ([IO.Path]::GetTempPath()) ('gate-smoke-' + [guid]::NewGuid())
    New-Item -ItemType Directory $smoke | Out-Null
    try {
        $env:GATE_SMOKE_OUT = Join-Path $smoke 'result.json'
        $profile = Join-Path $smoke 'Profile'
        $process = Start-Process (Join-Path $product 'Claude Proxy Guard.exe') -ArgumentList @('--smoke-test', "--user-data-dir=`"$profile`"") -PassThru
        if (-not $process.WaitForExit(45000)) { Stop-Process -Id $process.Id -Force; throw 'Packaged UI test timed out' }
        $result = Get-Content -Raw $env:GATE_SMOKE_OUT | ConvertFrom-Json
        if ($result.result -ne 'PASS') { throw 'Packaged UI test failed' }
    } finally {
        Remove-Item Env:\GATE_SMOKE_OUT -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force $smoke -ErrorAction SilentlyContinue
    }
}
$version = (Get-Content -Raw (Join-Path $PSScriptRoot 'package.json') | ConvertFrom-Json).version
$zip = Join-Path $PSScriptRoot "dist\ClaudeProxyGuard-Windows-x64-$version.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path $product -DestinationPath $zip -CompressionLevel Optimal
$digest = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$zip.sha256", "$digest  $([IO.Path]::GetFileName($zip))`n", [Text.UTF8Encoding]::new($false))
Write-Host $zip
