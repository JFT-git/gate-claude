[CmdletBinding()]
param([switch]$ClaudeE2E)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This check requires Windows.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Native WFP checks require an administrator Windows runner. No automatic elevation is performed by this script.'
}

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$Executable, [string[]]$Arguments = @(), [string]$Label = 'Command')
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed (exit $LASTEXITCODE)." }
}

function Get-OfficialClaudeMsix {
    param([Parameter(Mandatory)][string]$Destination)
    # Redirects are checked individually. No arbitrary host or HTTP downgrade is accepted.
    $allowedHosts = @('claude.ai', 'downloads.claude.ai')
    $uri = [Uri]'https://claude.ai/api/desktop/win32/x64/msix/latest/redirect'
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(8)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('gate-claude-windows-ci/0.5')
    try {
        for ($redirect = 0; $redirect -lt 8; $redirect++) {
            if ($uri.Scheme -ne 'https' -or $uri.Host -notin $allowedHosts -or -not $uri.IsDefaultPort -or $uri.UserInfo) {
                throw 'Official Claude download redirected outside the allowed HTTPS origins.'
            }
            $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            try {
                $status = [int]$response.StatusCode
                if ($status -in @(301, 302, 303, 307, 308)) {
                    if (-not $response.Headers.Location) { throw 'Official Claude redirect is missing its destination.' }
                    $uri = [Uri]::new($uri, $response.Headers.Location)
                    continue
                }
                if ($status -ne 200) { throw "Official Claude download failed (HTTP $status)." }
                $limit = 1GB
                $length = $response.Content.Headers.ContentLength
                if ($null -ne $length -and ($length -le 0 -or $length -gt $limit)) { throw 'Official Claude package has an unexpected size.' }
                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $downloadTimeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromMinutes(8))
                $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $buffer = [byte[]]::new(1MB)
                    [long]$total = 0
                    while (($read = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $downloadTimeout.Token).GetAwaiter().GetResult()) -gt 0) {
                        $total += $read
                        if ($total -gt $limit) { throw 'Official Claude package exceeded the download size limit.' }
                        $outputStream.Write($buffer, 0, $read)
                    }
                    if ($total -lt 1MB -or ($null -ne $length -and $total -ne $length)) { throw 'Official Claude package download is incomplete.' }
                } finally { $outputStream.Dispose(); $inputStream.Dispose(); $downloadTimeout.Dispose() }
                return
            } finally { $response.Dispose() }
        }
        throw 'Official Claude download exceeded the redirect limit.'
    } finally { $client.Dispose(); $handler.Dispose() }
}

function Expand-CheckedMsix {
    param([Parameter(Mandatory)][string]$Archive, [Parameter(Mandatory)][string]$Destination)
    [void][IO.Directory]::CreateDirectory($Destination)
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        [long]$expanded = 0
        if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt 100000) { throw 'Unexpected MSIX entry count.' }
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('/', '\')
            if ($name.IndexOf(':') -ge 0 -or $name.IndexOf([char]0) -ge 0 -or [IO.Path]::IsPathRooted($name)) { throw 'Unsafe MSIX entry path.' }
            $target = [IO.Path]::GetFullPath([IO.Path]::Combine($root, $name))
            if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'MSIX entry escapes its extraction directory.' }
            $mode = ($entry.ExternalAttributes -shr 16) -band 0xF000
            if ($mode -eq 0xA000) { throw 'MSIX symbolic links are not accepted.' }
            $expanded += $entry.Length
            if ($expanded -gt 4GB -or $entry.Length -gt 2GB) { throw 'MSIX exceeds the extraction size limit.' }
            if ($name.EndsWith('\')) { [void][IO.Directory]::CreateDirectory($target); continue }
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            $source = $entry.Open()
            $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $buffer = [byte[]]::new(1MB)
                [long]$written = 0
                while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $written += $read
                    if ($written -gt $entry.Length -or $written -gt 2GB) { throw 'MSIX expanded entry exceeded its declared length.' }
                    $output.Write($buffer, 0, $read)
                }
                if ($written -ne $entry.Length) { throw 'MSIX expanded entry is incomplete.' }
            } finally { $output.Dispose(); $source.Dispose() }
        }
    } finally { $zip.Dispose() }
}

$windowsRoot = Split-Path -Parent $PSScriptRoot
$repositoryRoot = Split-Path -Parent $windowsRoot
if (-not $env:RUNNER_TEMP -or -not (Test-Path -LiteralPath $env:RUNNER_TEMP -PathType Container)) {
    throw 'RUNNER_TEMP must name an existing private CI temporary directory.'
}
$work = Join-Path $env:RUNNER_TEMP ('gate-ci-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
$resources = Join-Path $work 'resources'
[void][IO.Directory]::CreateDirectory($resources)
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) { throw 'The stock .NET Framework x64 C# compiler was not found.' }
$nodeSource = (Get-Command node.exe -ErrorAction Stop).Source
$node = Join-Path $resources 'node.exe'
Copy-Item -LiteralPath $nodeSource -Destination $node
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'Resources\RuntimeBootstrap.cjs') -Destination (Join-Path $resources 'RuntimeBootstrap.cjs')
$hostHelper = Join-Path $resources 'GuardHost.exe'
$fenceHelper = Join-Path $resources 'NetworkFence.exe'
Invoke-Checked -Executable $csc -Arguments @('/nologo', '/optimize+', '/platform:anycpu', '/target:exe', ('/out:' + $hostHelper), (Join-Path $windowsRoot 'native\GuardHost.cs')) -Label 'GuardHost compilation'
Invoke-Checked -Executable $csc -Arguments @('/nologo', '/optimize+', '/platform:x64', '/target:exe', ('/out:' + $fenceHelper), (Join-Path $windowsRoot 'native\NetworkFence.cs')) -Label 'NetworkFence compilation'

$oldEnvironment = @{}
foreach ($name in @('GATE_HOST', 'GATE_FENCE_HELPER', 'NODE_EXTRA_CA_CERTS')) {
    $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$oldDirectory = Get-Location
try {
    $env:GATE_HOST = $hostHelper
    $env:GATE_FENCE_HELPER = $fenceHelper
    Set-Location -LiteralPath $windowsRoot
    # npm's *.test.cjs glob excludes explicit/manual installed-Claude and AppContainer probes.
    Invoke-Checked -Executable (Get-Command npm.cmd -ErrorAction Stop).Source -Arguments @('test') -Label 'Windows native/unit checks'
    Write-Host 'PASS: Windows unit checks, atomic Job Object termination and native WFP isolation.'
    if ($ClaudeE2E) {
        $archive = Join-Path $work 'official-claude.msix'
        $extracted = Join-Path $work 'official-claude'
        Get-OfficialClaudeMsix -Destination $archive
        Expand-CheckedMsix -Archive $archive -Destination $extracted
        $source = Join-Path $extracted 'app\Claude.exe'
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Official MSIX did not contain app\Claude.exe.' }
        $signature = Get-AuthenticodeSignature -LiteralPath $source
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) { throw 'The extracted Claude.exe does not have a valid Authenticode signature.' }
        # Generate one synthetic certificate. Trust applies only to these Node child processes.
        $git = (Get-Command git.exe -ErrorAction Stop).Source
        $gitRoot = Split-Path -Parent (Split-Path -Parent $git)
        $openssl = @((Join-Path $gitRoot 'usr\bin\openssl.exe'), (Join-Path $gitRoot 'mingw64\bin\openssl.exe')) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if (-not $openssl) { throw 'The runner Git installation does not provide OpenSSL.' }
        $certificate = Join-Path $work 'fixture.crt'
        $key = Join-Path $work 'fixture.key'
        $opensslArguments = @('req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '2', '-nodes', '-subj', '/CN=gate-claude-local-fixture', '-addext', 'subjectAltName=DNS:claude.ai,DNS:challenges.cloudflare.com,DNS:ipwho.is,DNS:api64.ipify.org,DNS:api.ipify.org,DNS:api6.ipify.org', '-keyout', $key, '-out', $certificate)
        & $openssl @opensslArguments *> (Join-Path $work 'openssl.log')
        if ($LASTEXITCODE -ne 0) { throw 'Synthetic fixture certificate generation failed.' }
        $env:NODE_EXTRA_CA_CERTS = $certificate
        foreach ($mode in @('network', 'socks5')) {
            $caseWork = Join-Path $work ('e2e-' + $mode)
            $arguments = @((Join-Path $windowsRoot 'test\installed-e2e.cjs'), '--claude', $source, '--work', $caseWork, '--cert', $certificate, '--key', $key, '--host', $hostHelper, '--fence', $fenceHelper)
            if ($mode -eq 'network') { $arguments += '--network' }
            # Do not put raw traffic records, full proof JSON, private profiles or fixture keys in Actions logs/artifacts.
            & $node @arguments *> (Join-Path $work ('e2e-' + $mode + '.log'))
            if ($LASTEXITCODE -ne 0) { throw "Installed Claude $mode fixture E2E failed (exit $LASTEXITCODE). Raw records remain only on this ephemeral runner." }
            $proof = Get-Content -Raw -LiteralPath (Join-Path $caseWork 'proof.json') | ConvertFrom-Json
            if ($proof.result -ne 'PASS') { throw "Installed Claude $mode fixture E2E did not confirm PASS." }
            Write-Host "PASS: official Claude $mode, local TLS, production WFP, same-IP recovery, IP kill and profile persistence."
        }
    }
} finally {
    Set-Location -LiteralPath $oldDirectory.Path
    foreach ($name in $oldEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $oldEnvironment[$name], 'Process') }
    # Runner lifetime owns cleanup. No vendor binaries, raw proof files or private profiles are uploaded.
}
