param(
    [string]$ProbePath = (Join-Path $PSScriptRoot 'AppContainerProbe.exe'),
    [string]$MetadataPath = '',
    [string]$TargetPath = '',
    [switch]$LPAC,
    [int]$Seconds = 16,
    [switch]$CaptureFatalLog,
    [switch]$KeepContainerProfile
)
# Compatibility observation only: no account login, IP-provider call, firewall
# change, loopback exemption, WindowsApps ACL change, or installed-app mutation.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$stage = 'arguments'
$process = $null
$containerName = $null
$cleanup = $null
$result = $null

function Quote-Argument([string]$Value) {
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * ($slashes * 2 + 1)))
            [void]$builder.Append('"')
        } else {
            [void]$builder.Append(('\' * $slashes))
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    [void]$builder.Append(('\' * ($slashes * 2)))
    [void]$builder.Append('"')
    return $builder.ToString()
}
function Invoke-ProfileCommand([string]$Mode, [string]$Name) {
    $lines = @(& $ProbePath $Mode --name $Name)
    if ($LASTEXITCODE -ne 0) { throw "ProfileApiFailed" }
    $value = ($lines -join "`n") | ConvertFrom-Json
    return $value
}

try {
    if ($Seconds -lt 15 -or $Seconds -gt 60 -or -not (Test-Path -LiteralPath $ProbePath -PathType Leaf)) { throw 'InvalidProbeArguments' }
    $ProbePath = (Resolve-Path -LiteralPath $ProbePath).Path
    $stage = 'profile'
    if ($MetadataPath) {
        $metadata = Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json
        $containerName = [string]$metadata.profile
        if ($containerName -notmatch '^gate-probe-[0-9a-f]{32}$') { throw 'InvalidContainerName' }
        $created = Invoke-ProfileCommand 'create' $containerName
        if ($created.sid -ne $metadata.sid) { throw 'ContainerSidMismatch' }
    } else {
        $containerName = 'gate-probe-' + [Guid]::NewGuid().ToString('N')
        $created = Invoke-ProfileCommand 'create' $containerName
    }
    if ([string]$created.sid -notmatch '^S-1-15-2-(?:[0-9]+-){6}[0-9]+$') { throw 'InvalidPackageSid' }
    $stage = 'target-discovery'
    if (-not $TargetPath) {
        $packages = @(Get-AppxPackage -ErrorAction Stop | Where-Object { $_.Name -match 'Claude|Anthropic' } | Sort-Object Version -Descending)
        foreach ($package in $packages) {
            $candidate = Join-Path $package.InstallLocation 'app\Claude.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $TargetPath = $candidate; break }
        }
    }
    if (-not $TargetPath -or -not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) { throw 'ClaudeNotFound' }
    $signed = (Get-AuthenticodeSignature -LiteralPath $TargetPath).Status -eq 'Valid'
    $stage = 'scratch-profile-acl'
    $scratch = Join-Path $PSScriptRoot ('scratch-' + [Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $scratch)
    foreach ($leaf in @('UserData', 'Temp', 'Roaming', 'Local', 'CrashDumps')) {
        [void](New-Item -ItemType Directory -Path (Join-Path $scratch $leaf))
    }
    # Only this newly-created scratch subtree receives the temporary package SID.
    & icacls.exe $scratch /grant ('*' + $created.sid + ':(OI)(CI)M') /T /C 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'ScratchAclFailed' }
    # DACL write permission alone is insufficient for a low-integrity process.
    & icacls.exe $scratch /setintegritylevel '(OI)(CI)L' /T /C 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'ScratchIntegrityLabelFailed' }
    $arguments = @('launch', '--name', $containerName, '--workdir', $scratch, '--heartbeat-ms', '5000')
    if ($LPAC) { $arguments += '--lpac' }
    $arguments += @('--', $TargetPath, ('--user-data-dir=' + (Join-Path $scratch 'UserData')),
        ('--crash-dumps-dir=' + (Join-Path $scratch 'CrashDumps')), '--no-first-run', '--no-default-browser-check')
    $debugLog = Join-Path $scratch 'chromium-debug.log'
    if ($CaptureFatalLog) { $arguments += @('--enable-logging=file', ('--log-file=' + $debugLog)) }
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $ProbePath
    $info.Arguments = (($arguments | ForEach-Object { Quote-Argument ([string]$_) }) -join ' ')
    $info.WorkingDirectory = $scratch
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables['CLAUDE_USER_DATA_DIR'] = Join-Path $scratch 'UserData'
    $info.EnvironmentVariables['TEMP'] = Join-Path $scratch 'Temp'
    $info.EnvironmentVariables['TMP'] = Join-Path $scratch 'Temp'
    $info.EnvironmentVariables['APPDATA'] = Join-Path $scratch 'Roaming'
    $info.EnvironmentVariables['LOCALAPPDATA'] = Join-Path $scratch 'Local'
    # PROXY_GUARD_CONFIG is inherited if the caller deliberately supplies it.
    $stage = 'launch'
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $process.HasExited -and $timer.Elapsed.TotalSeconds -lt $Seconds) {
        try { $process.StandardInput.WriteLine('ping'); $process.StandardInput.Flush() } catch { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $process.HasExited) { $process.StandardInput.Close() }
    if (-not $process.WaitForExit(7000)) { $process.Kill(); [void]$process.WaitForExit(3000) }
    $events = @()
    foreach ($line in ($stdout.GetAwaiter().GetResult() -split "`r?`n")) {
        if ($line.Trim()) { $events += ($line | ConvertFrom-Json) }
    }
    $tokens = @($events | Where-Object event -eq 'token')
    $jobs = @($events | Where-Object event -eq 'job')
    $observed15 = @($jobs | Where-Object { $_.mainAlive -eq $true -and $_.elapsedMilliseconds -ge 15000 }).Count -gt 0
    $tokenValid = $tokens.Count -eq 1 -and $tokens[0].isAppContainer -eq $true -and $tokens[0].capabilityCount -eq 0 -and $tokens[0].lpac -eq [bool]$LPAC
    $fatalDiagnostics = @()
    $logPresent = $CaptureFatalLog -and (Test-Path -LiteralPath $debugLog -PathType Leaf)
    if ($logPresent) {
        # The log belongs to this brand-new empty profile. Publish only bounded
        # source/check/code fields; never include raw log lines or user paths.
        foreach ($line in (Get-Content -LiteralPath $debugLog -TotalCount 2000)) {
            if ($line -notmatch '\bFATAL\b|Check failed') { continue }
            $source = [regex]::Match($line, '[A-Za-z0-9_]+\.(?:cc|cpp|c|h)(?:\([0-9]+\)|:[0-9]+)').Value
            $check = [regex]::Match($line, 'Check failed:\s*([A-Za-z0-9_:.<>=!(), +\-]{1,160})').Groups[1].Value.Trim()
            $codes = @([regex]::Matches($line, '\b0x[0-9a-fA-F]{4,16}\b') | ForEach-Object { $_.Value })
            $fatalDiagnostics += @{ source = $source; check = $check; statusCodes = $codes }
            if ($fatalDiagnostics.Count -ge 10) { break }
        }
    }
    $result = [ordered]@{
        test = 'AppContainer compatibility observation; not a functional login or leak-proof verdict'
        result = $(if ($tokenValid -and $observed15) { 'ALIVE_15S' } else { 'COMPATIBILITY_FAIL' })
        lpacRequested = [bool]$LPAC
        originalSignatureValid = $signed
        tokenVerified = $tokenValid
        mainObservedAlive15Seconds = $observed15
        helperExitCode = $process.ExitCode
        helperStderrEmpty = [string]::IsNullOrEmpty($stderr.GetAwaiter().GetResult())
        events = $events
        originalAclChanged = $false
        networkCapabilitiesGranted = $false
        loopbackExemptionAdded = $false
        scratchProfileCreated = $true
        debugLogPresent = $logPresent
        fatalDiagnostics = $fatalDiagnostics
    }
} catch {
    $result = [ordered]@{ result = 'PROBE_ERROR'; stage = $stage; type = $_.Exception.GetType().Name }
} finally {
    if ($process -and -not $process.HasExited) {
        try { $process.StandardInput.Close() } catch { }
        if (-not $process.WaitForExit(3000)) { $process.Kill(); [void]$process.WaitForExit(3000) }
    }
    if ($containerName -and -not $KeepContainerProfile) {
        try { $cleanup = Invoke-ProfileCommand 'delete' $containerName }
        catch { $cleanup = @{ event = 'cleanup'; deleted = $false; apiError = $true } }
    }
    if ($process) { $process.Dispose() }
}
$result['containerProfileCleanup'] = $cleanup
# Retain the owned scratch directory for the caller's scoped cleanup. Do not
# recursively delete untrusted child-created junctions from a privileged script.
$result | ConvertTo-Json -Depth 15 -Compress
