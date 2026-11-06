[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$TaskName,
  [Parameter(Mandatory)][string]$UserId,
  [Parameter(Mandatory)][string]$Executable,
  [Parameter(Mandatory)][string]$Arguments,
  [Parameter(Mandatory)][string]$LogPath,
  [hashtable]$Environment,
  [int]$TimeoutSeconds = 1800
)
$ErrorActionPreference = 'Stop'
if ($TaskName -notmatch '^ClaudeProxyGuard-Test-[A-Za-z0-9-]+$') { throw 'Unexpected test task name' }
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw 'Test task already exists' }
$prefix = ''
if ($Environment) { foreach ($key in $Environment.Keys) { $prefix += 'set "' + $key + '=' + $Environment[$key] + '"&& ' } }
$command = $prefix + '"' + $Executable + '" ' + $Arguments + ' > "' + $LogPath + '" 2>&1'
$action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\cmd.exe" -Argument ('/D /S /C "' + $command + '"')
$principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal | Out-Null
try {
  Start-ScheduledTask -TaskName $TaskName
  $started = Get-Date
  do {
    Start-Sleep -Milliseconds 500
    $task = Get-ScheduledTask -TaskName $TaskName
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    if (((Get-Date) - $started).TotalSeconds -gt $TimeoutSeconds) { throw 'Limited interactive task timed out' }
  } until ($task.State -eq 'Ready' -and $info.LastTaskResult -ne 267009)
  [pscustomobject]@{ result = $info.LastTaskResult; log = $LogPath } | ConvertTo-Json -Compress
  if ($info.LastTaskResult -ne 0) { exit $info.LastTaskResult }
} finally {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}
