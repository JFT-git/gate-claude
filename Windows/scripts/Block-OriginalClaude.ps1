#Requires -RunAsAdministrator
[CmdletBinding()]
param([ValidateSet('Install','Verify','Remove')][string]$Mode='Verify')
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$group='Claude Proxy Guard: original Claude isolation'
$owner='gate-claude.original-isolation.v1'
$prefix='GateClaude.Original.'
$packages=@(Get-AppxPackage -AllUsers -Name Claude | Where-Object {$_.PackageFamilyName -eq 'Claude_pzs8sxrjxfjjc'})
if($Mode -eq 'Remove') {
  Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Where-Object {$_.Name.StartsWith($prefix) -and $_.Description -eq $owner} | Remove-NetFirewallRule
  return
}
if(!$packages.Count){throw 'Official Claude WindowsApps package not found.'}
if(@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {!$_.Enabled}).Count){throw 'Windows Firewall must be enabled on every profile.'}
$specs=@()
foreach($p in $packages) {
  if(!$p.InstallLocation.StartsWith(($env:ProgramFiles+'\WindowsApps\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected package path.'}
  $specs+=@{Kind='Family';Value=$p.PackageFamilyName}
  foreach($f in Get-ChildItem -LiteralPath $p.InstallLocation -Filter *.exe -Recurse -File) {
    if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Executable reparse point refused.'}
    $specs+=@{Kind='Program';Value=$f.FullName}
  }
}
$specs=@($specs|Sort-Object { $_.Kind+':'+$_.Value } -Unique)
foreach($s in $specs) {
  $sha=[Security.Cryptography.SHA256]::Create()
  try {$hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($s.Kind+':'+$s.Value).ToLowerInvariant())))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  foreach($direction in @('Outbound','Inbound')) {
    $name=$prefix+$hash+'.'+$direction
    $r=Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction SilentlyContinue
    if($r -and ($r.Group -ne $group -or $r.Description -ne $owner)){throw 'Existing firewall rule ownership conflict.'}
    if($Mode -eq 'Install') {
      $ruleArgs=@{Name=$name;DisplayName=('Guard: block original Claude '+$direction);Description=$owner;Group=$group;Direction=$direction;Action='Block';Profile='Any';Enabled='True';Protocol='Any';PolicyStore='PersistentStore'}
      if($s.Kind -eq 'Family'){$ruleArgs.PackageFamilyName=$s.Value}else{$ruleArgs.Program=$s.Value}
      if($r){
        $ruleArgs.Remove('DisplayName'); $ruleArgs.Remove('Group'); $ruleArgs.NewDisplayName=('Guard: block original Claude '+$direction)
        Set-NetFirewallRule @ruleArgs | Out-Null
      }else{New-NetFirewallRule @ruleArgs | Out-Null}
    }
    $active=Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    if(!$active -or $active.Enabled -ne 'True' -or $active.Action -ne 'Block' -or $active.Direction -ne $direction -or $active.Profile -ne 'Any'){throw 'Required effective block rule missing.'}
    $app=$active|Get-NetFirewallApplicationFilter
    if($s.Kind -eq 'Program' -and $app.Program -ne $s.Value){throw 'Program filter mismatch.'}
    if($s.Kind -eq 'Family' -and $active.PackageFamilyName -ne $s.Value){throw 'Package family filter mismatch.'}
  }
}
[ordered]@{result='PASS';mode=$Mode;packageFamilies=@($packages.PackageFamilyName|Sort-Object -Unique).Count;programs=@($specs|Where-Object {$_.Kind -eq 'Program'}).Count;effectiveRules=$specs.Count*2;persistent=$true;allProfiles=$true;guardRuntimeExcluded=$true}|ConvertTo-Json -Compress
