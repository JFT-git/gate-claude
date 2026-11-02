!macro customInit
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\local.proxyguard.gate-claude_is1" "InstallLocation"
  StrCmp $0 "" guardInnoMigrationValidated
  StrCmp $0 "$LOCALAPPDATA\Programs\Claude Proxy Guard\" guardInnoMigrationValidated
  MessageBox MB_ICONSTOP 'The existing Claude Proxy Guard installation does not belong to this per-user directory. Remove it separately before installing this version.'
  Abort
  guardInnoMigrationValidated:
!macroend

!macro customInstall
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\local.proxyguard.gate-claude_is1" "InstallLocation"
  StrCmp $0 "$LOCALAPPDATA\Programs\Claude Proxy Guard\" 0 guardInnoMigrationDone
  Delete "$LOCALAPPDATA\Programs\Claude Proxy Guard\unins000.exe"
  Delete "$LOCALAPPDATA\Programs\Claude Proxy Guard\unins000.dat"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\local.proxyguard.gate-claude_is1"
  guardInnoMigrationDone:
!macroend

!macro customUnInstall
  ReadRegStr $0 HKCU "Software\GateClaudeGuard" "GateClaudeOwner"
  StrCmp $0 "gate-claude.protocol.v1" 0 guardProtocolCleanupDone
  ReadRegStr $1 HKCU "Software\Classes\GateClaudeGuard.Url.claude" "GateClaudeOwner"
  StrCmp $1 $0 0 guardProtocolCleanupDone
  ReadRegStr $2 HKCU "Software\Classes\GateClaudeGuard.Url.claude\shell\open\command" ""
  StrCmp $2 '"$INSTDIR\Claude Proxy Guard.exe" "%1"' 0 guardProtocolCleanupDone
  DeleteRegKey HKCU "Software\Classes\GateClaudeGuard.Url.claude"
  DeleteRegKey HKCU "Software\GateClaudeGuard"
  ReadRegStr $3 HKCU "Software\RegisteredApplications" "Claude Proxy Guard"
  StrCmp $3 "Software\GateClaudeGuard\Capabilities" 0 guardProtocolCleanupDone
  DeleteRegValue HKCU "Software\RegisteredApplications" "Claude Proxy Guard"
  guardProtocolCleanupDone:
!macroend
