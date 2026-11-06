!macro GuardSetupTrace stage
  ReadEnvStr $R0 CLAUDE_PROXY_GUARD_SETUP_TRACE
  StrCmp $R0 "1" 0 +4
  FileOpen $R1 "$TEMP\ClaudeProxyGuard-setup.log" a
  FileWrite $R1 "${stage}:$0$\r$\n"
  FileClose $R1
!macroend

!macro customInit
  !insertmacro GuardSetupTrace customInitStart
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\local.proxyguard.gate-claude_is1" "InstallLocation"
  StrCmp $0 "" guardInnoMigrationValidated
  StrCmp $0 "$LOCALAPPDATA\Programs\Claude Proxy Guard\" guardInnoMigrationValidated
  MessageBox MB_ICONSTOP 'The existing Claude Proxy Guard installation does not belong to this per-user directory. Remove it separately before installing this version.'
  Abort
  guardInnoMigrationValidated:
!macroend

!macro customInstall
  !insertmacro GuardSetupTrace customInstallStart
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\local.proxyguard.gate-claude_is1" "InstallLocation"
  StrCmp $0 "$LOCALAPPDATA\Programs\Claude Proxy Guard\" 0 guardInnoMigrationDone
  Delete "$LOCALAPPDATA\Programs\Claude Proxy Guard\unins000.exe"
  Delete "$LOCALAPPDATA\Programs\Claude Proxy Guard\unins000.dat"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\local.proxyguard.gate-claude_is1"
  guardInnoMigrationDone:
  !insertmacro GuardSetupTrace serviceInstallRequest
  ExecWait '"$INSTDIR\resources\GuardService.exe" --request-install --owner 0' $0
  !insertmacro GuardSetupTrace serviceInstallReceipt
  StrCmp $0 0 guardServiceReady
  StrCmp $0 2 guardServiceExitTwo
  MessageBox MB_ICONSTOP 'Claude Proxy Guard service installation was not confirmed (exit $0). The application was not installed. No retry or hidden elevation was attempted.'
  Abort
  guardServiceExitTwo:
  MessageBox MB_ICONSTOP 'Claude Proxy Guard service installation failed with native exit 2. The application was not installed. Review the service state before retrying.'
  Abort
  guardServiceReady:
  !insertmacro GuardSetupTrace serviceInstallReady
!macroend

!macro customUnInstall
  ${If} ${isUpdated}
    !insertmacro GuardSetupTrace serviceUpdatePreserved
  ${Else}
    !insertmacro GuardSetupTrace serviceUninstallRequest
    ExecWait '"$INSTDIR\resources\GuardService.exe" --request-uninstall --owner 0' $0
    !insertmacro GuardSetupTrace serviceUninstallReceipt
    StrCmp $0 0 guardServiceRemoved
    StrCmp $0 2 guardServiceUninstallExitTwo
    MessageBox MB_ICONSTOP 'Claude Proxy Guard service removal was not confirmed (exit $0). Uninstall was interrupted; application files and user data were not treated as service cleanup.'
    Abort
    guardServiceUninstallExitTwo:
    MessageBox MB_ICONSTOP 'Claude Proxy Guard service removal failed with native exit 2. Uninstall was interrupted. Repair the owned service installation before retrying.'
    Abort
  ${EndIf}
  guardServiceRemoved:
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
