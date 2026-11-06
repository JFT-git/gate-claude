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

!macro customUnInstallCheck
  IntCmp $R0 0 guardMigrationCheckDone
  Push $R2
  Push $R3
  Push $R4
  StrCmp $installMode "CurrentUser" 0 guardMigrationRejected
  ReadRegStr $R2 HKCU "${UNINSTALL_REGISTRY_KEY}" "DisplayVersion"
  StrCmp $R2 "0.8.1" 0 guardMigrationRejected
  ReadRegStr $R2 HKCU "${INSTALL_REGISTRY_KEY}" "InstallLocation"
  StrCmp $R2 "" guardMigrationRejected
  System::Call 'Kernel32::SetEnvironmentVariable(t "GUARD_MIGRATION_SOURCE", t "$R2\Uninstall Claude Proxy Guard.exe")'
  System::Call 'Kernel32::SetEnvironmentVariable(t "GUARD_MIGRATION_TEMP", t "$PLUGINSDIR\old-uninstaller.exe")'
  System::Call 'Kernel32::SetEnvironmentVariable(t "GUARD_MIGRATION_INSTALL", t "$R2")'
  nsExec::Exec `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -C "$$ErrorActionPreference='Stop';function C($$p){$$f=[IO.Path]::GetFullPath($$p);if($$f-ne$$p-or$$f.Length-gt240-or$$f-notmatch'^[A-Za-z]:\\'){exit 40};$$c=$$f;while($$c.Length-gt3){if((Get-Item -LiteralPath $$c -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 41};$$c=[IO.Path]::GetDirectoryName($$c)};$$f};$$s=$$env:GUARD_MIGRATION_SOURCE;$$t=$$env:GUARD_MIGRATION_TEMP;$$i=$$env:GUARD_MIGRATION_INSTALL;if((C $$s)-ne(Join-Path (C $$i) 'Uninstall Claude Proxy Guard.exe')){exit 42};if($$s-eq$$t){exit 43};if((Get-FileHash -LiteralPath (C $$s) -Algorithm SHA256).Hash.ToLowerInvariant()-ne'5dbbd29997a485289cfbc8ba382ab2f47bd10e20d926fc6196fb1e990fe21df1'){exit 44};if((Get-FileHash -LiteralPath (C $$t) -Algorithm SHA256).Hash.ToLowerInvariant()-ne'5dbbd29997a485289cfbc8ba382ab2f47bd10e20d926fc6196fb1e990fe21df1'){exit 45};if((Get-FileHash -LiteralPath (C (Join-Path $$i 'resources\app.asar')) -Algorithm SHA256).Hash.ToLowerInvariant()-ne'1a6cd4e62b2d5cb604d0b8f4d8ed6fdc6ffe3bfd058c2faa53d0cc64ffd13a9e'){exit 46};if((Get-FileHash -LiteralPath (C (Join-Path $$i 'Claude Proxy Guard.exe')) -Algorithm SHA256).Hash.ToLowerInvariant()-ne'b710f3b94d03ebdb29709edc35d2ec6200c593d1fc8685826aa5a95df45538a9'){exit 47};exit 0"`
  Pop $R3
  System::Call 'Kernel32::SetEnvironmentVariable(t "GUARD_MIGRATION_SOURCE", t "")'
  System::Call 'Kernel32::SetEnvironmentVariable(t "GUARD_MIGRATION_TEMP", t "")'
  System::Call 'Kernel32::SetEnvironmentVariable(t "GUARD_MIGRATION_INSTALL", t "")'
  StrCpy $0 $R3
  !insertmacro GuardSetupTrace migrationAuthorization
  IntCmp $R3 0 guardMigrationAuthorized
  Goto guardMigrationRejected
  guardMigrationAuthorized:
  ExecWait '"$PLUGINSDIR\old-uninstaller.exe" /NCRC /S /KEEP_APP_DATA /currentuser --updated _?=$R2' $R4
  StrCpy $0 $R4
  !insertmacro GuardSetupTrace migrationReceipt
  IntCmp $R4 0 guardMigrationAccepted
  Goto guardMigrationRejected
  guardMigrationAccepted:
  ClearErrors
  Pop $R4
  Pop $R3
  Pop $R2
  Goto guardMigrationCheckDone
  guardMigrationRejected:
  MessageBox MB_ICONSTOP 'The existing 0.8.1 installation or its uninstaller was not accepted for migration. Setup was interrupted. User data was not removed.'
  Abort
  guardMigrationCheckDone:
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
