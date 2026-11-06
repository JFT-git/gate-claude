; Inno Setup 6.3+; per-user application files and an explicitly elevated owned service request.
#ifndef AppVersion
  #error Pass /DAppVersion from Windows/package.json
#endif
#ifndef SourceDir
  #error Pass /DSourceDir pointing to the complete packaged Windows directory
#endif
#ifndef ArtifactDir
  #define ArtifactDir "..\..\release"
#endif
[Setup]
AppId=local.proxyguard.gate-claude
AppName=Claude Proxy Guard
AppVersion={#AppVersion}
AppPublisher=gate-claude contributors
AppPublisherURL=https://github.com/JFT-git/gate-claude
DefaultDirName={localappdata}\Programs\Claude Proxy Guard
DefaultGroupName=Claude Proxy Guard
PrivilegesRequired=lowest
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0
OutputDir={#ArtifactDir}
OutputBaseFilename=ClaudeProxyGuard-Windows-{#AppVersion}-x64-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
CloseApplications=no
RestartApplications=no
UninstallDisplayIcon={app}\Claude Proxy Guard.exe
LicenseFile=..\..\LICENSE
[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
[Messages]
WelcomeLabel2=Программа будет установлена для текущего пользователя.%n%nПеред обновлением остановите сессию и закройте Guard.%n%nПосле копирования файлов GuardService запросит установку или обновление системной службы. Если текущая совместимая служба уже работает, повторный UAC не вызывается.%n%nПрофиль и рабочая папка Code хранятся отдельно и не удаляются деинсталлятором.
[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; Flags: unchecked
[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
[Icons]
Name: "{userprograms}\Claude Proxy Guard"; Filename: "{app}\Claude Proxy Guard.exe"
Name: "{userdesktop}\Claude Proxy Guard"; Filename: "{app}\Claude Proxy Guard.exe"; Tasks: desktopicon
[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var ResultCode: Integer; Request: String;
begin
  if CurStep <> ssPostInstall then Exit;
  Request := ExpandConstant('{app}\resources\GuardService.exe');
  if (not Exec(Request, '--request-install --owner 0', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
    RaiseException('Claude Proxy Guard service installation was not confirmed. Native request exit code: ' + IntToStr(ResultCode) + '. Installation failed; exit 2 is not treated as success.');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var BaseOwner, ProgOwner, Command, Registered: String; ResultCode: Integer;
begin
  if CurUninstallStep <> usUninstall then Exit;
  if (not Exec(ExpandConstant('{app}\resources\GuardService.exe'), '--request-uninstall --owner 0', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
    RaiseException('Claude Proxy Guard service removal was not confirmed. Native request exit code: ' + IntToStr(ResultCode) + '. Uninstall interrupted; exit 2 is not treated as success.');
  { Never remove another installation's registration or UserChoice. }
  if RegQueryStringValue(HKCU64, 'Software\GateClaudeGuard', 'GateClaudeOwner', BaseOwner) and
     RegQueryStringValue(HKCU64, 'Software\Classes\GateClaudeGuard.Url.claude', 'GateClaudeOwner', ProgOwner) and
     RegQueryStringValue(HKCU64, 'Software\Classes\GateClaudeGuard.Url.claude\shell\open\command', '', Command) and
     (BaseOwner = 'gate-claude.protocol.v1') and (ProgOwner = BaseOwner) and
     (CompareText(Command, '"' + ExpandConstant('{app}\Claude Proxy Guard.exe') + '" "%1"') = 0) then
  begin
    RegDeleteKeyIncludingSubkeys(HKCU64, 'Software\Classes\GateClaudeGuard.Url.claude');
    RegDeleteKeyIncludingSubkeys(HKCU64, 'Software\GateClaudeGuard');
    if RegQueryStringValue(HKCU64, 'Software\RegisteredApplications', 'Claude Proxy Guard', Registered) and
       (CompareText(Registered, 'Software\GateClaudeGuard\Capabilities') = 0) then
      RegDeleteValue(HKCU64, 'Software\RegisteredApplications', 'Claude Proxy Guard');
  end;
end;
