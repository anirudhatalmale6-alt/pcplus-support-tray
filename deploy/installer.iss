; PC Plus Endpoint Protection - Inno Setup Installer
; Builds a setup.exe that installs Service + Tray with silent mode support

#define MyAppName "PC Plus Endpoint Protection"
#define MyAppPublisher "PC Plus Computing"
#define MyAppURL "https://pcpluscomputing.com"
#ifndef APP_VERSION
#define APP_VERSION "4.17.0"
#endif
#define MyAppVersion APP_VERSION

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={commonpf}\PC Plus\Endpoint Protection
DefaultGroupName={#MyAppName}
OutputBaseFilename=PCPlusEndpoint-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
UninstallDisplayIcon={app}\Tray\PCPlusTray.exe
DisableProgramGroupPage=yes
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=force

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SourcePath}\Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs
Source: "{#SourcePath}\Tray\*"; DestDir: "{app}\Tray"; Flags: ignoreversion recursesubdirs

[Dirs]
Name: "{commonappdata}\PCPlusEndpoint"
Name: "{commonappdata}\PCPlusEndpoint\Logs"
Name: "{commonappdata}\PCPlusEndpoint\Audits"

[Run]
; Write config if it doesn't exist
Filename: "powershell.exe"; Parameters: "-NoProfile -Command ""$f='{commonappdata}\PCPlusEndpoint\config.json'; if(-not(Test-Path $f)){{@{{dashboardApiUrl='https://dashboard.pcpluscomputing.com';deviceId='{computername}-'+[guid]::NewGuid().ToString('N').Substring(0,4).ToUpper();ransomwareProtectionEnabled='true';autoContainmentEnabled='true';showBalloonAlerts='true';logAlerts='true'}}|ConvertTo-Json|Set-Content $f -Encoding UTF8}}"""; Flags: runhidden
; Register and start service
Filename: "sc.exe"; Parameters: "create PCPlusEndpoint binPath= ""{app}\Service\PCPlusService.exe"" start= auto DisplayName= ""PC Plus Endpoint Protection"""; Flags: runhidden
Filename: "sc.exe"; Parameters: "description PCPlusEndpoint ""PC Plus Endpoint Protection - Security monitoring, ransomware defense, system health."""; Flags: runhidden
Filename: "sc.exe"; Parameters: "failure PCPlusEndpoint reset= 86400 actions= restart/5000/restart/10000/restart/30000"; Flags: runhidden
Filename: "net.exe"; Parameters: "start PCPlusEndpoint"; Flags: runhidden
; Start tray app
Filename: "{app}\Tray\PCPlusTray.exe"; Flags: nowait postinstall skipifsilent runhidden

[Registry]
; Auto-start tray on login
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "PCPlusEndpoint"; ValueData: """{app}\Tray\PCPlusTray.exe"""; Flags: uninsdeletevalue

[UninstallRun]
Filename: "net.exe"; Parameters: "stop PCPlusEndpoint"; Flags: runhidden
Filename: "sc.exe"; Parameters: "delete PCPlusEndpoint"; Flags: runhidden
Filename: "taskkill.exe"; Parameters: "/F /IM PCPlusTray.exe"; Flags: runhidden

[Code]
// Send heartbeat on install completion
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssDone then
  begin
    // Send immediate heartbeat via PowerShell
    Exec('powershell.exe',
      '-NoProfile -Command "try{$cfg=Get-Content ''C:\ProgramData\PCPlusEndpoint\config.json'' -Raw|ConvertFrom-Json;$v=try{(Get-Item '''+ExpandConstant('{app}')+'\Service\PCPlusService.exe'').VersionInfo.ProductVersion}catch{'''+'{#MyAppVersion}'+'''};$b=@{deviceId=$cfg.deviceId;hostname=$env:COMPUTERNAME;osVersion=''Windows'';agentVersion=$v;licenseTier=''Free''}|ConvertTo-Json;[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;Invoke-RestMethod -Uri ''https://dashboard.pcpluscomputing.com/api/endpoint/heartbeat'' -Method POST -ContentType ''application/json'' -Body $b -TimeoutSec 10}catch{}"',
      '', SW_HIDE, ewNoWait, ResultCode);
  end;
end;
