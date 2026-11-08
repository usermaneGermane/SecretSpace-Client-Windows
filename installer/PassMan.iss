; PassMan installer - compiled by the PassMan Builder (builder\build.py)
; with Inno Setup 6:
;     ISCC.exe /DAppVersion=2.1.0 installer\PassMan.iss
;
; Installs for the current user only (no admin prompt), by default into
; %LOCALAPPDATA%\Programs\PassMan, with a Start Menu entry, an optional
; desktop shortcut and an uninstaller in Settings > Apps.
;
; The vaults are NOT in the program folder. The "installed" marker file makes
; PassMan keep them in %APPDATA%\PassMan (see vault.get_home_dir), so an
; upgrade or an uninstall never touches them.
;
; Silent install, e.g. for testing:
;     PassMan-Client-Installer.exe /VERYSILENT /DIR="C:\somewhere" /TASKS="desktopicon"
;                       /MOVEVAULTS="E:\old\PassMan"

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
; Four plain numbers: a test version's AppVersion (3.0.0-alpha.1) is not
; one, so the builder passes 3.0.0.1 here as well.
#ifndef FileVersion
  #define FileVersion "0.0.0.0"
#endif

[Setup]
; Never change AppId: it is how an upgrade finds the copy it replaces.
AppId={{2142690B-93AA-41F8-9056-BE62EE0426B4}
AppName=PassMan
AppVersion={#AppVersion}
AppVerName=PassMan {#AppVersion}
VersionInfoVersion={#FileVersion}
DefaultDirName={autopf}\PassMan
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
; Windows 10 and 11 only (11 reports itself as 10.0.22000+). Older Windows
; gets a clear "needs Windows 10" message instead of a broken install.
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..
OutputBaseFilename=PassMan-Client-Installer
SetupIconFile=..\sourceFiles\PassMan-logo.ico
UninstallDisplayIcon={app}\PassMan.exe
UninstallDisplayName=PassMan
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
; Close a running PassMan before replacing its files.
CloseApplications=yes
; The vault move below writes to the user's own profile on purpose.
UsedUserAreasWarning=no

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[InstallDelete]
; An upgrade must not leave the previous version's libraries behind.
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\build\installer\PassMan\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "installed"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\PassMan"; Filename: "{app}\PassMan.exe"
Name: "{autodesktop}\PassMan"; Filename: "{app}\PassMan.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\PassMan.exe"; Description: "Start PassMan now"; Flags: nowait postinstall skipifsilent

[Code]
var
  MovePage: TInputOptionWizardPage;
  FromPage: TInputDirWizardPage;

function DataHome: String;
begin
  Result := ExpandConstant('{userappdata}\PassMan');
end;

function HasVaults(Dir: String): Boolean;
var
  FindRec: TFindRec;
begin
  Result := FindFirst(AddBackslash(Dir) + '*.vault.enc', FindRec);
  if Result then
    FindClose(FindRec);
end;

{ The folder that holds the *.vault.enc files of a portable PassMan in Dir:
  its vault folder, the older data folder, or Dir itself. '' if none. }
function VaultFolderIn(Dir: String): String;
begin
  Dir := RemoveBackslashUnlessRoot(Dir);
  if HasVaults(Dir + '\vault') then
    Result := Dir + '\vault'
  else if HasVaults(Dir + '\data') then
    Result := Dir + '\data'
  else if HasVaults(Dir) then
    Result := Dir
  else
    Result := '';
end;

procedure InitializeWizard;
begin
  MovePage := CreateInputOptionPage(wpSelectTasks,
    'Existing vaults', 'Have you used the portable PassMan.exe before?',
    'This copy of PassMan keeps its vaults in your user profile:' + #13#10 +
    '    ' + DataHome + #13#10 + #13#10 +
    'If you have vaults next to an earlier PassMan.exe, Setup can move ' +
    'them there now. They are moved, not copied, so you still have one ' +
    'copy. A vault that already exists in your profile is never ' +
    'overwritten.' + #13#10 + #13#10 +
    'Back up your vault folder first, as you would before any upgrade.',
    False, False);
  MovePage.Add('&Move my vaults from an earlier PassMan folder');

  FromPage := CreateInputDirPage(MovePage.ID,
    'Existing vaults', 'Where is your earlier PassMan?',
    'Choose the folder that contains the old PassMan.exe and its vault ' +
    'folder, then click Next.', False, '');
  FromPage.Add('');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = FromPage.ID) and not MovePage.Values[0];
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = FromPage.ID then
  begin
    if VaultFolderIn(FromPage.Values[0]) = '' then
    begin
      MsgBox('There are no vaults (*.vault.enc) in that folder or in a ' +
             'vault folder inside it.', mbError, MB_OK);
      Result := False;
    end
    else if CompareText(VaultFolderIn(FromPage.Values[0]),
                        DataHome + '\vault') = 0 then
    begin
      MsgBox('Those vaults are already where this copy keeps them.',
             mbInformation, MB_OK);
      Result := False;
    end;
  end;
end;

function SameSize(A, B: String): Boolean;
var
  SizeA, SizeB: Int64;
begin
  Result := FileSize64(A, SizeA) and FileSize64(B, SizeB) and (SizeA = SizeB);
end;

{ Move one user's vault: <user>.vault.enc plus its .bak and .base, if there.
  Everything is copied and checked before any original is deleted; if a
  copy fails, the copies are removed again and the originals stay put. }
function MoveUser(Src, Dest, VaultName: String): Boolean;
var
  Names: array[0..2] of String;
  I: Integer;
begin
  Names[0] := VaultName;
  Names[1] := VaultName + '.bak';
  Names[2] := VaultName + '.base';
  Result := True;
  for I := 0 to 2 do
    if FileExists(Src + '\' + Names[I]) then
      if not (FileCopy(Src + '\' + Names[I], Dest + '\' + Names[I], True)
              and SameSize(Src + '\' + Names[I], Dest + '\' + Names[I])) then
        Result := False;
  for I := 0 to 2 do
    if FileExists(Src + '\' + Names[I]) then
      if Result then
        DeleteFile(Src + '\' + Names[I])
      else
        DeleteFile(Dest + '\' + Names[I]);
end;

procedure MoveVaults(FromDir: String);
var
  Src, Dest, User, Moved, Kept, Failed, Report: String;
  FindRec: TFindRec;
begin
  Src := VaultFolderIn(FromDir);
  if Src = '' then
    Exit;
  Dest := DataHome + '\vault';
  ForceDirectories(Dest);
  if FindFirst(Src + '\*.vault.enc', FindRec) then
  try
    repeat
      User := Copy(FindRec.Name, 1, Length(FindRec.Name) - Length('.vault.enc'));
      if FileExists(Dest + '\' + FindRec.Name) then
        Kept := Kept + #13#10 + '    ' + User
      else if MoveUser(Src, Dest, FindRec.Name) then
        Moved := Moved + #13#10 + '    ' + User
      else
        Failed := Failed + #13#10 + '    ' + User;
    until not FindNext(FindRec);
  finally
    FindClose(FindRec);
  end;

  { Preferences are not secret and the old copy may still be used: copy. }
  FromDir := RemoveBackslashUnlessRoot(FromDir);
  if FileExists(FromDir + '\config.json') and
     not FileExists(DataHome + '\config.json') then
    FileCopy(FromDir + '\config.json', DataHome + '\config.json', True);

  if Moved <> '' then
    Report := Report + 'Moved to ' + Dest + ':' + Moved + #13#10 + #13#10;
  if Kept <> '' then
    Report := Report + 'Left where they were, because a vault of the same ' +
              'name is already in your profile:' + Kept + #13#10 + #13#10;
  if Failed <> '' then
    Report := Report + 'Could not be moved, and were left untouched in ' +
              Src + ':' + Failed + #13#10 + #13#10;
  Log(Report);
  SuppressibleMsgBox(Report, mbInformation, MB_OK, IDOK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  FromDir: String;
begin
  if CurStep <> ssPostInstall then
    Exit;
  FromDir := ExpandConstant('{param:MOVEVAULTS|}');
  if (FromDir = '') and MovePage.Values[0] then
    FromDir := FromPage.Values[0];
  if FromDir <> '' then
    MoveVaults(FromDir);
end;
