Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

!ifndef SOURCE_DIR
  !error "SOURCE_DIR is required; use scripts/package.ps1 or pass an absolute source root."
!endif

!ifndef VERSION
  !define VERSION "1.0.0"
!endif
!ifndef PUBLISH_DIR
  !define PUBLISH_DIR "../artifacts/publish"
!endif
!ifndef OUTPUT_FILE
  !define OUTPUT_FILE "../artifacts/SENTINEL-Setup-${VERSION}-win-x64.exe"
!endif

Name "SENTINEL Enterprise ${VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\SENTINEL"
InstallDirRegKey HKLM "Software\SENTINEL" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetCompressorDictSize 64
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "SENTINEL Enterprise"
VIAddVersionKey "FileDescription" "SENTINEL Setup (unsigned testing build)"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "SENTINEL contributors"

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TEXT "SENTINEL Enterprise installs the desktop application and a least-privilege Windows maintenance service.$\r$\n$\r$\nSecurity assessments require an explicit authorized scope in the desktop application. The service does not scan networks.$\r$\n$\r$\nThis unsigned testing build still requires the Windows QA acceptance checklist."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "SENTINEL requires Windows 10/11 x64."
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "SENTINEL requires Windows 10/11 x64."
    Abort
  ${EndIf}
  ${DisableX64FSRedirection}
  SetRegView 64
  SetShellVarContext all
  InitPluginsDir
FunctionEnd

Function un.onInit
  ${DisableX64FSRedirection}
  SetRegView 64
  SetShellVarContext all
  InitPluginsDir
FunctionEnd

!macro StopRunningSentinel PREFIX
  SetOutPath "$PLUGINSDIR"
  File /oname=Stop-Sentinel.ps1 "${SOURCE_DIR}/installer/helpers/Stop-Sentinel.ps1"
  ${PREFIX}retry_stop:
    nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Stop-Sentinel.ps1" -InstallationDirectory "$INSTDIR"'
    Pop $0
    Pop $1
    ${If} $0 != 0
      IfSilent ${PREFIX}abort_stop
      MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$1" IDRETRY ${PREFIX}retry_stop
      ${PREFIX}abort_stop:
      SetErrorLevel 10
      Abort
    ${EndIf}
!macroend

Section "SENTINEL Desktop and Maintenance Service" SecCore
  SectionIn RO
  !insertmacro StopRunningSentinel "install_"
  SetOutPath "$PLUGINSDIR"
  File /oname=Prepare-Sentinel.ps1 "${SOURCE_DIR}/installer/helpers/Prepare-Sentinel.ps1"
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Prepare-Sentinel.ps1" -InstallationDirectory "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "$1" /SD IDOK
    SetErrorLevel 14
    Abort
  ${EndIf}
  ClearErrors
  RMDir /r "$INSTDIR\Desktop"
  RMDir /r "$INSTDIR\Service"
  ${If} ${Errors}
    MessageBox MB_ICONSTOP "Existing SENTINEL binaries could not be replaced. Close SENTINEL and run Setup again." /SD IDOK
    SetErrorLevel 15
    Abort
  ${EndIf}
  SetOutPath "$INSTDIR\Desktop"
  File /r "${PUBLISH_DIR}/Desktop/*"
  SetOutPath "$INSTDIR\Service"
  File /r "${PUBLISH_DIR}/Service/*"
  SetOutPath "$INSTDIR"
  File /oname=INSTALLATION.md "${SOURCE_DIR}/docs/INSTALLATION.md"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\SENTINEL" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "DisplayName" "SENTINEL Enterprise (Setup incomplete)"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  SetOutPath "$PLUGINSDIR"
  File /oname=Configure-Sentinel.ps1 "${SOURCE_DIR}/installer/helpers/Configure-Sentinel.ps1"
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Configure-Sentinel.ps1" -InstallationDirectory "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_ICONSTOP "$1$\r$\nSetup could not complete. Repair by running Setup again with administrator access." /SD IDOK
    SetErrorLevel 12
    Abort
  ${EndIf}
  SetOutPath "$INSTDIR\Desktop"
  CreateDirectory "$SMPROGRAMS\SENTINEL"
  CreateShortCut "$SMPROGRAMS\SENTINEL\SENTINEL Enterprise.lnk" "$INSTDIR\Desktop\Sentinel.Desktop.exe"
  CreateShortCut "$SMPROGRAMS\SENTINEL\Uninstall SENTINEL.lnk" "$INSTDIR\Uninstall.exe"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\SENTINEL" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\SENTINEL" "Version" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "DisplayName" "SENTINEL Enterprise"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "Publisher" "SENTINEL"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "DisplayIcon" "$INSTDIR\Desktop\Sentinel.Desktop.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "NoRepair" 1
SectionEnd

Section /o "Desktop shortcut" SecDesktopShortcut
  CreateShortCut "$DESKTOP\SENTINEL Enterprise.lnk" "$INSTDIR\Desktop\Sentinel.Desktop.exe"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Installs the self-contained Windows desktop application, service, and Start Menu entries."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktopShortcut} "Adds a desktop shortcut for all users."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  !insertmacro StopRunningSentinel "uninstall_"
  SetOutPath "$PLUGINSDIR"
  File /oname=Remove-SentinelService.ps1 "${SOURCE_DIR}/installer/helpers/Remove-SentinelService.ps1"
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Remove-SentinelService.ps1"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "$1" /SD IDOK
    SetErrorLevel 13
    Abort
  ${EndIf}
  Delete "$DESKTOP\SENTINEL Enterprise.lnk"
  Delete "$SMPROGRAMS\SENTINEL\SENTINEL Enterprise.lnk"
  Delete "$SMPROGRAMS\SENTINEL\Uninstall SENTINEL.lnk"
  RMDir "$SMPROGRAMS\SENTINEL"
  RMDir /r "$INSTDIR\Desktop"
  RMDir /r "$INSTDIR\Service"
  Delete "$INSTDIR\INSTALLATION.md"
  Delete "$INSTDIR\Uninstall.exe"
  SetOutPath "$TEMP"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL"
  DeleteRegKey HKLM "Software\SENTINEL"
  DetailPrint "Operator assessment data in LocalAppData and service audit files in ProgramData were preserved."
SectionEnd
