Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!include "WordFunc.nsh"
!insertmacro VersionCompare
; This x86 NSIS bootstrapper must launch native 64-bit PowerShell explicitly.
; Do not rely on thread-local WOW64 redirection state inherited from .onInit.
!define NATIVE_POWERSHELL "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
!define NATIVE_POWERSHELL_MODULES "$WINDIR\System32\WindowsPowerShell\v1.0\Modules"

!macro ConfigureNativePowerShellModules
  ; Windows PowerShell must not inherit PowerShell 7 or user module search paths.
  ; This changes only Setup's process environment and its helper child processes.
  System::Call 'kernel32::SetEnvironmentVariableW(w "PSModulePath", w "${NATIVE_POWERSHELL_MODULES}") i.r0'
  ${If} $0 == 0
    MessageBox MB_ICONSTOP "Setup could not configure the native Windows PowerShell module path." /SD IDOK
    SetErrorLevel 16
    Abort
  ${EndIf}
!macroend

!macro VerifyNativePowerShell
  ${IfNot} ${FileExists} "${NATIVE_POWERSHELL}"
    MessageBox MB_ICONSTOP "Native 64-bit Windows PowerShell is unavailable. Repair Windows PowerShell before running SENTINEL Setup." /SD IDOK
    SetErrorLevel 16
    Abort
  ${EndIf}
!macroend

!ifndef STOP_HELPER
  !error "STOP_HELPER is required; use scripts/package.ps1 to resolve the absolute helper path."
!endif
!ifndef PREPARE_HELPER
  !error "PREPARE_HELPER is required; use scripts/package.ps1 to resolve the absolute helper path."
!endif
!ifndef CONFIGURE_HELPER
  !error "CONFIGURE_HELPER is required; use scripts/package.ps1 to resolve the absolute helper path."
!endif
!ifndef REMOVE_HELPER
  !error "REMOVE_HELPER is required; use scripts/package.ps1 to resolve the absolute helper path."
!endif
!ifndef INSTALLATION_DOC
  !error "INSTALLATION_DOC is required; use scripts/package.ps1 to resolve the absolute documentation path."
!endif

!ifndef VERSION
  !define VERSION "1.1.1"
!endif
!ifndef PUBLISH_DIR
  !error "PUBLISH_DIR is required; use scripts/package.ps1 to resolve the absolute payload directory."
!endif
!ifndef OUTPUT_FILE
  !error "OUTPUT_FILE is required; use scripts/package.ps1 to resolve the absolute output path."
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
  !insertmacro VerifyNativePowerShell
  !insertmacro ConfigureNativePowerShellModules
  SetRegView 64
  ; Resolve the existing 64-bit installation explicitly before any file changes.
  ; InstallDirRegKey must not depend on the bootstrapper's initial registry view.
  ReadRegStr $2 HKLM "Software\SENTINEL" "InstallDir"
  ${If} $2 != ""
    StrCpy $INSTDIR $2
  ${EndIf}
  ; Preserve the stable V1.0 installation identity and block accidental downgrades.
  ReadRegStr $0 HKLM "Software\SENTINEL" "Version"
  ${If} $0 != ""
    ${VersionCompare} $0 "${VERSION}" $1
    ${If} $1 == 1
      MessageBox MB_ICONSTOP "A newer SENTINEL version ($0) is already installed. Setup ${VERSION} cannot downgrade it. Your installation and evidence were preserved." /SD IDOK
      SetErrorLevel 17
      Abort
    ${EndIf}
  ${EndIf}
  SetShellVarContext all
  InitPluginsDir
FunctionEnd

Function un.onInit
  !insertmacro VerifyNativePowerShell
  !insertmacro ConfigureNativePowerShellModules
  SetRegView 64
  SetShellVarContext all
  InitPluginsDir
FunctionEnd

!macro LogHelperResult HELPER
  ; Diagnostics must preserve helper results, scratch registers, and the error flag.
  Push $2
  Push $3
  StrCpy $3 0
  IfErrors 0 +2
    StrCpy $3 1
  ClearErrors
  FileOpen $2 "$TEMP\SENTINEL-Setup.log" a
  ${IfNot} ${Errors}
    FileSeek $2 0 END
    FileWrite $2 "Helper=${HELPER}$\r$\n"
    FileWrite $2 "InstallationDirectory=$INSTDIR$\r$\n"
    FileWrite $2 "PowerShell=${NATIVE_POWERSHELL}$\r$\n"
    FileWrite $2 "Exit=$0$\r$\n"
    FileWrite $2 "Output=$1$\r$\n$\r$\n"
    FileWrite $2 "PSModulePath=${NATIVE_POWERSHELL_MODULES}$\r$\n"
    FileClose $2
  ${EndIf}
  ${If} $3 == 1
    SetErrors
  ${Else}
    ClearErrors
  ${EndIf}
  Pop $3
  Pop $2
!macroend

!macro StopRunningSentinel PREFIX
  SetOutPath "$PLUGINSDIR"
  File /oname=Stop-Sentinel.ps1 "${STOP_HELPER}"
  ${PREFIX}retry_stop:
    nsExec::ExecToStack '"${NATIVE_POWERSHELL}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Stop-Sentinel.ps1" -InstallationDirectory "$INSTDIR"'
    Pop $0
    Pop $1
    !insertmacro LogHelperResult "Stop-Sentinel.ps1"
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
  File /oname=Prepare-Sentinel.ps1 "${PREPARE_HELPER}"
  nsExec::ExecToStack '"${NATIVE_POWERSHELL}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Prepare-Sentinel.ps1" -InstallationDirectory "$INSTDIR"'
  Pop $0
  Pop $1
  !insertmacro LogHelperResult "Prepare-Sentinel.ps1"
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
  File /r "${PUBLISH_DIR}\Desktop\*"
  SetOutPath "$INSTDIR\Service"
  File /r "${PUBLISH_DIR}\Service\*"
  SetOutPath "$INSTDIR"
  File /oname=INSTALLATION.md "${INSTALLATION_DOC}"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\SENTINEL" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "DisplayName" "SENTINEL Enterprise (Setup incomplete)"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SENTINEL" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  SetOutPath "$PLUGINSDIR"
  File /oname=Configure-Sentinel.ps1 "${CONFIGURE_HELPER}"
  nsExec::ExecToStack '"${NATIVE_POWERSHELL}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Configure-Sentinel.ps1" -InstallationDirectory "$INSTDIR"'
  Pop $0
  Pop $1
  !insertmacro LogHelperResult "Configure-Sentinel.ps1"
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
  File /oname=Remove-SentinelService.ps1 "${REMOVE_HELPER}"
  nsExec::ExecToStack '"${NATIVE_POWERSHELL}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\Remove-SentinelService.ps1"'
  Pop $0
  Pop $1
  !insertmacro LogHelperResult "Remove-SentinelService.ps1"
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
