; SPDX-License-Identifier: GPL-2.0-or-later
;
; NSIS installer for EtherApe 2026 (Windows).
; Build (from the bin/ directory produced by the MSYS2 build, after
; `cmake --build build --target deploy` and the MinGW runtime DLLs):
;
;   makensis -DAPPDIR=build/bin packaging/windows/etherape2026.nsi
;
; Requires Npcap at runtime (https://npcap.com); the installer does not bundle
; it because the driver needs an interactive, signed installation.

!ifndef APPDIR
  !define APPDIR "build\bin"
!endif

!define APPNAME "EtherApe 2026"
!define APPEXE "etherape2026.exe"
!define VERSION "1.0.0"
!define PUBLISHER "EtherApe"
!define UNKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\EtherApe2026"

Name "${APPNAME}"
OutFile "EtherApe2026-Setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES64\EtherApe2026"
InstallDirRegKey HKLM "${UNKEY}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!define MUI_ABORTWARNING
!define MUI_ICON "${APPDIR}\..\..\data\etherape.ico"
!define MUI_UNICON "${APPDIR}\..\..\data\etherape.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "French"

Section "EtherApe 2026" SecMain
  SetOutPath "$INSTDIR"
  File /r "${APPDIR}\*.*"

  CreateShortCut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${APPEXE}" "" "$INSTDIR\${APPEXE}" 0
  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortCut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\${APPEXE}" "" "$INSTDIR\${APPEXE}" 0
  CreateShortCut "$SMPROGRAMS\${APPNAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNKEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNKEY}" "DisplayIcon" "$INSTDIR\${APPEXE}"
  WriteRegStr HKLM "${UNKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNKEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegDWORD HKLM "${UNKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNKEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  RMDir /r "$INSTDIR"
  Delete "$DESKTOP\${APPNAME}.lnk"
  RMDir /r "$SMPROGRAMS\${APPNAME}"
  DeleteRegKey HKLM "${UNKEY}"
SectionEnd
