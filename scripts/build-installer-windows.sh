#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the Windows installer (NSIS). Run inside MSYS2/UCRT64:
#
#   export MSYSTEM=UCRT64
#   export PATH=/ucrt64/bin:$PATH
#   ./scripts/build-installer-windows.sh [build-dir]
#
# Npcap is not bundled: its driver needs a signed, interactive installation.

set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

command -v makensis >/dev/null || {
  echo "makensis not found (pacman -S mingw-w64-ucrt-x86_64-nsis)" >&2
  exit 1
}

build="${1:-build}"
./scripts/build-windows.sh "$build"

version="$(sed -n 's/^project(etherape2026 VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)"
[ -n "$version" ] || { echo "cannot read the version from CMakeLists.txt" >&2; exit 1; }

# makensis is a Windows program: it needs a Windows path.
appdir="$(cygpath -w "$(cd "$build/bin" && pwd)")"
makensis -DAPPDIR="$appdir" -DVERSION="$version" packaging/windows/etherape2026.nsi
# NSIS writes next to the script; keep the artifact at the project root.
mv -f packaging/windows/EtherApe2026-Setup-*.exe .
echo "built $(ls EtherApe2026-Setup-*.exe)"
