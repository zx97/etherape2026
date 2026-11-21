#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the Windows installer (NSIS). Run inside MSYS2/UCRT64, after the app
# has been built and deployed:
#
#   export MSYSTEM=UCRT64
#   export PATH=/ucrt64/bin:$PATH
#   ./scripts/build-installer-windows.sh
#
# Npcap is not bundled: its driver needs a signed, interactive installation.

set -euo pipefail
export MSYSTEM="${MSYSTEM:-UCRT64}"
export PATH="/ucrt64/bin:$PATH"

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

command -v makensis >/dev/null || {
  echo "makensis not found (pacman -S mingw-w64-ucrt-x86_64-nsis)" >&2
  exit 1
}

build="${1:-build}"
if [ ! -f "$build/CMakeCache.txt" ]; then
  # Npcap SDK location can be overridden with NPCAP_SDK_DIR.
  cmake -S . -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DNPCAP_SDK_DIR="${NPCAP_SDK_DIR:-C:/npcap-sdk}"
fi
cmake --build "$build" -j"${NUMBER_OF_PROCESSORS:-4}"
cmake --build "$build" --target deploy >/dev/null || true

# windeployqt covers Qt but not the MinGW runtime.
for dll in libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll zlib1.dll \
           libb2-1.dll libbrotlidec.dll libbrotlicommon.dll \
           libdouble-conversion.dll libfreetype-6.dll libharfbuzz-0.dll \
           libicuin78.dll libicuuc78.dll libicudt78.dll libmd4c.dll \
           libpcre2-16-0.dll libpcre2-8-0.dll libpng16-16.dll libz-1.dll \
           libzstd.dll libbz2-1.dll libgraphite2.dll; do
  [ -f "/ucrt64/bin/$dll" ] && cp -f "/ucrt64/bin/$dll" "$build/bin/" || true
done

# makensis is a Windows program: it needs a Windows path.
appdir="$(cygpath -w "$(cd "$build/bin" && pwd)")"
makensis -DAPPDIR="$appdir" packaging/windows/etherape2026.nsi
# NSIS writes next to the script; keep the artifact at the project root.
mv -f packaging/windows/EtherApe2026-Setup-1.0.0.exe .
echo "built EtherApe2026-Setup-1.0.0.exe"
