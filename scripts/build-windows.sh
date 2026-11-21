#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build EtherApe 2026 for Windows and put every runtime DLL next to the exe.
# Run inside MSYS2/UCRT64:
#
#   export MSYSTEM=UCRT64
#   export PATH=/ucrt64/bin:$PATH
#   NPCAP_SDK_DIR=C:/npcap ./scripts/build-windows.sh [build-dir]
#
# This is the same sequence the CI and the VM use; scripts/build-installer-windows.sh
# calls it before running makensis.

set -euo pipefail

export MSYSTEM="${MSYSTEM:-UCRT64}"
export PATH="/ucrt64/bin:$PATH"

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

build="${1:-build}"
sdk="${NPCAP_SDK_DIR:-C:/npcap-sdk}"
# cmake is a native Windows program: a POSIX path from the MSYS2 shell (as CI
# passes it) has to be converted first.
if command -v cygpath >/dev/null; then
  case "$sdk" in /?*) sdk="$(cygpath -w "$sdk")" ;; esac
fi

# Always configure: cmake reuses the cache, and a directory left over by a
# failed configure (cache present, no build.ninja) is repaired instead of
# aborting with "loading 'build.ninja'".
cmake -S . -B "$build" -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DNPCAP_SDK_DIR="$sdk" \
      -DETH_WINDOWS_GUI=ON
cmake --build "$build" -j"${NUMBER_OF_PROCESSORS:-4}"
cmake --build "$build" --target deploy >/dev/null

# windeployqt covers Qt but not the MinGW/C++ runtime, ICU or the image codecs.
bin="$build/bin"
for dll in libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll zlib1.dll \
           libb2-1.dll libbrotlidec.dll libbrotlicommon.dll \
           libdouble-conversion.dll libfreetype-6.dll libharfbuzz-0.dll \
           libicuin78.dll libicuuc78.dll libicudt78.dll libmd4c.dll \
           libpcre2-16-0.dll libpcre2-8-0.dll libpng16-16.dll libz-1.dll \
           libzstd.dll libbz2-1.dll libgraphite2.dll libglib-2.0-0.dll \
           libintl-8.dll libiconv-2.dll; do
  [ -f "/ucrt64/bin/$dll" ] && cp -f "/ucrt64/bin/$dll" "$bin/"
done

# The build must be self-contained: a missing DLL only shows up at run time.
[ -f "$bin/etherape2026.exe" ] || { echo "no executable in $bin" >&2; exit 1; }
echo "built $bin/etherape2026.exe"
