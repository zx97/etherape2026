#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build a portable AppImage.
#
# Requires linuxdeploy and appimagetool (download both, chmod +x, put them in
# PATH) plus the Qt plugin for linuxdeploy. On Fedora/Bazzite:
#
#   curl -LO https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
#   curl -LO https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage
#   curl -LO https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
#
# Then: ./scripts/build-appimage.sh [build-dir]

set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
build="${1:-$root/build}"
cd "$root"

for tool in linuxdeploy appimagetool; do
  command -v "$tool" >/dev/null || {
    echo "missing $tool in PATH (see the header of this script)" >&2
    exit 1
  }
done

cmake --build "$build" -j"$(nproc)"

QMAKE="$(command -v qmake6 || command -v qmake)"
[ -n "$QMAKE" ] || { echo "qmake6 not found" >&2; exit 1; }
export QMAKE

stage="$(mktemp -d -p /dev/shm appimage.XXXXXX)"
# appimagetool refuses a 0700 AppDir: the AppImage is meant to be run by others.
chmod 0755 "$stage"
trap 'rm -rf "$stage"' EXIT
install -Dm755 "$build/bin/etherape2026" "$stage/usr/bin/etherape2026"
install -Dm644 data/etherape2026.desktop "$stage/usr/share/applications/etherape2026.desktop"
install -Dm644 data/etherape.png "$stage/usr/share/icons/hicolor/48x48/apps/etherape2026.png"
install -Dm644 etherape2026.1 "$stage/usr/share/man/man1/etherape2026.1"

# linuxdeploy only deploys the platform plugin of the build machine (xcb on a
# CI runner). Ask for Wayland explicitly, otherwise the AppImage falls back to
# XWayland on every modern desktop and prints a plugin warning at start-up.
export EXTRA_PLATFORM_PLUGINS="${EXTRA_PLATFORM_PLUGINS:-libqwayland.so}"

# linuxdeploy bundles its own binutils, which predates the .relr.dyn section
# emitted by recent toolchains; stripping would fail on every Qt library.
export NO_STRIP="${NO_STRIP:-1}"

VERSION="$(sed -n 's/^project(etherape2026 VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)"
export VERSION
export LDAI_OUTPUT="$root/etherape2026-${VERSION}-x86_64.AppImage"

linuxdeploy --appdir "$stage" \
  --desktop-file "$stage/usr/share/applications/etherape2026.desktop" \
  --icon-file "$stage/usr/share/icons/hicolor/48x48/apps/etherape2026.png" \
  --plugin qt

appimagetool "$stage" "$LDAI_OUTPUT"
echo "built $LDAI_OUTPUT"
