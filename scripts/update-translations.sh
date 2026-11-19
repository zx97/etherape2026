#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Refresh the translation catalogue and rebuild the .qm files.
# Requires lupdate/lrelease from Qt Linguist (qt6-linguist, or
# mingw-w64-ucrt-x86_64-qt6-tools under MSYS2).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

for tool in lupdate lrelease; do
  command -v "$tool" >/dev/null || {
    echo "missing: $tool (install Qt Linguist tools)" >&2
    exit 1
  }
done

echo "== updating catalogue"
lupdate src -ts translations/etherape2026.ts -no-obsolete

echo "== recompiling .qm"
for ts in translations/etherape2026_*.ts; do
  lrelease "$ts" -qm "${ts%.ts}.qm" >/dev/null
  printf '  %-34s %s\n' "$(basename "$ts")" "$(stat -c%s "${ts%.ts}.qm") bytes"
done

echo
echo "Now rebuild: cmake --build build"
echo "Check completeness with: lupdate translations/*.ts -no-obsolete (or Qt Linguist)"
