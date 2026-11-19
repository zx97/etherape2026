#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build a self-contained release archive for Linux.
#
#   ./scripts/package-linux.sh [build-dir] [output-dir]
#
# The archive contains the binary, the desktop entry, the icon and the README.
# Qt is linked dynamically (distribution package); libpcap too, as any other
# system library.

set -euo pipefail

build_dir="${1:-build}"
out_dir="${2:-dist}"
version="$(sed -n 's/^project(etherape2026 VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)"
name="etherape2026-${version}-linux-x86_64"

cmake --build "$build_dir" -j"$(nproc)"

stage="$(mktemp -d -p /dev/shm "etherape-pkg.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$name"
install -m 0755 "$build_dir/bin/etherape2026" "$stage/$name/"
install -m 0644 data/etherape2026.desktop "$stage/$name/"
install -m 0644 data/etherape.png "$stage/$name/etherape2026.png"
install -m 0644 README.md "$stage/$name/"

cat > "$stage/$name/install.sh" <<'EOF'
#!/bin/sh
# Install EtherApe 2026 for the current user.
set -e
prefix="${PREFIX:-$HOME/.local}"
here="$(cd "$(dirname "$0")" && pwd)"
install -Dm0755 "$here/etherape2026" "$prefix/bin/etherape2026"
install -Dm0644 "$here/etherape2026.desktop" "$prefix/share/applications/etherape2026.desktop"
install -Dm0644 "$here/etherape2026.png" "$prefix/share/pixmaps/etherape2026.png"
echo "Installed in $prefix"
echo "Live capture needs CAP_NET_RAW:"
echo "  sudo setcap cap_net_raw,cap_net_admin+eip $prefix/bin/etherape2026"
EOF
chmod 0755 "$stage/$name/install.sh"

mkdir -p "$out_dir"
tar -C "$stage" -czf "$out_dir/$name.tar.gz" "$name"
echo "$out_dir/$name.tar.gz"
