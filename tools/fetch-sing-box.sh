#!/bin/sh
# Download the pinned sing-box release (static musl arm64) used by mu300-vpn and verify it.
#   tools/fetch-sing-box.sh [OUT]   (default: ./sing-box, picked up by the rootfs builds)
set -eu
VER=1.14.1
SHA256=d94fc9704372ca2fa2854e54c20b406e4b8779b5ccdd0c557da90ea9344e9631
NAME=sing-box-$VER-linux-arm64-musl
OUT=${1:-sing-box}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$NAME.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v$VER/$NAME.tar.gz"
have=$(shasum -a 256 "$tmp/$NAME.tar.gz" 2>/dev/null || sha256sum "$tmp/$NAME.tar.gz")
[ "${have%% *}" = "$SHA256" ] || { echo "checksum mismatch for $NAME.tar.gz" >&2; exit 1; }
tar -xzf "$tmp/$NAME.tar.gz" -C "$tmp"
install -m 755 "$tmp/$NAME/sing-box" "$OUT"
echo "sing-box $VER -> $OUT"
