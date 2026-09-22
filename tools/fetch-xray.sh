#!/bin/sh
# Download the pinned Xray-core and hev-socks5-tunnel releases (static arm64) used by mu300-vpn's xray engine and
# verify them. Xray speaks VLESS (it is the reference implementation); hev-socks5-tunnel turns a kernel TUN
# device into connections on Xray's local SOCKS port.
#   tools/fetch-xray.sh [OUTDIR]   (default: .; writes OUTDIR/xray and OUTDIR/hev-socks5-tunnel)
set -eu
XRAY_VER=26.3.27
XRAY_SHA256=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c
HEV_VER=2.17.1
HEV_SHA256=958206dcebcdc390cdc4d5b88c8504ec81483e2a04b46d37c835a179830c86ba
OUT=${1:-.}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sha() { s=$(shasum -a 256 "$1" 2>/dev/null || sha256sum "$1"); printf '%s' "${s%% *}"; }

curl -fsSL -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VER/Xray-linux-arm64-v8a.zip"
[ "$(sha "$tmp/xray.zip")" = "$XRAY_SHA256" ] || { echo "checksum mismatch for Xray $XRAY_VER" >&2; exit 1; }
unzip -q -o "$tmp/xray.zip" xray -d "$tmp"
install -m 755 "$tmp/xray" "$OUT/xray"

curl -fsSL -o "$tmp/hev" "https://github.com/heiher/hev-socks5-tunnel/releases/download/$HEV_VER/hev-socks5-tunnel-linux-arm64"
[ "$(sha "$tmp/hev")" = "$HEV_SHA256" ] || { echo "checksum mismatch for hev-socks5-tunnel $HEV_VER" >&2; exit 1; }
install -m 755 "$tmp/hev" "$OUT/hev-socks5-tunnel"

echo "xray $XRAY_VER, hev-socks5-tunnel $HEV_VER -> $OUT"
