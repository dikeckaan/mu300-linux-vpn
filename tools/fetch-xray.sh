#!/bin/sh
# Download the pinned Xray-core and hev-socks5-tunnel releases (static arm64) used by mu300-vpn's xray engine and
# verify them. Xray speaks VLESS (it is the reference implementation); hev-socks5-tunnel turns a kernel TUN
# device into connections on Xray's local SOCKS port.
#   tools/fetch-xray.sh [OUTDIR]   (default: .; writes OUTDIR/bin/xray, OUTDIR/bin/hev-socks5-tunnel and
#                                   OUTDIR/share/xray/geoip.dat and geosite.dat, for tools/make-module.sh)
# The geodata: Xray reads geoip.dat and geosite.dat when a config's routing or DNS names geoip: or geosite: (a raw
# config from a panel nearly always does: geoip:private, geosite:category-ads...), and refuses to start without them.
# They come in Xray's own release zip, beside the binary, under the same hash; the driver points Xray at them
# (XRAY_LOCATION_ASSET, lib/vpn/xray.sh). Up to v2.0.2 only the binary was taken out of the zip
# (docs/FINDINGS.md 26o).
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
unzip -q -o "$tmp/xray.zip" xray geoip.dat geosite.dat -d "$tmp"
mkdir -p "$OUT/bin" "$OUT/share/xray"
install -m 755 "$tmp/xray" "$OUT/bin/xray"
install -m 644 "$tmp/geoip.dat" "$OUT/share/xray/geoip.dat"
install -m 644 "$tmp/geosite.dat" "$OUT/share/xray/geosite.dat"

curl -fsSL -o "$tmp/hev" "https://github.com/heiher/hev-socks5-tunnel/releases/download/$HEV_VER/hev-socks5-tunnel-linux-arm64"
[ "$(sha "$tmp/hev")" = "$HEV_SHA256" ] || { echo "checksum mismatch for hev-socks5-tunnel $HEV_VER" >&2; exit 1; }
install -m 755 "$tmp/hev" "$OUT/bin/hev-socks5-tunnel"

echo "xray $XRAY_VER (with geoip.dat, geosite.dat), hev-socks5-tunnel $HEV_VER -> $OUT"
