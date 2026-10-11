#!/bin/sh
# Download the pinned dae release (linux arm64) that runs mu300-vpn's dae profiles, with the geodata it ships
# (v2fly's geoip.dat and geosite.dat), and verify it.
#   tools/fetch-dae.sh [OUTDIR]   (default: .; writes OUTDIR/bin/dae and OUTDIR/share/dae/geo{ip,site}.dat, for
#                                  tools/make-module.sh)
set -eu
VER=2.1.1
SHA256=6f36783acbe151b656a10a0a9b620afd607bba2a2504b8fd58504e919c6586bc
NAME=dae-linux-arm64.zip
OUT=${1:-.}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$NAME" "https://github.com/daeuniverse/dae/releases/download/v$VER/$NAME"
have=$(shasum -a 256 "$tmp/$NAME" 2>/dev/null || sha256sum "$tmp/$NAME")
[ "${have%% *}" = "$SHA256" ] || { echo "checksum mismatch for $NAME" >&2; exit 1; }
unzip -q -o "$tmp/$NAME" dae-linux-arm64 geoip.dat geosite.dat -d "$tmp"
mkdir -p "$OUT/bin" "$OUT/share/dae"
install -m 755 "$tmp/dae-linux-arm64" "$OUT/bin/dae"
install -m 644 "$tmp/geoip.dat" "$OUT/share/dae/geoip.dat"
install -m 644 "$tmp/geosite.dat" "$OUT/share/dae/geosite.dat"
echo "dae $VER (with geoip.dat, geosite.dat) -> $OUT"
