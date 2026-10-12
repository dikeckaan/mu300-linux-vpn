#!/bin/sh
# Download the pinned mihomo (Clash.Meta) release (linux arm64) that runs mu300-vpn's mihomo profiles, and the geodata
# its GEOIP and GEOSITE rules read, and verify them.
#   tools/fetch-mihomo.sh [OUTDIR]   (default: .; writes OUTDIR/bin/mihomo and OUTDIR/share/mihomo/Country.mmdb and
#                                     GeoSite.dat, for tools/make-module.sh)
# The geodata: mihomo downloads what its home lacks while it reads a config, before the tunnel exists, and refuses
# the config when it cannot - on an uplink where only the tunnel gets out, a profile with such rules never started
# (docs/FINDINGS.md 26j). The driver copies these two into mihomo's home when a config needs them and the home has
# none (lib/vpn/mihomo.sh, mihomo_geodata); a config's geo-auto-update has mihomo update them. They come from Loyalsoldier's
# dated releases, under tags that stay (mihomo's own downloads are a rolling "latest" that cannot be pinned):
# Country.mmdb (github.com/Loyalsoldier/geoip, CC-BY-SA-4.0, with GeoLite2 data created by MaxMind) and geosite.dat
# (github.com/Loyalsoldier/v2ray-rules-dat, GPL-3.0), which mihomo looks for as GeoSite.dat.
set -eu
VER=1.19.32
SHA256=9dd862e28b46ff7d775f169cceebc28deccaa0a9e804237d421cd2571e0caba0
NAME=mihomo-linux-arm64-v$VER.gz
GEOIP_VER=202610080033
GEOIP_SHA256=ad2a3b90848bccd2065545e295de53b324931f710e0077a1a0fae2b89fddc5e5
GEOSITE_VER=202610112207
GEOSITE_SHA256=8ba3b9f1731b3626c7bd11e97f6eadf54e654ca8523584e1b71b4df8eb4dd4c2
OUT=${1:-.}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# get URL FILE SHA256: downloaded and checked
get() {
    curl -fsSL -o "$tmp/$2" "$1"
    have=$(shasum -a 256 "$tmp/$2" 2>/dev/null || sha256sum "$tmp/$2")
    [ "${have%% *}" = "$3" ] || { echo "checksum mismatch for $2" >&2; exit 1; }
}
get "https://github.com/MetaCubeX/mihomo/releases/download/v$VER/$NAME" "$NAME" "$SHA256"
get "https://github.com/Loyalsoldier/geoip/releases/download/$GEOIP_VER/Country.mmdb" Country.mmdb "$GEOIP_SHA256"
get "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/$GEOSITE_VER/geosite.dat" geosite.dat "$GEOSITE_SHA256"
gzip -dc "$tmp/$NAME" > "$tmp/mihomo"
mkdir -p "$OUT/bin" "$OUT/share/mihomo"
install -m 755 "$tmp/mihomo" "$OUT/bin/mihomo"
install -m 644 "$tmp/Country.mmdb" "$OUT/share/mihomo/Country.mmdb"
install -m 644 "$tmp/geosite.dat" "$OUT/share/mihomo/GeoSite.dat"
echo "mihomo $VER (with Country.mmdb $GEOIP_VER, GeoSite.dat $GEOSITE_VER) -> $OUT"
