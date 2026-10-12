#!/bin/sh
# Build the module's release files:
#   tools/make-module.sh OUTDIR [TAG]    (TAG: vMAJOR.MINOR.PATCH, default v0.0.0-dev)
#   OUTDIR/mu300-linux-vpn-core.tar.gz     the vpn extra: mu300-vpn, its library, services, hooks - no engine
#   OUTDIR/mu300-linux-vpn-xray.tar.gz     vpn-xray: Xray-core and hev-socks5-tunnel (tools/fetch-xray.sh)
#   OUTDIR/mu300-linux-vpn-singbox.tar.gz  vpn-singbox: sing-box (tools/fetch-sing-box.sh)
#   OUTDIR/mu300-linux-vpn-mihomo.tar.gz   vpn-mihomo: mihomo and the geodata its rules read (tools/fetch-mihomo.sh)
#   OUTDIR/mu300-linux-vpn-dae.tar.gz      vpn-dae: dae and its geodata (tools/fetch-dae.sh)
#   OUTDIR/mu300-linux-vpn.tar.gz          the vpn extra as v1.0.0 had it: the core with xray, hev-socks5-tunnel and
#                                          sing-box in it. The compatibility bundle: the mu300-extra and mu300-update
#                                          of mu300-linux releases from before the engine extras download this name
#                                          as vpn and nothing else, and must get the engines they had along with it
#   OUTDIR/VERSIONS                        extra, version, bytes, components (name ver,name ver), asset - TSV
#   OUTDIR/SHA256SUMS                      all of the above, in sha256sum's format
# The engines are the pinned releases, checked against their hashes by the fetch scripts. MU300_VPN_FAKE_ENGINES=1
# puts small scripts in their place instead (tests/, no network).
# Each unpacks into mu300-extra's directory for it ($DISK/extra/NAME): files and directories only, owned by root,
# modes set here (programs and hooks 755, the rest 644), the same bytes from macOS and Linux for the same inputs.
# Besides their files: VERSION, components, requires, and for mu300-extra's checks name, release (= VERSION) and
# manifest (the sha256 of every other file, as sha256sum writes it). Every engine extra has hooks/link and
# hooks/unlink (hooks/engine-link, hooks/engine-unlink).
set -eu
OUT=${1:?usage: tools/make-module.sh OUTDIR [TAG]}
TAG=${2:-v0.0.0-dev}
case $TAG in v[0-9]*) ;; *) echo "TAG is vMAJOR.MINOR.PATCH" >&2; exit 2 ;; esac
# the first mu300-linux release whose mu300-extra installs this module (and that has no mu300-vpn of its own); the
# engine extras need the same, and an mu300-extra that knows their names (mu300-vpn falls back to the bundle)
REQUIRES='mu300-linux v2026.10.16'
TOP=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

ver() { sed -n "s/^$2=//p" "$TOP/tools/$1"; }
XRAY_VER=$(ver fetch-xray.sh XRAY_VER); HEV_VER=$(ver fetch-xray.sh HEV_VER)
SB_VER=$(ver fetch-sing-box.sh VER); MIHOMO_VER=$(ver fetch-mihomo.sh VER); DAE_VER=$(ver fetch-dae.sh VER)
GEOIP_VER=$(ver fetch-mihomo.sh GEOIP_VER); GEOSITE_VER=$(ver fetch-mihomo.sh GEOSITE_VER)
fake() { printf '#!/bin/sh\necho "%s (fake engine for tests)"\n' "$2" > "$1"; chmod 755 "$1"; }
FAKE=${MU300_VPN_FAKE_ENGINES:-}

# the engines, once: $tmp/eng/{xray,singbox,mihomo,dae}
e=$tmp/eng
mkdir -p "$e/xray/bin" "$e/singbox/bin" "$e/mihomo/bin" "$e/mihomo/share/mihomo" "$e/dae/bin" "$e/dae/share/dae"
if [ "$FAKE" = 1 ]; then
    fake "$e/xray/bin/xray" xray; fake "$e/xray/bin/hev-socks5-tunnel" hev-socks5-tunnel
    fake "$e/singbox/bin/sing-box" sing-box; fake "$e/mihomo/bin/mihomo" mihomo; fake "$e/dae/bin/dae" dae
    echo fake > "$e/dae/share/dae/geoip.dat"; echo fake > "$e/dae/share/dae/geosite.dat"
    echo fake > "$e/mihomo/share/mihomo/Country.mmdb"; echo fake > "$e/mihomo/share/mihomo/GeoSite.dat"
else
    sh "$TOP/tools/fetch-xray.sh" "$e/xray/bin" >&2
    sh "$TOP/tools/fetch-sing-box.sh" "$e/singbox/bin/sing-box" >&2
    sh "$TOP/tools/fetch-mihomo.sh" "$e/mihomo" >&2
    sh "$TOP/tools/fetch-dae.sh" "$e/dae" >&2
fi

# meta DIR NAME COMPONENTS...: the files every extra has
meta() {
    _d=$1 _n=$2; shift 2
    echo "$TAG" > "$_d/VERSION"
    echo "$TAG" > "$_d/release"
    echo "$_n" > "$_d/name"
    echo "$REQUIRES" > "$_d/requires"
    printf '%s\n' "$@" > "$_d/components"
}

# ---- the core, and the bundle (the core with the v1 engines) --------------------------------------------------
core() {
    mkdir -p "$1/bin" "$1/lib" "$1/etc" "$1/service/systemd" "$1/service/procd" "$1/hooks"
    cp "$TOP/bin/mu300-vpn" "$1/bin/"
    cp -R "$TOP/lib/vpn" "$1/lib/vpn"
    cp "$TOP/etc/vpn.conf.example" "$1/etc/"
    cp "$TOP/service/systemd/mu300-vpn.service" "$TOP/service/systemd/mu300-vpn-subscriptions.service" \
        "$TOP/service/systemd/mu300-vpn-subscriptions.timer" "$1/service/systemd/"
    cp "$TOP/service/procd/mu300-vpn" "$1/service/procd/"
    cp "$TOP/hooks/link" "$TOP/hooks/unlink" "$1/hooks/"
    cp "$TOP/install.sh" "$1/"
}
c=$tmp/core; core "$c"; meta "$c" vpn "mu300-linux-vpn $TAG"
b=$tmp/bundle; core "$b"
cp "$e/xray/bin/xray" "$e/xray/bin/hev-socks5-tunnel" "$e/singbox/bin/sing-box" "$b/bin/"
meta "$b" vpn "mu300-linux-vpn $TAG" "xray $XRAY_VER" "hev-socks5-tunnel $HEV_VER" "sing-box $SB_VER"

# ---- the engine extras ------------------------------------------------------------------------------------------
engine() { # engine NAME SRC COMPONENTS...
    _x=$1; _d=$tmp/$1; _s=$2; shift 2
    mkdir -p "$_d/hooks"
    cp -R "$_s/." "$_d/"
    cp "$TOP/hooks/engine-link" "$_d/hooks/link"; cp "$TOP/hooks/engine-unlink" "$_d/hooks/unlink"
    meta "$_d" "$_x" "$@"
}
engine vpn-xray "$e/xray" "xray $XRAY_VER" "hev-socks5-tunnel $HEV_VER"
engine vpn-singbox "$e/singbox" "sing-box $SB_VER"
engine vpn-mihomo "$e/mihomo" "mihomo $MIHOMO_VER" "geoip $GEOIP_VER" "geosite $GEOSITE_VER"
engine vpn-dae "$e/dae" "dae $DAE_VER"

# python's tarfile, not tar: the same root-owned archive from macOS (bsdtar) and Linux (GNU tar), sorted, with fixed
# modes and times (SOURCE_DATE_EPOCH, else the last commit's time, else 0) and a gzip header without a time or name
python3 - "${SOURCE_DATE_EPOCH:-$(git -C "$TOP" log -1 --format=%ct 2>/dev/null || echo 0)}" \
    "$c" "$OUT/mu300-linux-vpn-core.tar.gz" "$b" "$OUT/mu300-linux-vpn.tar.gz" \
    "$tmp/vpn-xray" "$OUT/mu300-linux-vpn-xray.tar.gz" "$tmp/vpn-singbox" "$OUT/mu300-linux-vpn-singbox.tar.gz" \
    "$tmp/vpn-mihomo" "$OUT/mu300-linux-vpn-mihomo.tar.gz" "$tmp/vpn-dae" "$OUT/mu300-linux-vpn-dae.tar.gz" <<'PY'
import gzip, hashlib, io, os, sys, tarfile
mtime = int(sys.argv[1] or 0)
EXEC_DIRS = ('bin/', 'hooks/', 'service/procd/')
def executable(rel):
    return rel.startswith(EXEC_DIRS) or rel in ('install.sh', 'lib/vpn/openvpn-up')
def build(src, out):
    files = []
    for d, ds, fs in os.walk(src):
        ds.sort()
        for f in sorted(fs):
            files.append(os.path.relpath(os.path.join(d, f), src))
    with open(os.path.join(src, 'manifest'), 'w') as m:
        for rel in sorted(files):
            m.write('%s  ./%s\n' % (hashlib.sha256(open(os.path.join(src, rel), 'rb').read()).hexdigest(), rel))
    files.append('manifest')
    entries = set()
    for rel in files:
        parts = rel.split('/')
        for i in range(1, len(parts)):
            entries.add(('/'.join(parts[:i]), True))
        entries.add((rel, False))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.GNU_FORMAT) as t:
        for rel, isdir in sorted(entries):
            ti = tarfile.TarInfo('./' + rel)
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = 'root'
            ti.mtime = mtime
            if isdir:
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                t.addfile(ti)
            else:
                data = open(os.path.join(src, rel), 'rb').read()
                ti.size, ti.mode = len(data), 0o755 if executable(rel) else 0o644
                t.addfile(ti, io.BytesIO(data))
    with open(out, 'wb') as f, gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=0, compresslevel=9) as g:
        g.write(buf.getvalue())
args = sys.argv[2:]
for i in range(0, len(args), 2):
    build(args[i], args[i + 1])
PY
ASSETS='mu300-linux-vpn-core.tar.gz mu300-linux-vpn.tar.gz mu300-linux-vpn-xray.tar.gz mu300-linux-vpn-singbox.tar.gz mu300-linux-vpn-mihomo.tar.gz mu300-linux-vpn-dae.tar.gz'
# VERSIONS: what mu300-vpn engines --check shows as available, without downloading a tarball
( cd "$OUT"
  for f in $ASSETS; do
      case $f in mu300-linux-vpn-core.tar.gz) x=vpn; d=$c ;; mu300-linux-vpn.tar.gz) x=vpn-bundle; d=$b ;;
          *) x=${f#mu300-linux-}; x=${x%.tar.gz}; d=$tmp/$x ;; esac
      printf '%s\t%s\t%s\t%s\t%s\n' "$x" "$TAG" "$(wc -c < "$f" | tr -d ' ')" "$(paste -sd, "$d/components")" "$f"
  done > VERSIONS
  for f in $ASSETS VERSIONS; do
      s=$(shasum -a 256 "$f" 2>/dev/null || sha256sum "$f"); printf '%s  %s\n' "${s%% *}" "$f"
  done > SHA256SUMS )
for f in $ASSETS; do
    echo "$f ($TAG): $(du -h "$OUT/$f" | cut -f1)"
done
echo "SHA256SUMS: $OUT/SHA256SUMS"
