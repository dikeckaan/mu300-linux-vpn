#!/bin/sh
# Build the module's release files:
#   tools/make-module.sh OUTDIR [TAG]    (TAG: vMAJOR.MINOR.PATCH, default v0.0.0-dev)
#   OUTDIR/mu300-linux-vpn.tar.gz         mu300-vpn, its library, services, hooks and the engines Xray-core,
#                                         hev-socks5-tunnel (tools/fetch-xray.sh) and sing-box (tools/fetch-sing-box.sh)
#   OUTDIR/mu300-linux-vpn-mihomo.tar.gz  mihomo (tools/fetch-mihomo.sh), the engine of mihomo profiles
#   OUTDIR/SHA256SUMS                     both, in sha256sum's format
# The engines are the pinned releases, checked against their hashes by the fetch scripts. MU300_VPN_FAKE_ENGINES=1
# puts small scripts in their place instead (tests/, no network).
# Both unpack into mu300-extra's directory for them ($DISK/extra/vpn, $DISK/extra/vpn-mihomo): files and directories
# only, owned by root, modes set here (programs 755, the rest 644), the same bytes from macOS and Linux for the same
# inputs. Besides the module's files: VERSION, components, requires, and for older mu300-extra checks name, release
# (= VERSION) and manifest (the sha256 of every other file, as sha256sum writes it).
set -eu
OUT=${1:?usage: tools/make-module.sh OUTDIR [TAG]}
TAG=${2:-v0.0.0-dev}
case $TAG in v[0-9]*) ;; *) echo "TAG is vMAJOR.MINOR.PATCH" >&2; exit 2 ;; esac
# the first mu300-linux release whose mu300-extra installs this module (and that has no mu300-vpn of its own)
REQUIRES='mu300-linux v2026.10.16'
TOP=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

ver() { sed -n "s/^$2=//p" "$TOP/tools/$1"; }
XRAY_VER=$(ver fetch-xray.sh XRAY_VER); HEV_VER=$(ver fetch-xray.sh HEV_VER)
SB_VER=$(ver fetch-sing-box.sh VER); MIHOMO_VER=$(ver fetch-mihomo.sh VER)
fake() { printf '#!/bin/sh\necho "%s (fake engine for tests)"\n' "$2" > "$1"; chmod 755 "$1"; }

# ---- mu300-linux-vpn -------------------------------------------------------------------------------------------
m=$tmp/vpn
mkdir -p "$m/bin" "$m/lib" "$m/etc" "$m/service/systemd" "$m/service/procd" "$m/hooks"
cp "$TOP/bin/mu300-vpn" "$m/bin/"
cp -R "$TOP/lib/vpn" "$m/lib/vpn"
cp "$TOP/etc/vpn.conf.example" "$m/etc/"
cp "$TOP/service/systemd/mu300-vpn.service" "$m/service/systemd/"
cp "$TOP/service/procd/mu300-vpn" "$m/service/procd/"
cp "$TOP/hooks/link" "$TOP/hooks/unlink" "$m/hooks/"
cp "$TOP/install.sh" "$m/"
if [ "${MU300_VPN_FAKE_ENGINES:-}" = 1 ]; then
    fake "$m/bin/xray" xray; fake "$m/bin/hev-socks5-tunnel" hev-socks5-tunnel; fake "$m/bin/sing-box" sing-box
else
    sh "$TOP/tools/fetch-xray.sh" "$m/bin" >&2
    sh "$TOP/tools/fetch-sing-box.sh" "$m/bin/sing-box" >&2
fi
echo "$TAG" > "$m/VERSION"
echo "$TAG" > "$m/release"
echo vpn > "$m/name"
echo "$REQUIRES" > "$m/requires"
printf 'mu300-linux-vpn %s\nxray %s\nhev-socks5-tunnel %s\nsing-box %s\n' "$TAG" "$XRAY_VER" "$HEV_VER" "$SB_VER" > "$m/components"

# ---- mu300-linux-vpn-mihomo ------------------------------------------------------------------------------------
h=$tmp/mihomo
mkdir -p "$h/bin"
if [ "${MU300_VPN_FAKE_ENGINES:-}" = 1 ]; then fake "$h/bin/mihomo" mihomo
else sh "$TOP/tools/fetch-mihomo.sh" "$h/bin" >&2; fi
echo "$TAG" > "$h/VERSION"
echo "$TAG" > "$h/release"
echo vpn-mihomo > "$h/name"
echo "$REQUIRES" > "$h/requires"
printf 'mihomo %s\n' "$MIHOMO_VER" > "$h/components"

# python's tarfile, not tar: the same root-owned archive from macOS (bsdtar) and Linux (GNU tar), sorted, with fixed
# modes and times (SOURCE_DATE_EPOCH, else the last commit's time, else 0) and a gzip header without a time or name
python3 - "$m" "$OUT/mu300-linux-vpn.tar.gz" "$h" "$OUT/mu300-linux-vpn-mihomo.tar.gz" \
    "${SOURCE_DATE_EPOCH:-$(git -C "$TOP" log -1 --format=%ct 2>/dev/null || echo 0)}" <<'PY'
import gzip, hashlib, io, os, sys, tarfile
mtime = int(sys.argv[5] or 0)
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
build(sys.argv[1], sys.argv[2])
build(sys.argv[3], sys.argv[4])
PY
( cd "$OUT"
  for f in mu300-linux-vpn.tar.gz mu300-linux-vpn-mihomo.tar.gz; do
      s=$(shasum -a 256 "$f" 2>/dev/null || sha256sum "$f"); printf '%s  %s\n' "${s%% *}" "$f"
  done > SHA256SUMS )
for f in mu300-linux-vpn.tar.gz mu300-linux-vpn-mihomo.tar.gz; do
    echo "$f ($TAG): $(du -h "$OUT/$f" | cut -f1)"
done
echo "SHA256SUMS: $OUT/SHA256SUMS"
