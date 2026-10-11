#!/bin/sh
# Install this module on the MU300 without the device's own connection: copy the release's files into one directory
# on the device - SHA256SUMS and either
#   mu300-linux-vpn-core.tar.gz and the engines you want (mu300-linux-vpn-xray.tar.gz, -singbox, -mihomo, -dae), or
#   mu300-linux-vpn.tar.gz (the core with xray and sing-box in it, as module v1 was; any mu300-extra takes it)
# then, as root, in that directory:
#   tar -xzf mu300-linux-vpn-core.tar.gz ./install.sh && sh install.sh    (or the same from mu300-linux-vpn.tar.gz)
# It runs mu300-extra install vpn --from that directory, which checks every tarball against SHA256SUMS, installs the
# engines the profiles on the device need first and the core last (and refuses, changing nothing, when one of them is
# not there), unpacks them to /mnt/mu300-disk/extra/ and links the core into every installed system (hooks/link).
# Every other engine tarball in the directory is installed as well.
#   sh install.sh [DIR|TARBALL]   another directory, or the tarball itself (then nothing checks it against SHA256SUMS)
# Needs mu300-linux v2026.10.16 or newer (its mu300-extra installs modules: see requires); the split engines need an
# mu300-extra that knows them (mu300-linux with the engine extras) - an older one takes mu300-linux-vpn.tar.gz.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
from=${1:-}
if [ -z "$from" ]; then
    for d in "$here" "$(pwd)"; do
        if [ -f "$d/mu300-linux-vpn-core.tar.gz" ] || [ -f "$d/mu300-linux-vpn.tar.gz" ]; then from=$d; break; fi
    done
    [ -n "$from" ] || { echo "neither mu300-linux-vpn-core.tar.gz nor mu300-linux-vpn.tar.gz is next to install.sh or in $(pwd): sh install.sh DIR|TARBALL" >&2; exit 1; }
fi
extra=$(command -v mu300-extra 2>/dev/null) || extra=/opt/mu300/bin/mu300-extra
[ -x "$extra" ] || { echo "mu300-extra is not on this system: this is not an MU300 with mu300-linux" >&2; exit 1; }
[ -d "$from" ] && [ ! -f "$from/SHA256SUMS" ] && echo "note: no SHA256SUMS in $from, so the tarballs are not checked" >&2
# knows NAME: this mu300-extra installs that extra (an older one knows vpn and vpn-mihomo only)
knows() { "$extra" list 2>/dev/null | grep -q "^$1[[:space:]]"; }
if ! "$extra" install vpn --from "$from"; then
    if [ -d "$from" ] && [ ! -f "$from/mu300-linux-vpn.tar.gz" ] && ! knows vpn-xray; then
        echo "not installed: this mu300-linux's mu300-extra is older than the engine extras. Copy mu300-linux-vpn.tar.gz" \
            "(the core with xray and sing-box) here too, or update mu300-linux first (mu300-update apply)" >&2
    else
        echo "not installed. mu300-linux v2026.10.16 or newer is needed (mu300-update, then try again)" >&2
    fi
    exit 1
fi
if [ -d "$from" ]; then
    for x in xray singbox mihomo dae; do
        [ -f "$from/mu300-linux-vpn-$x.tar.gz" ] && [ ! -d "/mnt/mu300-disk/extra/vpn-$x/bin" ] || continue
        if knows "vpn-$x"; then "$extra" install "vpn-$x" --from "$from" || echo "vpn-$x was not installed (see above)" >&2
        else echo "vpn-$x: this mu300-extra does not know it yet (update mu300-linux)" >&2; fi
    done
fi
echo "done: mu300-vpn profile import 'LINK', mu300-vpn on (see the README)"
