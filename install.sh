#!/bin/sh
# Install this module on the MU300 without the device's own connection: copy mu300-linux-vpn.tar.gz and the
# release's SHA256SUMS (and mu300-linux-vpn-mihomo.tar.gz, for mihomo profiles) into one directory on the device,
# then, as root, in that directory:
#   tar -xzf mu300-linux-vpn.tar.gz ./install.sh && sh install.sh
# It runs mu300-extra install vpn --from that directory, which checks the tarball against SHA256SUMS, unpacks it to
# /mnt/mu300-disk/extra/vpn and links it into every installed system (hooks/link). The same for vpn-mihomo when its
# tarball is there too.
#   sh install.sh [DIR|TARBALL]   another directory, or the tarball itself (then nothing checks it against SHA256SUMS)
# Needs mu300-linux v2026.10.16 or newer (its mu300-extra installs modules: see requires).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
from=${1:-}
if [ -z "$from" ]; then
    for d in "$here" "$(pwd)"; do
        if [ -f "$d/mu300-linux-vpn.tar.gz" ]; then from=$d; break; fi
    done
    [ -n "$from" ] || { echo "mu300-linux-vpn.tar.gz is not next to install.sh or in $(pwd): sh install.sh DIR|TARBALL" >&2; exit 1; }
fi
extra=$(command -v mu300-extra 2>/dev/null) || extra=/opt/mu300/bin/mu300-extra
[ -x "$extra" ] || { echo "mu300-extra is not on this system: this is not an MU300 with mu300-linux" >&2; exit 1; }
[ -d "$from" ] && [ ! -f "$from/SHA256SUMS" ] && echo "note: no SHA256SUMS in $from, so the tarball is not checked" >&2
if ! "$extra" install vpn --from "$from"; then
    echo "not installed. mu300-linux v2026.10.16 or newer is needed (mu300-update, then try again)" >&2
    exit 1
fi
if [ -d "$from" ] && [ -f "$from/mu300-linux-vpn-mihomo.tar.gz" ]; then
    "$extra" install vpn-mihomo --from "$from"
fi
echo "done: mu300-vpn profile import 'LINK', mu300-vpn on (see the README)"
