# The OpenVPN driver of mu300-vpn (sourced by load_driver): an .ovpn file ($PDIR/client.ovpn) run by the openvpn
# package, with our own routing, our own up script and its sockets marked 0x2d0 so that rule 9000 keeps them off the
# tunnel and the kill switch lets them out. The core installs the routing (DRV_ROUTES=core); openvpn only makes the
# tun device and brings the session up (--route-noexec).
#
# What the file may say is limited, because an .ovpn is a program for openvpn: every directive that runs a script,
# loads code, takes over the device, the routes, the log or the process is removed from the copy that runs. Keys,
# certificates and passwords are never printed, logged or put on a command line: they stay in client.ovpn and
# auth.txt (0600) and in the runtime copy (0600), and every message names the problem, never the value.
DRV_EXTRA=
# the package is openvpn-openssl on OpenWrt (apk), openvpn elsewhere
DRV_PKG=openvpn
[ ! -e "${MU300_OPENWRT_RELEASE:-/etc/openwrt_release}" ] || DRV_PKG=openvpn-openssl
DRV_KEYS='OVPN_USER OVPN_PASS'
TUN=tun-mu300

OVPN_PID=

# The binary: the OPENVPN setting when there is one, else the package's.
ovpn_bin() { if [ -n "${_openvpn:-}" ]; then printf '%s\n' "$_openvpn"; else engine_path openvpn; fi; }

# ---- reading an .ovpn -----------------------------------------------------------------------------------------
# One awk program does all the reading, in four modes, so that what is checked, what is looked up and what is copied
# can never disagree about where a directive is:
#   check    what is wrong (stdout, exit 1), notes and warnings
#   hosts    the remote names that are not addresses, one per line
#   remotes  every remote host, one per line (after the names were replaced)
#   filter   the config that runs: names replaced by the addresses in MAP (name=address pairs, space separated),
#            the removed directives left out, everything else byte for byte
# A directive is the first word of a line that is not a comment and is not inside an inline <tag> ... </tag> block
# (a certificate or key, where a line such as "up" is data). <connection> is the exception: it is not data, its
# lines are directives like the top level's, and its remotes are remotes. The word is read the way openvpn reads it:
# quotes and backslashes do not hide it ("up" is up) and a leading "--" is allowed.
ovpn_awk() {
    awk -v mode="$1" -v map="$2" -v hasauth="$3" '
    function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
    function bad(m) { print "the OpenVPN config " m; err = 1 }
    BEGIN {
        # scripts and code, the device, the routes, the process, the log and the files the config would write
        n = split("up down route-up route-pre-down ipchange tls-verify auth-user-pass-verify learn-address " \
                  "client-connect client-disconnect script-security plugin dev dev-type dev-node daemon log " \
                  "log-append status management cd chroot user group writepid iproute redirect-gateway route " \
                  "route-ipv6 auth-user-pass config mark engine inetd genkey mktun rmtun tls-export-cert " \
                  "pkcs11-providers memstats test-crypto", d, " ")
        for (i = 1; i <= n; i++) drop[d[i]] = 1
        n = split(map, t, " ")
        for (i = 1; i <= n; i++) { j = index(t[i], "="); m[substr(t[i], 1, j - 1)] = substr(t[i], j + 1) }
    }
    {
        line = $0; l = trim(line)
        if (op != "") {                                  # inside a block: data, kept as it is
            if (mode == "filter") print line
            if (l == "</" op ">") op = ""
            next
        }
        if (l ~ /^<[A-Za-z0-9_-]+>$/) {
            tag = substr(l, 2, length(l) - 2)
            if (mode == "filter") print line
            if (tag != "connection") op = tag
            next
        }
        if (l == "" || l ~ /^[#;]/ || l == "</connection>") { if (mode == "filter") print line; next }
        nw = split(l, w, /[ \t\r]+/)
        k = w[1]; gsub("\"", "", k); gsub("\047", "", k); gsub("\\\\", "", k); sub(/^--/, "", k)
        if (k == "dev" && w[2] ~ /^"?tap/) bad("is a tap (bridged) profile, which this driver does not run: the tunnel is a tun device")
        if (k == "remote") {
            h = w[2]
            if (nw < 2 || nw > 4 || h !~ /^[A-Za-z0-9._:][A-Za-z0-9._:-]*$/) { bad("has a remote that is not a plain HOST [PORT [PROTO]]"); next }
            if (nw >= 3 && (w[3] !~ /^[0-9]+$/ || w[3] + 0 < 1 || w[3] + 0 > 65535)) { bad("has a remote with a port that is not a number from 1 to 65535"); next }
            if (nw == 4 && w[4] !~ /^(udp|tcp)[46]?(-client)?$/) { bad("has a remote with a protocol that is not udp or tcp (tcp-client)"); next }
            nrem++
            lit = (h ~ /^[0-9.]+$/ || index(h, ":") > 0)
            if (mode == "hosts" && !lit && !(h in seen)) { seen[h] = 1; print h }
            if (mode == "remotes" && !(h in seen)) { seen[h] = 1; print h }
            if (mode == "filter") {
                if (h in m) { out = "remote " m[h]; for (i = 3; i <= nw; i++) out = out " " w[i]; print out } else print line
            }
            next
        }
        if (k in drop || k ~ /^management/ || k ~ /^show-/) {
            if (k == "auth-user-pass") needauth = 1
            if (k ~ /^[a-z0-9-]+$/) gone[k] = 1
            next
        }
        if (mode == "filter") print line
    }
    END {
        if (mode != "check") exit 0
        if (op != "") bad("has a block (<" op ">) that is never closed")
        if (!nrem) bad("has no remote server")
        if (err) exit 1
        s = ""; for (k in gone) s = s " " k
        if (s != "") print "note: directives of the file that are not used (this driver runs its own scripts and routing):" s
        if (needauth && hasauth != 1) print "warning: the profile asks for a user name and password: mu300-vpn profile set ID OVPN_USER NAME, then mu300-vpn profile set ID OVPN_PASS - (the password is read from stdin)"
    }' "$4"
}

# ---- the contract ---------------------------------------------------------------------------------------------
drv_engines() { ovpn_bin; }
drv_engines_ok() { [ -x "$(ovpn_bin)" ]; }

drv_check() {
    [ -n "${PDIR:-}" ] && [ -r "$PDIR/client.ovpn" ] || { echo "the profile has no client.ovpn" >&2; return 1; }
    _ha=0; [ -r "$PDIR/auth.txt" ] && _ha=1
    ovpn_awk check '' "$_ha" "$PDIR/client.ovpn" >&2
}

drv_gen() {
    drv_check || exit 1
    _of=$PDIR/client.ovpn
    mkdir -p "$RUN"; chmod 700 "$RUN"
    # The remote names are looked up now, before the tunnel exists: openvpn's own lookups would go out on a socket
    # the kill switch does not know. One window around all of them; every remote of the file is kept, each resolved.
    _names=$(ovpn_awk hosts '' 0 "$_of")
    _map=
    if [ -n "$_names" ]; then
        resolve_window || { resolve_close; echo "could not open the resolve window" >&2; exit 1; }
        while IFS= read -r _h; do
            [ -n "$_h" ] || continue
            _ip=$(vpn_resolve "$_h") || _ip=
            [ -n "$_ip" ] || { resolve_close; echo "cannot resolve the VPN server $_h" >&2; exit 1; }
            _map="$_map $_h=$_ip"
            echo "server $_h -> $_ip"
        done <<EOF
$_names
EOF
        resolve_close || { echo "could not put the kill switch back after the lookups" >&2; exit 1; }
    fi
    rm -f "$RUN/openvpn.conf" "$RUN/server-ip" "$RUN/dns" "$RUN/ovpn-up"
    ( umask 077; ovpn_awk filter "$_map" 0 "$_of" > "$RUN/openvpn.conf" ) || { rm -f "$RUN/openvpn.conf"; echo "cannot write $RUN/openvpn.conf" >&2; exit 1; }
    ( umask 077; ovpn_awk remotes '' 0 "$RUN/openvpn.conf" > "$RUN/server-ip" ) || { rm -f "$RUN/openvpn.conf" "$RUN/server-ip"; echo "cannot write $RUN/server-ip" >&2; exit 1; }
    echo "openvpn config OK ($RUN/openvpn.conf)"
}

# The core runs this without set -e: every step whose failure leaves half a tunnel returns 1 itself, and openvpn is
# stopped again when it does not come up. The up script is the signal that it did.
drv_start() {
    OVPN_PID=; DRV_PIDS=
    rm -f "$RUN/ovpn-up" "$RUN/dns"
    set -- "$(ovpn_bin)" --config "$RUN/openvpn.conf" --dev "$TUN" --dev-type tun --route-noexec \
        --pull-filter ignore redirect-gateway --mark "$((MARK))" --script-security 2 --up "$LIB/openvpn-up" \
        --setenv MU300_VPN_RUN "$RUN" --auth-nocache --verb 3
    [ ! -r "$PDIR/auth.txt" ] || set -- "$@" --auth-user-pass "$PDIR/auth.txt"
    "$@" < /dev/null &
    OVPN_PID=$!; DRV_PIDS=$OVPN_PID
    _n=0
    until [ -e "$RUN/ovpn-up" ]; do
        kill -0 "$OVPN_PID" 2>/dev/null || { echo "openvpn exited during start" >&2; OVPN_PID=; DRV_PIDS=; return 1; }
        _n=$((_n + 1))
        if [ "$_n" -gt 60 ]; then
            echo "openvpn did not bring the tunnel up within 60 s" >&2
            drv_stop
            return 1
        fi
        sleep 1
    done
    echo "tunnel up on $TUN"
}
drv_alive() {
    [ -n "$OVPN_PID" ] && kill -0 "$OVPN_PID" 2>/dev/null || { DRV_GONE=openvpn; return 1; }
    ip link show "$TUN" >/dev/null 2>&1 || { DRV_GONE=openvpn; return 1; }
}
# TERM lets openvpn close the session and take its device away; KILL after 5 s for one that does not. The runtime
# copy of the config holds the keys, so it goes too.
drv_stop() {
    if [ -n "$OVPN_PID" ]; then
        kill "$OVPN_PID" 2>/dev/null || true
        _n=0
        while kill -0 "$OVPN_PID" 2>/dev/null && [ "$_n" -lt 5 ]; do sleep 1; _n=$((_n + 1)); done
        if kill -0 "$OVPN_PID" 2>/dev/null; then kill -9 "$OVPN_PID" 2>/dev/null || true; fi
        wait "$OVPN_PID" 2>/dev/null || true
    fi
    OVPN_PID=; DRV_PIDS=
    rm -f "$RUN/openvpn.conf" "$RUN/ovpn-up"
    return 0
}

# an .ovpn, as it is: checked first, so that nothing is written for one that cannot run
drv_import() {
    [ -n "${PDIR:-}" ] && [ -d "$PDIR" ] || { echo "no profile to import into" >&2; return 1; }
    [ -f "$1" ] && [ -r "$1" ] || { echo "an OpenVPN profile is a config file (.ovpn)" >&2; return 1; }
    ovpn_awk check '' 0 "$1" >&2 || return 1
    ( umask 077; cat "$1" > "$PDIR/client.ovpn.new.$$" ) && mv "$PDIR/client.ovpn.new.$$" "$PDIR/client.ovpn" && return 0
    rm -f "$PDIR/client.ovpn.new.$$"; return 1
}

# profile set ID OVPN_USER NAME / OVPN_PASS SECRET: auth.txt, two lines, for openvpn's --auth-user-pass. The
# password is better given as "-", which reads it from stdin and keeps it out of the process list. An empty value
# clears that line, and a file with neither goes away. Values are never printed.
drv_set() {
    [ -n "${PDIR:-}" ] && [ -d "$PDIR" ] || return 1
    _v=$2
    if [ "$_v" = - ]; then IFS= read -r _v || :; fi
    _nl='
'
    case $_v in
        *"$_nl"*|*"$(printf '\r')"*) echo "$1 cannot hold a line break" >&2; return 2 ;;
    esac
    _u=; _p=
    if [ -r "$PDIR/auth.txt" ]; then { IFS= read -r _u || :; IFS= read -r _p || :; } < "$PDIR/auth.txt"; fi
    case $1 in OVPN_USER) _u=$_v ;; OVPN_PASS) _p=$_v ;; *) return 2 ;; esac
    if [ -z "$_u" ] && [ -z "$_p" ]; then rm -f "$PDIR/auth.txt"; return 0; fi
    ( umask 077; printf '%s\n%s\n' "$_u" "$_p" > "$PDIR/auth.txt.new.$$" ) && mv "$PDIR/auth.txt.new.$$" "$PDIR/auth.txt" && return 0
    rm -f "$PDIR/auth.txt.new.$$"; return 1
}
