# The xray driver of mu300-vpn (sourced by load_driver): a vless, vmess, trojan or ss link ($PDIR/uri), or a raw
# Xray config ($PDIR/config.json), run by Xray behind hev-socks5-tunnel.
DRV_EXTRA=vpn
# the per-profile options profile set takes (link_opt_set checks them)
DRV_KEYS='TLS_PIN_SHA256 UPSTREAM_HTTP_PROXY'
DRV_PKG=
TUN=xtun
XPID=; HPID=; DRV_GONE=

# ---- xray engine ----------------------------------------------------------------------------------------------
# Xray speaks the link's protocol; hev-socks5-tunnel owns the TUN and hands every TCP/UDP flow to Xray's
# SOCKS port on loopback. Neither installs routes, so the core does (routes_up, DRV_ROUTES=core), with the same rule
# prefs and table as sing-box's auto_route - which is what lets routing_cleanup and the kill switch serve both engines.

listening() { { ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null; } | grep -q "127.0.0.1:$1 "; }

xray_stream_json() {
    case "$TYPE" in tcp|raw) net=raw ;; ws|grpc|httpupgrade|xhttp) net=$TYPE ;;
        *) echo "transport type '$TYPE' is not supported by this helper" >&2; exit 1 ;; esac
    printf '"streamSettings":{"network":"%s"' "$net"
    case "$TYPE" in
        ws) printf ',"wsSettings":{"path":%s' "$(json_str "${WSPATH:-/}")"; [ -n "$WSHOST" ] && printf ',"host":%s' "$(json_str "$WSHOST")"; printf '}' ;;
        grpc) printf ',"grpcSettings":{"serviceName":%s}' "$(json_str "$SVC")" ;;
        httpupgrade) printf ',"httpupgradeSettings":{"path":%s' "$(json_str "${WSPATH:-/}")"; [ -n "$WSHOST" ] && printf ',"host":%s' "$(json_str "$WSHOST")"; printf '}' ;;
        xhttp) printf ',"xhttpSettings":{"path":%s' "$(json_str "${WSPATH:-/}")"; [ -n "$WSHOST" ] && printf ',"host":%s' "$(json_str "$WSHOST")"
               [ -n "$XMODE" ] && printf ',"mode":%s' "$(json_str "$XMODE")"; printf '}' ;;
    esac
    case "$SECURITY" in
        tls)
            printf ',"security":"tls","tlsSettings":{"serverName":%s' "$(json_str "${SNI:-$HOST}")"
            # Xray 26 removed allowInsecure. Its replacement pins the one certificate the server presents,
            # which is stricter: anything else is refused, including a correctly signed certificate for a
            # different host. It also skips the expiry check, so an expired certificate keeps working until
            # the server renews it - and then the pin has to change with it.
            [ -n "$PIN" ] && printf ',"pinnedPeerCertSha256":%s' "$(json_str "$PIN")"
            [ -n "$VCN" ] && printf ',"verifyPeerCertByName":%s' "$(json_str "$VCN")"
            [ -n "$ALPN" ] && printf ',"alpn":%s' "$(json_list "$ALPN")"
            [ -n "$FP" ] && printf ',"fingerprint":%s' "$(json_str "$FP")"
            printf '}' ;;
        reality)
            printf ',"security":"reality","realitySettings":{"serverName":%s,"fingerprint":%s,"publicKey":%s,"shortId":%s' \
                "$(json_str "${SNI:-$HOST}")" "$(json_str "${FP:-chrome}")" "$(json_str "$PBK")" "$(json_str "$SID")"
            [ -n "$SPX" ] && printf ',"spiderX":%s' "$(json_str "$SPX")"
            printf '}' ;;
    esac
    printf ',"sockopt":{"mark":%d}}' "$((MARK))"
}

# Xray 26 has no allowInsecure; pinnedPeerCertSha256 is its replacement. For a link that asks for allowInsecure the
# pin is managed here: fetched once when there is none, kept with the link (save_pin), and fetched again only when
# Xray reports that the server's certificate no longer matches (a renewal). A pin that came from the link (pcs) or
# was written by hand without allowInsecure is left alone.
pin_managed() { [ "$SECURITY" = tls ] && case "$INSECURE" in 1|true) true ;; *) false ;; esac; }

# SHA-256 of the leaf certificate the server presents, in the form Xray expects. Goes out directly: at start the
# tunnel's rules are not in place yet, and while it runs rule 9002 keeps the server's address off the tunnel.
fetch_pin() {
    command -v openssl >/dev/null 2>&1 || { echo "fetching the server certificate needs openssl (OpenWrt: apk add openssl-util)" >&2; return 1; }
    t=; command -v timeout >/dev/null 2>&1 && t="timeout 20"
    h=$($t openssl s_client -connect "$SERVER_IP:$PORT" -servername "${SNI:-$HOST}" </dev/null 2>/dev/null |
        openssl x509 -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
    # the hash of nothing is what an empty pipe produces when the handshake failed
    case "$h" in ""|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) return 1 ;; esac
    printf '%s' "$h"
}

# the pin goes where the link is: the active profile's meta, or vpn.conf when the store is not used
save_pin() {
    if [ -n "$ACTIVE" ]; then kv_set "$PDIR/meta" TLS_PIN_SHA256 "$1"; return; fi
    if grep -q '^TLS_PIN_SHA256=' "$CONF"; then sed -i "s/^TLS_PIN_SHA256=.*/TLS_PIN_SHA256=$1/" "$CONF"
    else printf '# fetched by mu300-vpn: the VPN server certificate, standing in for allowInsecure (Xray 26)\nTLS_PIN_SHA256=%s\n' "$1" >> "$CONF"; fi
}

# hev-socks5-tunnel's config: it owns the TUN and hands every flow to Xray's SOCKS inbound on loopback
xray_hev_yml() {
    cat > "$RUN/hev.yml" <<YML
tunnel:
  name: $TUN
  mtu: 8500
  multi-queue: false
  ipv4: 198.18.0.1
socks5:
  port: $SOCKS_PORT
  address: 127.0.0.1
  udp: 'udp'
misc:
  log-level: warn
YML
}

gen_xray() {
    link_need
    parse_link "$VLESS_URI" || exit 1
    ENC=$(urldecode "$(param encryption)")
    # pcs/vcn are the share-link spellings of pinnedPeerCertSha256/verifyPeerCertByName; TLS_PIN_SHA256 in
    # vpn.conf is for links written before those existed
    PIN=${TLS_PIN_SHA256:-$(urldecode "$(param pcs)")}; VCN=$(urldecode "$(param vcn)")
    # the name is looked up now and Xray is given the address, so it never has to resolve anything itself - the
    # resolver it would use sits behind the tunnel it is trying to build. The name stays as the SNI. Behind the kill
    # switch the lookup goes through the resolve window (vpn_resolve).
    # (an IPv6 address in the link is used as it is: vpn_resolve looks up IPv4 only)
    case $HOST in *:*) SERVER_IP=$HOST ;; *) SERVER_IP=$(vpn_resolve "$HOST") ;; esac
    [ -n "$SERVER_IP" ] || { echo "cannot resolve the VPN server $HOST" >&2; exit 1; }
    # allowInsecure with nothing pinned yet: take whatever certificate the server presents now and keep it
    if pin_managed && [ -z "$PIN" ]; then
        # The certificate is fetched by openssl, unmarked: behind the kill switch it cannot get out, and no window
        # is opened for it (it would have to let the device talk to any server). Closed, with what to do instead.
        if [ "$ENABLE" = 1 ] && [ "$KILL_SWITCH" = 1 ]; then
            echo "the link asks for allowInsecure, which Xray no longer has, and behind the kill switch the" \
                "server's certificate cannot be fetched to pin instead:" \
                "mu300-vpn profile set ${ACTIVE:-ID} TLS_PIN_SHA256 ..." >&2
            exit 1
        fi
        PIN=$(fetch_pin) || { echo "the link asks for allowInsecure, which Xray no longer has, and the server's" \
            "certificate could not be fetched to pin instead: mu300-vpn profile set ${ACTIVE:-ID} TLS_PIN_SHA256 ..." \
            "(or TLS_PIN_SHA256 in $CONF without a profile store)" >&2; exit 1; }
        save_pin "$PIN"
        echo "pinned the server's current certificate ($PIN)"
    fi
    mkdir -p "$RUN"; chmod 700 "$RUN"
    {
    # info, not warning: a failed outbound - including a pin mismatch - is only reported at info. drv_start's
    # reader scans every line and passes on only warnings and worse, so the system log does not fill up.
    printf '{"log":{"loglevel":"info","access":"none"},\n'
    printf '"inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],\n' "$SOCKS_PORT"
    # the proxy outbound in the link's protocol; every one gets the same stream settings, with the mark
    case $PROTO in
        vless)
            printf '"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":%s,"port":%s,"users":[{"id":%s,"encryption":%s' \
                "$(json_str "$SERVER_IP")" "$PORT" "$(json_str "$UUID")" "$(json_str "${ENC:-none}")"
            [ -n "$FLOW" ] && printf ',"flow":%s' "$(json_str "$FLOW")"
            printf '}]}]},' ;;
        vmess)
            printf '"outbounds":[{"tag":"proxy","protocol":"vmess","settings":{"vnext":[{"address":%s,"port":%s,"users":[{"id":%s,"alterId":%s,"security":%s}]}]},' \
                "$(json_str "$SERVER_IP")" "$PORT" "$(json_str "$UUID")" "$AID" "$(json_str "${METHOD:-auto}")" ;;
        trojan)
            printf '"outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":%s,"port":%s,"password":%s}]},' \
                "$(json_str "$SERVER_IP")" "$PORT" "$(json_str "$PASSWORD")" ;;
        ss)
            printf '"outbounds":[{"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":%s,"port":%s,"method":%s,"password":%s}]},' \
                "$(json_str "$SERVER_IP")" "$PORT" "$(json_str "$METHOD")" "$(json_str "$PASSWORD")" ;;
    esac
    xray_stream_json; printf '},\n'
    printf '{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":%d}}}]}\n' "$((MARK))"
    } > "$RUN/xray.json"
    chmod 600 "$RUN/xray.json"
    xray_hev_yml
    printf '%s\n' "$SERVER_IP" > "$RUN/server-ip"
    "$XRAY" run -test -c "$RUN/xray.json" >/dev/null || { "$XRAY" run -test -c "$RUN/xray.json" >&2; exit 1; }
    echo "xray config OK ($RUN/xray.json), server $HOST -> $SERVER_IP"
}

# ---- a raw Xray config ----------------------------------------------------------------------------------------
# A config from a panel is run as it is, except for what the device cannot leave to it: its inbounds are replaced by
# our SOCKS inbound on loopback (a panel's config usually listens on 0.0.0.0, which here would be the LAN and the
# uplink), every outbound gets the mark the kill switch lets out, and the server names in vnext and servers are looked
# up by the core and replaced by their addresses, for the same reason as with a link: Xray's own resolver sits behind
# the tunnel it is building. The name stays as the TLS or REALITY serverName where the config gave none, so the
# certificate is still checked against it. There is no certificate pin management here: a raw config says itself
# what it wants verified.
XRAY_JSON_TEST='.outbounds | type == "array"'
xray_raw() { [ -n "${PDIR:-}" ] && [ -r "$PDIR/config.json" ]; }
# every server address in the config's vnext and servers, one per line. Names and addresses are told apart in the
# shell, not with jq's test(): OpenWrt's jq may be built without regular expressions.
xray_json_addresses() {
    jq -r '.outbounds[]? | objects | .settings | objects | (.vnext, .servers) | arrays | .[] | objects
           | .address | strings' "$PDIR/config.json"
}
gen_xray_json() {
    command -v jq >/dev/null 2>&1 || { echo "a raw Xray config needs jq" >&2; exit 1; }
    _all=$(xray_json_addresses 2>/dev/null) || { echo "cannot read the servers of the profile's Xray config" >&2; exit 1; }
    # an address goes into a lookup, into JSON and into a routing rule: only what a host name or an address can be
    if printf '%s\n' "$_all" | grep -q '[^A-Za-z0-9._:-]'; then
        echo "a server in the profile's Xray config is not a host name or an address" >&2; exit 1
    fi
    _names=; _lits=
    for _a in $(printf '%s\n' "$_all" | sort -u); do
        case $_a in *:*) _lits="$_lits $_a" ;; *[!0-9.]*) _names="$_names $_a" ;; *) _lits="$_lits $_a" ;; esac
    done
    # Every name is resolved inside one window (behind the kill switch), and it closes before anything else runs,
    # whether a lookup failed or not.
    _map=; _ips=
    if [ -n "$_names" ]; then
        resolve_window || { resolve_close; echo "could not open the resolve window" >&2; exit 1; }
        for _h in $_names; do
            _ip=$(vpn_resolve "$_h") || _ip=
            [ -n "$_ip" ] || { resolve_close; echo "cannot resolve the VPN server $_h" >&2; exit 1; }
            _map="$_map${_map:+,}$(json_str "$_h"):$(json_str "$_ip")"; _ips="$_ips $_ip"
            echo "server $_h -> $_ip"
        done
        resolve_close || { echo "could not put the kill switch back after the lookups" >&2; exit 1; }
    fi
    mkdir -p "$RUN"; chmod 700 "$RUN"
    # Logged at warning, where a link's config logs at info: info is only needed for the pin-mismatch line
    # drv_start's reader looks for, and a raw config has no managed pin.
    ( umask 077; jq --argjson port "$SOCKS_PORT" --argjson mark "$((MARK))" --argjson map "{$_map}" '
        def resolved: if type == "object" and (.address | type) == "string" and $map[.address]
                      then .address = $map[.address] else . end;
        .log = {"loglevel":"warning","access":"none"}
        | .inbounds = [{"tag":"socks-in","listen":"127.0.0.1","port":$port,"protocol":"socks",
                        "settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}]
        | .outbounds |= map(
            ([(.settings.vnext, .settings.servers) | arrays | .[] | objects | .address | strings
              | select($map[.])] | first) as $n
            | .streamSettings.sockopt.mark = $mark
            | if (.settings.vnext | type) == "array" then .settings.vnext |= map(resolved) else . end
            | if (.settings.servers | type) == "array" then .settings.servers |= map(resolved) else . end
            | if $n and ((.streamSettings.security // "") == "tls")
                    and ((.streamSettings.tlsSettings.serverName // "") == "")
              then .streamSettings.tlsSettings.serverName = $n
              elif $n and ((.streamSettings.security // "") == "reality")
                    and ((.streamSettings.realitySettings.serverName // "") == "")
              then .streamSettings.realitySettings.serverName = $n
              else . end)' "$PDIR/config.json" > "$RUN/xray.json" ) ||
        { rm -f "$RUN/xray.json"; echo "cannot rewrite the profile's Xray config" >&2; exit 1; }
    chmod 600 "$RUN/xray.json"
    xray_hev_yml
    # the resolved names and the addresses the config gave: rule 9002 keeps every one of them off the tunnel
    for _a in $_ips $_lits; do printf '%s\n' "$_a"; done > "$RUN/server-ip"
    "$XRAY" run -test -c "$RUN/xray.json" >/dev/null || { "$XRAY" run -test -c "$RUN/xray.json" >&2; exit 1; }
    echo "xray config OK ($RUN/xray.json)"
}

drv_engines() { printf '%s\n' "$XRAY" "$HEV"; }
drv_engines_ok() {
    [ -x "$XRAY" ] && [ -x "$HEV" ] && return 0
    # an image built before the xray engine existed has only sing-box: a VLESS link keeps working with what is
    # there (the core runs it on the sing-box driver)
    case ${PURI:-${VLESS_URI:-}} in vless://*) [ -x "$BIN" ] ;; *) return 1 ;; esac
}
# the link takes apart and its transport is one the stream settings can express, or the raw config has outbounds
# whose servers can be read (Xray itself checks in drv_gen)
drv_check() {
    if xray_raw; then
        json_check "$XRAY_JSON_TEST" 'an Xray config with outbounds' || return 1
        xray_json_addresses >/dev/null 2>&1 || { echo "cannot read the servers of the profile's Xray config" >&2; return 1; }
        return 0
    fi
    ( link_need; parse_link "$VLESS_URI" || exit 1; PIN=; VCN=; xray_stream_json >/dev/null )
}
drv_gen() { if xray_raw; then gen_xray_json; else gen_xray; fi; }
drv_import() {
    if is_json "$1"; then json_import "$1" "$XRAY_JSON_TEST" 'an Xray config (no outbounds list)'
    else link_import "$1" 'vless vmess trojan ss'; fi
}
drv_set() { link_opt_set "$1" "$2"; }

# Two processes and the routing between them, torn down together: if either dies the service exits, the routes
# go with it and procd starts the whole thing again. Leaving rules behind with nothing at the other end is what
# made sing-box's crashes look like a dead modem (routing_cleanup), so every way out of the core's run goes through
# drv_stop and routes_down.
drv_start() {
    # Xray's output goes through a reader that passes it on and notes a pin mismatch, so a renewed server
    # certificate is noticed without polling the server
    # (every step that can fail returns 1 itself: the core runs this without set -e, see load_driver)
    rm -f "$RUN/pin-mismatch" "$RUN/xray.out"
    mkfifo "$RUN/xray.out" || { echo "cannot create $RUN/xray.out" >&2; return 1; }
    while IFS= read -r l; do
        case "$l" in *"peer cert is unrecognized (against pinnedPeerCertSha256)"*) : > "$RUN/pin-mismatch" ;; esac
        case "$l" in *"[Info]"*|*"[Debug]"*) ;; *) printf '%s\n' "$l" ;; esac
    done < "$RUN/xray.out" &
    "$XRAY" run -c "$RUN/xray.json" > "$RUN/xray.out" 2>&1 & XPID=$!
    HPID=; DRV_PIDS=$XPID
    n=0
    until listening "$SOCKS_PORT"; do
        kill -0 "$XPID" 2>/dev/null || { echo "xray exited during start" >&2; return 1; }
        n=$((n + 1)); [ "$n" -lt 15 ] || { echo "xray did not open its SOCKS port" >&2; return 1; }
        sleep 1
    done
    "$HEV" "$RUN/hev.yml" & HPID=$!
    DRV_PIDS="$XPID $HPID"
    n=0
    until ip link show "$TUN" >/dev/null 2>&1; do
        kill -0 "$HPID" 2>/dev/null || { echo "hev-socks5-tunnel exited during start" >&2; return 1; }
        n=$((n + 1)); [ "$n" -lt 15 ] || { echo "$TUN did not appear" >&2; return 1; }
        sleep 1
    done
    ip link set "$TUN" up || { echo "cannot bring $TUN up" >&2; return 1; }
    echo "tunnel up on $TUN (xray $XPID, hev $HPID)"
}
# whichever exits first ends the service
drv_alive() {
    kill -0 "$XPID" 2>/dev/null || { DRV_GONE=xray; return 1; }
    kill -0 "$HPID" 2>/dev/null || { DRV_GONE=hev-socks5-tunnel; return 1; }
}
drv_stop() {
    # (one of them has usually exited already: a kill that finds nothing must not end the teardown under set -e)
    if [ -n "$HPID" ]; then kill "$HPID" 2>/dev/null || true; fi
    if [ -n "$XPID" ]; then kill "$XPID" 2>/dev/null || true; fi
    wait 2>/dev/null || true
    XPID=; HPID=; DRV_PIDS=
    return 0
}
# every 2 s while it runs: a pin mismatch Xray reported means a renewed certificate - pinned again and restarted
drv_poll() {
    [ -e "$RUN/pin-mismatch" ] && pin_managed || return 0
    rm -f "$RUN/pin-mismatch"
    new=$(fetch_pin) || { sleep 30; return 0; }
    [ "$new" = "$PIN" ] && { sleep 30; return 0; }
    save_pin "$new"
    echo "the server's certificate changed; pinned the new one and restarting" >&2
    return 1
}
