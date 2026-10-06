# The xray driver of mu300-vpn (sourced by load_driver): a VLESS link, run by Xray behind hev-socks5-tunnel.
DRV_EXTRA=vpn
DRV_PKG=
TUN=xtun
XPID=; HPID=; DRV_GONE=

# ---- xray engine ----------------------------------------------------------------------------------------------
# Xray does VLESS and nothing else here; hev-socks5-tunnel owns the TUN and hands every TCP/UDP flow to Xray's
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

gen_xray() {
    link_need
    parse_uri
    XMODE=$(param mode); SPX=$(urldecode "$(param spx)"); ENC=$(urldecode "$(param encryption)")
    # pcs/vcn are the share-link spellings of pinnedPeerCertSha256/verifyPeerCertByName; TLS_PIN_SHA256 in
    # vpn.conf is for links written before those existed
    PIN=${TLS_PIN_SHA256:-$(urldecode "$(param pcs)")}; VCN=$(urldecode "$(param vcn)")
    # the name is looked up now and Xray is given the address, so it never has to resolve anything itself - the
    # resolver it would use sits behind the tunnel it is trying to build. The name stays as the SNI. Behind the kill
    # switch the lookup goes through the resolve window (vpn_resolve).
    SERVER_IP=$(vpn_resolve "$HOST")
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
            "certificate could not be fetched to pin instead. Set TLS_PIN_SHA256 in $CONF, or ENGINE=sing-box." >&2; exit 1; }
        save_pin "$PIN"
        echo "pinned the server's current certificate ($PIN)"
    fi
    mkdir -p "$RUN"; chmod 700 "$RUN"
    {
    # info, not warning: a failed outbound - including a pin mismatch - is only reported at info. drv_start's
    # reader scans every line and passes on only warnings and worse, so the system log does not fill up.
    printf '{"log":{"loglevel":"info","access":"none"},\n'
    printf '"inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],\n' "$SOCKS_PORT"
    printf '"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":%s,"port":%s,"users":[{"id":%s,"encryption":%s' \
        "$(json_str "$SERVER_IP")" "$PORT" "$(json_str "$UUID")" "$(json_str "${ENC:-none}")"
    [ -n "$FLOW" ] && printf ',"flow":%s' "$(json_str "$FLOW")"
    printf '}]}]},'; xray_stream_json; printf '},\n'
    printf '{"tag":"direct","protocol":"freedom","streamSettings":{"sockopt":{"mark":%d}}}]}\n' "$((MARK))"
    } > "$RUN/xray.json"
    chmod 600 "$RUN/xray.json"
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
    printf '%s\n' "$SERVER_IP" > "$RUN/server-ip"
    "$XRAY" run -test -c "$RUN/xray.json" >/dev/null || { "$XRAY" run -test -c "$RUN/xray.json" >&2; exit 1; }
    echo "xray config OK ($RUN/xray.json), server $HOST -> $SERVER_IP"
}

drv_engines() { printf '%s\n' "$XRAY" "$HEV"; }
drv_engines_ok() {
    [ -x "$XRAY" ] && [ -x "$HEV" ] && return 0
    # an image built before the xray engine existed has only sing-box: a VLESS link keeps working with what is
    # there (the core runs it on the sing-box driver)
    case ${PURI:-${VLESS_URI:-}} in vless://*) [ -x "$BIN" ] ;; *) return 1 ;; esac
}
drv_check() { ( link_need; parse_uri ); }
drv_gen() { gen_xray; }
drv_import() { link_import "$1"; }

# Two processes and the routing between them, torn down together: if either dies the service exits, the routes
# go with it and procd starts the whole thing again. Leaving rules behind with nothing at the other end is what
# made sing-box's crashes look like a dead modem (routing_cleanup), so every way out of the core's run goes through
# drv_stop and routes_down.
drv_start() {
    # Xray's output goes through a reader that passes it on and notes a pin mismatch, so a renewed server
    # certificate is noticed without polling the server
    rm -f "$RUN/pin-mismatch" "$RUN/xray.out"; mkfifo "$RUN/xray.out"
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
    ip link set "$TUN" up
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
