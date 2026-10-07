# The sing-box driver of mu300-vpn (sourced by load_driver): a VLESS link ($PDIR/uri) or a raw sing-box config
# ($PDIR/config.json), run by sing-box with its own TUN inbound (gvisor stack, see FINDINGS 26b). sing-box installs
# its policy routing itself (auto_route: rule prefs 9000-9010 and table 2022, exactly what the core's routes_up does
# for the other drivers), so DRV_ROUTES=self for both forms; and it is exec'd in the foreground, as the service always
# ran it (DRV_FOREGROUND=1).
DRV_EXTRA=vpn
DRV_PKG=
# (sing-box has no certificate pin: TLS_PIN_SHA256 is the xray driver's)
DRV_KEYS=UPSTREAM_HTTP_PROXY
DRV_ROUTES=self
DRV_FOREGROUND=1
TUN=sbtun

drv_engines() { printf '%s\n' "$BIN"; }
drv_engines_ok() { [ -x "$BIN" ]; }
# the link takes apart (parse_uri exits on a bad one, hence the subshell), or the raw config names an outbound type;
# the config itself is checked by sing-box in drv_gen
drv_check() {
    if singbox_raw; then
        json_check "$SING_BOX_JSON_TEST" 'a sing-box config with outbounds' && singbox_json_keys_ok; return
    fi
    ( link_need; parse_uri )
}
drv_gen() { if singbox_raw; then gen_singbox_json; else gen_singbox; fi; }
drv_start() { exec "$BIN" run -c "$RUN/config.json"; }
drv_alive() { ip link show "$TUN" >/dev/null 2>&1; }
# exec'd: nothing of its own is left to stop here, and it removes its TUN when it exits
drv_stop() { :; }
drv_import() {
    if is_json "$1"; then json_import "$1" "$SING_BOX_JSON_TEST" 'a sing-box config (no outbound with a type)'
    else link_import "$1"; fi
}
drv_set() { link_opt_set "$1" "$2"; }

outbound_json() {
    printf '{"type":"vless","tag":"proxy","server":%s,"server_port":%s,"uuid":%s' "$(json_str "$HOST")" "$PORT" "$(json_str "$UUID")"
    [ -n "$FLOW" ] && printf ',"flow":%s' "$(json_str "$FLOW")"
    printf ',"packet_encoding":"xudp","domain_resolver":"bootstrap"'
    [ -n "$UPSTREAM_HTTP_PROXY" ] && printf ',"detour":"upstream"'
    case "$SECURITY" in
        tls|reality)
            printf ',"tls":{"enabled":true,"server_name":%s' "$(json_str "${SNI:-$HOST}")"
            case "$INSECURE" in 1|true) printf ',"insecure":true' ;; esac
            # h3 (QUIC) does not apply to VLESS over TCP
            ALPN=$(printf '%s' "$ALPN" | awk -F, '{n = 0; for (i = 1; i <= NF; i++) if ($i != "h3") printf "%s%s", (n++ ? "," : ""), $i}')
            [ -n "$ALPN" ] && printf ',"alpn":%s' "$(json_list "$ALPN")"
            [ -n "$FP" ] && printf ',"utls":{"enabled":true,"fingerprint":%s}' "$(json_str "$FP")"
            [ "$SECURITY" = reality ] && printf ',"reality":{"enabled":true,"public_key":%s,"short_id":%s}' "$(json_str "$PBK")" "$(json_str "$SID")"
            printf '}' ;;
    esac
    case "$TYPE" in
        ws) printf ',"transport":{"type":"ws","path":%s' "$(json_str "${WSPATH:-/}")"; [ -n "$WSHOST" ] && printf ',"headers":{"Host":%s}' "$(json_str "$WSHOST")"; printf '}' ;;
        grpc) printf ',"transport":{"type":"grpc","service_name":%s}' "$(json_str "$SVC")" ;;
        httpupgrade) printf ',"transport":{"type":"httpupgrade","path":%s' "$(json_str "${WSPATH:-/}")"; [ -n "$WSHOST" ] && printf ',"host":%s' "$(json_str "$WSHOST")"; printf '}' ;;
        tcp|raw) ;;
        *) echo "transport type '$TYPE' is not supported by this helper" >&2; exit 1 ;;
    esac
    printf '}'
}

# The TUN's addresses: IPv6 through the tunnel only when the server side has it. Otherwise programs prefer the
# (dead) IPv6 route and every connection to a dual-stack host fails first.
singbox_addrs() {
    if [ "$IPV6" = 1 ]; then printf '"172.19.0.1/30","fdfe:dcba:9876::1/126"'; else printf '"172.19.0.1/30"'; fi
}

gen_singbox() {
    link_need
    parse_uri
    mkdir -p "$RUN"; chmod 700 "$RUN"
    excl=$(json_list "$LAN_CIDRS")
    {
    printf '{"log":{"level":"warn","timestamp":false},\n'
    printf '"dns":{"servers":[{"type":"tcp","tag":"remote","server":%s,"detour":"proxy"},' "$(json_str "$REMOTE_DNS")"
    # the VPN server name is looked up via BOOTSTRAP_DNS (directly, or over TCP through UPSTREAM_HTTP_PROXY)
    if [ -n "$UPSTREAM_HTTP_PROXY" ]; then
        printf '{"type":"tcp","tag":"bootstrap","server":%s,"detour":"upstream"}],' "$(json_str "$BOOTSTRAP_DNS")"
    else
        printf '{"type":"udp","tag":"bootstrap","server":%s}],' "$(json_str "$BOOTSTRAP_DNS")"
    fi
    # IPv6 through the tunnel only when the server side has it: otherwise programs prefer the (dead) IPv6 route and
    # every connection to a dual-stack host fails first, so DNS answers only A records and the TUN gets no IPv6 address
    if [ "$IPV6" = 1 ]; then strategy=prefer_ipv4; else strategy=ipv4_only; fi
    addrs=$(singbox_addrs)
    printf '"final":"remote","strategy":"%s"},\n' "$strategy"
    # "stack":"gvisor", not the default system stack. On this device's 5.4 vendor kernel the system stack
    # takes the connection off the tun and then drops it: sing-box logs one "router: pre-match => sniff" and
    # nothing more, the client gets an RST ("Connection refused", or uclient-fetch's "Operation not permitted")
    # and not a single packet reaches an outbound. DNS still worked, which is what made it look like a routing
    # or firewall problem for so long. The warning it prints on startup is the same story from the other end:
    # "inbound/tun[tun-in]: enable offload: set udp offload: TUNSETOFFLOAD: invalid argument" - the kernel does
    # not have what that stack expects. gvisor carries its own TCP/IP and does not care.
    printf '"inbounds":[{"type":"tun","tag":"tun-in","stack":"gvisor","interface_name":"%s","address":[%s],"mtu":1400,' "$TUN" "$addrs"
    printf '"auto_route":true,"strict_route":true,"route_exclude_address":%s}],\n' "$excl"
    printf '"outbounds":['; outbound_json
    [ -n "$UPSTREAM_HTTP_PROXY" ] && printf ',{"type":"http","tag":"upstream","server":%s,"server_port":%s}' "$(json_str "${UPSTREAM_HTTP_PROXY%:*}")" "${UPSTREAM_HTTP_PROXY##*:}"
    printf ',{"type":"direct","tag":"direct"}],\n'
    # A LAN client's packet to a private address is refused rather than sent "direct": direct leaves outside the
    # tunnel, onto the uplink's own network (the Wi-Fi client's home LAN; wifi-client keeps LAN clients off it
    # when the VPN is off too). The LAN itself never comes in here (route_exclude_address).
    printf '"route":{"rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"},{"source_ip_cidr":%s,"ip_is_private":true,"action":"reject"},{"ip_is_private":true,"outbound":"direct"}],' "$excl"
    printf '"final":"proxy","auto_detect_interface":true,"default_mark":%d,"default_domain_resolver":"bootstrap"}}\n' "$MARK"
    } > "$RUN/config.json"
    chmod 600 "$RUN/config.json"
    "$BIN" check -c "$RUN/config.json"
}

# ---- a raw sing-box config ------------------------------------------------------------------------------------
# A config from a panel keeps its outbounds, DNS and route rules. What the device needs is put over it: its inbounds
# are replaced by our TUN, as gen_singbox writes it (a panel's mixed or socks inbound on 0.0.0.0 would listen on the
# LAN and the uplink), every connection sing-box makes carries the mark the kill switch lets out (default_mark), it
# leaves on whichever uplink is up (auto_detect_interface), and a UDP server at BOOTSTRAP_DNS resolves the server
# names, unless the config names a default_domain_resolver of its own. sing-box looks them up itself, on its marked
# socket, so no resolve window is needed. A mu300-bootstrap server the config already has (one rewritten before,
# copied from $RUN) is replaced, not doubled: sing-box refuses two servers with one tag.
#
# What a raw config may contain is a list (the spec's Security section), not whatever sing-box accepts: sing-box adds
# features that listen (services such as ssm-api and derp, the clash and v2ray APIs, the debug server) faster than a
# denylist would follow. Top level: dns, outbounds and route are the config's; log is ours (warn, stdout only: an
# output path from the config would be a file written as root); inbounds and experimental are dropped (experimental
# holds the control APIs and a cache file path); endpoints are allowed when every one is WireGuard, whose listen_port
# is dropped so it dials out from a port the kernel picks. A Tailscale endpoint joins a tailnet whose members can
# reach the device, so it refuses the config, as does any other top-level key. In route: rules, rule_set, final and
# default_domain_resolver are the config's, default_mark and auto_detect_interface ours, default_interface is
# dropped (the uplink is auto-detected), and any other key refuses the config.
SING_BOX_JSON_TEST='.outbounds[0].type | type == "string"'
SING_BOX_JSON_KEYS='dns outbounds route endpoints log inbounds experimental'
SING_BOX_ROUTE_KEYS='rules rule_set final default_domain_resolver default_mark auto_detect_interface default_interface'
singbox_raw() { [ -n "${PDIR:-}" ] && [ -r "$PDIR/config.json" ]; }
singbox_json_keys_ok() {
    json_refuse_keys "$PDIR/config.json" . "$SING_BOX_JSON_KEYS" "the profile's sing-box config" || return 1
    json_refuse_keys "$PDIR/config.json" '.route' "$SING_BOX_ROUTE_KEYS" "the profile's sing-box route" || return 1
    jq -e '(.endpoints // []) | type == "array" and all(type == "object" and .type == "wireguard")' \
        "$PDIR/config.json" >/dev/null 2>&1 ||
        { echo "the profile's sing-box config has an endpoint that is not WireGuard" >&2; return 1; }
}
gen_singbox_json() {
    command -v jq >/dev/null 2>&1 || { echo "a raw sing-box config needs jq" >&2; exit 1; }
    singbox_json_keys_ok || exit 1
    mkdir -p "$RUN"; chmod 700 "$RUN"
    ( umask 077; jq --arg tun "$TUN" --argjson addrs "[$(singbox_addrs)]" --argjson excl "$(json_list "$LAN_CIDRS")" \
        --argjson mark "$((MARK))" --arg boot "$BOOTSTRAP_DNS" '
        {dns, outbounds, route, endpoints} | with_entries(select(.value != null))
        | .log = {"level":"warn","timestamp":false}
        | .inbounds = [{"type":"tun","tag":"tun-in","stack":"gvisor","interface_name":$tun,"address":$addrs,"mtu":1400,
                        "auto_route":true,"strict_route":true,"route_exclude_address":$excl}]
        | if .endpoints then .endpoints |= map(del(.listen_port)) else . end
        | .route = ((.route // {}) | del(.default_interface))
        | .route.default_mark = $mark | .route.auto_detect_interface = true
        | .dns.servers = ((.dns.servers // []) | map(select(type != "object" or .tag != "mu300-bootstrap"))
                          | . + [{"type":"udp","tag":"mu300-bootstrap","server":$boot}])
        | .route.default_domain_resolver = (.route.default_domain_resolver // "mu300-bootstrap")' \
        "$PDIR/config.json" > "$RUN/config.json" ) ||
        { rm -f "$RUN/config.json"; echo "cannot rewrite the profile's sing-box config" >&2; exit 1; }
    chmod 600 "$RUN/config.json"
    json_listens_loopback_only "$RUN/config.json" ||
        { rm -f "$RUN/config.json"; echo "the rewritten sing-box config listens beyond 127.0.0.1" >&2; exit 1; }
    "$BIN" check -c "$RUN/config.json"
}
