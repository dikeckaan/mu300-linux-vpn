# The sing-box driver of mu300-vpn (sourced by load_driver): a VLESS link, run by sing-box with its own TUN inbound
# (gvisor stack, see FINDINGS 26b). sing-box installs its policy routing itself (auto_route: rule prefs 9000-9010
# and table 2022, exactly what the core's routes_up does for the other drivers), so DRV_ROUTES=self; and it is
# exec'd in the foreground, as the service always ran it (DRV_FOREGROUND=1).
DRV_EXTRA=vpn
DRV_PKG=
DRV_ROUTES=self
DRV_FOREGROUND=1
TUN=sbtun

drv_engines() { printf '%s\n' "$BIN"; }
drv_engines_ok() { [ -x "$BIN" ]; }
# the link takes apart (parse_uri exits on a bad one, hence the subshell); the config itself is checked by sing-box
# in drv_gen
drv_check() {
    ( link_need; parse_uri )
}
drv_gen() { gen_singbox; }
drv_start() { exec "$BIN" run -c "$RUN/config.json"; }
drv_alive() { ip link show "$TUN" >/dev/null 2>&1; }
# exec'd: nothing of its own is left to stop here, and it removes its TUN when it exits
drv_stop() { :; }
drv_import() { link_import "$1"; }

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
    if [ "$IPV6" = 1 ]; then strategy=prefer_ipv4; addrs='"172.19.0.1/30","fdfe:dcba:9876::1/126"'
    else strategy=ipv4_only; addrs='"172.19.0.1/30"'; fi
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
