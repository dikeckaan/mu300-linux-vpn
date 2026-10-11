# The dae driver of mu300-vpn (sourced by load_driver): dae (github.com/daeuniverse/dae, the vpn-dae extra), an eBPF
# transparent proxy, for a raw dae config ($PDIR/config.dae), one share link ($PDIR/uri: vless, vmess, trojan, ss,
# hysteria2, tuic) or several ($PDIR/links, one per line, a subscription's). dae needs BTF and Linux 5.17 or newer
# (dae_kernel_ok in the core): the 5.4 vendor kernel cannot run it, and drv_runnable says so before anything starts.
#
# Routing is the core's (DRV_ROUTES=core), as for a TUN: drv_start makes a dummy interface, $TUN, and the core sends
# everything into it (rules 9000-9010, table 2022). dae binds its wan side to that interface (the device's own traffic,
# caught on its egress) and its lan side to the LAN (dae_lan), and every socket dae opens carries our mark
# (so_mark_from_dae), so rule 9000 sends dae's own connections to the uplink and the kill switch lets them out. When dae
# is not running, what is routed into the dummy ends there: closed, as with a TUN whose engine died. dae's wan side
# cannot be the uplink itself: the kill switch drops the device's packets in nft's output hook, before tc egress,
# where dae would take them.
#
# DNS: dae's DNS module answers what it catches; the device's own lookups are DNAT'd to REMOTE_DNS by the core
# (routes_up), which routes them into dae. Upstream mu300_remote is REMOTE_DNS through the proxy; the names of the
# nodes and subscriptions go to mu300_bootstrap (BOOTSTRAP_DNS) on dae's marked sockets. Nothing asks the carrier.
#
# A raw config is hostile input, as the JSON drivers' (dae runs as root): it is accepted only in a subset that
# dae_read parses exactly as dae does (single-quoted one-line strings, whole-line comments, no escapes), anything else
# refuses it, and the file dae gets is rebuilt from it: our global and dns sections, its node, group and routing.
# Links become config text only through dae_link (URL characters only, no certificate check turned off). A refusal
# names a rule, never a value or a line of the file. dae_written_ok checks the result once more.
DRV_EXTRA=vpn-dae
DRV_PKG=
DRV_KEYS='DAE_LAN DAE_POLICY'
DRV_ROUTES=core
TUN=mu300dae
DAEPID=; DRV_GONE=
DAE_SCHEMES='vless vmess trojan ss hysteria2 hy2 tuic'
DAE_ADDR=198.18.9.1/30

dae_bin() { if [ -n "${_dae:-}" ]; then printf '%s\n' "$_dae"; else engine_path dae vpn-dae; fi; }
# the geodata next to the binary (the extra's share/dae)
dae_assets() { _b=$(dae_bin); _b=${_b%/*}; printf '%s\n' "${_b%/*}/share/dae"; }
DAE_DIR=$RUN/dae

# ---- links into dae's config ----------------------------------------------------------------------------------
# A node is written as  mu300_N: 'LINK'  - so a link may hold nothing that ends or escapes a dae string or starts
# anything else: dae_link_ok allows only the characters of a URL (RFC 3986's unreserved, reserved and %), never a
# quote, a backslash, a blank, a brace or a line break, and the #fragment (the link's display name) is not written at
# all. The link must take apart (parse_link) and be one of the kinds dae speaks. And it must not turn the server's
# certificate check off: Xray and sing-box keep checking unless a link asks, and then Xray pins the certificate it
# saw; dae has no pin, so a link that asks for allowInsecure (insecure, allow_insecure, skip-cert-verify) is refused
# for dae, with what to do instead.
# dae_link LINK: the link as it is written (no fragment), or a reason on stderr and 1
dae_link() {
    case $1 in *'
'*|*"$(printf '\r')"*) echo "a link is one line" >&2; return 1 ;; esac
    _dl=${1%%#*}
    case $_dl in *://*) ;; *) echo "not a link" >&2; return 1 ;; esac
    case " $DAE_SCHEMES " in *" ${_dl%%://*} "*) ;; *) echo "not a link dae takes ($DAE_SCHEMES)" >&2; return 1 ;; esac
    _bad=$(printf '%s' "$_dl" | LC_ALL=C tr -d 'A-Za-z0-9._~:/?@!$&()*+,;=%\133\135-')
    [ -z "$_bad" ] || { echo "a link with a character a dae config cannot hold (a quote, a blank, a backslash, a brace ...)" >&2; return 1; }
    ( parse_link "$_dl" ) >/dev/null || return 1
    if dae_insecure "$_dl"; then
        echo "the link turns the server's certificate check off (allowInsecure), and dae cannot pin the certificate" \
            "as the xray driver does: use the link on xray (profile add xray ...), or one that verifies" >&2
        return 1
    fi
    printf '%s\n' "$_dl"
}
# dae_insecure LINK: the link asks for no certificate check (its query, or vmess's JSON)
dae_insecure() {
    _lo=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    case $_lo in
        *[?\&]allowinsecure=1*|*[?\&]allowinsecure=true*|*[?\&]insecure=1*|*[?\&]insecure=true*|\
        *[?\&]allow_insecure=1*|*[?\&]allow_insecure=true*|*[?\&]skip-cert-verify=1*|*[?\&]skip-cert-verify=true*)
            return 0 ;;
    esac
    case $1 in vmess://*)
        _vj=$(b64d "${1#vmess://}") || _vj=
        printf '%s' "$_vj" | jq -e '[to_entries[] | select(.key | ascii_downcase | . == "allowinsecure"
            or . == "insecure" or . == "skip-cert-verify" or . == "allow_insecure") | .value]
            | any(. == true or . == 1 or . == "1" or . == "true")' >/dev/null 2>&1 && return 0 ;;
    esac
    return 1
}

# ---- reading a raw dae config ----------------------------------------------------------------------------------
# A raw config is taken only in a subset this reader parses exactly as dae does, and anything outside it refuses the
# config (fail closed) rather than being cleaned up: a differential between this reader and dae's own parser is how
# something hidden here would reach dae.
# - No double quote, backslash or backquote anywhere (so no escape and no second kind of string); strings are single
#   quoted and end on their line.
# - A comment is a whole line ("#" its first character after blanks); a "#" anywhere else outside a string refuses.
# - Top level: node, group and routing are kept; global and dns are dropped and ours written (interfaces, ports, marks,
#   listeners and resolvers are ours); subscription refuses (dae would fetch nodes nobody checked: mu300-vpn
#   subscription add --type dae fetches and checks them); include and anything else refuse.
# - Every string in node is a link that dae_link accepts (URL characters, no certificate check turned off); every
#   string in group and routing holds only URL characters and blanks.
# MODE check prints what is wrong (exit 1) and notes; MODE gen prints the kept sections.
DAE_SECTIONS='node group routing'
dae_read() {
    json_size_ok "$2" || { [ "$1" != check ] || echo "the dae config is larger than 1 MiB"; return 1; }
    _cc=$(LC_ALL=C tr -d '\011\012\015\040-\176' < "$2" | wc -c | tr -d ' \t') || return 1
    if [ "$((_cc))" -ne 0 ]; then
        [ "$1" != check ] || echo "the dae config has a character outside printable ASCII (a control character, UTF-8 ...)"
        return 1
    fi
    if LC_ALL=C grep -q '["\\`]' "$2"; then
        [ "$1" != check ] || echo "the dae config has a double quote, a backslash or a backquote: write strings in single quotes"
        return 1
    fi
    LC_ALL=C awk -v mode="$1" -v keep="$DAE_SECTIONS" -v schemes="$DAE_SCHEMES" '
    function bad(m) { if (mode == "check" && !(m in said)) { said[m] = 1; print "the dae config " m }; err = 1 }
    function urlchars(s, extra,    t) { t = s; gsub(/[A-Za-z0-9._~:\/?@!$&()*+,;=%-]/, "", t); gsub(/[][]/, "", t)
        if (extra) gsub(/[ \t]/, "", t); return t == "" }
    function insecure(s,    lo) { lo = tolower(s)
        return lo ~ /[?&](allowinsecure|insecure|allow_insecure|skip-cert-verify)=(1|true)/ }
    # str(s): a string of the section cur (without its quotes)
    function str(s,    sc) {
        if (cur == "node") {
            sc = s; sub(/:\/\/.*/, "", sc)
            if (!(sc in scheme)) { bad("has a node that is not a link dae takes here (" schemes ")"); return }
            sub(/#.*/, "", s)
            if (!urlchars(s, 0)) bad("has a node link with a character a dae config cannot hold safely (a blank, a brace, a chain ->)")
            else if (insecure(s)) bad("has a node link that turns the certificate check off (allowInsecure): dae cannot pin the certificate; use it on xray")
        } else if (!urlchars(s, 1)) bad("has a string in " cur " with a character this reader does not take")
    }
    BEGIN { n = split(keep, a, " "); for (i = 1; i <= n; i++) ok[a[i]] = 1
            k = split(schemes, b, " "); for (i = 1; i <= k; i++) scheme[b[i]] = 1
            depth = 0; cur = "" }
    { sub(/\r$/, "")
      line = $0
      if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) next
      out = ""; q = 0; word = ""; s = ""
      for (i = 1; i <= length(line); i++) {
          c = substr(line, i, 1)
          if (q) { if (c == "\047") { q = 0; out = out c; if (cur != "-" && cur != "global" && cur != "dns") str(s) } else { s = s c; out = out c }; continue }
          if (c == "#") { bad("has a # after text on a line (comments are whole lines here)"); next }
          if (c == "\047") {
              if (depth == 0) { bad("has text at the top level that is not a section"); next }
              q = 1; s = ""; out = out c; continue
          }
          if (depth == 0) {
              if (c == "{") {
                  name = word; word = ""; wordend = 0
                  if (name == "") bad("has a block without a name at the top level")
                  else if (name == "include") bad("has an include (the config must be one file)")
                  else if (name == "subscription") bad("has a subscription section: dae would fetch nodes nobody checked (mu300-vpn subscription add NAME URL --type dae does it checked)")
                  else if (name == "global" || name == "dns") { cur = name; noted[name] = 1 }
                  else if (!(name in ok)) bad("has a top-level section that is not node, group or routing (global and dns are ours)")
                  else if (name in seen) bad("has the section " name " twice")
                  else { seen[name] = 1; cur = name }
                  if (cur == "" || name != cur) cur = "-"
                  depth = 1; buf[cur] = buf[cur] name " {\n"; continue
              }
              if (c == "}") { bad("has a } without its {"); continue }
              if (c ~ /[A-Za-z0-9_]/) { if (wordend) bad("has text at the top level that is not a section"); word = word c; continue }
              if (c ~ /[ \t]/) { if (word != "") wordend = 1; continue }
              bad("has text at the top level that is not a section"); continue
          }
          if (c == "{") depth++
          else if (c == "}") {
              depth--
              if (depth == 0) { keepline(out); buf[cur] = buf[cur] "}\n"; out = ""; cur = ""; continue }
          }
          out = out c
      }
      if (q) bad("has a quoted string that is not closed on its line")
      if (depth == 0) { if (word != "") wordend = 1; next }
      keepline(out)
    }
    function keepline(l) {
      if (cur == "" || cur == "-" || cur == "global" || cur == "dns" || l !~ /[^ \t]/) return
      buf[cur] = buf[cur] l "\n"
    }
    END {
        if (depth != 0) bad("has a { without its }")
        if (word != "") bad("has text at the top level that is not a section")
        if (!("node" in seen)) bad("has no node section")
        if (!("routing" in seen)) bad("has no routing section")
        if (err) exit 1
        if (mode == "gen") { for (i = 1; i <= n; i++) if (a[i] in seen) printf "%s", buf[a[i]]; exit 0 }
        if ("global" in noted) print "note: the config'"'"'s global section is replaced by this driver'"'"'s (interfaces, ports and marks are ours)"
        if ("dns" in noted) print "note: the config'"'"'s dns section is replaced by this driver'"'"'s (REMOTE_DNS through the proxy)"
    }' "$2"
}


# dae_lan: the LAN interfaces, comma-separated - DAE_LAN of the profile, or br-lan, or the usb0/wlan0 that are neither a
# bridge's port nor the uplink
dae_lan() {
    _l=; kv_var _l "$PDIR/meta" DAE_LAN 2>/dev/null || _l=
    if [ -n "$_l" ]; then printf '%s\n' "$_l"; return 0; fi
    if ip link show br-lan >/dev/null 2>&1; then echo br-lan; return 0; fi
    _up=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
    _o=
    for _i in usb0 wlan0; do
        ip link show "$_i" >/dev/null 2>&1 || continue
        ip -o link show "$_i" 2>/dev/null | grep -q ' master ' && continue
        [ "$_i" != "$_up" ] || continue
        _o=${_o:+$_o,}$_i
    done
    printf '%s\n' "$_o"
}
# a DNS server as dae writes one: host:port, [v6]:port
dae_hostport() { case $1 in *:*) printf '[%s]:53' "$1" ;; *) printf '%s:53' "$1" ;; esac; }

# dae_global: our global section (the only one dae gets)
dae_global() {
    _lan=$(dae_lan)
    cat <<EOF
global {
    tproxy_port: 12345
    tproxy_port_protect: true
    pprof_port: 0
    so_mark_from_dae: $((MARK))
    log_level: warn
    disable_waiting_network: true
EOF
    [ -z "$_lan" ] || printf '    lan_interface: %s\n' "$_lan"
    cat <<EOF
    wan_interface: $TUN
    auto_config_kernel_parameter: true
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'
    udp_check_dns: 'dns.google:53,8.8.8.8'
    check_interval: 30s
    check_tolerance: 50ms
    dial_mode: domain
    allow_insecure: false
    bootstrap_resolver: '$(dae_hostport "$BOOTSTRAP_DNS")'
    fallback_resolver: '$(dae_hostport "$BOOTSTRAP_DNS")'
}
EOF
}
dae_dns() {
    case $REMOTE_DNS in *:*) _r="[$REMOTE_DNS]" ;; *) _r=$REMOTE_DNS ;; esac
    case $BOOTSTRAP_DNS in *:*) _b="[$BOOTSTRAP_DNS]" ;; *) _b=$BOOTSTRAP_DNS ;; esac
    cat <<EOF
dns {
    upstream {
        mu300_remote: 'tcp+udp://$_r:53'
        mu300_bootstrap: 'udp://$_b:53'
    }
    routing {
        request {
            subnode(name_regex: '.') -> mu300_bootstrap
            node(name_regex: '.') -> mu300_bootstrap
            fallback: mu300_remote
        }
    }
}
EOF
}
# dae_links_conf FILE: node, group and routing for the links in FILE (one per line)
dae_links_conf() {
    _pol=; kv_var _pol "$PDIR/meta" DAE_POLICY
    _n=0
    echo 'node {'
    while IFS= read -r _l || [ -n "$_l" ]; do
        [ -n "$_l" ] || continue
        _n=$((_n + 1))
        # only what dae_link lets through: URL characters, no quote, no fragment
        _s=$(dae_link "$_l") || return 1
        printf "    mu300_%d: '%s'\n" "$_n" "$_s"
    done < "$1"
    echo '}'
    [ "$_n" -gt 0 ] || { echo "no link" >&2; return 1; }
    if [ -z "$_pol" ]; then if [ "$_n" = 1 ]; then _pol='fixed(0)'; else _pol=min_moving_avg; fi; fi
    cat <<EOF
group {
    proxy {
        policy: $_pol
    }
}
routing {
    dip(224.0.0.0/3, 'ff00::/8') -> direct
    dip(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 127.0.0.0/8, 'fc00::/7', 'fe80::/10') -> direct
    fallback: proxy
}
EOF
}
# dae_written_ok FILE: the guard behind the rebuild, on the file dae gets - one global and one dns section, both ours
# (our mark, our wan interface, pprof 0, the certificate check on), nothing but printable ASCII, no double quote,
# backslash or backquote, no include, subscription or bind anywhere, no link that turns the certificate check off,
# every top-level line one of our sections
dae_written_ok() {
    [ "$(grep -c '^global {$' "$1")" = 1 ] && [ "$(grep -c '^dns {$' "$1")" = 1 ] || return 1
    grep -qx "    so_mark_from_dae: $((MARK))" "$1" && grep -qx "    wan_interface: $TUN" "$1" &&
        grep -qx '    pprof_port: 0' "$1" && grep -qx '    allow_insecure: false' "$1" || return 1
    [ -z "$(LC_ALL=C tr -d '\012\040-\176' < "$1")" ] || return 1
    ! LC_ALL=C grep -q '["\\`]' "$1" || return 1
    ! grep -Eqi '(^|[^a-z_])(include|subscription|bind)[[:space:]]*[:{]' "$1" || return 1
    ! grep -Eqi '[?&](allowinsecure|insecure|allow_insecure|skip-cert-verify)=(1|true)' "$1" || return 1
    ! grep -Ev '^(global|node|group|routing|dns) \{$' "$1" | grep -q '^[^ }]'
}
# dae_rebuild OUT: the profile's config, as dae gets it, into OUT (0600)
dae_rebuild() {
    _out=$1; rm -f "$_out"
    { ip4_ok "$REMOTE_DNS" || ip6_ok "$REMOTE_DNS"; } && { ip4_ok "$BOOTSTRAP_DNS" || ip6_ok "$BOOTSTRAP_DNS"; } ||
        { echo "REMOTE_DNS and BOOTSTRAP_DNS must be IP addresses" >&2; return 1; }
    if [ -r "$PDIR/config.dae" ]; then
        dae_read check "$PDIR/config.dae" >&2 || return 1
        if ! ( umask 077; { dae_global; dae_dns; dae_read gen "$PDIR/config.dae"; } > "$_out.r" ); then
            rm -f "$_out.r"; echo "cannot write $_out" >&2; return 1
        fi
    elif [ -r "$PDIR/uri" ] || [ -r "$PDIR/links" ]; then
        if [ -r "$PDIR/links" ]; then _src=$PDIR/links; else _src=$PDIR/uri; fi
        if ! ( umask 077; { dae_global; dae_dns; dae_links_conf "$_src"; } > "$_out.r" ); then
            rm -f "$_out.r"; echo "cannot write $_out" >&2; return 1
        fi
    else
        echo "the profile has no config.dae, uri or links" >&2; return 1
    fi
    if ! dae_written_ok "$_out.r"; then
        rm -f "$_out.r"; echo "the rebuilt dae config is not what this driver writes: refused" >&2; return 1
    fi
    mv "$_out.r" "$_out" && chmod 600 "$_out" && return 0
    rm -f "$_out.r" "$_out"; echo "cannot write $_out" >&2; return 1
}

# ---- the contract ---------------------------------------------------------------------------------------------
drv_engines() { dae_bin; }
drv_engines_ok() { [ -x "$(dae_bin)" ]; }
drv_runnable() { _why=$(dae_kernel_ok) || { echo "$_why" >&2; return 1; }; }
drv_check() {
    [ -n "${PDIR:-}" ] || { echo "no profile" >&2; return 1; }
    if [ -r "$PDIR/links" ]; then
        while IFS= read -r _l || [ -n "$_l" ]; do [ -z "$_l" ] || dae_link "$_l" >/dev/null || return 1; done < "$PDIR/links"
    elif [ -r "$PDIR/uri" ]; then
        dae_link "$(head -n1 "$PDIR/uri")" >/dev/null || return 1
    fi
    _chk=$PDIR/.check.$$
    dae_rebuild "$_chk" || { rm -f "$_chk"; return 1; }
    rm -f "$_chk"; return 0
}
drv_gen() {
    drv_runnable || exit 1
    ( umask 077; mkdir -p "$DAE_DIR" ) && chmod 700 "$RUN" "$DAE_DIR" || { echo "cannot create $DAE_DIR" >&2; exit 1; }
    rm -f "$DAE_DIR/config.dae" "$RUN/server-ip"
    dae_rebuild "$DAE_DIR/config.dae" || exit 1
    # dae marks its own sockets and looks the nodes up itself: no address to keep off the routing
    : > "$RUN/server-ip"
    # dae checks the rebuilt file (no BPF, no network); its own words are not shown, they can quote the config
    DAE_LOCATION_ASSET=$(dae_assets) "$(dae_bin)" validate -c "$DAE_DIR/config.dae" >/dev/null 2>&1 ||
        { echo "dae rejects the rebuilt config: $(dae_bin) validate -c $DAE_DIR/config.dae says why" >&2; exit 1; }
    echo "dae config OK ($DAE_DIR/config.dae)"
}
# the bpf filesystem dae pins its maps in
dae_bpffs() {
    grep -q ' /sys/fs/bpf bpf ' /proc/mounts 2>/dev/null && return 0
    mkdir -p /sys/fs/bpf 2>/dev/null; mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
}
# the core runs this without set -e: every failing step returns 1 itself (and undoes what it made)
drv_start() {
    DAEPID=; DRV_PIDS=
    ip link del "$TUN" 2>/dev/null
    ip link add "$TUN" type dummy || { echo "cannot create $TUN (a dummy interface)" >&2; return 1; }
    ip addr add "$DAE_ADDR" dev "$TUN" && ip link set "$TUN" up ||
        { ip link del "$TUN" 2>/dev/null; echo "cannot bring $TUN up" >&2; return 1; }
    dae_lan > "$DAE_DIR/lan" 2>/dev/null || :
    dae_bpffs
    DAE_LOCATION_ASSET=$(dae_assets) "$(dae_bin)" run --disable-timestamp -c "$DAE_DIR/config.dae" < /dev/null &
    DAEPID=$!; DRV_PIDS=$DAEPID
    # up when its program sits on the dummy's egress (tc), or after 8 s alive where there is no tc to ask
    _n=0
    while :; do
        if ! kill -0 "$DAEPID" 2>/dev/null; then
            wait "$DAEPID" 2>/dev/null || true
            echo "dae exited during start" >&2; DAEPID=; DRV_PIDS=; dae_cleanup; return 1
        fi
        if command -v tc >/dev/null 2>&1; then
            tc filter show dev "$TUN" egress 2>/dev/null | grep -q bpf && break
        elif [ "$_n" -ge 8 ]; then break; fi
        _n=$((_n + 1))
        [ "$_n" -lt 40 ] || { echo "dae did not attach to $TUN within 40 s" >&2; drv_stop; return 1; }
        sleep 1
    done
    echo "dae up on $TUN and $(cat "$DAE_DIR/lan" 2>/dev/null || echo 'no LAN interface') (dae $DAEPID)"
}
drv_alive() {
    [ -n "$DAEPID" ] && kill -0 "$DAEPID" 2>/dev/null || { DRV_GONE=dae; return 1; }
    ip link show "$TUN" >/dev/null 2>&1 || { DRV_GONE=dae; return 1; }
}
# dae_cleanup: what a dae that did not exit cleanly can leave - its programs on the LAN interfaces (the LAN's packets
# would go to a tproxy port nobody listens on), the dummy, the runtime config (it holds the credentials)
dae_cleanup() {
    if command -v tc >/dev/null 2>&1; then
        for _i in $(tr ',' ' ' < "$DAE_DIR/lan" 2>/dev/null); do
            case $_i in *[!A-Za-z0-9_.-]*) continue ;; esac
            for _d in ingress egress; do
                tc filter show dev "$_i" "$_d" 2>/dev/null | grep -q 'tproxy' && tc filter del dev "$_i" "$_d" 2>/dev/null
            done
        done
    fi
    ip link del "$TUN" 2>/dev/null || true
    rm -f "$DAE_DIR/config.dae" "$DAE_DIR/lan"
    return 0
}
# TERM lets dae take its programs off the interfaces; KILL after 10 s for one that does not
drv_stop() {
    if [ -n "$DAEPID" ]; then
        kill "$DAEPID" 2>/dev/null || true
        _n=0
        while kill -0 "$DAEPID" 2>/dev/null && [ "$_n" -lt 10 ]; do sleep 1; _n=$((_n + 1)); done
        if kill -0 "$DAEPID" 2>/dev/null; then kill -9 "$DAEPID" 2>/dev/null || true; fi
        wait "$DAEPID" 2>/dev/null || true
    fi
    DAEPID=; DRV_PIDS=
    dae_cleanup
}
# the number of nodes and the LAN interfaces: nothing of a node itself
drv_status() {
    [ -r "$DAE_DIR/config.dae" ] || return 0
    awk '/^node \{$/ {n = 1; next} /^\}/ {n = 0} n && /[^ \t]/ {c++} END {if (c) print "nodes: " c}' "$DAE_DIR/config.dae"
    [ ! -s "$DAE_DIR/lan" ] || echo "lan: $(cat "$DAE_DIR/lan")"
}
# a raw dae config, one link, or a file of links (one per line)
drv_import() {
    [ -n "${PDIR:-}" ] && [ -d "$PDIR" ] || { echo "no profile to import into" >&2; return 1; }
    if [ ! -f "$1" ]; then
        dae_link "$1" >/dev/null || return 1
        link_import "$1" "$DAE_SCHEMES"; return
    fi
    json_size_ok "$1" || { echo "the dae config is larger than 1 MiB" >&2; return 1; }
    if grep -Eq '^[[:space:]]*(global|node|subscription|routing|group|dns|include)[[:space:]]*\{' "$1"; then
        dae_read check "$1" >&2 || return 1
        ( umask 077; cat "$1" > "$PDIR/config.dae.new.$$" ) && mv "$PDIR/config.dae.new.$$" "$PDIR/config.dae" && return 0
        rm -f "$PDIR/config.dae.new.$$"; return 1
    fi
    # links, one per line (CRs and blank lines dropped)
    _t=$PDIR/links.new.$$
    ( umask 077; tr -d '\r' < "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d' > "$_t" ) || { rm -f "$_t"; return 1; }
    [ -s "$_t" ] || { rm -f "$_t"; echo "neither a dae config nor links" >&2; return 1; }
    while IFS= read -r _l; do
        dae_link "$_l" >/dev/null || { rm -f "$_t"; return 1; }
    done < "$_t"
    if [ "$(wc -l < "$_t")" -eq 1 ]; then mv "$_t" "$PDIR/uri" && return 0; fi
    mv "$_t" "$PDIR/links" && return 0
    rm -f "$_t"; return 1
}
# profile set ID DAE_LAN IF[,IF...] | DAE_POLICY POLICY
drv_set() {
    case $1 in
        DAE_LAN) case $2 in *[!A-Za-z0-9_.,-]*|,*|*,|*,,*) echo "DAE_LAN is interface names, comma-separated" >&2; return 2 ;; esac ;;
        DAE_POLICY) case $2 in ''|min_moving_avg|min_avg10|min|random|'fixed(0)') ;;
                        *) echo "DAE_POLICY is min_moving_avg, min_avg10, min, random or fixed(0)" >&2; return 2 ;; esac ;;
        *) return 2 ;;
    esac
    drv_set_default "$1" "$2"
}
