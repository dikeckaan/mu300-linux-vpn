# mu300-vpn's link parsing and JSON helpers, sourced by mu300-vpn when it loads (tests call parse_uri and json_str
# straight after sourcing it). Nothing here runs anything: it only takes a link apart and writes JSON strings.

# json_str VALUE : JSON string literal
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
# json_list "a,b,c" : JSON array of strings
json_list() { printf '%s' "$1" | awk -F, '{printf "["; for (i = 1; i <= NF; i++) { gsub(/"/, "\\\"", $i); printf "%s\"%s\"", (i > 1 ? "," : ""), $i } printf "]"}'; }
hex2dec() { printf '%d' "0x$1"; }
# busybox awk has no hex string conversion: decode %XX with printf instead
urldecode() {
    rest=$1; out=
    while :; do
        case "$rest" in
            *%[0-9A-Fa-f][0-9A-Fa-f]*)
                pre=${rest%%%*}; tail=${rest#*%}; hh=$(printf '%s' "$tail" | cut -c1-2); rest=$(printf '%s' "$tail" | cut -c3-)
                out="$out$pre$(printf "\\$(printf '%03o' "$(hex2dec "$hh")")")" ;;
            *) out="$out$rest"; break ;;
        esac
    done
    printf '%s' "$out"
}
param() { printf '%s' "$QUERY" | tr '&' '\n' | sed -n "s/^$1=//p" | head -n1; }

# b64d TEXT: TEXT base64-decoded, standard or URL-safe, with or without its padding (share links use all four).
# jq does the decoding because busybox's base64 applet is optional in OpenWrt's builds, and jq is in every image.
b64d() {
    command -v jq >/dev/null 2>&1 || { echo "reading this link needs jq" >&2; return 1; }
    _b=$(printf '%s' "$1" | tr -d ' \t\r\n' | tr '_-' '/+')
    case $(( ${#_b} % 4 )) in 1) return 1 ;; 2) _b="$_b==" ;; 3) _b="$_b=" ;; esac
    printf '%s\n' "$_b" | jq -Rr '@base64d' 2>/dev/null
}

# The fields every link sets (empty when it does not have them); PROTO is vless, vmess, trojan or ss. METHOD is the
# cipher: vmess's scy, Shadowsocks' method. QUERY is the link's query string, for param.
LINK_FIELDS='PROTO UUID HOST PORT TYPE SECURITY SNI FP ALPN FLOW INSECURE PBK SID WSPATH WSHOST SVC XMODE SPX PASSWORD METHOD AID QUERY'

# link_hostport HOST:PORT: HOST and PORT, from host:port, [v6]:port, or a host alone (port 443). The host goes
# into JSON and into lookups, and the port into JSON as a number, so both are checked here.
link_hostport() {
    _hp=${1%/}
    case $_hp in
        \[*\]:*) HOST=${_hp#\[}; HOST=${HOST%%\]*}; PORT=${_hp##*:} ;;
        \[*\]) HOST=${_hp#\[}; HOST=${HOST%\]}; PORT=443 ;;
        *:*) HOST=${_hp%:*}; PORT=${_hp##*:} ;;
        *) HOST=$_hp; PORT=443 ;;
    esac
    case $HOST in ''|*[!A-Za-z0-9._:-]*) return 1 ;; esac
    case $PORT in ''|*[!0-9]*|??????*) return 1 ;; esac
    [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]
}
# the transport and TLS fields of a link's query string (vless, trojan): the share-link names Xray's clients use
link_query() {
    TYPE=$(param type); SECURITY=$(param security)
    SNI=$(urldecode "$(param sni)"); [ -n "$SNI" ] || SNI=$(urldecode "$(param peer)")
    FP=$(param fp); ALPN=$(urldecode "$(param alpn)"); FLOW=$(param flow)
    INSECURE=$(param allowInsecure); PBK=$(param pbk); SID=$(param sid)
    WSPATH=$(urldecode "$(param path)"); WSHOST=$(urldecode "$(param host)"); SVC=$(urldecode "$(param serviceName)")
    XMODE=$(param mode); SPX=$(urldecode "$(param spx)")
}
# vmess_field KEY: a key of the vmess link's JSON ($_vm) as text, with control characters dropped (a value is put
# into JSON and into one-line files). No regular expressions: OpenWrt's jq may be built without them.
vmess_field() {
    printf '%s' "$_vm" | jq -r --arg k "$1" '.[$k] // empty | tostring | explode | map(select(. >= 32)) | implode'
}

# parse_link URI: a vless, vmess, trojan or ss (Shadowsocks) share link taken apart into LINK_FIELDS. Returns 1
# with a message on a link it cannot use; the message never repeats the link, which carries the credentials.
parse_link() {
    for _f in $LINK_FIELDS; do eval "$_f="; done
    _u=$1
    _cr=$(printf '\r')
    case $_u in *'
'*|*"$_cr"*) echo "a link is one line" >&2; return 1 ;; esac
    _u=${_u%%#*}
    case $_u in
        vless://*)
            PROTO=vless; _u=${_u#vless://}
            case $_u in *\?*) QUERY=${_u#*\?}; _u=${_u%%\?*} ;; esac
            case $_u in *@*) ;; *) echo "cannot parse the vless link" >&2; return 1 ;; esac
            UUID=$(urldecode "${_u%%@*}")
            link_hostport "${_u#*@}" || { echo "cannot parse the vless link's server" >&2; return 1; }
            link_query
            [ -n "$UUID" ] || { echo "the vless link has no id" >&2; return 1; } ;;
        trojan://*)
            PROTO=trojan; _u=${_u#trojan://}
            case $_u in *\?*) QUERY=${_u#*\?}; _u=${_u%%\?*} ;; esac
            case $_u in *@*) ;; *) echo "cannot parse the trojan link" >&2; return 1 ;; esac
            # the password is everything before the last @ (an @ in it should be %40, but is not always)
            PASSWORD=$(urldecode "${_u%@*}")
            link_hostport "${_u##*@}" || { echo "cannot parse the trojan link's server" >&2; return 1; }
            link_query
            SECURITY=${SECURITY:-tls}
            [ -n "$PASSWORD" ] || { echo "the trojan link has no password" >&2; return 1; } ;;
        vmess://*)
            # v2rayN's format: base64 of a JSON object
            PROTO=vmess
            _vm=$(b64d "${_u#vmess://}") || _vm=
            printf '%s' "$_vm" | jq -e 'type == "object"' >/dev/null 2>&1 ||
                { echo "cannot read the vmess link (base64 JSON)" >&2; return 1; }
            UUID=$(vmess_field id); AID=$(vmess_field aid); METHOD=$(vmess_field scy)
            _h=$(vmess_field add); _p=$(vmess_field port)
            case $_h in *:*) _h="[$_h]" ;; esac
            link_hostport "$_h:$_p" || { echo "cannot parse the vmess link's server" >&2; return 1; }
            TYPE=$(vmess_field net); _ht=$(vmess_field type)
            WSHOST=$(vmess_field host); WSPATH=$(vmess_field path)
            # gRPC's service name travels in path
            [ "$TYPE" != grpc ] || SVC=$WSPATH
            case $(vmess_field tls) in tls) SECURITY=tls ;; reality) SECURITY=reality ;; *) SECURITY=none ;; esac
            SNI=$(vmess_field sni); ALPN=$(vmess_field alpn); FP=$(vmess_field fp)
            PBK=$(vmess_field pbk); SID=$(vmess_field sid)
            _vm=
            case ${TYPE:-tcp}:$_ht in tcp:|tcp:none|raw:|raw:none|ws:*|grpc:*|httpupgrade:*|xhttp:*) ;;
                tcp:*|raw:*) echo "vmess over TCP with a '$_ht' header is not supported" >&2; return 1 ;;
            esac
            AID=${AID:-0}
            case $AID in *[!0-9]*) echo "the vmess link's alterId is not a number" >&2; return 1 ;; esac
            [ -n "$UUID" ] || { echo "the vmess link has no id" >&2; return 1; } ;;
        ss://*)
            PROTO=ss; SECURITY=none; TYPE=tcp; _u=${_u#ss://}
            case $_u in *\?*) QUERY=${_u#*\?}; _u=${_u%%\?*} ;; esac
            # obfs and v2ray plugins are separate programs Xray does not run
            [ -z "$(param plugin)" ] || { echo "ss plugins are not supported" >&2; return 1; }
            _u=${_u%/}
            case $_u in
                *@*)
                    # SIP002: userinfo@host:port, the userinfo base64 of method:password, or (2022 ciphers)
                    # method:password URL-encoded. Base64 has no ":", so a ":" tells the two apart.
                    _d=$(urldecode "${_u%@*}")
                    case $_d in *:*) ;; *) _d=$(b64d "$_d") || _d= ;; esac
                    _hp=${_u##*@} ;;
                *)
                    # the legacy form: base64 of method:password@host:port
                    _d=$(b64d "$_u") || _d=
                    case $_d in *@*) ;; *) echo "cannot read the ss link" >&2; return 1 ;; esac
                    _hp=${_d##*@}; _d=${_d%@*} ;;
            esac
            case $_d in *:*) ;; *) echo "cannot read the ss link's method and password" >&2; return 1 ;; esac
            METHOD=${_d%%:*}; PASSWORD=${_d#*:}
            case $METHOD in ''|*[!A-Za-z0-9-]*) echo "the ss link's method is not one Xray knows" >&2; return 1 ;; esac
            link_hostport "$_hp" || { echo "cannot parse the ss link's server" >&2; return 1; }
            case $METHOD in none|plain) ;; *) [ -n "$PASSWORD" ] || { echo "the ss link has no password" >&2; return 1; } ;; esac ;;
        *) echo "not a vless, vmess, trojan or ss link" >&2; return 1 ;;
    esac
    TYPE=${TYPE:-tcp}; SECURITY=${SECURITY:-none}
    return 0
}
# link_tag URI: the name a link gives itself (the #fragment, vmess's ps), for a profile imported without one
link_tag() {
    case $1 in
        vmess://*) _vm=$(b64d "${1#vmess://}") || _vm=; _t=$(vmess_field ps 2>/dev/null) || _t=; _vm= ;;
        *\#*) _t=$(urldecode "${1#*\#}") ;;
        *) _t= ;;
    esac
    printf '%s' "$_t" | tr -d '\000-\037\177'
}

# parse_uri: the VLESS-only entry point the sing-box driver and the tests use; exits on a link it cannot use
parse_uri() {
    case "$VLESS_URI" in vless://*) ;; *) echo "VLESS_URI must start with vless://" >&2; exit 1 ;; esac
    parse_link "$VLESS_URI" || exit 1
}

# link_need: VLESS_URI set to the link the drivers work from - the active profile's (PURI), or vpn.conf's where the
# store is not used; the run ends when there is none. Only the profile's id is named, never the link.
link_need() {
    VLESS_URI=${PURI:-${VLESS_URI:-}}
    [ -n "$VLESS_URI" ] && return 0
    if [ -n "${ACTIVE:-}" ]; then echo "profile $ACTIVE has no link" >&2
    else echo "VLESS_URI is not set in $CONF" >&2; fi
    exit 1
}
# link_import SRC [SCHEMES]: a link into the profile ($PDIR/uri, 0600, through a temporary file and mv), after it
# has been taken apart once. SCHEMES (default: vless) are the kinds the driver runs; anything else is refused.
link_import() {
    [ -n "${PDIR:-}" ] && [ -d "$PDIR" ] || { echo "no profile to import into" >&2; return 1; }
    _ok=${2:-vless}
    case $1 in *'
'*) echo "a link is one line" >&2; return 1 ;; esac
    case $1 in *://*) _s=${1%%://*} ;; *) _s= ;; esac
    case " $_ok " in *" ${_s:-none} "*) ;; *)
        echo "not a link this profile type takes (it takes: $_ok)" >&2; return 1 ;; esac
    ( parse_link "$1" ) >/dev/null || return 1
    ( umask 077; printf '%s\n' "$1" > "$PDIR/uri.new.$$" ) && mv "$PDIR/uri.new.$$" "$PDIR/uri" && return 0
    rm -f "$PDIR/uri.new.$$"; return 1
}
# link_opt_set KEY VALUE: an option of a link profile (profile set), checked, into its meta; empty removes it.
# Both go into generated configs, the proxy's port as a JSON number.
link_opt_set() {
    case $1 in
        TLS_PIN_SHA256) case $2 in *[!0-9A-Fa-f:,]*) echo "TLS_PIN_SHA256 is a SHA-256 in hex" >&2; return 2 ;; esac ;;
        UPSTREAM_HTTP_PROXY)
            [ -z "$2" ] || ( link_hostport "$2" && case $2 in *:*) true ;; *) false ;; esac ) ||
                { echo "UPSTREAM_HTTP_PROXY is HOST:PORT" >&2; return 2; } ;;
        *) return 2 ;;
    esac
    if [ -n "$2" ]; then kv_set "$PDIR/meta" "$1" "$2"; else kv_del "$PDIR/meta" "$1"; fi
}
