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

parse_uri() {
    u=$VLESS_URI
    case "$u" in vless://*) ;; *) echo "VLESS_URI must start with vless://" >&2; exit 1 ;; esac
    u=${u#vless://}; u=${u%%#*}
    case "$u" in *\?*) QUERY=${u#*\?}; u=${u%%\?*} ;; *) QUERY= ;; esac
    UUID=$(urldecode "${u%%@*}"); hp=${u#*@}; hp=${hp%/}
    case "$hp" in
        \[*\]:*) HOST=${hp#\[}; HOST=${HOST%%\]*}; PORT=${hp##*:} ;;
        *:*) HOST=${hp%:*}; PORT=${hp##*:} ;;
        *) HOST=$hp; PORT=443 ;;
    esac
    TYPE=$(param type); TYPE=${TYPE:-tcp}
    SECURITY=$(param security); SECURITY=${SECURITY:-none}
    SNI=$(urldecode "$(param sni)"); [ -n "$SNI" ] || SNI=$(urldecode "$(param peer)")
    FP=$(param fp); ALPN=$(urldecode "$(param alpn)"); FLOW=$(param flow)
    INSECURE=$(param allowInsecure); PBK=$(param pbk); SID=$(param sid)
    WSPATH=$(urldecode "$(param path)"); WSHOST=$(urldecode "$(param host)"); SVC=$(urldecode "$(param serviceName)")
    [ -n "$UUID" ] && [ -n "$HOST" ] || { echo "cannot parse VLESS_URI" >&2; exit 1; }
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
# link_import SRC: a VLESS link into the profile ($PDIR/uri, 0600, through a temporary file and mv), after it has
# been taken apart once; anything else is refused (other link types and raw configs come with their own drivers)
link_import() {
    [ -n "${PDIR:-}" ] && [ -d "$PDIR" ] || { echo "no profile to import into" >&2; return 1; }
    case $1 in vless://*) ;; *) echo "not a VLESS link" >&2; return 1 ;; esac
    case $1 in *'
'*) echo "a link is one line" >&2; return 1 ;; esac
    ( VLESS_URI=$1; parse_uri ) || return 1
    ( umask 077; printf '%s\n' "$1" > "$PDIR/uri.new.$$" ) && mv "$PDIR/uri.new.$$" "$PDIR/uri" && return 0
    rm -f "$PDIR/uri.new.$$"; return 1
}
