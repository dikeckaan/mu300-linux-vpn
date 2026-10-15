#!/bin/sh
# Every VLESS variant a share link can name, against a real Xray server, through the client config mu300-vpn writes
# for that link: on sing-box (the sing-box driver's drv_check and outbound_json) and on Xray (gen_xray). For each
# case: the server is started, the link is checked and turned into the engine's outbound by the module's own code,
# the engine runs it behind a SOCKS port, and a page is fetched through it. The table says, per engine, whether the
# page came back ("ok"), the link was refused at check with a message ("refused"), or the tunnel failed ("FAIL",
# with the server's or the client's last word). docs/FINDINGS.md 26o has the table and what it found.
#   tools/vless-matrix.sh [CASE...]     (default: every case; exit 1 when a case does not do what the table expects)
# Needs: xray and sing-box (XRAY, SING_BOX; default: on PATH - tools/fetch-xray.sh and tools/fetch-sing-box.sh
# give the pinned builds, arm64), jq, curl, openssl, python3. Everything stays on 127.0.0.1: no root, no TUN, no
# network beyond loopback. The keys, ids and certificates are made for the run and thrown away with it.
# On an Apple silicon Mac, in a container (the pinned engines are linux/arm64):
#   mkdir -p /tmp/eng/bin && sh tools/fetch-sing-box.sh /tmp/eng/bin/sing-box && sh tools/fetch-xray.sh /tmp/eng
#   docker run --rm -v "$PWD:/m:ro" -v /tmp/eng:/e:ro alpine:3 sh -c \
#       'apk add -q jq curl openssl python3 && XRAY=/e/bin/xray SING_BOX=/e/bin/sing-box sh /m/tools/vless-matrix.sh'
# (CI runs it on an arm64 runner: .github/workflows/tests.yml, job vless-matrix.)
set -u
TOP=$(cd "$(dirname "$0")/.." && pwd)
XRAY=${XRAY:-$(command -v xray || true)}
SB=${SING_BOX:-$(command -v sing-box || true)}
for _c in "$XRAY" "$SB"; do [ -x "$_c" ] || { echo "needs xray and sing-box (XRAY=, SING_BOX=)" >&2; exit 2; }; done
for _c in jq curl openssl python3; do command -v $_c >/dev/null || { echo "needs $_c" >&2; exit 2; }; done
T=$(mktemp -d)
PIDS=
stop() { for _p in $PIDS; do kill "$_p" 2>/dev/null; done; for _p in $PIDS; do wait "$_p" 2>/dev/null; done; PIDS=; }
trap 'stop; rm -rf "$T"' EXIT
trap 'exit 130' INT TERM

# ---- the fixtures: a CA and a certificate for vless.test and reality.test, an id, REALITY and VLESS Encryption keys
cd "$T" || exit 2
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=matrix-ca \
    -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=vless.test \
    -keyout srv.key -out srv.csr 2>/dev/null
printf 'subjectAltName=DNS:vless.test,DNS:reality.test\n' > srv.ext
openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile srv.ext -out srv.pem 2>/dev/null
[ -s srv.pem ] || { echo "openssl could not make the certificates" >&2; exit 2; }
# the engines trust the run's CA and nothing else (Go reads SSL_CERT_FILE)
export SSL_CERT_FILE="$T/ca.pem"
ID=$("$XRAY" uuid)
_k=$("$XRAY" x25519)
RPRIV=$(printf '%s\n' "$_k" | sed -n 's/^PrivateKey: *//p')
RPUB=$(printf '%s\n' "$_k" | sed -n 's/^Password.*: *//p; s/^Public key: *//p' | head -n1)
# VLESS Encryption (Xray 25.9 and later): the X25519 pair of the two vlessenc prints
_k=$("$XRAY" vlessenc)
DEC=$(printf '%s\n' "$_k" | sed -n 's/^"decryption": "\(.*\)"$/\1/p' | head -n1)
ENC=$(printf '%s\n' "$_k" | sed -n 's/^"encryption": "\(.*\)"$/\1/p' | head -n1)
[ -n "$ID" ] && [ -n "$RPRIV" ] && [ -n "$RPUB" ] && [ -n "$DEC" ] && [ -n "$ENC" ] ||
    { echo "xray did not make the keys" >&2; exit 2; }
mkdir -p www run root/run/mu300 disk opt
TOKEN=matrix-$$-ok
echo "$TOKEN" > www/index.html
echo f50 > root/run/mu300/device
: > vpn.conf
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$T/www" >/dev/null 2>&1 &
WEB=$!
trap 'stop; kill $WEB 2>/dev/null; rm -rf "$T"' EXIT

# mod CODE: CODE run with mu300-vpn's functions loaded (as tests/ load them), $LINK the case's link
mod() {
    ( export MU300_LIB=1 MU300_VPN_CONF="$T/vpn.conf" MU300_VPN_RUN="$T/run" MU300_LAN_CONF="$T/nolan" \
          MU300_BIN="$TOP/tests/fixtures/bin" MU300_SYSROOT="$T/root" MU300_VPN_LIB="$TOP/lib/vpn" \
          MU300_DISK="$T/disk" MU300_OPT="$T/opt" MU300_DNS_PROBE=true MU300_V6_PROBE=false
      . "$TOP/bin/mu300-vpn"; eval "$1" )
}
# listening PORT: something listens on 127.0.0.1:PORT, within 8 s
listening() {
    _n=0
    while [ $_n -lt 40 ]; do
        { netstat -ltn 2>/dev/null || ss -ltn 2>/dev/null; } | grep -q "127.0.0.1:$1 " && return 0
        sleep 0.2; _n=$((_n + 1))
    done
    return 1
}
# fetch PORT: the page through the SOCKS port PORT
fetch() { [ "$(curl -s --max-time "${MATRIX_TIMEOUT:-8}" -x "socks5h://127.0.0.1:$1" http://127.0.0.1:18080/ 2>/dev/null)" = "$TOKEN" ]; }
# last FILE: the last line of a log that says something, made short and safe to print
last() { grep -v '^$' "$1" 2>/dev/null | tail -n 1 | clean; }
# why FILE: the last line of an engine's log that says what went wrong (they log at info here)
why() { grep -iE 'reject|invalid|fail|error|unknown|not |EOF|bogus|refuse|closed' "$1" 2>/dev/null | tail -n 1 | clean; }
clean() {
    sed 's/^[0-9/]* [0-9:.]* //; s/\[[0-9;]*m//g; s/^[A-Z]*\[[0-9]*\] //' | cut -c1-"${MATRIX_WIDTH:-100}" | tr -c 'A-Za-z0-9 ._:/=()[],<>-\n' '?'
}

# ---- the server: the case's VLESS inbound, and a TLS server for REALITY to borrow (its target)
TLS_CERT='{"certificates":[{"certificateFile":"'$T'/srv.pem","keyFile":"'$T'/srv.key"}]'
# srv_stream SECURITY NETWORK [SETTINGS]: the inbound's streamSettings
srv_stream() {
    _s='{"network":"'$2'"'
    [ -n "${3:-}" ] && _s="$_s,$3"
    case $1 in
        tls) _s="$_s"',"security":"tls","tlsSettings":'"$TLS_CERT"'}' ;;
        reality) _s="$_s"',"security":"reality","realitySettings":{"target":"127.0.0.1:18443","serverNames":["reality.test"],"privateKey":"'$RPRIV'","shortIds":["","a1b2c3d4"]}' ;;
    esac
    printf '%s}' "$_s"
}
server() { # server PORT FLOW DECRYPTION STREAM
    cat > srv.json <<JSON
{"log":{"loglevel":"info","access":"none"},
 "inbounds":[{"listen":"127.0.0.1","port":18443,"protocol":"vless","settings":{"clients":[{"id":"$ID"}],"decryption":"none"},
              "streamSettings":$(srv_stream tls raw)},
             {"listen":"127.0.0.1","port":$1,"protocol":"vless","settings":{"clients":[{"id":"$ID","flow":"$2"}],"decryption":"$3"},
              "streamSettings":$4}],
 "outbounds":[{"protocol":"freedom"}]}
JSON
    # (appended to: each client's turn starts the log afresh, and a truncated log is written at its start again)
    : > srv.log
    "$XRAY" run -c srv.json >> srv.log 2>&1 &
    PIDS="$PIDS $!"
    listening "$1"
}

# ---- one case
FAILS=0
N=0
# run NAME EXPECT_SINGBOX EXPECT_XRAY FLOW DECRYPTION STREAM QUERY   (EXPECT: ok, refused - at check, with a message - or fails: the server turns the client away, whichever engine)
run() {
    N=$((N + 1))
    [ -n "$ONLY" ] && case " $ONLY " in *" $1 "*) ;; *) return 0 ;; esac
    _port=$((20000 + N)); _sbp=$((21000 + N)); _xp=$((22000 + N))
    export LINK="vless://$ID@127.0.0.1:$_port?$7#m"
    if ! server "$_port" "$4" "$5" "$6"; then
        printf '%-26s %-40s %s\n' "$1" "server: $(last srv.log)" "-"; stop; FAILS=$((FAILS + 1)); return
    fi
    # sing-box: the driver's check, then its outbound in a client of its own
    _sb=
    if ! mod 'VLESS_URI=$LINK; UPSTREAM_HTTP_PROXY=; load_driver sing-box; drv_check' > sb.chk 2>&1; then
        _sb="refused: $(last sb.chk)"
    elif ! mod 'VLESS_URI=$LINK; UPSTREAM_HTTP_PROXY=; load_driver sing-box; parse_uri; outbound_json' > sb.out 2> sb.chk; then
        _sb="refused: $(last sb.chk)"
    else
        jq -n --slurpfile o sb.out --argjson p "$_sbp" '{"log":{"level":"info","timestamp":false},
            "dns":{"servers":[{"type":"local","tag":"bootstrap"}]},
            "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":$p}],"outbounds":$o}' > sb.json
        if ! "$SB" check -c sb.json > sb.log 2>&1; then _sb="FAIL check: $(last sb.log)"
        else
            "$SB" run -c sb.json --disable-color > sb.log 2>&1 &
            PIDS="$PIDS $!"
            if ! listening "$_sbp"; then _sb="FAIL start: $(last sb.log)"
            elif fetch "$_sbp"; then _sb=ok
            else _sb="FAIL: $(why srv.log) / $(why sb.log)"; fi
        fi
    fi
    # xray: gen_xray's outbound (without the mark: the container has no CAP_NET_ADMIN) behind a SOCKS inbound
    _x=; : > srv.log
    if ! mod 'PURI=$LINK; load_driver xray; drv_check' > x.chk 2>&1; then
        _x="refused: $(last x.chk)"
    elif ! mod "PURI=\$LINK; load_driver xray; XRAY='$XRAY'; gen_xray" > x.chk 2>&1; then
        _x="refused: $(last x.chk)"
    else
        jq --argjson p "$_xp" '{"log":{"loglevel":"info","access":"none"},
            "inbounds":[{"listen":"127.0.0.1","port":$p,"protocol":"socks","settings":{"udp":true}}],
            "outbounds":[.outbounds[0] | del(.streamSettings.sockopt)]}' run/xray.json > x.json
        "$XRAY" run -c x.json > x.log 2>&1 &
        PIDS="$PIDS $!"
        if ! listening "$_xp"; then _x="FAIL start: $(last x.log)"
        elif fetch "$_xp"; then _x=ok
        else _x="FAIL: $(why srv.log) / $(why x.log)"
            [ -z "${MATRIX_DEBUG:-}" ] || { echo "-- $1 xray:"; tail -n 8 x.log; echo "-- server:"; tail -n 8 srv.log; }; fi
    fi
    stop
    rm -f run/xray.json vpn.conf; : > vpn.conf
    _bad=
    case $2 in ok) [ "$_sb" = ok ] ;; refused) case $_sb in refused*) ;; *) false ;; esac ;; fails) case $_sb in FAIL*) ;; *) false ;; esac ;; esac || _bad=1
    case $3 in ok) [ "$_x" = ok ] ;; refused) case $_x in refused*) ;; *) false ;; esac ;; fails) case $_x in FAIL*) ;; *) false ;; esac ;; esac || _bad=1
    [ -z "$_bad" ] || FAILS=$((FAILS + 1))
    printf '%-26s %-60s %s%s\n' "$1" "$_sb" "$_x" "${_bad:+   <- expected sing-box $2, xray $3}"
}
ONLY=${*:-}

V=xtls-rprx-vision
R="security=reality&sni=reality.test&pbk=$RPUB&sid=a1b2c3d4"
printf '%-26s %-60s %s\n' case sing-box xray
# -- no TLS
run none-raw              ok ok '' none "$(srv_stream none raw)" 'type=tcp&security=none&encryption=none'
run none-raw-header-http  refused ok '' none "$(srv_stream none raw '"rawSettings":{"header":{"type":"http","request":{"path":["/h"],"headers":{"Host":["h.test"]}}}}')" 'type=tcp&headerType=http&host=h.test&path=%2Fh'
run none-ws               ok ok '' none "$(srv_stream none ws '"wsSettings":{"path":"/ws","host":"ws.test"}')" 'type=ws&path=%2Fws&host=ws.test'
run none-ws-ed            ok ok '' none "$(srv_stream none ws '"wsSettings":{"path":"/ws","host":"ws.test"}')" 'type=ws&path=%2Fws%3Fed%3D2048&host=ws.test'
# (a server whose own path has the ?ed=: Xray's server takes it off its path as its client does)
run none-ws-ed-both       ok ok '' none "$(srv_stream none ws '"wsSettings":{"path":"/ws?ed=2048"}')" 'type=ws&path=%2Fws%3Fed%3D2048'
run none-grpc             ok ok '' none "$(srv_stream none grpc '"grpcSettings":{"serviceName":"svc"}')" 'type=grpc&serviceName=svc'
run none-grpc-multi       ok ok '' none "$(srv_stream none grpc '"grpcSettings":{"serviceName":"svc","multiMode":true}')" 'type=grpc&serviceName=svc&mode=multi'
run none-httpupgrade      ok ok '' none "$(srv_stream none httpupgrade '"httpupgradeSettings":{"path":"/hu","host":"hu.test"}')" 'type=httpupgrade&path=%2Fhu&host=hu.test'
# (Xray takes ?ed= off an HTTPUpgrade path too, on both ends; sing-box sent it and got "bad path")
run none-httpupgrade-ed  ok ok '' none "$(srv_stream none httpupgrade '"httpupgradeSettings":{"path":"/hu","host":"hu.test"}')" 'type=httpupgrade&path=%2Fhu%3Fed%3D2048&host=hu.test'
run none-httpupgrade-ed-both ok ok '' none "$(srv_stream none httpupgrade '"httpupgradeSettings":{"path":"/hu?ed=2048","host":"hu.test"}')" 'type=httpupgrade&path=%2Fhu%3Fed%3D2048&host=hu.test'
run none-xhttp            refused ok '' none "$(srv_stream none xhttp '"xhttpSettings":{"path":"/xh","mode":"auto"}')" 'type=xhttp&path=%2Fxh&mode=auto'
run none-splithttp        refused ok '' none "$(srv_stream none xhttp '"xhttpSettings":{"path":"/xh"}')" 'type=splithttp&path=%2Fxh'
run none-vlessenc         refused ok '' "$DEC" "$(srv_stream none raw)" "type=tcp&security=none&encryption=$ENC"
# -- TLS
run tls-raw               ok ok '' none "$(srv_stream tls raw)" 'type=tcp&security=tls&sni=vless.test'
run tls-raw-fp            ok ok '' none "$(srv_stream tls raw)" 'type=tcp&security=tls&sni=vless.test&fp=chrome'
run tls-raw-alpn          ok ok '' none "$(srv_stream tls raw)" 'type=tcp&security=tls&sni=vless.test&alpn=h2%2Chttp%2F1.1'
# (a randomized TLS hello is random: now and then it offers what the server's TLS cannot take - "tls: internal
# error" - on either engine: Xray's randomizednoalpn has no expectation. sing-box has no randomizednoalpn and runs
# such a link with chrome; its own randomized failed about every third handshake, fp-random)
run tls-raw-fp-noalpn     ok - '' none "$(srv_stream tls raw)" 'type=tcp&security=tls&sni=vless.test&fp=randomizednoalpn'
run tls-raw-insecure      ok ok '' none "$(srv_stream tls raw)" 'type=tcp&security=tls&sni=other.test&allowInsecure=1'
run tls-ws                ok ok '' none "$(srv_stream tls ws '"wsSettings":{"path":"/ws"}')" 'type=ws&security=tls&sni=vless.test&path=%2Fws&fp=chrome'
run tls-ws-alpn           ok ok '' none "$(srv_stream tls ws '"wsSettings":{"path":"/ws"}')" 'type=ws&security=tls&sni=vless.test&path=%2Fws&alpn=h2%2Chttp%2F1.1&fp=chrome'
run tls-ws-ed             ok ok '' none "$(srv_stream tls ws '"wsSettings":{"path":"/ws"}')" 'type=ws&security=tls&sni=vless.test&path=%2Fws%3Fed%3D2048&fp=chrome'
run tls-ws-fp-noalpn      ok - '' none "$(srv_stream tls ws '"wsSettings":{"path":"/ws"}')" 'type=ws&security=tls&sni=vless.test&path=%2Fws&fp=randomizednoalpn'
run tls-ws-fp-random      - - '' none "$(srv_stream tls ws '"wsSettings":{"path":"/ws"}')" 'type=ws&security=tls&sni=vless.test&path=%2Fws&fp=randomized'
run tls-grpc-alpn        ok ok '' none "$(srv_stream tls grpc '"grpcSettings":{"serviceName":"svc"}')" 'type=grpc&security=tls&sni=vless.test&serviceName=svc&alpn=h2%2Chttp%2F1.1&fp=chrome'
run tls-grpc              ok ok '' none "$(srv_stream tls grpc '"grpcSettings":{"serviceName":"svc"}')" 'type=grpc&security=tls&sni=vless.test&serviceName=svc&fp=chrome'
run tls-httpupgrade       ok ok '' none "$(srv_stream tls httpupgrade '"httpupgradeSettings":{"path":"/hu"}')" 'type=httpupgrade&security=tls&sni=vless.test&path=%2Fhu'
run tls-xhttp             refused ok '' none "$(srv_stream tls xhttp '"xhttpSettings":{"path":"/xh"}')" 'type=xhttp&security=tls&sni=vless.test&path=%2Fxh'
# (Xray 26 has no HTTP/2 transport to serve this: "The feature HTTP transport ... has been removed". Both drivers
# refuse the link at check; the server here is any)
run tls-h2                refused refused '' none "$(srv_stream tls raw)" 'type=h2&security=tls&sni=vless.test&path=%2Fh2&host=vless.test'
run tls-vision            ok ok $V none "$(srv_stream tls raw)" "type=tcp&security=tls&sni=vless.test&fp=chrome&flow=$V"
run tls-vision-udp443     ok ok $V none "$(srv_stream tls raw)" "type=tcp&security=tls&sni=vless.test&fp=chrome&flow=$V-udp443"
run tls-vision-xudp       ok ok $V none "$(srv_stream tls raw)" "type=tcp&security=tls&sni=vless.test&fp=chrome&flow=$V&packetEncoding=xudp"
run tls-vlessenc          refused ok '' "$DEC" "$(srv_stream tls raw)" "type=tcp&security=tls&sni=vless.test&encryption=$ENC"
# -- REALITY
run reality-raw           ok ok '' none "$(srv_stream reality raw)" "type=tcp&$R&fp=chrome"
run reality-raw-nofp      ok ok '' none "$(srv_stream reality raw)" "type=tcp&$R"
run reality-sid-empty     ok ok '' none "$(srv_stream reality raw)" "type=tcp&security=reality&sni=reality.test&pbk=$RPUB&fp=firefox"
run reality-vision        ok ok $V none "$(srv_stream reality raw)" "type=tcp&$R&fp=chrome&flow=$V"
run reality-vision-spx    ok ok $V none "$(srv_stream reality raw)" "type=tcp&$R&fp=chrome&flow=$V&spx=%2F"
run reality-grpc          ok ok '' none "$(srv_stream reality grpc '"grpcSettings":{"serviceName":"svc"}')" "type=grpc&$R&fp=chrome&serviceName=svc"
run reality-xhttp         refused ok '' none "$(srv_stream reality xhttp '"xhttpSettings":{"path":"/xh"}')" "type=xhttp&$R&fp=chrome&path=%2Fxh"
echo "$FAILS case(s) not as expected"
[ "$FAILS" = 0 ]
