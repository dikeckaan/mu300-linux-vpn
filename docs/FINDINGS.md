# Findings: the VPN on the MU300

Copied from mu300-linux's [docs/FINDINGS.md](https://github.com/dikeckaan/mu300-linux/blob/main/docs/FINDINGS.md)
(sections 26b, 26e and 26f) when the VPN moved to this repository; the numbers are kept so references to them
still work. Measured on the ZTE F50 and the U30 Air (hardware MU300, Unisoc T760). New VPN findings go here.

### 26b. The tunnel needs sing-box's gvisor stack on this kernel
Everything through the VPN failed while the VPN itself looked healthy: it connected to its server, resolved
names through the tunnel, and `sbtun` counted the packets going in. Applications got `Connection refused` from
`nc` and `Failed to send request: Operation not permitted` from `uclient-fetch`, and sing-box logged one line
per connection - `router: pre-match[0] => sniff` - and nothing after it. No outbound was ever selected.

The cause is the tun inbound's default **system** stack, which this 5.4 vendor kernel cannot support. It says so
at startup, in a warning that is easy to read as cosmetic:

    inbound/tun[tun-in]: enable offload: set udp offload: TUNSETOFFLOAD: invalid argument

`"stack": "gvisor"` carries its own TCP/IP and does not ask the kernel for any of it. With that one field,
`apk update` goes from "8 unavailable, 145 distinct packages" to **"OK: 11168 distinct packages available"**,
with the kill switch active the whole time.

Worth remembering while chasing something like this: DNS kept working throughout, because it is hijacked and
answered inside sing-box rather than carried as a TCP connection. A tunnel that resolves names but carries no
traffic points at the stack, not at routing or the firewall - both of which were searched first, and neither of
which had a rule with a non-zero counter.

### 26e. The Xray engine, and a connectivity test that could only say no

**Update 2026-10-07:** since PR #31 the engines (Xray-core, hev-socks5-tunnel, sing-box) are not in the Ubuntu or
OpenWrt images. They are an optional release asset, `mu300-extra-vpn.tar.gz`, installed with
`mu300-extra install vpn` or by the installer's question. `mu300-vpn` looks in `extra/vpn/bin` first. Since PR #49,
Tailscale's own traffic also goes through the tunnel (`TAILSCALE=0` opts out). The engine choice below still
holds (`mu300-vpn`, `ENGINE` default).
`mu300-vpn` now defaults to `ENGINE=xray`: Xray-core does VLESS, hev-socks5-tunnel owns a plain kernel TUN (`xtun`)
and hands each flow to Xray's SOCKS port on loopback. Neither installs routes, so the script does, with sing-box's
rule prefs and table (9000-9010, table 2022): Xray's own sockets carry mark `0x2d0` and go to `main`, as do the LAN
and the server's address; everything else goes to `xtun`. The device's own DNS - dnsmasq's upstream, which is the
carrier resolver and does not answer from the far end of a tunnel - is DNAT'd to `REMOTE_DNS`. Every exit path
removes all of it, because routing left behind by a dead engine is what made sing-box's crashes look like a dead
modem.

The kill switch does **not** carry over, even though Xray's sockets carry the same mark: before the tunnel exists
the server's name is resolved through dnsmasq and its certificate fetched with openssl, both unmarked, and the kill
switch drops both - the engine never comes up and the device is left with nothing. sing-box does its bootstrap
lookup on its own marked socket, which is why it never had this problem. So an unset `ENGINE` picks sing-box when
`KILL_SWITCH=1` (what an updated device with an old `vpn.conf` has), and `ENGINE=xray` with the kill switch on
runs without it and says so.

Measured on OpenWrt: the device's exit IP is the server's, `apk add` works through the tunnel, and a Wi-Fi client's
flows are forwarded into `xtun`. The Ubuntu side uses the same script but has not been run on the device.

**allowInsecure is gone in Xray 26.** Its replacement, `pinnedPeerCertSha256`, accepts exactly one leaf
certificate. For a link that asks for allowInsecure the script manages the pin: fetched once with openssl when
there is none and stored as `TLS_PIN_SHA256` in `vpn.conf`, left alone on later starts, and fetched again only when
Xray reports `peer cert is unrecognized (against pinnedPeerCertSha256)` - a renewal - after which the service
restarts itself. Xray reports that failure at **info** level, which a `warning` log level hides completely; the
script runs Xray at info with the access log off and passes only warnings and worse to the system log. `xray tls
ping` is no substitute for openssl here: it tries without SNI first, and a server that ignores that attempt keeps it
waiting past any sensible timeout. (The server this was tested against presents a Let's Encrypt certificate that
expired in December 2025 - which is why its link asks for allowInsecure. The pin skips the expiry check.)

**busybox `nc` on this OpenWrt has no `-w`.** `nc -w 6 HOST PORT` prints the usage text and exits 1, so a
reachability test built on its exit status reports every destination as closed. That produced a confident and
wrong "this SIM reaches nothing but the carrier's DNS" - the same bearer carried the VPN minutes later. Test TCP
with `wget -T` or `curl -m`, check the tool's own exit status rather than a pipe's, and run the test once against
something that must succeed before believing a failure. To test the bearer while a tunnel runs, route a single
address around it: `ip rule add pref 8999 to <addr> lookup main`, test, delete the rule.

### 26f. One VPN command for every protocol: profiles and engine drivers
`mu300-vpn` spoke one protocol: a VLESS link in `vpn.conf`. People have WireGuard configs, OpenVPN files,
Clash/mihomo subscriptions and raw Xray/sing-box JSON from their panels, so it now keeps named profiles under
`/etc/mu300/vpn` (`profile import|add|edit|use|remove|export|show|list`, `settings`, `engines`, `check`) and runs
the active one through a driver per engine (`/opt/mu300/lib/vpn/<type>.sh`: `drv_check`, `drv_gen`, `drv_start`,
`drv_alive`, `drv_stop`, `drv_import`...). The core owns what the drivers must not differ in: the kill switch, the
routing (rules 9000-9010, table 2022), the DNS nat and the Tailscale rules. The decisions:

* **ENABLE stays in `vpn.conf`.** Everything else moved, but the switch has too many readers to move with it:
  `mu300-update` and `android-install.sh` (a VPN in use keeps its engines across an update), `wifi-client` (the kill
  switch is fatal only when the VPN is on), `mu300-extra` (refuses to remove the vpn extra while ENABLE=1), the
  dashboard, and every older image, which must find a working VLESS VPN after a downgrade. So `on`/`off` write that
  one line and `vpn.conf` keeps its legacy keys; `wifi-client` and the dashboard read `KILL_SWITCH` and the engine
  from the store first and fall back to `vpn.conf`.
* **Migration by snapshot diff.** At every start (any command, as root) the legacy keys of `vpn.conf` are compared
  with `legacy.snapshot`, the keys as last migrated; only a key whose value changed since is applied (a setting
  set, or profile `legacy` updated). The first run moves everything, a later run does nothing, and a later edit of
  `vpn.conf` - the old README's way, or an older image's `save_pin` after a downgrade and upgrade - wins for the
  keys it touched while settings made with the new commands are kept otherwise. A plain "vpn.conf wins" would undo
  every `settings set`; "the store wins" would ignore the edit the old instructions tell people to make.
* **Marks per engine.** The kill switch lets only traffic marked `0x2d0` (720) out on an uplink, and rule 9000
  keeps marked traffic off the tunnel, so each driver marks its engine's own sockets: Xray's `sockopt.mark` on every
  outbound (and on every dialer nested inside one - xhttp's `downloadSettings`, a `dialerProxy`), sing-box's
  `route.default_mark`, mihomo's `routing-mark`, WireGuard's `wg set fwmark`, OpenVPN's `--mark`. No engine needs an
  exception in the kill switch, which is unchanged.
* **The resolve window.** A server name (WireGuard's Endpoint, OpenVPN's remote, a link's host, the `vnext`
  servers of raw JSON) has to be resolved before the tunnel exists, and with the kill switch up the device's own DNS
  is dropped too (26e's reason Xray needed the sing-box substitute). The core opens the download window's ruleset
  with only the DNS sets filled, resolves, and puts the full kill switch back - one nft transaction each way, never
  a gap. VLESS on Xray behind the kill switch still runs on sing-box, as before, so the existing tests hold.
* **Raw configs are parsed once, strictly, and rebuilt from an allowlist.** A panel's JSON runs as root and could
  open a listener on the LAN, expose an API, bind another interface or write a file. It is read by `jq` once
  (`json_strict`: one object, no duplicate keys, no two keys equal under Go's case folding, since the engines'
  decoders match field names without regard to case and jq keeps the last duplicate silently) and the engine gets a
  new document built from what the allowlist accepts, with the inbound, the log, the mark and the bootstrap DNS
  written last so they always win. An allowlist, not a denylist, because each engine release adds features (some of
  which listen) faster than a denylist would follow. No jq regex (OpenWrt's jq may lack it) and jq's own errors are
  never shown (they quote the file); refusals name a key from our own lists, never a value. What a config may do -
  pick outbounds, route between them, name its DNS - is also its exposure: a `direct`/`freedom` outbound goes past
  the kill switch with the engine's mark, by the config's own choice.
* **OpenVPN never reads the user's file.** The `.ovpn` is tokenized with openvpn's own lexical rules (what the two
  could read differently is refused: a backslash, a quote inside a word, a `</` prefix inside a key block), held to
  an allowlist of directives and key blocks, and openvpn runs only `$RUN/openvpn.conf`, which we write, with our
  options after it: `--route-noexec` and pull-filters for `redirect-gateway`, `route`, `setenv`,
  `block-outside-dns`, and only our own `--up` script. Not `--route-nopull`: it would also drop the pushed
  `dhcp-option DNS`, which is the one thing from the server the up script wants.
* **sing-box keeps `auto_route`.** Its own routing does exactly what the core does (same prefs, same table), so the
  driver says `DRV_ROUTES=self` and the core only adds the Tailscale rules and the DNS nat, as before.
* **jq is in the images** (Ubuntu, OpenWrt, Arch): the raw-JSON drivers need it, and `wireguard-tools` goes into
  Ubuntu and Arch (OpenWrt has it). Nothing else grows; mihomo is the new `vpn-mihomo` extra.

Measured on the U30 Air (OpenWrt, mainline), stated as what was seen and no more: the migration of the device's
working legacy VLESS `vpn.conf` produced profile `legacy` with the same exit IP, without the link ever being read
or printed. Import from stdin, `check`, and switching `legacy` -> a WireGuard profile -> `legacy` worked, with the
routes and rules of the previous profile cleaned up each time and the tunnel up. Then the carrier: on the U30 Air's
SIM, UDP to the WireGuard port never reaches the server - `tcpdump` on `sipa_eth0` shows the marked packets leaving
the device, and the same UDP sent from a Mac on another network arrives at the server - and OpenVPN over TCP
connects but the TLS handshake times out, while the same `.ovpn` completes from the home network. The carrier
drops that UDP and DPI-blocks OpenVPN's TLS; the VLESS profile goes through. The WireGuard and OpenVPN drivers were
verified on the device up to that point, no further.


### 26g. IPv6 beside an IPv4 tunnel: the carrier's address, and a leak where it works
Seen on an F50 (OpenWrt, v2026.10.18, the VPN on with an xray profile): the carrier hands out a global IPv6 address
on `sipa_eth0` (2a00:...), and in Turkey nothing routes over it. The tunnel carries IPv4 only, so the device's own
programs that prefer IPv6 fail: OpenWrt's `uclient-fetch` (wget) does not fall back to IPv4, `wget -4` works. Where
the carrier's IPv6 does route, the same situation is a leak: IPv6 from the device and the LAN leaves on the bearer
beside the tunnel. The kill switch (an `inet` table) already dropped unmarked IPv6 on the uplinks, so with it on
nothing leaked - but silently, and programs waited out their IPv6 attempt first.

Module v2: while a tunnel is up that has no IPv6 address of its own, `table inet mu300_vpn_v6` (the IPv6 guard,
whatever KILL_SWITCH says) **rejects** IPv6 on the uplinks - TCP with a reset, the rest with ICMPv6
administratively prohibited - for the device and for forwarded traffic, so programs fall back to IPv4 at once; the
engine's marked sockets, neighbour/router discovery and DHCPv6 from the device stay allowed. The kill switch carries
the same rejects before its drop. `nft list` shows these rules without their `meta nfproto ipv6`; the bytecode
(`nft --debug=netlink list table ...`) keeps the match (`meta load nfproto`, `cmp eq 0x0a`): only IPv6 is
rejected. The `IPV6` setting's new default `auto` routes IPv6 into a tunnel that has an IPv6 address (WireGuard with
IPv6 in its config); LAN clients keep the address the router gives them and are rejected the same way.
Tested: the rulesets load into a real kernel's nftables (a Docker container with NET_ADMIN); on the device: not yet.

### 26h. dae behind the kill switch: the wan side on a dummy interface
dae (eBPF, kernels with BTF and 5.17 or newer, so mainline only here) catches the device's own traffic on the
egress of its `wan_interface` with tc. The kill switch drops unmarked traffic in nft's output hook, which runs before
tc egress: with the uplink itself as dae's wan interface, the device's packets would be dropped before dae ever saw
them. So the dae driver routes as the TUN engines do (rules 9000-9010, table 2022) into a dummy interface,
`mu300dae`, and gives dae that as its wan interface; dae's own sockets carry the mark (`so_mark_from_dae: 720`) and
leave by rule 9000. A dead dae leaves the dummy as a dead end: closed. `dae validate` (v2.1.1) accepts every config
the driver writes (checked in a container); `node()` without a parameter is refused by it ("empty parameter list"),
so the node lookups go to the bootstrap resolver with `node(name_regex: '.')`. Whether dae's node and subscription
lookups really leave marked is the device test that remains.

### 26i. An engine that looks its server up itself, on an uplink where only the carrier's resolver answers
Reported as "a problem in the VPN part, mihomo and the like"; measured on the U30 Air (OpenWrt, kernel 7.2.10, module
v2.0.0, a SIM on which nothing but the VPN server and the carrier's own DNS answers without the tunnel). The working
profile is a VLESS link on Xray. The same server as a mihomo YAML, and as a link on sing-box, came up - TUN there,
routing there, `status` "running" - and carried nothing: `exit IP: unreachable`, and for every connection one line,

    [TCP] dial PROXY ... error: <server>:443 connect error: dns resolve failed: couldn't find ip        (mihomo)
    connection: open connection to ... using outbound/vless[proxy]: lookup <server>: context deadline exceeded   (sing-box)

sing-box, mihomo and dae resolve their server's name themselves, on their own marked sockets, at `BOOTSTRAP_DNS`
(1.1.1.1 unless set). On this bearer `nslookup example.com 1.1.1.1` times out, and 8.8.8.8 too; the two resolvers the
bearer handed out answer at once. Xray never noticed: its driver (and WireGuard's and OpenVPN's) asks the system
resolver, which is the carrier's. Setting `BOOTSTRAP_DNS` to the carrier's resolver made all three work - the
workaround, and nothing a user finds.

Now `mu300-vpn run` asks before it writes such an engine's config (`bootstrap_pick`, for a driver that says
`DRV_BOOTSTRAP=1`): `BOOTSTRAP_DNS` first, then the uplink's own resolvers (`fetch_resolvers`: what the bearer or the
Wi-Fi client's DHCP gave), and the first that answers is the engine's bootstrap resolver for that run; the setting is
not changed, and `BOOTSTRAP_DNS` still comes first for the networks whose own resolver lies about the server's name.
The question is one lookup with a 3 s limit: busybox's or BIND's `nslookup`; without it (Ubuntu's image) one query
through bash's `/dev/udp` - and `read -n 1` there, not 2: a read of a datagram socket takes the whole datagram, a
second byte never comes. Behind the kill switch the questions go through the resolve window, opened for these
addresses too (so a start on these engines is now three nft transactions, as on the others: kill switch, window,
kill switch); the engine's own lookups stay marked and need none. Nothing answers and there is no default route: the
run ends and the service manager repeats it, as it does for Xray when its lookup fails (at boot the service starts
before the bearer). Nothing answers on an uplink that is up: on with `BOOTSTRAP_DNS` as set - a server given by its
address needs no resolver. sing-box with `UPSTREAM_HTTP_PROXY` is not asked for: its lookup goes through that proxy.

Measured after, with the device's settings untouched (`BOOTSTRAP_DNS='1.1.1.1'`): the log says `BOOTSTRAP_DNS 1.1.1.1
does not answer on this uplink: the servers' names are looked up at the uplink's resolver ... instead`, and mihomo
(a plain YAML and one with rule providers and GEOSITE/GEOIP rules), sing-box (the link) and dae each give the server's
exit address on the device and to a LAN client (a Mac on the USB link: DNS through the router and to 8.8.8.8 and
9.9.9.9 itself, HTTP, HTTPS, 1 MB down), with the kill switch off and on. Not measured: the bash path (the device
runs OpenWrt), the start before the bearer (no reboot), an uplink change while the engine runs (it keeps the resolver
of its start, as Xray keeps the address of its).

### 26j. mihomo: geodata it could only fetch without the tunnel, an IPv6 address nobody asked for, every connection in the log
Three more on the same device, each seen once the server was found.

**Geodata.** A Clash file with `GEOSITE,...` or `GEOIP,...` rules - most subscriptions - needs `GeoSite.dat` and an
mmdb. mihomo downloads what its home lacks while it reads the config (also for `-t`), from GitHub, on its marked
socket: outside the tunnel. Here that is `net/http: TLS handshake timeout` after 10 s, `mihomo -t` fails, and the
profile never starts: `mihomo rejects the rebuilt config`. Worse, `check` had passed (it did not ask mihomo) and
`use` had switched to it, so the working tunnel was gone and the device offline until someone switched back over the
LAN. In mihomo's home `Country.mmdb` (also read as `geoip.metadb` or `geoip.db`, names compared without case) and
`GeoSite.dat` are enough for both rule kinds; `-t` then takes 0.6 s and nothing is fetched. So the `vpn-mihomo`
extra carries the two (`share/mihomo`; the tarball goes from 20.7 to 28.1 MB; Loyalsoldier's dated releases, pinned
by hash in `tools/fetch-mihomo.sh` - mihomo's own source, MetaCubeX/meta-rules-dat, has only a rolling `latest` whose
commits are orphans), and the driver copies them into the home when the rebuilt config names geoip or geosite and
the home has none. They stay as copied unless the file says `geo-auto-update: true` (kept from the file now, with
`geo-update-interval`, as `geox-url` already was; mihomo's downloads go through the tunnel once it runs - by its
design, not measured here) or they are deleted from the home. `geodata-mode` is no longer kept from the file: with it GEOIP rules read `GeoIP.dat`, a third file of 17 MB for the same countries. `IP-ASN` rules need
`ASN.mmdb` (9 MB), which is not carried; the refusal says so. And a profile is now tested by mihomo when it is
imported, edited or checked (where mihomo is installed), and `use` on a running VPN asks what `on` asks - the config
checks, the engine is installed, the kernel can run it - before it gives up the old tunnel: with the v2.0.0 extra
(no geodata) the same switch now answers `profile ... does not check: the VPN stays on profile legacy`, exit address
unchanged, and so does a switch to a profile whose engine was removed (it used to start a download the uplink could
never finish). mihomo's own message is still not repeated (it quotes the rule or the proxy); only where it points
is: `(at rules[1], as mihomo counts)`.

**IPv6.** mihomo gives its TUN `fdfe:dcba:9876::1/126` by default (and takes its IPv4 address from the fake-IP
range, 198.18.0.1/30, whatever `inet4-address` says). The core takes a tunnel with a global-scope IPv6 address for one
that carries IPv6 (26g): it routed IPv6 into mihomo and left the IPv6 guard off (`status --json`: `"tunnel": true,
"guard": false`). The server has no IPv6, so `wget https://www.google.com` on the device (uclient-fetch prefers
IPv6) ended in `SSL error: The connection indicated an EOF` while `wget -4` worked. `inet6-address: []` in the tun
section gives the TUN no IPv6 address (`[TUN] Tun adapter listening at: mh-mu300([198.18.0.1/30],[])`); the driver
writes it unless the `IPV6` setting is 1, as the setting's table says. After: guard on, the same wget works; with
`IPV6=1` the address and the IPv6 route are there as before.

**The log.** mihomo's default level, info, writes `[TCP] a --> b match ... using PROXY[...]` for every connection of
every client into the system log, which pushes the service's own lines out of its ring within minutes and keeps a
list of where the LAN went. The driver writes `log-level: warning` when the file names none.

### 26k. dae never came up: tcx, and a start that waited for a tc filter
dae had not been run on a device (26h says so). On 7.2.10 the service logged, every 40 s,

    dae did not attach to mu300dae within 40 s
    mu300-vpn: line 380: can't open /run/mu300-vpn/dae/lan: no such file

and started it again. dae itself was fine: by hand, with the routing the core would add, its log reaches `Bind to
LAN: br-lan`, `Bind to WAN: mu300dae`, `Total startup time: 995ms`, and the device and a LAN client leave through
its node. The driver waited for `tc filter show dev mu300dae egress` to list a bpf filter. From Linux 6.6 on dae
attaches with tcx, which tc does not list (`tc filter show` is empty on the dummy, the bridge and dae0 while it
works), there is no bpftool on the device, and its listener is in a namespace of its own (`daens`, behind a netkit
pair), so the tproxy port is not in `/proc/net/tcp` either. Both mainline kernels this project ships are past 6.6: the
wait could not end well on any device. What does show is in `/proc/<dae>/fdinfo`: one of its open files is a BPF link
with `link_type: tcx` and the dummy's `ifindex` (six tcx links in all: the dummy, the bridge, dae0 and its peer). The
start is now "a tc filter (older kernels), or that tcx link, or dae alive for 10 s"; a dae that cannot load its
programs exits, which the loop sees, and until they are bound what the core routes into the dummy ends there. The
second line was `dae_cleanup` reading a file a failed start never wrote.

Measured after (node: a Shadowsocks server on the USB link, since dae refuses the working profile's link: it asks
for `allowInsecure`, the server's certificate has expired, and dae cannot pin one): `dae up on mu300dae and br-lan`
one second after `dae config OK`, the node's exit address on the device and on the LAN client, with the kill switch
off and on - which answers 26h's open question: dae's own connections leave marked, the kill switch lets them out
and nothing else. A link subscription with `--type dae` gave one profile with its nodes.

### 26l. The panel's view of an engine: logs that hid its errors, latency that was always "unreachable", a check that did not exist
* `logs ENGINE` took the lines that name the engine. An engine's own lines do not: they are logged under the
  service's name like everything else. For mihomo that left the two lines this script writes and none of the `dial
  ... error` lines of 26i; for sing-box the pattern was also `sing`, which is in "using" - every mihomo connection
  line - and for dae it took the kernel's lines about `dae0`. `run` now prints `engine: NAME (profile ID)` first, and
  the lines of that process id are the engine's; lines of runs from before are matched by name as they were.
  sing-box runs with `--disable-color` (its `ERROR` came as `\u001b[31mERROR\u001b[0m` in the panel), and `logs`
  strips the colour codes of older lines.
* `latency` without curl (OpenWrt) fetched `http://server:port/` with `wget -q` and read the error text. OpenWrt's
  wget is uclient-fetch, whose `-q` prints nothing, so every server that does not answer plain HTTP with 200 was
  `unreachable` - all of them, the running profile's included. Without `-q` it says `HTTP error 400` or `Connection
  reset prematurely` for a server that answered and `Connection timed out` / `Failed to send request` for one that
  did not. That still calls a silent server dead (a Shadowsocks server answers nothing to a stranger; this carrier
  drops plain HTTP to the VPN server's port 443). busybox's `nc HOST PORT </dev/null` connects and ends: the connect
  and nothing else, 90 ms to the running Xray profile's server. But in a tunnel the engine's own TCP answers the
  connect on the device whatever is at the far end (10 ms for every server through dae), so nc is used for a
  connection whose route is not the tunnel (no VPN, the running Xray profile's server, a server on the LAN) and the
  fetch for the rest. curl, where there is one (Ubuntu), still times the connect in both cases, as before: through a
  tunnel that number says little. In `latency --all --json` a profile with no server (mihomo) carried the host and
  port of the profile before it.
* `profile check ID`, which the spec's table lists and the control panel calls, did not exist: the panel's check
  always answered with the usage text. It is `check ID` now.
* Seen and left as it is: with the kill switch off, a run that finds its engine missing waits in `mu300-extra
  install` (on this uplink until its downloads time out, minutes); an engine installed by hand meanwhile is picked up
  only after that, and a service stopped meanwhile leaves that download running. `mu300-vpn restart` gets past both,
  and `use` no longer leads there.

### 26m. A raw sing-box config that says nothing about DNS left the device without names
A sing-box JSON with outbounds and `route.final` and no `dns` section or hijack rule (some panels export just that)
imported, checked and connected on the U30 Air: the exit address was there, a LAN client with its own DNS (8.8.8.8)
worked - and after the resolver's cache had run out, the device itself and every client that asks the router had no
names: `nslookup example.com 127.0.0.1` "connection timed out; no servers could be reached". dnsmasq forwards to the
resolver the bearer handed out; sing-box's auto_route sends that into the tunnel like everything else; and from the
far end of the tunnel the carrier's resolver does not answer (through the same tunnel 1.1.1.1 does). For every other
driver the core redirects the device's own port-53 traffic to `REMOTE_DNS` (`mu300_vpn_dns`, in routes_up); for
sing-box, which routes by itself, it did not - 26f says "the core only adds the Tailscale rules and the DNS nat", and
only the first was true. A link's config never showed it: it answers every DNS packet itself (`hijack-dns`).

`run` now loads the redirect for sing-box too (`dns_nat_up`, before the engine starts; the next start and `off` take
it down with the rest). Measured: the same raw profile resolves names it had never asked for, on the device and
for the LAN client through the router; the link profile is unchanged (its hijack takes the redirected packets as it
took the others).

### 26n. IPV6=auto on the proxy engines: the tunnel is asked, at every start
Asked for in mu300-linux issue 202: with `IPV6=auto` a sing-box tunnel stayed IPv4 whatever its server could do.
That was the documented meaning (26g, 26j): a WireGuard config says itself whether it has IPv6, a proxy does not -
its TUN takes every IPv6 packet, the engine answers the TCP connect on the device, and whether anything comes back
is the server's business. A tunnel that takes IPv6 it cannot deliver leaves every dual-stack program waiting (26j),
so auto left Xray, sing-box, mihomo and dae on IPv4, and `IPV6=1` was the user's word that the server can.

Now a start asks (`ipv6_ask` in the core, for a driver that says `DRV_V6ASK=1`: xray, sing-box, mihomo):

* The engine comes up with an IPv6 address on its TUN (hev-socks5-tunnel: `ipv6: 'fdfe:dcba:9875::1'`; mihomo: its
  default, by not writing `inet6-address: []`; sing-box: the second `address`) and **no IPv6 routed into it** except
  the question: `ip -6 rule` 9003 keeps the engine's own marked sockets in main, 9004 sends the device's own packets
  (`iif lo`) to two addresses into table 2023, whose only route is the TUN.
* The question is `HEAD / HTTP/1.0` on port 80 of both addresses at once (curl where there is one; else busybox's
  nc, which has no timeout and ends with its input: `{ printf ...; sleep 5; } | nc ADDR 80`), and a yes is a reply
  that begins `HTTP/` within 5 s. Not a connect: that is answered by the engine's own TCP whatever the far end can
  do (26l) - `uclient-fetch` through the working profile's tunnel, whose exit has no IPv6, says "Connecting to ...",
  then "Connection reset prematurely" after 2-3 s. Not DNS to an IPv6 resolver: sing-box's `hijack-dns` and dae
  answer that themselves. Addresses, not names: at that moment nothing resolves names through the tunnel yet.
  The two: `2606:4700:4700::1111` (Cloudflare: a 301) and `2620:119:35::35` (OpenDNS: over IPv4 its twin
  208.67.222.222 answers a 404). Google's and Quad9's resolvers say nothing on port 80 (8.8.8.8 and 9.9.9.9, from
  here). Two operators, so that one of them blocked at an exit does not turn IPv6 off; a wrong no costs IPv6, never
  a leak.
* Yes: the core adds the IPv6 rules 9000-9010 (`routes6_up`). No, or nothing to ask with: the question's rules go,
  the address is taken off the TUN again (`ip -6 addr flush dev TUN scope global`), and everything is as v2.0.1 left
  it. IPv4 is routed before the question, so clients do not wait for it.
* sing-box is exec'd and routes by its config (`auto_route`), and its DNS strategy (`ipv4_only` or `prefer_ipv4`)
  is in that config too: it is asked **before** the config it will run is written - started once with the IPv6
  config but `auto_route: false` and log level `panic` (`drv_v6ask`), asked, stopped - and the config that is then
  written is exactly v2.0.1's for IPV6=1 after a yes and for auto after a no.
* One line of the log, and the same in `status` (`IPv6: ... (probe: ...)`) and `status --json` (`ipv6.tunnel`,
  `ipv6.source`: `probe`, `setting` or `config`, and `ipv6.reason`), from `$RUN/ipv6`, which every run writes:

      IPv6: through the tunnel - 2606:4700:4700::1111 answered through the tunnel (IPV6=auto asks at every start)
      IPv6: not through the tunnel, rejected on the uplinks - nothing answered over IPv6 through the tunnel, asked for 5s at most: 2606:4700:4700::1111 2620:119:35::35 (IPV6=auto asks at every start)

**Nothing beside the tunnel, at any moment.** A run that asks puts the IPv6 guard up before it takes the previous
run's routing away (`run`, before `routes_down`; behind the kill switch there is nothing to add, it rejects the
same), and never takes it down, whatever the answer: sing-box adds its IPv6 routes some time after it is exec'd, and
nothing of ours runs then to take a guard down at the right moment. So after a yes `status --json` says `"tunnel":
true, "guard": true`: IPv6 that is routed into the tunnel does not meet the guard (it rejects on the uplinks only,
and lets the engine's marked sockets out), and what the routing does not send into the tunnel is rejected, not
carried by the carrier. Behind the kill switch the question adds no nft transaction at all. `IPV6=1`, and a
WireGuard or OpenVPN config with its own IPv6, keep the guard as they had it (off while the tunnel carries IPv6).

**The LAN's side, found on the way.** With IPv6 routed into the tunnel by the core (xray and mihomo now; mihomo with
`IPV6=1` and WireGuard before), a LAN client's IPv6 never worked: rule 9010 sent *everything* into the tunnel,
including the tunnel's answers to the client and the device's own (a ping of the router's IPv6 address from the LAN
got no answer; `ip -6 route get <client>`: `dev xtun table 2022`). `LAN_CIDRS` names IPv4 networks, and a prefix
that comes from the carrier (the images relay the bearer's /64 to the LAN: `dhcp.lan.ra='relay'`) cannot be a
setting. `routes6_up` now has, at 9001, `lookup main suppress_prefixlength 0`: what main has a route to that is not
its default stays there - the LAN's prefix, and the host routes odhcpd keeps for the clients of a relayed prefix.
sing-box's auto_route has the same rule. (The bearer's own /64 is such a route too: a packet to an address in it
that is no LAN client's leaves on the bearer when neither guard nor kill switch is up - that is with `IPV6=1`, or a
WireGuard or OpenVPN config's IPv6, and the kill switch off.)

**`IPV6=1` on Xray** did nothing before: hev-socks5-tunnel was never given an IPv6 address, so the core never
routed IPv6 into it. It gets one now, as the setting's description always said.

**Measured** on the U30 Air (OpenWrt, kernel 7.2.10; the bearer has no IPv6 at all, the LAN has its ULA prefix). The
LAN client was a network namespace on the device, bridged into br-lan with an address of that prefix and the router
as its gateway: the Mac on the USB link gets no IPv6 address there, the carrier gives none to relay.

* **No, on the working profile's server** (its exit has no IPv6). Xray: `tunnel up` at :51, the line above at :54;
  no IPv6 rule, no global address left on xtun, guard on, exit address unchanged - the state v2.0.1 leaves. The
  same link on sing-box: the line 3 s after the bootstrap resolver was found, which is what the question adds to
  that start (the engine started and stopped once more, and the question); the config it then runs is v2.0.1's.
* **No, on a throwaway server on the USB link** (VLESS and Shadowsocks, on the Mac, which has no IPv6 route: it
  dials the asked addresses and gets "no route to host"). xray and mihomo with the kill switch off, sing-box with
  it on: the line after 1-2 s, the same state; an IPv6 fetch fails at once on the device, and after 1 s on the LAN
  client (sing-box: 8 s, see below); the client's IPv4 is not touched.
* **Yes, on the same server made to deliver** every IPv6 destination to an HTTP server on its own `::1` (a route
  rule of the server; the device knows nothing of it). xray, sing-box and mihomo with the kill switch off, sing-box
  and mihomo also with it on: the line after 1-2 s (sing-box 2-3 s, its second start included); then
  `uclient-fetch 'http://[2001:db8::80]/'` answers on the device and on the LAN client within a second, the client's
  IPv4 works as before, the client pings the router's IPv6 address, and `status --json` says `"tunnel": true,
  "guard": true, "source": "probe"`.
* `IPV6=1` on the working profile (xray): IPv6 routed in, guard off, an IPv6 fetch ends after 2 s with nothing -
  what the setting asks for. `IPV6=0`: nothing routed, guard on, `"source": "setting"`.

**Not measured.** An exit with real IPv6: neither the working profile's server nor the Mac has any, so the yes was
measured against a server that hands every IPv6 destination to a local HTTP server - the device's side of it (the
TUN, the routing, the question, the guard, a LAN client) is the real thing, the IPv6 internet behind the server is
not. For the same reason the two addresses were never fetched over IPv6 from here: Cloudflare's is known to
answer, OpenDNS's is taken from its IPv4 twin. A leak on a bearer that has IPv6 (this one has none; the unit tests
hold the order of the nft and ip calls). curl's path of the question on a device (Ubuntu's images; the unit tests
run both paths against a server on `::1`). A relayed carrier prefix on the LAN. Xray behind the kill switch (a
VLESS link runs on sing-box there).

**The yes against a real server** (v2.0.2, measured by the reporter of mu300-linux issue 202 on mu300-linux
v2026.10.22, OpenWrt 25.12.5, kernel 7.2.10; not on our devices): Xray with `IPV6=auto` and a VLESS server whose exit
has IPv6. `status` said `IPv6: through the tunnel (probe: 2606:4700:4700::1111 answered through the tunnel)`, `curl
-6` from a LAN client got the server's own IPv6 exit address, and the IPv4 exit stayed as it was. That is the first
measurement of the "yes" outcome against a real IPv6 exit, and of Cloudflare's address answering over IPv6 through a
tunnel. sing-box could not be measured against the same server then: every connection of its VLESS outbound was
turned away (26o). (A restart loop of hev-socks5-tunnel reported with it was, by the reporter's own account, state
left from switching profiles back and forth: a clean restart cured it.)

**Left as it is.** dae: its "tunnel" is a dummy interface without an IPv6 address, the core has never routed IPv6
into it with any setting, and its LAN side catches the LAN's packets itself: not asked, IPv4 as before. OpenVPN and
WireGuard: their config's own address decides, as before. A server that gains or loses IPv6 while the tunnel is up
is noticed at the next start. An engine whose rules send the asked addresses `DIRECT` is asked about the uplink,
which is where its clients' IPv6 would go, too. mihomo, with an IPv6 address on its TUN, puts a default route into
table 2022 and an `oif mh-mu300` rule itself (with `IPV6=1` in v2.0.1 as well): after a no both are still there and
reach nothing. And sing-box without an IPv6 address adds `ip -6 rule 9000: from all unreachable` (strict_route), in
v2.0.1 as now: the device's own IPv6 fails at once, but a LAN client's waits 8 s for nothing and the router's own
IPv6 address does not answer the LAN while that tunnel is up - the guard's "rejected at once" does not hold for
forwarded IPv6 on sing-box.

### 26o. v2.0.2's two defects: Xray without its geodata, and VLESS links sing-box wrote differently from Xray
Reported in mu300-linux issue 202 against the v2.0.2 pre-release (mu300-linux v2026.10.22, OpenWrt 25.12.5, kernel
7.2.10): "v2.0.2 ships without geosite.dat/geoip.dat, xray fails to start until they are downloaded by hand", and
"sing-box: tunnel up, every connection EOF; same server, UUID and port, xray works". Everything below was measured
on a Mac, in containers and from the release assets; no device was used.

**Packaging.** The release tarballs, listed (`tar tzvf`, every asset of v1.0.0 to v2.0.2):

| release | `vpn-xray` | the bundle (`mu300-linux-vpn.tar.gz`) | `vpn-mihomo` share | `vpn-dae` share |
|---|---|---|---|---|
| v1.0.0 | (no engine extras) | bin/xray, hev-socks5-tunnel, sing-box - no geodata | (none) | - |
| v2.0.0 | bin/xray, bin/hev-socks5-tunnel - no geodata | as v1.0.0 | **none** | geoip.dat, geosite.dat |
| v2.0.1 | the same files, the same bytes | the same | Country.mmdb, GeoSite.dat (26j) | the same |
| v2.0.2 | the same files, the same bytes | the same | the same | the same |

So nothing changed between v2.0.1 and v2.0.2 in `vpn-xray` or the bundle (the same xray, 34209918 bytes, and
hev-socks5-tunnel, 395416; the tarballs differ only in their metadata): **no release ever carried Xray's
`geoip.dat` and `geosite.dat`**. `tools/fetch-xray.sh` took only the binary out of Xray's release zip
(`unzip xray.zip xray`), which has both files beside it. A VLESS/VMess/Trojan/Shadowsocks link profile never
needed them (the config the driver writes names no `geoip:` or `geosite:`), but an Xray JSON profile from a panel
nearly always does (`geoip:private`, `geosite:category-ads-all`), and Xray refuses to start such a config without
the files. Xray looks for them beside its binary (and in `/usr/share/xray`, `/usr/local/share/xray`) unless
`XRAY_LOCATION_ASSET` says where. Why it looked like "share/ is gone" in v2.0.2: `mu300-extra install` replaces an
extra's whole directory, so whatever was put into it by hand (or by an earlier experiment) is gone after every
install of the extra - the files never came from a release.

Fixed in v2.0.3: `fetch-xray.sh` takes `geoip.dat` and `geosite.dat` from the same zip (the same pinned hash) into
`share/xray`; `vpn-xray` and the bundle carry them; the xray driver sets `XRAY_LOCATION_ASSET` to the extra's
`share/xray` when both files are there and nothing else set it (`xray_assets`, before `xray run -test` and before
the run); a raw config Xray rejects while it names `geoip:`/`geosite:` and no geodata was found says so.
`tools/make-module.sh` refuses to build when an engine's files are missing (Xray: geoip.dat, geosite.dat; mihomo:
Country.mmdb, GeoSite.dat; dae: geoip.dat, geosite.dat). `tests/test_module.py` unpacks every extra and the bundle
where `mu300-extra` puts them and asks each driver where it points its engine (`xray_assets`, `mihomo_share`,
`dae_assets`): a tarball without the files fails it, as v2.0.0's `vpn-mihomo` and every `vpn-xray` so far would
have. The two files are Loyalsoldier's v2ray-rules-dat (its categories `GREATFIRE`, `WIN-SPY`, `GFW` are in
geosite.dat), 30 MB together, 7.8 MB compressed: `vpn-xray` grows from 12.4 to about 20 MB.

**The VLESS matrix.** `tools/vless-matrix.sh` runs every VLESS variant a share link can name against a real Xray
server: a fresh CA and certificate, a UUID, REALITY and VLESS Encryption keys (all made for the run and thrown
away), an Xray 26.3.27 server whose inbound is the variant, and for each engine the client config the module's own
code writes from the link - the sing-box driver's `drv_check` and `outbound_json`, the xray driver's `drv_check` and
`gen_xray` - run by the pinned sing-box 1.14.1 and Xray 26.3.27 behind a SOCKS port, and a page fetched through it.
Everything on loopback, no TUN, no root: in a linux/arm64 Alpine container on an Apple silicon Mac (the pinned
engines are arm64), and in CI on an arm64 runner (`tests.yml`, job `vless-matrix`). `ok`: the page came back;
`refused`: the link was refused at check with a message; `FAIL`: the engine ran and nothing came back (with the
server's and the client's last words).

| case (link) | sing-box v2.0.2 | sing-box v2.0.3 | xray v2.0.2 | xray v2.0.3 |
|---|---|---|---|---|
| none, tcp | ok | ok | ok | ok |
| none, tcp, `headerType=http` | FAIL: "unknown version: 72" | refused | FAIL: "invalid method" | ok |
| none, ws | ok | ok | ok | ok |
| none, ws, `path=/ws?ed=2048` | **FAIL**: server "failed to validate path, request:/ws?ed=2048, config:/ws", client EOF | ok | ok | ok |
| none, ws, the server's path with `?ed=2048` too | **FAIL**: the same | ok | ok | ok |
| none, grpc; grpc `mode=multi` | ok | ok | ok | ok |
| none, httpupgrade | ok | ok | ok | ok |
| none, httpupgrade, `path=/hu?ed=2048` (either server path) | **FAIL**: server "bad path" | ok | FAIL: never dialled | ok |
| none, xhttp | refused ("not supported by this helper") | refused (no XHTTP in sing-box) | ok | ok |
| none, `type=splithttp` | refused | refused | refused | ok |
| none, tcp, VLESS Encryption (`encryption=mlkem768x25519plus...`) | **FAIL**: server "ML-KEM-768 handshake" | refused | ok | ok |
| tls, tcp; with `fp=chrome`; with `alpn=h2,http/1.1` | ok | ok | ok | ok |
| tls, tcp, `fp=randomizednoalpn` | FAIL: "unknown uTLS fingerprint" | ok (chrome) | ok | ok |
| tls, tcp, `allowInsecure=1`, another SNI | ok | ok | ok | ok |
| tls, ws (`fp=chrome`) | ok | ok | ok | ok |
| tls, ws, `alpn=h2,http/1.1` | **FAIL**: server "http2: error reading preface ... bogus greeting GET /ws", client EOF | ok | ok | ok |
| tls, ws, `path=/ws?ed=2048` | **FAIL**: "failed to validate path" | ok | ok | ok |
| tls, ws, `fp=randomizednoalpn` | FAIL: "unknown uTLS fingerprint" | ok | ok | ok |
| tls, ws, `fp=randomized` | FAIL: "tls: internal error" (now and then) | ok (this run) | ok | ok |
| tls, grpc; with `alpn=h2,http/1.1` | ok | ok | ok | ok |
| tls, httpupgrade | ok | ok | ok | ok |
| tls, xhttp | refused | refused | ok | ok |
| tls, `type=h2` | refused | refused | refused | refused |
| tls, tcp, vision; vision + `packetEncoding=xudp` | ok | ok | ok | ok |
| tls, tcp, `flow=xtls-rprx-vision-udp443` | FAIL: "unsupported flow" | ok | ok | ok |
| tls, tcp, VLESS Encryption | **FAIL**: "ML-KEM-768 handshake" | refused | ok | ok |
| reality, tcp (`fp=chrome`; `fp=firefox`, no `sid`) | ok | ok | ok | ok |
| reality, tcp, no `fp` | FAIL: "uTLS is required by reality client" | ok (chrome) | ok | ok |
| reality, vision; vision + `spx=/`; grpc | ok | ok | ok | ok |
| reality, xhttp | refused | refused | ok | ok |

v2.0.2: 14 of the 39 cases not as they should be (the table's expectations are v2.0.3's); v2.0.3: none. The cases in
bold are the report's symptom exactly: the tunnel comes up (sing-box starts, its config checks), every connection
reaches the server, the server drops it, the client sees EOF, and the same link works on Xray. The most common links
of that shape are a WebSocket path with `?ed=2048` (panels add it for early data), `alpn=h2,http/1.1` on a WebSocket
link, and VLESS Encryption.

What changed, all in `sb_vless` (lib/vpn/uri.sh), which the sing-box outbound is now written from:
* `?ed=N` on a ws or httpupgrade path is early data, not part of the path: Xray takes it off on both ends.
  sing-box gets the path without it, and for ws `max_early_data: N` with `early_data_header_name:
  Sec-WebSocket-Protocol`, which is how Xray's client sends it (httpupgrade: no early data; Xray's server waits for
  none). Only `ed=` with a number of at most 5 digits counts, anywhere in the query; the rest of the query stays.
* `h2` is taken out of the ALPN of a ws or httpupgrade link (an HTTP/1.1 upgrade: a server that accepts h2 reads
  the request as an HTTP/2 preface and closes), as `h3` always was for every link; gRPC keeps h2.
* `fp=randomizednoalpn` (Xray's; sing-box does not know it) is chrome; a REALITY link without `fp` gets chrome, which
  is Xray's default too; `flow=xtls-rprx-vision-udp443` is vision (sing-box's vision lets UDP/443 through anyway).
* Refused, at import and check of a sing-box profile and before any config is written, with a message that never
  repeats the link's id or keys: VLESS Encryption (sing-box 1.14 has none), XHTTP and `splithttp`, `headerType=http`
  on TCP, HTTP/2 (`type=h2`/`http`, removed from Xray 25 as well: the xray driver refuses it too), a flow or uTLS
  fingerprint sing-box does not know, a REALITY link without `pbk`, a transport sing-box has none of for Xray.
* **Behind the kill switch**, where a VLESS link of an xray profile runs on sing-box when sing-box is installed: a
  link sing-box cannot run stays on Xray (the log says why), behind the kill switch through the resolve window as
  on a device with only `vpn-xray`; with only sing-box installed it is not started, the kill switch stays up, and the
  message says `mu300-vpn engine install xray`. `mu300-vpn check` and adding or editing such a profile print a note
  that says the same (the link is fine for Xray, so it is not refused there).
* Xray, found on the way: `headerType=http` on TCP is now written (`rawSettings.header`, with the link's path and
  Host lists; v2.0.2 dropped it and the server read the VLESS header as a broken HTTP request), `type=splithttp` is
  XHTTP, and an httpupgrade path loses its `?ed=` (Xray 26's HTTPUpgrade client with early data waited for ever and
  never dialled).

`tests/test_vless_links.py` holds the table as unit tests: links and the exact sing-box outbound JSON each gives,
the refused links and what the refusal says (and that it names no secret), Xray's streamSettings for the variants
above, `vless_on_sing_box` behind the kill switch, and `xray_assets`.

**A tunnel that is up and carries nothing** said nothing in the log: sing-box logged at `warn`, and a server that
drops the client is a connection that ends. Now a tunnel that comes up gets a watch beside it (`exit_watch`, every
engine): the exit check `status` runs (`api.ipify.org`, an address and nothing else, so a captive portal's page does
not count) is asked every 20 s until it answers - one fetch for a working tunnel - and after three in a row that got
nothing the log gets one line:

    sing-box: the tunnel is up, but nothing gets through it (3 checks in a row, exit IP unreachable). Most likely the server turns this client away: a link parameter it reads differently (transport, path, ALPN, flow, VLESS Encryption, fingerprint: mu300-vpn check), a wrong or expired id or password, the server's clock, or a server that is down or blocked on this uplink; or REMOTE_DNS (1.1.1.1) does not answer through it. The engine's own words: mu300-vpn logs sing-box -n 50

then it asks once a minute and says so when something gets through; it ends with the engine.

**Not measured.** All of the above is container-only: no device, no TUN, no real server. The matrix runs the
outbound sing-box would use, not the whole config `gen_singbox` writes (TUN, DNS, routes are as v2.0.2 had them,
and the reporter's tunnel came up); one Xray server version (26.3.27) and only Xray as the server (a sing-box or
3x-ui server reads links its own way); `fp=randomized` failed now and then on sing-box with Xray's TLS server and
has no expectation in the table. Which variant the reporter's link has is not known (no secrets were asked for):
the bold rows are the candidates, and v2.0.3 either runs it or says why it does not. The exit watch's line was
seen only in the unit tests.
