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
