# VPN toolkit ①: profiles, engine drivers, one command for every protocol

Date: 2026-10-07. Status: architecture approved in conversation (sub-project ① of the VPN toolkit); this document
fixes the details. ② is the LuCI screen on top of it, ④ adds L2TP, PPTP, IKEv2 and Tailscale exit nodes.

## Why

`mu300-vpn` speaks one protocol: a VLESS share link in `/etc/mu300/vpn.conf`, run by Xray (behind
hev-socks5-tunnel) or sing-box. People have WireGuard configs, OpenVPN files, Clash/mihomo subscriptions, VMess,
Trojan and Shadowsocks links, and raw Xray/sing-box JSON from their panels. The user's goal is one VPN screen for all
of them. That needs, under the screen, a store of named profiles, one driver per engine behind a fixed contract, and
a core that owns everything the drivers must not differ in: the kill switch, policy routing, DNS, Tailscale.

What works today must keep working unchanged: the U30 Air runs a legacy VLESS `vpn.conf` (ENGINE=xray, kill switch
off), and every test in `tests/test_vpn.py` stays green (the kill switch fails closed, the download window, xray never
runs without the kill switch's sing-box substitute, Tailscale rules 5198-5200).

## What the user gets

```
mu300-vpn profile list                       id, type, name, * on the active one (TSV)
mu300-vpn profile show ID                    name, type, source, created, server - never a secret
mu300-vpn profile add TYPE NAME FILE|URI     store a profile of that type
mu300-vpn profile import FILE|URI [NAME]     the same, type sniffed from the scheme or the content
mu300-vpn profile edit ID FILE|URI           replace its config (checked first)
mu300-vpn profile set ID KEY VALUE           a per-type option (TLS_PIN_SHA256, MIHOMO_STACK, OVPN_USER, ...)
mu300-vpn profile remove ID                  not the active one while the VPN is on
mu300-vpn profile use ID                     make it active; a running VPN restarts on it
mu300-vpn profile export ID                  the raw config to the terminal (the one place secrets are printed)
mu300-vpn on | off | restart | status        on: ENABLE=1 + service; off: ENABLE=0, service stopped, kill switch down
mu300-vpn settings [get [KEY] | set KEY VALUE]
mu300-vpn engines [install ENGINE]           TSV: engine, present|missing, path or the command that gets it
mu300-vpn check [ID]                         validate a profile with its engine (default: the active one)
mu300-vpn gen | run | guard | status | engines   unchanged for the service units, mobile-data and wifi-client
```

`mu300-toolkit`'s VPN menu works in profiles: list, activate, import (paste a link or a path), remove, kill switch,
engines, on/off, restart.

## Storage

Everything under `/etc/mu300`, which updates keep. Each system (Ubuntu, OpenWrt, openwrt-luci, Arch) has its own.

```
/etc/mu300/vpn.conf                    ENABLE=0|1 - still THE switch (mu300-update, android-install.sh, wifi-client,
                                       mu300-extra, the dashboard and older images read it); legacy keys below it
/etc/mu300/vpn/                        0700
    settings                           KEY=VALUE, 0600
    active                             the active profile id
    legacy.snapshot                    the legacy keys as last migrated (0600; see Migration)
    profiles/<id>/                     0700; id: [a-z0-9-]{1,32}
        meta                           NAME= TYPE= SOURCE=manual|subscription:<id> CREATED=<epoch> + per-type options
        uri | config.json | config.yaml | wg.conf | client.ovpn      (0600) exactly one
        auth.txt                       OpenVPN user/password (0600), only when the profile has them
    cache/mihomo/                      mihomo's home (GeoIP/GeoSite downloads survive reboots)
/run/mu300-vpn/                        0700, generated configs, iface, server-ip, dns, pids
```

`meta` and `settings` are never sourced: values are read with `sed -n "s/^KEY=//p"` and written single-quoted with
`'` escaped, so a name typed in LuCI cannot run anything. `MU300_VPN_DIR` (tests) defaults to the directory of
`MU300_VPN_CONF` + `/vpn`, so a test that points the conf into a scratch directory gets its store there too.

### Settings

| key | values | default | |
|---|---|---|---|
| KILL_SWITCH | 0, 1 | 1 | anything but 0 is 1 (as today) |
| TAILSCALE | 0, 1 | 1 | anything but 0 is 1 |
| IPV6 | 0, 1 | 0 | |
| REMOTE_DNS | IPv4/IPv6 address | 1.1.1.1 | DNS for the device and clients, through the tunnel |
| BOOTSTRAP_DNS | IPv4/IPv6 address | 1.1.1.1 | for server names, outside the tunnel (sing-box, mihomo) |
| LAN_CIDRS | comma list of CIDRs | empty | the device's own LAN is always added (as today) |
| MIHOMO_CONTROLLER | empty or `127.0.0.1:PORT` / `[::1]:PORT` | empty | mihomo's external-controller; off by default |
| XRAY HEV SING_BOX MIHOMO OPENVPN | absolute path | empty | another engine binary (as XRAY= in vpn.conf today) |

`settings set` validates and refuses (exit 2) a value outside these; on read an invalid value counts as the default.

### Profiles and types

| TYPE | config | engine | from |
|---|---|---|---|
| xray | `uri` (vless/vmess/trojan/ss link) or `config.json` (raw Xray JSON) | xray + hev-socks5-tunnel | vpn extra |
| sing-box | `uri` (vless link) or `config.json` (raw sing-box JSON) | sing-box | vpn extra |
| mihomo | `config.yaml` (Clash/mihomo) | mihomo | new `vpn-mihomo` extra |
| wireguard | `wg.conf` (wg-quick format) | kernel WireGuard + `wg` | wireguard-tools package |
| openvpn | `client.ovpn` (+ `auth.txt`) | openvpn | `apk add openvpn-openssl` / `apt-get install openvpn` |
| l2tp pptp ikev2 tailscale-exit | reserved | - | "not available in this version" (④) |

Import sniffing: `vless://` → xray, `vmess://` `trojan://` `ss://` → xray; a file: `[Interface]` → wireguard;
`client`/`remote ` lines or `<ca>` → openvpn; JSON with `"protocol"` in outbounds → xray, with `"type"` → sing-box;
YAML with `proxies:` or `proxy-providers:` → mihomo. The ID is the name lowercased, every run of other characters a
`-`, cut to 32, `-2`, `-3` ... when taken; empty → the type.

## Engine drivers

`/opt/mu300/lib/vpn/<type>.sh`, sourced by `mu300-vpn` (`MU300_VPN_LIB` for tests). The loader refuses a type that
is not `[a-z-]+` or has no file; for the reserved ones it says `TYPE: not available in this version`. Each driver
defines:

| function | does |
|---|---|
| `drv_engines` | prints the programs it needs, one path per line (resolved: extra, then /opt/mu300/bin, then PATH) |
| `drv_engines_ok` | 0 when they are all executable (and, for wireguard, the kernel has it) |
| `drv_check` | validates the profile (`$PDIR`), with the engine's own checker where there is one; errors to stderr |
| `drv_gen` | the runtime config under `$RUN` from the profile + settings; writes `$RUN/server-ip` (addresses to keep off the tunnel, one per line) and optionally `$RUN/dns` |
| `drv_start` | brings up ONE tunnel interface, sets `TUN` and `DRV_PIDS`, prints `tunnel up on $TUN`; or, with `DRV_FOREGROUND=1`, execs the engine (sing-box) |
| `drv_alive` | 0 while the engine and its interface are there |
| `drv_stop` | stops what `drv_start` started, removes its interface |
| `drv_status` | extra status lines, never a secret |
| `drv_import SRC` | writes the profile files into `$PDIR` from a link or a file, or fails |

`DRV_ROUTES=core` (default) means the core installs the routing; sing-box sets `self` (its `auto_route` does exactly
what the core does, same prefs and table, as today). The core then:

1. puts the full kill switch up (KILL_SWITCH=1), before anything that can fail - unchanged;
2. migrates a legacy vpn.conf (below), loads the active profile and its driver;
3. gets missing engines: vpn / vpn-mihomo extras by `mu300-extra adopt`/`install` (through the download window when
   the kill switch is up - the window code is unchanged, the extra's name is now a parameter); packages are never
   installed by the service, it fails closed with the command to run;
4. `drv_gen` (which includes the check);
5. adds the tunnel to the wan firewall zone on OpenWrt (as today, for every tunnel name);
6. KILL_SWITCH=0: the kill switch down;
7. clears leftover routing, `drv_start`, then (core routing) `routes_up`: rule 9000 `fwmark 0x2d0 lookup main`, 9001
   LAN_CIDRS → main, 9002 each server address → main, `default dev $TUN table 2022`, 9010 `lookup 2022`, the
   Tailscale rules, and the DNS nat (device's own port 53 → `$RUN/dns` or REMOTE_DNS, marked traffic exempt). IPV6=1
   adds the same for IPv6 (`ip -6`) when the tunnel has an IPv6 address;
8. waits while `drv_alive`; on any exit `drv_stop` and `routes_down` - the kill switch stays.

### Marks: every engine's own traffic carries 0x2d0

The kill switch lets only marked traffic out on an uplink, and rule 9000 keeps it off the tunnel. Each driver marks:

* **xray**: `streamSettings.sockopt.mark = 720` on every outbound - from links as today, and for raw JSON injected
  with `jq` into every outbound. Raw JSON also gets our SOCKS inbound in place of its own `inbounds` (nothing listens
  on the LAN), and server names in `vnext`/`servers` are resolved by the core and replaced by addresses (the name
  stays as `serverName` where TLS/REALITY had none) - Xray's own resolver sits behind the tunnel it is building.
* **sing-box**: `route.default_mark`. Raw JSON: `jq` replaces `inbounds` with our TUN (gvisor, `sbtun`,
  `auto_route`, `strict_route`, the LAN excluded - as generated today), sets `default_mark`, `auto_detect_interface`,
  and adds a `mu300-bootstrap` UDP DNS server (BOOTSTRAP_DNS) used as `default_domain_resolver` unless the config
  names its own. Checked with `sing-box check`.
* **mihomo**: `routing-mark: 720`. The YAML's top-level `tun`, `dns`, `routing-mark`, `interface-name`,
  `auto-redirect`, `external-controller*`, `external-ui*`, `secret`, `allow-lan`, `bind-address`, `listeners`,
  `iptables`, `tproxy-port`, `redir-port` blocks are removed (awk: a top-level key and its indented block) and ours
  appended: TUN `mh-mu300`, stack from the profile's `MIHOMO_STACK` (default gvisor), `auto-route: false`,
  `auto-detect-interface: false`, no DNS hijack; `dns` with `proxy-server-nameserver`/`default-nameserver` =
  BOOTSTRAP_DNS, `nameserver` = REMOTE_DNS, `respect-rules: true`; `allow-lan: false`; `external-controller` only
  when MIHOMO_CONTROLLER is set. Checked with `mihomo -t`.
* **wireguard**: `wg set wg-mu300 fwmark 0x2d0`. `wg.conf`'s wg-quick keys (Address, DNS, MTU, Table, Pre/PostUp/Down,
  SaveConfig) are stripped for `wg setconf`, the Endpoint name is resolved, Address goes on with `ip addr`, MTU
  default 1420, DNS (first) to `$RUN/dns`. A peer without `0.0.0.0/0` in AllowedIPs gets a warning (traffic outside
  it is dropped by WireGuard - closed, not leaked). A kernel without WireGuard (the 5.4 vendor kernel) fails the check
  with that message.
* **openvpn**: `--mark 720`. The `.ovpn` is copied with every script or local-system directive removed (`up`, `down`,
  `route-up`, `route-pre-down`, `ipchange`, `tls-verify`, `auth-user-pass-verify`, `learn-address`,
  `client-connect`, `client-disconnect`, `script-security`, `plugin`, `dev`, `dev-type`, `dev-node`, `daemon`, `log`,
  `log-append`, `status`, `management*`, `cd`, `chroot`, `user`, `group`, `writepid`, `iproute`, `redirect-gateway`,
  `route`, `route-ipv6`, `auth-user-pass`), inline `<blocks>` untouched; `remote` names are resolved to addresses.
  Run as `openvpn --config $RUN/openvpn.conf --dev tun-mu300 --dev-type tun --route-noexec --pull-filter ignore
  redirect-gateway --mark 720 --script-security 2 --up /opt/mu300/lib/vpn/openvpn-up --setenv MU300_VPN_RUN $RUN
  [--auth-user-pass $PDIR/auth.txt] --auth-nocache`. `openvpn-up` is our own script and the only one: it writes the
  pushed DNS (`dhcp-option DNS`) to `$RUN/dns` and `$RUN/ovpn-up`. The driver waits for that file.

### Names behind the kill switch: the resolve window

Server names (wireguard Endpoint, openvpn remote, xray link and raw JSON) are resolved before the tunnel exists. With
the kill switch up the device's own DNS is dropped too (today's reason xray needs the sing-box substitute). The core
opens a **resolve window**: the download window's ruleset with only the DNS sets filled (the device's resolvers,
30 s timeouts; clients' DNS to the device dropped), resolves, and puts the full kill switch back - one transaction
each way, never a gap. The legacy behaviour stays as it is for VLESS links: with the kill switch, a VLESS xray profile
runs on sing-box when it is installed, and an allowInsecure link that needs a pin is refused rather than moved
(the existing tests). A non-VLESS xray link that asks for allowInsecure with no pin under the kill switch fails closed
(`mu300-vpn profile set ID TLS_PIN_SHA256 ...`).

## Migration

Per system, at every start of `mu300-vpn` (any command), idempotent, and only when `/etc/mu300/vpn` can be written
(as root); otherwise the legacy file is read in memory, as today.

* vpn.conf's legacy keys (everything but ENABLE: VLESS_URI ENGINE KILL_SWITCH TAILSCALE REMOTE_DNS BOOTSTRAP_DNS
  LAN_CIDRS IPV6 UPSTREAM_HTTP_PROXY TLS_PIN_SHA256 XRAY HEV SING_BOX) are compared with `legacy.snapshot`. Every key
  whose value differs (or is new, or is gone) is applied: a settings key is set (normalized: KILL_SWITCH/TAILSCALE
  not 0 → 1) or reset to its default; VLESS_URI/ENGINE/UPSTREAM_HTTP_PROXY/TLS_PIN_SHA256 update profile `legacy`
  (TYPE = ENGINE, or sing-box when ENGINE is unset and the kill switch on, else xray - today's default), created on
  the first non-empty VLESS_URI. The snapshot is rewritten. A first migration with no active profile makes `legacy`
  active.
* So: the first run moves everything; a later run does nothing; a later edit of vpn.conf (the old README's way, or an
  older image's `save_pin` after a downgrade and upgrade) wins for the keys it changed, and settings changed with the
  new commands are kept otherwise.
* vpn.conf is left in place with its keys (an older image installed over this one finds a working VLESS VPN) and
  gets one comment line at the top: `# mu300-vpn: migrated to /etc/mu300/vpn (profile legacy); only ENABLE is read
  from this file now`. `on`/`off` change only its ENABLE line (and create the file with just that line when there is
  none). The xray pin fetched for a link is saved in the profile's meta.

## Engines and the new extra

* `tools/fetch-mihomo.sh [OUTDIR]`: MetaCubeX/mihomo v1.19.32 `mihomo-linux-arm64-v1.19.32.gz`, pinned by sha256,
  writes `OUTDIR/mihomo`. `tools/make-extra.sh vpn-mihomo OUT TAG` builds `mu300-extra-vpn-mihomo.tar.gz`
  (`bin/mihomo`, `components`). `tools/make-release.sh` builds it, audits it with the others and lists it in the
  release notes. `mu300-update`: `EXTRAS="vpn lang vpn-mihomo"`, its description; `mu300-extra list` shows it.
* `mu300-vpn engines` prints one TSV line per engine: `xray`, `hev-socks5-tunnel`, `sing-box` (vpn extra),
  `mihomo` (vpn-mihomo extra), `wireguard` (kernel + wg), `openvpn` (package), each `present PATH` or
  `missing HOW`. Exit 0 when the active profile's engines are present (as the toolkit expects today).
* `mu300-vpn engines install ENGINE`: `mu300-extra install vpn|vpn-mihomo`, or `apk add openvpn-openssl` /
  `apk add wireguard-tools` on OpenWrt, `apt-get install -y openvpn` / `wireguard-tools` on Ubuntu, `pacman -S
  --noconfirm openvpn` / `wireguard-tools` on Arch. LuCI's Engines tab (②) calls this.
* Images: `jq` is added to Ubuntu, OpenWrt and Arch (the raw-JSON drivers need it), `wireguard-tools` to Ubuntu
  and Arch (OpenWrt has it). Nothing else grows.

## Other callers

* `wifi-client`'s `vpn_kill_switch` reads KILL_SWITCH from `etc/mu300/vpn/settings` first, then vpn.conf.
* The OpenWrt dashboard (`dashboard-info`) shows the active profile's type as the engine and treats the tunnel as up
  when `/run/mu300-vpn/iface` names an interface that exists (any type).
* systemd unit and init script: descriptions only; both still start on `vpn.conf`, which `on` creates.
* `mu300-extra remove vpn` still refuses while ENABLE=1 (the switch stayed where it was).

## Security

* IDs `[a-z0-9-]{1,32}` everywhere a path is built from one; profile directories 0700, files 0600, `$RUN` 0700.
* No secret reaches stdout, stderr or the log except through `profile export` (and `settings get` of a non-secret
  set); error messages name the profile id, never the link. `profile show` shows the server host and port only.
* OpenVPN: `--script-security 2` with only our `--up` script; every script directive of the file removed.
* mihomo: external controller off unless MIHOMO_CONTROLLER says so, and then only on loopback; `allow-lan: false`.
* xray raw JSON: its inbounds replaced by our loopback SOCKS. sing-box raw JSON: its inbounds replaced by our TUN.
* The kill switch is unchanged: only marked traffic, NTP and the Wi-Fi client's DHCP leave on an uplink; forwarded
  traffic to an uplink is dropped. Every new driver marks its own sockets, so none of them needs an exception.

## Testing

* `tests/test_vpn.py`: kept green; functions that moved into drivers are called through the loader.
* `tests/test_vpn_drivers.py` (every shell): the driver contract per type with stub engines recording their
  arguments (`xray`, `hev-socks5-tunnel`, `sing-box`, `mihomo`, `wg`, `openvpn`, `ip`, `nft`); the URI parsers
  (vless, vmess base64 JSON, trojan, ss SIP002 and legacy base64, wg .conf); raw JSON/YAML forcing (marks, inbounds,
  TUN, controller); migration (first, idempotent, an edited vpn.conf, not writable); profile CRUD, ID validation,
  `use` keeping the kill switch (no `delete table` between two runs); settings validation; `engines` output;
  reserved types; nothing secret in stdout/stderr of `list`/`show`/`status`/`run`.
* `tests/test_static.py`: the vpn-mihomo extra in make-release's build and audit lists and mu300-update's EXTRAS;
  jq in the three image package lists.
* On the device (U30 Air, OpenWrt, mainline 7.2): migration of the working legacy VLESS conf without reading it,
  `status` with the exit IP afterwards; WireGuard and OpenVPN against test servers in Docker on the oracle-arm box;
  mihomo with a minimal YAML to a Shadowsocks server there.

## Not in ①

L2TP, PPTP, IKEv2 (`CONFIG_XFRM_INTERFACE=m` is in the mainline config, so ④ can use an xfrm interface), Tailscale
exit nodes as a profile, subscriptions (SOURCE=subscription is reserved), per-app/per-client routing, the LuCI screen.
