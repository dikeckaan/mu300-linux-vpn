# Engine extras, dae, IPv6 and a machine-readable CLI (module v2)

Status: design, implemented on branch `engine-extras` (this repository) and `vpn-engine-extras` (mu300-linux).
Audience: the people who run the module, and the LuCI app that is built on the CLI below (section 4 is its contract).

## 1. Goals and hard rules

* Engines are installed **one by one**: the `vpn` extra is the core (mu300-vpn, the drivers, the kill switch, the
  hooks, the link parser), every engine is an extra of its own.
* **dae** is an engine (eBPF transparent proxy, kernels with BTF only).
* Everything the panel needs is a command with `--json` output; no secret is ever printed unless asked for by root
  with `--reveal`.
* **A VPN must never break on an update.** A device with module v1.0.0 and an active profile keeps working after
  the upgrade, online and offline, on Ubuntu and on OpenWrt, also with an *older* mu300-extra/mu300-update that knows
  nothing of engine extras. The kill switch fails closed when an engine is missing.
* While the VPN is up, IPv6 never leaves on the bearer beside a tunnel that does not carry it (section 7).

## 2. The release files

| asset | extra name | contents | who downloads it |
|---|---|---|---|
| `mu300-linux-vpn.tar.gz` | `vpn` | **the compatibility bundle**: the core plus xray, hev-socks5-tunnel and sing-box, exactly the set v1.0.0 had | mu300-extra / mu300-update **from before v2** (they know only this name), and anyone pinning it by hand |
| `mu300-linux-vpn-core.tar.gz` | `vpn` | the core alone: `bin/mu300-vpn`, `lib/vpn`, services, hooks, `install.sh` | mu300-extra / mu300-update from mu300-linux with engine extras (PR `vpn-engine-extras`) |
| `mu300-linux-vpn-xray.tar.gz` | `vpn-xray` | `bin/xray`, `bin/hev-socks5-tunnel` | |
| `mu300-linux-vpn-singbox.tar.gz` | `vpn-singbox` | `bin/sing-box` | |
| `mu300-linux-vpn-mihomo.tar.gz` | `vpn-mihomo` | `bin/mihomo` (unchanged name and layout) | |
| `mu300-linux-vpn-dae.tar.gz` | `vpn-dae` | `bin/dae`, `share/dae/geoip.dat`, `share/dae/geosite.dat` | |
| `VERSIONS` | - | one TSV line per tarball: `extra  version  bytes  components` (`components`: `name ver,name ver`) | `mu300-vpn engines --json --check` |
| `SHA256SUMS` | - | every file above | everybody |

Why the bundle stays under the old name: an mu300-extra or mu300-update already on a device downloads
`mu300-linux-vpn.tar.gz` as `vpn` and installs nothing else. If that file became the bare core, an old updater
would replace v1's engines with nothing, the service would put the kill switch up and find no engine: the device
would be offline. With the bundle under the old name, an old client gets the new core *and* the engines it had.

**hev-socks5-tunnel is folded into `vpn-xray`**: only the xray driver uses it (it owns the TUN for Xray's SOCKS
inbound); an extra of its own would be one more thing that can be missing.

**No `vpn-tailscale`**: Tailscale is not an engine of a profile here (the `tailscale-exit` type stays reserved);
mu300-vpn only routes tailscaled's traffic through whichever tunnel runs.

**WireGuard and OpenVPN** stay the system's packages (`wireguard-tools` is in the images, the kernel module in
mainline; `openvpn` via apk/apt). `mu300-vpn engines` lists them with the command that installs them, and
`mu300-vpn engine install wireguard|openvpn` runs it.

Every engine extra has `VERSION`, `release`, `name`, `requires`, `components`, `manifest` and `hooks/link`,
`hooks/unlink` (the same two small scripts for every engine): `link SYSROOT` starts a wanted VPN service on the
running system that is not running (an engine that was missing comes back by itself), `unlink` does nothing to the
system (mu300-extra refuses to remove an engine that the active profile of a system with the VPN on needs, unless
`--force`).

### Where mu300-vpn finds an engine

`engine_path NAME EXTRA`: `$DISK/extra/EXTRA/bin/NAME`, then `$DISK/extra/vpn/bin/NAME` (the bundle, or v1), then
`/opt/mu300/bin/NAME` (images from before the module), then `PATH`; the settings `XRAY HEV SING_BOX MIHOMO DAE
OPENVPN` name another binary. So the bundle, the split extras, and a mixture of both all work.

## 3. Migration from v1.0.0 (and from the bundle)

The mu300-linux side (mu300-update's functions, shared by mu300-extra) decides which engine extras the device needs,
**before anything is changed**:

`vpn_engines_needed`: the union over every installed system (`$DISK/<os>`) and the running one of
* the type of every profile in `etc/mu300/vpn/profiles/*/meta` (`TYPE`): xray -> `vpn-xray`, sing-box ->
  `vpn-singbox`, mihomo -> `vpn-mihomo`, dae -> `vpn-dae`; wireguard and openvpn are packages;
* a `vpn.conf` with a `VLESS_URI` and no profile store (never migrated) -> `vpn-xray vpn-singbox`;
* the engines of the installed `vpn` extra when it is the bundle or v1 (`extra/vpn/bin/xray` -> `vpn-xray`,
  `extra/vpn/bin/sing-box` -> `vpn-singbox`): **everything v1 had stays**, so a VLESS profile behind the kill switch
  keeps running on sing-box as it did;
* an engine extra that is installed already (it is refreshed);
* for a first install, `MU300_VPN_ENGINES` (default `vpn-xray`; `none` for the core alone).

`mu300-extra install vpn` and mu300-update's module step then:

1. get the core (`mu300-linux-vpn-core.tar.gz`; a release without it - a pinned v1 - gives the bundle instead) and
   every needed engine extra, from the same source: the download (`MU300_VPN_URL`, default the latest release),
   or `--from DIR` / `MU300_VPN_MODULE=DIR` / mu300-update's staging directory `/mnt/mu300-disk/.mu300-update/vpn/`;
2. if **any** needed file cannot be had or fails its check: with the bundle available from the same source, the
   bundle is installed instead (a complete set); otherwise **nothing is changed** and the command fails with the
   list of files to stage (mu300-update: the same refusal as for the core today, "nothing was changed");
3. install the engine extras first (new directories, harmless to a running VPN), then the core over the old `vpn`
   (the running engine keeps its open files; the next start finds the engines in their new places);
4. link (hooks) as before.

**Offline file set** (copy into one directory with `SHA256SUMS`; any of these forms works):
* `mu300-linux-vpn-core.tar.gz` + the engine tarballs the device needs (`mu300-vpn engines` on the device, or the
  rule above: v1 had xray and sing-box) - the split install; or
* `mu300-linux-vpn.tar.gz` (the bundle) - core plus xray and sing-box, nothing else needed for v1 profiles; plus
  `mu300-linux-vpn-mihomo.tar.gz` / `-dae.tar.gz` when profiles of those types exist.

**Runtime, an engine missing** (removed with `--force`, a failed link): the service puts the kill switch up first as
always, then `ensure_engines` runs `mu300-extra install vpn-<engine>` through the download window (only the device,
only the release hosts, 15 minutes at most) and starts once it is there; until then nothing leaves. mu300-linux's
`lib/vpn-orphan.sh` gains `vpn_engine_missing [ROOT]` (the extra the active profile needs, when it is not installed),
which mu300-toolkit and the panel show as the reason; mobile data and the Wi-Fi client still come up (behind the
kill switch), because the download window needs an uplink to heal the device. Only a missing **mu300-vpn** (the core)
keeps the uplinks down, as before.

## 4. The CLI (the LuCI app's contract)

All commands exist on Ubuntu and OpenWrt; changes need root, reads of the store need root too (the store is 0700).
Exit status: 0 OK, 1 failed (message on stderr), 2 usage. **JSON goes to stdout, messages to stderr**; a JSON command
that fails prints `{"error": "message"}` on stdout as well, exit 1. Strings in JSON are built with `jq --arg`, never
by hand. IDs are `[a-z0-9-]{1,32}`. Secrets (UUIDs, passwords, private and pre-shared keys, subscription URLs and
their tokens) are never in any output except `profile show --reveal` / `profile export` / `subscription show --reveal`,
which need root and print the raw config.

### Status and service

| command | does |
|---|---|
| `mu300-vpn status [--json] [--exit-ip]` | the state; `--exit-ip` adds the exit address (a network request through the tunnel, up to 8 s) |
| `mu300-vpn on` / `start` | ENABLE=1, checks the active profile and its engine, starts the service |
| `mu300-vpn off` / `stop` | ENABLE=0, stops the service, removes the kill switch and the IPv6 guard |
| `mu300-vpn restart` | restarts the service (the VPN must be on) |
| `mu300-vpn use ID` | = `profile use ID` |
| `mu300-vpn killswitch [on\|off] [--json]` | without an argument prints it; sets `KILL_SWITCH` and restarts a running VPN |
| `mu300-vpn enabled` | `0` or `1`, nothing else (unchanged) |
| `mu300-vpn version [--json]` | the module's version and the engines' components |
| `mu300-vpn logs [ENGINE] [-n N]` | the service's log (journalctl / logread), the last N lines (default 100), filtered to one engine's lines |

`status --json`:
```json
{"version": "v2.0.0", "enabled": true, "running": true, "since": 1760180000,
 "kill_switch": {"setting": true, "active": true},
 "ipv6": {"setting": "auto", "tunnel": false, "guard": true},
 "profile": {"id": "office", "name": "Office", "type": "xray", "engine": "sing-box"},
 "engine": {"name": "sing-box", "extra": "vpn-singbox", "installed": true, "usable": true, "reason": null},
 "tunnel": {"iface": "sbtun", "up": true, "addresses": ["172.19.0.1/30"]},
 "exit_ip": null, "missing_engine": null}
```
`profile` is `null` without an active profile; `engine.reason` says why an installed engine cannot run (dae: no BTF);
`missing_engine` is the extra to install when the active profile's engine is not there. `since`: epoch seconds the
tunnel came up (when `running`), else `null`.

### Profiles

| command | does |
|---|---|
| `profile list [--json]` | every profile |
| `profile show ID [--json] [--reveal]` | one; `--reveal` (root only, with `--json` only: exit 2 without it, exit 1 for non-root) adds `"config"`: the raw config text as stored (a link, JSON, YAML, `.conf`, `.ovpn` or dae config) |
| `profile import SRC\|- [NAME]` | from a link, a file, or stdin (`-`); prints the new id (unchanged). The type is sniffed: vless/vmess/trojan/ss links -> `xray`; **hysteria2://, hy2:// and tuic:// -> `dae`** (only dae runs them here; sing-box is not given links of these kinds); `.conf` -> wireguard, `.ovpn` -> openvpn, YAML -> mihomo, JSON -> xray/sing-box, a dae config -> dae |
| `profile import --url URL\|- [NAME] [--insecure]` | a config file (or one link) downloaded from URL: **https only, the certificate checked**; plain http only with `--insecure` (a warning; the panel never sets it). URL from stdin with `-` (it can hold a token) |
| `profile add TYPE NAME SRC\|-` | with the type said (unchanged); TYPE: xray sing-box mihomo wireguard openvpn dae |
| `profile edit ID SRC\|-` | the raw config replaced (stdin with `-`), checked first (unchanged) |
| `profile set ID KEY VALUE` | NAME, or an option of its type (unchanged) |
| `profile use ID` / `remove ID` / `export ID` / `check ID` | unchanged |

A profile object (`list` gives an array of them, `show` one):
```json
{"id": "office", "name": "Office", "type": "xray", "engine": "xray", "extra": "vpn-xray",
 "active": true, "source": "manual", "subscription": null, "stale": false, "created": 1760000000,
 "server": {"host": "vpn.example.com", "port": 443}, "protocol": "vless", "transport": "ws", "security": "tls",
 "options": {"UPSTREAM_HTTP_PROXY": ""}, "engine_installed": true}
```
`source`: `manual`, `legacy` (migrated vpn.conf) or `subscription`; `subscription` the id of the subscription that
made it. `protocol/transport/security` only for link profiles. `options`: the type's option keys with their values,
except the secret ones (`OVPN_PASS` is shown as `"set"` or `""`). `server` is `null` when the config names none.

### Engines

| command | does |
|---|---|
| `engines [--json] [--check]` | every engine; `--check` downloads the release's `VERSIONS` for `available` |
| `engine install NAME [--from FILE\|DIR]` | the engine's extra (`mu300-extra install vpn-NAME`), or its package |
| `engine remove NAME [--force]` | the extra (`mu300-extra remove vpn-NAME`); refused while the running profile needs it |
| `engines install NAME` | the v1 spelling, still accepted |

NAME: `xray` (also `hev-socks5-tunnel`), `sing-box` (also `singbox`), `mihomo`, `dae`, `wireguard`, `openvpn`.
`engines --json`:
```json
[{"name": "xray", "extra": "vpn-xray", "kind": "extra", "installed": true, "path": "/mnt/mu300-disk/extra/vpn-xray/bin/xray",
  "version": "26.3.27", "available": "26.3.27", "size": 31457280, "needed_by": ["office"],
  "usable": true, "reason": null, "install": "mu300-vpn engines install xray (mu300-extra install vpn-xray)"}]
```
`kind`: `extra`, `package` (wireguard, openvpn) or `bundle` (found in the `vpn` bundle or a v1 extra). `size`: bytes
on disk, or the download size when not installed and `--check` gave it, else `null`. `needed_by`: the ids of the
profiles that run on it. `usable: false` with a `reason` for dae without BTF, wireguard without the kernel module.
The plain-text form keeps v1's TSV lines (`name TAB present|missing TAB path|how`).

### Subscriptions

| command | does |
|---|---|
| `subscription add NAME URL\|- [--type auto\|links\|mihomo\|dae] [--interval HOURS] [--insecure]` | fetch (https, certificate checked; http only with `--insecure`, remembered), store and import; prints the id |
| `subscription list [--json]` | id, name, type, host of the URL (never the path or the query), updated, count, interval, insecure, profile ids |
| `subscription show ID [--json] [--reveal]` | one; `--reveal` (root) adds the URL |
| `subscription refresh [ID\|--all\|--due]` | fetch again and update its profiles (the active one in place: the running VPN restarts). `--due`: those whose `--interval` has passed since their last refresh - **no timer is installed**: the panel (or cron) calls `subscription refresh --due` hourly |
| `subscription remove ID [--keep-profiles]` | the subscription and (unless kept) its profiles; not the active one while on |

`subscription --json` object: `{"id", "name", "type", "format", "host", "updated", "count", "interval", "insecure",
"profiles": [ids]}` (+ `"url"` with `--reveal`).

Formats: a Clash/mihomo YAML (`proxies:`) becomes **one mihomo profile**; a list of share links (plain or base64,
one per line) becomes **one profile per link** (vless/vmess/trojan/ss on xray; hysteria2/tuic on dae, or skipped
when vpn-dae is not installed) - or, with `--type dae`, **one dae profile** with every node in one group
(`min_moving_avg`); a link dae cannot take safely (section 5) is left out and counted as skipped. A refresh keeps the
ids of profiles whose name is unchanged, adds new ones, removes the ones that vanished (never the active one while
the VPN is on; it is kept and marked `stale`). Stored under `/etc/mu300/vpn/subscriptions/ID/` (0700; `url` and
`meta` 0600). The URL is never a command-line argument (curl reads it from its config on stdin, GNU wget from its
URL list on stdin; only OpenWrt's uclient-fetch, where every process is root's, takes it as one). Fetched over the
device's own connection: through the tunnel when the VPN is up, directly otherwise; with the kill switch up and the
tunnel down it fails (no window is opened for arbitrary hosts).

### Latency

`mu300-vpn latency ID [--json]`: one object `{"id", "host", "port", "ms", "via", "error": null}`; when no time was
had, **exit 1** and (as every failing `--json` command) `{"error": "unreachable" | "kill switch" | "udp" | "no
server"}`. `latency --all --json` (or several ids): **always an array** of those objects, exit 0, `ms: null` with
`"error"` for the ones that failed. `via` is `tunnel` when the VPN is up (the test connection is not the engine's and
is routed like any other); the active profile's own server is not tested while the kill switch is up (`"kill
switch"`); wireguard/openvpn-over-UDP, hysteria2 and tuic servers are UDP: a TCP test says nothing (`"udp"`).

### Settings

`settings --json`: one object, every key a string value (empty: the default in force is shown, never `null`):
```json
{"KILL_SWITCH": "1", "TAILSCALE": "1", "IPV6": "auto", "REMOTE_DNS": "1.1.1.1", "BOOTSTRAP_DNS": "1.1.1.1",
 "LAN_CIDRS": "", "XRAY": "", "HEV": "", "SING_BOX": "", "MIHOMO": "", "OPENVPN": "", "DAE": ""}
```
Types: `KILL_SWITCH`, `TAILSCALE` `0|1`; `IPV6` `0|1|auto`; `REMOTE_DNS`, `BOOTSTRAP_DNS` an IPv4 or IPv6 address;
`LAN_CIDRS` CIDRs comma-separated; the engine paths an absolute path or empty. `settings set KEY VALUE`: exit 0 set
(an empty VALUE puts the default back; a running VPN uses it from its next restart, said on stderr), exit 2 an unknown
key or an invalid value (nothing written), exit 1 the store cannot be written (not root). `killswitch on|off` is
`settings set KILL_SWITCH` plus the restart. Not offered (yet): the mihomo mode (rule/global/direct) and an engine
log level - the mihomo mode is the YAML's own `mode:`, which the profile keeps.

## 5. dae

* Profile type `dae`, three forms in the profile directory: `config.dae` (a raw dae config), `uri` (one share link:
  vless, vmess, trojan, ss, hysteria2, tuic, as dae speaks them) or `links` (several, from a subscription).
* **Kernel**: dae needs BTF (`/sys/kernel/btf/vmlinux`) and kernel 5.17 or newer. On the 5.4 vendor kernel or a
  kernel without BTF, `check`, `on` and the service refuse with a clear message (`mu300-update kernel 6.18`), and
  `engines --json` says `usable: false`. The vpn-dae extra can still be installed.
* **Routing (same model as the TUN engines)**: the driver makes a dummy interface `mu300dae` (198.18.9.1/30) and
  the core routes everything into it as into a TUN (rules 9000-9010, table 2022). dae binds `wan_interface:
  mu300dae` (the device's own traffic, caught on that interface's egress) and `lan_interface:` the LAN (`br-lan`, or
  `usb0`/`wlan0` that are not bridge ports and not the uplink; `DAE_LAN` overrides). dae's own sockets carry our mark
  (`so_mark_from_dae: 720`), so rule 9000 sends them to the uplink and the kill switch lets them out. When dae is
  not running, whatever is routed into `mu300dae` ends there: closed, as with a dead TUN. (A wan_interface on the
  uplink itself would not work behind the kill switch: the nft output hook drops the device's packets before tc
  egress, where dae would catch them.)
* **DNS**: dae's DNS module answers; upstream `remote` = `tcp+udp://REMOTE_DNS:53` through the proxy, node and
  subscription names through `bootstrap` = `udp://BOOTSTRAP_DNS:53` (`node(name_regex: '.')`, `subnode(name_regex: '.')` -> bootstrap,
  `bootstrap_resolver`, `fallback_resolver`; dae 2.1.1 refuses `node()` without a parameter), on dae's marked sockets. The device's own lookups are DNAT'd to REMOTE_DNS as for every
  core-routed engine, which routes them into dae. Nothing goes to the carrier's resolver.
* **Generated config** (from links): our `global` (above, plus `log_level: warn`, `pprof_port: 0`,
  `dial_mode: domain`, **`allow_insecure: false` always**), `node { mu300_N: 'LINK' }`, one group `proxy`
  (`min_moving_avg`, `fixed(0)` for one link), routing: multicast and private ranges direct, `fallback: proxy`. No
  geodata needed.
* **Links into the config** (`dae_link`, the security review's injection finding): a link is written only when it
  holds nothing but URL characters (RFC 3986 unreserved, reserved and `%`) - never a quote, backslash, blank, brace,
  backquote or line break - so it cannot end its single-quoted string or start a directive; its `#fragment` is never
  written; it must take apart (`parse_link`) and be a kind dae speaks.
* **Certificates** (the review's TLS finding): Xray and sing-box keep checking unless a link asks, and Xray then pins
  the certificate it saw; dae has no pin, so **a link that turns the check off (`allowInsecure`, `insecure`,
  `allow_insecure`, `skip-cert-verify`, also in vmess's JSON) is refused for dae** with what to do instead (run it
  on xray). A dae subscription leaves such links out.
* **Raw config** (the review's parser-differential finding) is taken only in a subset this reader parses exactly as
  dae does, and anything outside it refuses the config (fail closed), nothing is "cleaned up": no double quote,
  backslash, backquote or non-ASCII anywhere; strings single-quoted on one line; comments whole lines only; top level
  `node`, `group`, `routing` kept, `global` and `dns` replaced by ours, `subscription` refused (dae would fetch nodes
  nobody checked: `subscription add --type dae` does it checked), `include` and anything else refused; every node
  string a link `dae_link` accepts, every other string URL characters and blanks only. The rebuilt file is checked
  again (`dae_written_ok`: one global and one dns, ours, no include/subscription/bind, no insecure link, printable
  ASCII only) and by `dae validate` (no BPF, no network) before it runs.
* Geodata: `DAE_LOCATION_ASSET` points at the extra's `share/dae`.
* Tailscale: dae catches tailscaled's packets like any other on `mu300dae`; the Tailscale rules are not installed.

## 6. Kill switch

Unchanged in principle: only marked traffic leaves on an uplink; it goes up before anything can fail, and only `off`
takes it down. An engine that is missing at runtime: kill switch up, download window for that one extra, else closed
(section 3). New: IPv6 that would leave on an uplink is **rejected** (TCP reset, ICMPv6 admin-prohibited) instead of
dropped, so programs fall back to IPv4 at once; ICMPv6 neighbour and router discovery stay allowed on the uplinks.

## 7. IPv6 while the VPN is up

Measured on an F50 (OpenWrt, v2026.10.18, VPN on with an xray profile, kill switch off): the carrier hands out a
global IPv6 address on `sipa_eth0`, nothing routes over it, and programs that prefer IPv6 (uclient-fetch) fail; in a
country where the carrier's IPv6 works, the device's and the LAN's IPv6 would leave beside an IPv4-only tunnel: a
leak. The rule:

* `IPV6` setting: `0` (never through the tunnel), `1` (ask the engine for an IPv6 tunnel address: sing-box, mihomo,
  WireGuard), `auto` (default: WireGuard uses the IPv6 addresses of its config, the others stay IPv4).
* The tunnel **carries IPv6** when it has a global IPv6 address (and IPV6 is not 0): the core routes IPv6 into it
  (rules 9000-9010 for IPv6, as before).
* Otherwise, while the tunnel is up, the **IPv6 guard** (`table inet mu300_vpn_v6`, separate from the kill switch,
  installed whatever KILL_SWITCH says): on the uplinks (`sipa_eth*` and the Wi-Fi client), IPv6 in the output and
  forward hooks is rejected - TCP with a reset, everything else with ICMPv6 admin-prohibited - except the engine's
  marked sockets (an IPv6 server), ICMPv6 neighbour/router solicitation and advertisement, and DHCPv6 (UDP 546/547)
  from the device. LAN clients keep whatever IPv6 address the router gives them (the router's RA/odhcpd config is not
  touched), and their IPv6 is rejected at once, so they fall back to IPv4.
* The guard goes when the tunnel goes down; with the kill switch on, the kill switch's own IPv6 rejects take over.
  `off` removes both. VPN off: nothing changes.

## 8. Tests

`tests/`: the extras' naming and contents (`test_module.py`), the migration from a v1 layout and a bundle (engine
lookup in every combination), refusal paths, every `--json` output parsed and checked for secrets (a fixture link's
UUID, password and key must not appear), dae config generation and the raw-config reader, the kill switch with an
engine missing, the IPv6 guard's nft rules per profile capability. mu300-linux's `tests/test_extra.py` and
`test_update.py`: the new names, `vpn_engines_needed`, the offline staging of engine tarballs, the refusal.

## 9. Decisions made while building it

* **A VLESS link behind the kill switch without sing-box** (vpn-xray installed alone, the first-install default) runs
  on Xray, its server looked up through the resolve window - as v1 already did for VMess, Trojan and Shadowsocks links.
  With sing-box installed it still runs on sing-box (v1's behaviour; a v1 upgrade keeps vpn-singbox). A link that asks
  for allowInsecure still refuses behind the kill switch (its pin is fetched unmarked).
* **`mu300-vpn engine install xray|sing-box` with an mu300-extra from before the engine extras** gets the vpn extra
  instead (the bundle carries both); mihomo and dae need the new mu300-extra.
* The IPv6 guard is not installed when the kill switch is on: the kill switch carries the same rejects.

## 10. What was tested, and how

* `tests/` (dash, bash, busybox sh; in an arm64 Ubuntu 24.04 container): 188 tests, among them `test_v2.py` (engine
  lookup in every layout, `--json` outputs parsed and searched for the fixtures' UUID, password, token and key,
  subscriptions, latency, logs, the IPv6 guard per engine and setting, the dae driver and its raw-config reader, a
  missing engine and a kernel without BTF failing closed) and `test_module.py` (every tarball's layout).
* The kill switch, the download window and the IPv6 guard loaded into a real kernel's nftables (container with
  NET_ADMIN); `nft --debug=netlink` shows the IPv6 rejects keep their `nfproto ipv6` match.
* Every config the dae driver writes passes the real `dae validate` (v2.1.1, arm64, in a container).
* **v1.0.0 -> v2 upgrade with a live tunnel**, in the release v2026.10.18 rootfs images (OpenWrt with LuCI and
  Ubuntu, imported as arm64 Docker images) and in Ubuntu 24.04: module v1.0.0 (the real release) installed with the
  image's own mu300-extra, a VLESS profile to a throwaway Xray server in a second container, the tunnel up (a third
  container sees the server's address); then v2 (built with the real pinned engines) installed (a) with the image's
  own, old mu300-extra (it takes the bundle) and (b) with the branch's mu300-extra (core + vpn-xray + vpn-singbox);
  in both the same profile comes up again through the v2 tunnel, `status --json` / `profile list --json` hold no
  UUID, the IPv6 guard is up beside the IPv4 tunnel and `off` removes it; (b) also: with the engine extras removed
  and the release unreachable, `run` fails closed (kill switch up, no tunnel, the extra named).
* Not tested here (device tests): see the PR.

## 11. The security review (and what changed for it)

* **dae config injection** and **TLS verification**: section 5 (`dae_link`); tests in `tests/test_hardening.py`
  (hostile links yield no extra line or directive, insecure links never reach dae, the config always says
  `allow_insecure: false`).
* **dae parser differential**: section 5 (the raw-config subset, fail closed); adversarial configs tested.
* **Temporary files**: the one temp file outside the 0700 run directory (the `--json` error capture) is `mktemp`'s,
  never a fixed name; everything else lives in `/run/mu300-vpn` (0700) or the store (0700 directories, 0600 files).
* **Transport and secret exposure**: subscription and `profile import --url` fetches are HTTPS with the certificate
  checked (curl `--proto =https --proto-redir =https`, GNU wget `--https-only`, uclient-fetch; busybox's own wget is
  never used for them); plain http only with `--insecure`. The URL goes to curl/wget on stdin, never on the command
  line (OpenWrt's uclient-fetch excepted, see section 4). No output prints a URL's path or query or a profile's
  secret except `--reveal` (root). Engines come only through mu300-extra, from the pinned release, checked by
  SHA-256 (and mu300-extra hashes and unpacks the same private copy: mu300-linux PR).
* **JSON**: every JSON this version adds is built by `jq --arg`; nothing new is `eval`ed (`kv_var` assigns to names
  of our own).
