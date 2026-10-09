# mu300-linux-vpn

[![Latest Release](https://img.shields.io/github/v/release/dikeckaan/mu300-linux-vpn?logo=github)](https://github.com/dikeckaan/mu300-linux-vpn/releases/latest)
[![Tests](https://github.com/dikeckaan/mu300-linux-vpn/actions/workflows/tests.yml/badge.svg)](https://github.com/dikeckaan/mu300-linux-vpn/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

The VPN for [mu300-linux](https://github.com/dikeckaan/mu300-linux) - Linux on the ZTE F50 / MU300 and U30 Air - as
a module you install on the device when you want it. It sends the device's own traffic **and** everything from its
USB and Wi-Fi clients through a VPN server, with a kill switch, on Ubuntu and on OpenWrt.

`mu300-vpn` keeps **profiles** - a WireGuard `.conf`, an OpenVPN `.ovpn`, a Clash/mihomo YAML, a VLESS, VMess,
Trojan or Shadowsocks share link, or a raw Xray or sing-box JSON from a panel - and runs the active one with the
engine that speaks its protocol. One command for all of them; the kill switch, the routing, DNS and Tailscale are
the same whatever the type.

It used to be part of mu300-linux itself; since mu300-linux v2026.10.16 the images carry only what the VPN needs
from the system (the kernel's TUN, WireGuard and nftables, `jq`, `openssl`, `wireguard-tools`) and the places that
work with it when it is there (mobile data and the Wi-Fi client put the kill switch up before their uplink, the
power profiles stop it while the modem is off, `mu300-toolkit`'s VPN menu, the control panel's VPN page). Everything
else is here.

## What you need

* A device with **mu300-linux v2026.10.16 or newer** (`mu300-update` brings an older one there). Ubuntu or OpenWrt,
  either works, and one installation serves every system on the device.
* For the online install, a working connection on the device (mobile data, the Wi-Fi client, or USB from a
  computer that shares its connection).

## Install

### Online, on the device

```sh
sudo mu300-extra install vpn            # Ubuntu
mu300-extra install vpn                 # OpenWrt (you are root)
```

`mu300-extra` downloads `mu300-linux-vpn.tar.gz` from this repository's latest release, checks it against the
release's `SHA256SUMS`, unpacks it to `/mnt/mu300-disk/extra/vpn` (the Linux partition, next to the systems) and
links it into every installed system - Ubuntu and OpenWrt share one copy, and an update or reinstall of a system
keeps it. For mihomo (Clash YAML) profiles, add its engine the same way: `mu300-extra install vpn-mihomo`.

`MU300_VPN_URL` takes another place with the same files, e.g. a pinned release:
`MU300_VPN_URL=https://github.com/dikeckaan/mu300-linux-vpn/releases/download/v1.0.0 mu300-extra install vpn`.

### Offline

Download `mu300-linux-vpn.tar.gz` and `SHA256SUMS` from the [latest release](https://github.com/dikeckaan/mu300-linux-vpn/releases/latest)
(and `mu300-linux-vpn-mihomo.tar.gz` if you want mihomo), copy them into one directory on the device (`scp`, a USB
stick, the SD card) and there, as root:

```sh
tar -xzf mu300-linux-vpn.tar.gz ./install.sh && sh install.sh
```

`install.sh` runs `mu300-extra install vpn --from` that directory, which checks the tarball against `SHA256SUMS`
exactly as the online install does (and `vpn-mihomo` too when its tarball is there). `mu300-extra install vpn
--from /path/to/mu300-linux-vpn.tar.gz` does the same by hand.

### Updates and removal

`mu300-update apply` brings the module to its latest release together with the systems, and refuses to update a
device whose VPN is on when it cannot get the module (offline): an update must never leave a VPN with the kill
switch on without its engine. Stage the module for it as its message says. `mu300-extra status` shows the
installed version; `sudo mu300-extra remove vpn` takes it off again, and the VPN with it (it is turned off first, so
no kill switch is left behind that nothing could take down).

## Use

```sh
sudo mu300-vpn profile import 'vless://...'          # a share link (vless, vmess, trojan, ss)
sudo mu300-vpn profile import ~/office.conf Office    # a file: wg .conf, .ovpn, Xray/sing-box .json, mihomo .yaml
cat client.ovpn | sudo mu300-vpn profile import -     # from stdin (ssh: nothing is left on the device's disk)
mu300-vpn profile list                                # id, type, name; * marks the active one
sudo mu300-vpn profile use office                     # make it active (a running VPN restarts on it)
sudo mu300-vpn on                                     # ENABLE=1, starts at boot; off: stops and removes the kill switch
mu300-vpn status                                      # profile, engine, tunnel, exit IP - never a secret
```

(On OpenWrt, without `sudo`.) The type is sniffed from the link's scheme or the file's content; `profile add TYPE
NAME SRC` says it outright. A profile is checked with its engine when it is imported and again at every start
(`mu300-vpn check [ID]` does it by hand). `profile show ID` tells name, type, source, date and the server's host and
port; `profile edit ID SRC` replaces its config, `profile set ID KEY VALUE` sets a per-type option
(`TLS_PIN_SHA256`, `MIHOMO_STACK`, `OVPN_USER`...), `profile remove ID` removes it (not the active one while the VPN
is on), and `profile export ID` prints the raw config back - the one command that prints a secret. Everything
lives under `/etc/mu300/vpn` (profiles and settings, 0600, kept across updates; each system - Ubuntu, OpenWrt - has
its own) and `/etc/mu300/vpn.conf` holds only the `ENABLE` switch, which `on`/`off` write. A `vpn.conf` written the
old way (a `VLESS_URI` and the keys next to it, see `/etc/mu300/vpn.conf.example`) still works: it is moved into the
store as the profile `legacy` the first time `mu300-vpn` runs, and an edit to it later wins for the keys it changed.

**Settings** (`mu300-vpn settings`, `settings get KEY`, `settings set KEY VALUE`; an empty value is the default; a
VPN that is on uses a new value from its next `mu300-vpn restart`):

| key | values | default | |
|---|---|---|---|
| `KILL_SWITCH` | 0, 1 | 1 | nothing but the tunnel leaves the device, also while the tunnel is down |
| `TAILSCALE` | 0, 1 | 1 | Tailscale's own traffic through the tunnel (below) |
| `IPV6` | 0, 1 | 0 | IPv6 through the tunnel as well, when the tunnel has an IPv6 address |
| `REMOTE_DNS` | an address | 1.1.1.1 | DNS for the device and its clients, through the tunnel |
| `BOOTSTRAP_DNS` | an address | 1.1.1.1 | for the server's own name, outside the tunnel (sing-box, mihomo) |
| `LAN_CIDRS` | CIDRs, comma-separated | empty | more networks that stay local (the device's own LAN always does) |
| `XRAY` `HEV` `SING_BOX` `MIHOMO` `OPENVPN` | a path | empty | another binary for that engine |

`mu300-vpn enabled` prints the switch (0 or 1) and nothing else; `mu300-vpn restart` restarts the service.

## Engines

`mu300-vpn engines` says which engines are present and how to get the missing ones; `sudo mu300-vpn engines
install ENGINE` gets one.

| engine | for | where it comes from | licence |
|---|---|---|---|
| [Xray-core](https://github.com/XTLS/Xray-core) 26.3.27 + [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) 2.17.1 | VLESS, VMess, Trojan, Shadowsocks links, Xray JSON | in `mu300-linux-vpn.tar.gz` | MPL-2.0, MIT |
| [sing-box](https://github.com/SagerNet/sing-box) 1.14.1 | the same links behind the kill switch, sing-box JSON | in `mu300-linux-vpn.tar.gz` | GPL-3.0-or-later |
| [mihomo](https://github.com/MetaCubeX/mihomo) 1.19.32 | Clash/mihomo YAML | `mu300-linux-vpn-mihomo.tar.gz` (`mu300-extra install vpn-mihomo`) | GPL-3.0 |
| WireGuard | `.conf` | the kernel's, with `wireguard-tools` (in the images; the 5.4 vendor kernel has no WireGuard, mainline does) | GPL-2.0 |
| OpenVPN | `.ovpn` | the system's package: `apk add openvpn-openssl` (OpenWrt), `apt-get install openvpn` (Ubuntu) | GPL-2.0 |

The engines in the tarballs are the projects' own static arm64 release builds, downloaded by `tools/fetch-*.sh`
and checked against the hashes pinned there; the components file in each tarball names their versions. The service
never installs a package by itself: without OpenVPN it fails closed and names the command.

A VLESS link runs on Xray by default; with the kill switch it runs on sing-box, because Xray resolves the server's
name and fetches its certificate (Xray 26 has no `allowInsecure`: the certificate is fetched once, pinned in the
profile, and fetched again when the server renews it) before the tunnel exists, and the kill switch would drop both.
Other types resolve their server's name through a short **resolve window** (only the device's DNS, only for
seconds), so they all work behind the kill switch.

## Security model

* **The kill switch** lets only marked traffic out on an uplink (the modem's bearer and the Wi-Fi client), and every
  engine marks its own packets (Xray and sing-box in their configs, mihomo's `routing-mark`, WireGuard's `fwmark`,
  OpenVPN's `--mark`), so no type needs an exception and nothing else leaves the device. With it on, when the
  tunnel is down nothing goes out; it goes up before anything that can fail, before the modem's bearer at boot
  (mobile data and the Wi-Fi client call `mu300-vpn guard`), and a stopped or crashed engine never takes it down -
  only `mu300-vpn off` (or `ENABLE=0`) does. When the engines are missing it stays up while they are downloaded
  (only the device itself, only to the release hosts, for 15 minutes at most).
* **Raw configs** (Xray and sing-box JSON, mihomo YAML) are hostile input: a panel's export is parsed once,
  strictly, and the engine runs a new file rebuilt from an allowlist of what a config may contain - its outbounds
  and the servers they reach, its routing rules between them, its DNS servers. The inbound is always ours (nothing
  listens on the LAN or the device), the mark is ours, an API or controller is dropped, a key file path or a TLS key
  log is refused, and anything the allowlist does not know refuses the config with the key's name, never its value.
  What a raw config may do is also its exposure, said plainly: a `direct` or `freedom` outbound (or a DNS server
  that goes through one) sends that traffic out of the tunnel onto the uplink with the engine's mark, past the kill
  switch. Split tunnelling is the config's own choice and the kill switch does not override it.
* **OpenVPN files** are held the same way: parsed with openvpn's own lexical rules into an allowlist of directives
  and key blocks; openvpn reads only the file we write, and a file that wants to run a script is refused.
* **Secrets** stay in the store (0600, root only); `status`, `profile list` and `profile show` never print one,
  only `profile export` does. Profiles are imported from stdin to keep links out of the process list.

**Tailscale through the VPN.** Tailscale marks its own connections and routes them past the tunnel straight to the
carrier; on a network where only the VPN gets out it then never connects. When the tunnel comes up, `mu300-vpn`
puts a rule before Tailscale's (pref 5200, into the tunnel's table 2022); private addresses stay outside the tunnel
(pref 5199) and the engine's own connection keeps going to the carrier even with an exit node (pref 5198). IPv4
only; `mu300-vpn settings set TAILSCALE 0` turns it off.

**What the carrier lets through.** Measured on one carrier's SIM: UDP to a WireGuard port never reached the server
and OpenVPN's TLS handshake timed out, while the VLESS profile went through. If a WireGuard or OpenVPN profile never
comes up on mobile data while it works on Wi-Fi, try the same profile over `wifi-client`, or a type the carrier does
not touch ([FINDINGS 26f](docs/FINDINGS.md)).

## How it fits into mu300-linux

`mu300-linux-vpn.tar.gz` unpacks into `/mnt/mu300-disk/extra/vpn`:

```
VERSION components requires   the module's version, what it holds, the oldest mu300-linux it works with
name release manifest         for mu300-extra's checks (manifest: the sha256 of every other file)
bin/mu300-vpn                 the command; bin/xray bin/hev-socks5-tunnel bin/sing-box: the engines
lib/vpn/                      the engine drivers and the link parser
etc/vpn.conf.example
service/systemd/mu300-vpn.service   service/procd/mu300-vpn
hooks/link hooks/unlink       sh hooks/link SYSROOT  ("" = the running system, or /mnt/mu300-disk/<os>)
install.sh                    the offline install
```

`hooks/link SYSROOT` makes one system use the module: `/opt/mu300/bin/mu300-vpn` and `/opt/mu300/lib/vpn` become
links into the extra, the service is installed (systemd's unit on Ubuntu, procd's init script on OpenWrt) and
enabled when the VPN is on in that system (`mu300-vpn enabled`), and `vpn.conf.example` is copied to `/etc/mu300`.
What an older image had there itself is moved aside to `NAME.builtin`, never deleted. For the running system it also
reloads systemd and starts a wanted VPN that is not running. `hooks/unlink SYSROOT` undoes exactly that and puts the
`*.builtin` back. Both can run any number of times. `mu300-extra` runs them after an install and a removal, and
`hooks/link ""` at every boot.

## For developers

```sh
cd tests && python3 -m unittest discover          # every shell the device has: dash, bash, busybox sh
sh tools/make-module.sh out v1.0.0                # out/mu300-linux-vpn.tar.gz, out/mu300-linux-vpn-mihomo.tar.gz, out/SHA256SUMS
```

The tests run each script under every POSIX shell the machine has (`MU300_TEST_SHELLS="dash,busybox sh"` picks
others); commands that touch the device (`nft`, `ip`, `systemctl`...) are stubs. `MU300_VPN_FAKE_ENGINES=1
tools/make-module.sh` builds with small scripts in place of the engines, without network. The tarballs are the same
bytes from macOS and Linux for the same inputs: files and directories only, owned by root, fixed modes and times.

A release is the **Release** workflow (Actions > Release > Run workflow on main, with the tag `vMAJOR.MINOR.PATCH`):
it runs the tests, builds with `make-module.sh` and publishes the three files under fixed names, so
`releases/latest/download/NAME` always gives the newest. It refuses another branch and a tag that exists.

The design: [docs/superpowers/specs](docs/superpowers/specs), and the measurements behind it in
[docs/FINDINGS.md](docs/FINDINGS.md) (copied from mu300-linux's FINDINGS 26).

## Credits and licenses

* The scripts, tools and documentation in this repository: MIT (see `LICENSE`).
* The engines keep their own licences: [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0),
  [sing-box](https://github.com/SagerNet/sing-box) (GPL-3.0-or-later),
  [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) (MIT) and
  [mihomo](https://github.com/MetaCubeX/mihomo) (GPL-3.0). They are their projects' release builds, downloaded,
  pinned and checked by hash, not changed; their source is at those links.
* A hobby project, at your own risk, as [mu300-linux](https://github.com/dikeckaan/mu300-linux) is.
