"""Module v2 (docs/superpowers/specs/2026-10-11-engine-extras.md): the engines in extras of their own and where
mu300-vpn finds them (the bundle, v1, the split extras, a mixture), the machine-readable interface for the control
panel (every --json output parsed, and no secret in any of it), the IPv6 guard and the kill switch's IPv6 rejects,
the dae driver, subscriptions and latency - under every shell."""
import base64
import json
import os
import shutil

from helpers import BIN, LIB, SYSBIN, ShellTest
from test_vpn_drivers import MH_CONF, WG_CONF, WG_PRIV

UUID = '6f1c2d3e-4b5a-4c6d-8e7f-0123456789ab'
PASSWORD = 's3cr3t-Pa55word'
VLESS = f'vless://{UUID}@vpn.example.com:443?security=tls&type=ws&path=%2Fws&sni=vpn.example.com#Home'
TROJAN = f'trojan://{PASSWORD}@tr.example.net:8443?sni=tr.example.net#Tro'
HY2 = f'hysteria2://{PASSWORD}@hy.example.org:8443/?sni=hy.example.org#Hy'
TOKEN = 'tok-9f8e7d6c5b4a'
SECRETS = (UUID, PASSWORD, TOKEN, WG_PRIV)


class Base(ShellTest):
    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('ENABLE=0\n')
        self.disk = self.tmp / 'disk'
        self.stub('svc', 'echo "svc $*" >> "$STUBLOG/svc.log"')
        self.stub('ip', 'case "$*" in "link show"*|"-6 addr show"*|"-4 -o addr"*|"-o addr"*|"rule del"*|"-6 rule del"*) exit 1 ;; esac; exit 0')
        self.stub('pgrep', 'exit 1')
        self.stub('getent', 'echo "203.0.113.10    STREAM $2"')
        self.stub('nft', 'case "$1" in\n'
                         '  -f) cat >> "$STUBLOG/nft.log"; echo "-- loaded" >> "$STUBLOG/nft.log" ;;\n'
                         '  list) exit 1 ;;\n'
                         '  *) echo "nft $*" >> "$STUBLOG/nft.log" ;;\n'
                         'esac')
        self.stub('extra', 'echo "extra $*" >> "$STUBLOG/extra.log"; exit "${EXTRA_RC:-0}"')

    def fresh(self):
        for d in (self.tmp / 'vpn', self.disk, self.tmp / 'run'):
            shutil.rmtree(d, ignore_errors=True)
        for f in ('svc.log', 'nft.log', 'extra.log'):
            (self.tmp / f).unlink(missing_ok=True)
        self.conf.write_text('ENABLE=0\n')

    def env_(self, **extra):
        e = dict(MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB,
                 MU300_LAN_CONF=self.tmp / 'no', MU300_BIN=SYSBIN, MU300_OPT=self.tmp / 'opt', MU300_DISK=self.disk,
                 MU300_VPN_SVC=self.stubs / 'svc', MU300_EXTRA_CMD=self.stubs / 'extra')
        e.update(extra)
        return e

    def vpn(self, shell, *args, stdin=None, **extra):
        return self.script(shell, BIN / 'mu300-vpn', *args, stdin=stdin, **self.env_(**extra))

    def lib(self, shell, code, **extra):
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', MU300_LIB=1, **self.env_(**extra))

    def put(self, extra, *names):
        d = self.disk / 'extra' / extra / 'bin'
        d.mkdir(parents=True, exist_ok=True)
        for n in names:
            (d / n).write_text('#!/bin/sh\nexit 0\n')
            (d / n).chmod(0o755)
        return d

    def no_secret(self, *texts):
        for t in texts:
            for s in SECRETS:
                self.assertNotIn(s, t)

    def log(self, name):
        p = self.tmp / name
        return p.read_text() if p.exists() else ''


class EngineLookup(Base):
    def kinds(self, shell):
        r = self.vpn(shell, 'engines', '--json')
        self.assertEqual(r.returncode, 0, r.stderr)
        return {e['name']: e for e in json.loads(r.stdout)}

    def test_bundle_split_and_a_mixture(self):
        for shell in self.each_shell():
            self.fresh()
            # module v1 / the bundle: the engines in the vpn extra
            self.put('vpn', 'xray', 'hev-socks5-tunnel', 'sing-box')
            (self.disk / 'extra/vpn/components').write_text('mu300-linux-vpn v1.0.0\nxray 26.3.27\nhev-socks5-tunnel 2.17.1\nsing-box 1.14.1\n')
            e = self.kinds(shell)
            self.assertEqual([x['name'] for x in e.values()], ['xray', 'sing-box', 'mihomo', 'dae', 'wireguard', 'openvpn'])
            self.assertEqual((e['xray']['kind'], e['xray']['installed'], e['xray']['version'], e['xray']['extra']),
                             ('bundle', True, '26.3.27', 'vpn-xray'))
            self.assertEqual(e['xray']['path'], str(self.disk / 'extra/vpn/bin/xray'))
            self.assertEqual(e['sing-box']['kind'], 'bundle')
            self.assertFalse(e['dae']['installed'])
            self.assertIsNone(e['dae']['path'])
            self.assertEqual(e['wireguard']['kind'], 'package')
            # the split extra wins over the bundle, one engine at a time
            d = self.put('vpn-xray', 'xray', 'hev-socks5-tunnel')
            (d.parent / 'components').write_text('xray 26.9.1\nhev-socks5-tunnel 2.18.0\n')
            e = self.kinds(shell)
            self.assertEqual((e['xray']['kind'], e['xray']['path'], e['xray']['version']),
                             ('extra', str(d / 'xray'), '26.9.1'))
            self.assertIsInstance(e['xray']['size'], int)
            self.assertEqual(e['sing-box']['kind'], 'bundle')
            r = self.lib(shell, 'echo "$XRAY $HEV $BIN"')
            self.assertEqual(r.stdout.split(), [str(d / 'xray'), str(d / 'hev-socks5-tunnel'),
                                                str(self.disk / 'extra/vpn/bin/sing-box')])
            # the core alone (the vpn extra without engines) and the split extras: no bundle at all
            shutil.rmtree(self.disk / 'extra/vpn')
            self.put('vpn-singbox', 'sing-box')
            e = self.kinds(shell)
            self.assertEqual((e['xray']['kind'], e['sing-box']['kind']), ('extra', 'extra'))

    def test_needed_by_and_install_how(self):
        for shell in self.each_shell():
            self.fresh()
            for link in (VLESS, TROJAN):
                self.assertEqual(self.vpn(shell, 'profile', 'import', '-', stdin=link).returncode, 0)
            e = self.kinds(shell)
            self.assertEqual(e['xray']['needed_by'], ['home', 'tro'])
            self.assertEqual(e['xray']['install'], 'mu300-vpn engines install xray (mu300-extra install vpn-xray)')
            self.assertEqual(e['mihomo']['needed_by'], [])

    def test_engine_install_and_remove(self):
        for shell in self.each_shell():
            self.fresh()
            for name, extra in (('xray', 'vpn-xray'), ('singbox', 'vpn-singbox'), ('dae', 'vpn-dae')):
                (self.tmp / 'extra.log').unlink(missing_ok=True)
                r = self.vpn(shell, 'engine', 'install', name)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self.log('extra.log').splitlines(), [f'extra install {extra}'])
            (self.tmp / 'extra.log').unlink(missing_ok=True)
            self.assertEqual(self.vpn(shell, 'engine', 'install', 'dae', '--from', '/media/usb').returncode, 0)
            self.assertEqual(self.log('extra.log').splitlines(), ['extra install vpn-dae --from /media/usb'])
            # remove: refused while the VPN is on and its profile runs on it
            self.assertEqual(self.vpn(shell, 'profile', 'import', '-', stdin=VLESS).returncode, 0)
            self.assertEqual(self.vpn(shell, 'profile', 'use', 'home').returncode, 0)
            self.conf.write_text('ENABLE=1\n')
            (self.tmp / 'extra.log').unlink(missing_ok=True)
            r = self.vpn(shell, 'engine', 'remove', 'xray')
            self.assertEqual(r.returncode, 1)
            self.assertIn('runs on xray', r.stderr)
            self.assertEqual(self.log('extra.log'), '')
            self.assertEqual(self.vpn(shell, 'engine', 'remove', 'xray', '--force').returncode, 0)
            self.assertEqual(self.vpn(shell, 'engine', 'remove', 'mihomo').returncode, 0)
            self.assertEqual(self.log('extra.log').splitlines(),
                             ['extra remove vpn-xray --force', 'extra remove vpn-mihomo'])
            r = self.vpn(shell, 'engine', 'remove', 'openvpn')
            self.assertEqual(r.returncode, 2)

    def test_an_old_mu300_extra_gets_the_bundle(self):
        """an mu300-extra from before the engine extras knows no vpn-xray: the vpn extra (the bundle) is fetched"""
        for shell in self.each_shell():
            self.fresh()
            self.stub('extra', 'echo "extra $*" >> "$STUBLOG/extra.log"\n'
                               'case "$1 $2" in "install vpn-"*) echo "there is no extra called $2" >&2; exit 1 ;;\n'
                               '  "list "*) printf "vpn    installed (v1.0.0)\\n       the VPN\\n" ;; esac; exit 0')
            r = self.vpn(shell, 'engine', 'install', 'xray')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.log('extra.log').splitlines(),
                             ['extra install vpn-xray', 'extra list', 'extra install vpn'])
            # mihomo and dae have no such fallback (the bundle does not carry them)
            (self.tmp / 'extra.log').unlink()
            self.assertEqual(self.vpn(shell, 'engine', 'install', 'dae').returncode, 1)
            self.assertEqual(self.log('extra.log').splitlines(), ['extra install vpn-dae'])


class Json(Base):
    def setup_profiles(self, shell):
        self.fresh()
        for link in (VLESS, TROJAN):
            r = self.vpn(shell, 'profile', 'import', '-', stdin=link)
            self.assertEqual(r.returncode, 0, r.stderr)
        wg = self.tmp / 'office.conf'
        wg.write_text(WG_CONF)
        r = self.vpn(shell, 'profile', 'import', wg, 'Office')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.vpn(shell, 'profile', 'use', 'home').returncode, 0)

    def test_profile_list_and_show_never_print_a_secret(self):
        for shell in self.each_shell():
            self.setup_profiles(shell)
            r = self.vpn(shell, 'profile', 'list', '--json')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.no_secret(r.stdout, r.stderr)
            ps = {p['id']: p for p in json.loads(r.stdout)}
            self.assertEqual(sorted(ps), ['home', 'office', 'tro'])
            h = ps['home']
            self.assertEqual((h['name'], h['type'], h['engine'], h['extra'], h['active'], h['source']),
                             ('Home', 'xray', 'xray', 'vpn-xray', True, 'manual'))
            self.assertEqual(h['server'], {'host': 'vpn.example.com', 'port': 443})
            self.assertEqual((h['protocol'], h['transport'], h['security']), ('vless', 'ws', 'tls'))
            self.assertEqual(h['options'], {'TLS_PIN_SHA256': '', 'UPSTREAM_HTTP_PROXY': ''})
            self.assertFalse(h['engine_installed'])
            self.assertIsInstance(h['created'], int)
            self.assertEqual(ps['office']['type'], 'wireguard')
            self.assertIsNone(ps['office']['extra'])
            self.assertIsNone(ps['office']['protocol'])
            self.assertFalse(ps['tro']['active'])
            r = self.vpn(shell, 'profile', 'show', 'office', '--json')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.no_secret(r.stdout, r.stderr)
            self.assertNotIn('config', json.loads(r.stdout))
            # the plain list is unchanged
            r = self.vpn(shell, 'profile', 'list')
            self.assertIn('*\thome\txray\tHome', r.stdout)

    def test_reveal_is_root_only_and_json_only(self):
        for shell in self.each_shell():
            self.setup_profiles(shell)
            r = self.vpn(shell, 'profile', 'show', 'home', '--reveal')
            self.assertEqual(r.returncode, 2)
            r = self.vpn(shell, 'profile', 'show', 'home', '--json', '--reveal')
            if os.geteuid() == 0:
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(json.loads(r.stdout)['config'].strip(), VLESS)
            else:
                self.assertEqual(r.returncode, 1)
                self.assertNotIn(UUID, r.stdout + r.stderr)

    def test_status_settings_version_killswitch(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.vpn(shell, 'status', '--json')
            self.assertEqual(r.returncode, 0, r.stderr)
            s = json.loads(r.stdout)
            self.assertIsNone(s['profile'])
            self.assertEqual((s['enabled'], s['running'], s['kill_switch']['setting'], s['ipv6']['setting']),
                             (False, False, True, 'auto'))
            self.setup_profiles(shell)
            s = json.loads(self.vpn(shell, 'status', '--json').stdout)
            self.assertEqual(s['profile'], {'id': 'home', 'name': 'Home', 'type': 'xray', 'engine': 'xray'})
            # nothing installed: the xray profile's engine is what is missing
            self.assertEqual(s['missing_engine'], 'vpn-xray')
            self.assertEqual(s['engine']['installed'], False)
            self.put('vpn-xray', 'xray', 'hev-socks5-tunnel')
            s = json.loads(self.vpn(shell, 'status', '--json').stdout)
            # without sing-box a VLESS link runs on xray behind the kill switch (the resolve window)
            self.assertEqual((s['engine']['name'], s['engine']['installed'], s['missing_engine']), ('xray', True, None))
            # with it, on sing-box, as v1 did
            self.put('vpn-singbox', 'sing-box')
            s = json.loads(self.vpn(shell, 'status', '--json').stdout)
            self.assertEqual((s['profile']['engine'], s['engine']['name'], s['engine']['extra']),
                             ('sing-box', 'sing-box', 'vpn-singbox'))
            shutil.rmtree(self.disk / 'extra/vpn-singbox')
            st = json.loads(self.vpn(shell, 'settings', '--json').stdout)
            self.assertEqual((st['KILL_SWITCH'], st['IPV6'], st['DAE']), ('1', 'auto', ''))
            self.assertEqual(len(st), 12)
            v = json.loads(self.vpn(shell, 'version', '--json').stdout)
            self.assertIn('version', v)
            k = json.loads(self.vpn(shell, 'killswitch', '--json').stdout)
            self.assertEqual(k, {'setting': True, 'active': False})
            self.assertEqual(self.vpn(shell, 'killswitch', 'off').returncode, 0)
            self.assertEqual(self.vpn(shell, 'killswitch').stdout.strip(), 'off')
            self.assertEqual(self.vpn(shell, 'settings', 'get', 'KILL_SWITCH').stdout.strip(), '0')
            self.assertNotIn('svc restart', self.log('svc.log'))
            self.conf.write_text('ENABLE=1\n')
            self.assertEqual(self.vpn(shell, 'killswitch', 'on').returncode, 0)
            self.assertIn('svc restart', self.log('svc.log'))

    def test_the_kill_switch_is_not_turned_on_under_a_profile_that_cannot_run_behind_it(self):
        """an xray link with allowInsecure cannot run behind the kill switch (run refuses it and the device stays
        offline): killswitch on and settings set KILL_SWITCH refuse it while the VPN is on, --force overrides"""
        insecure = VLESS.replace('&sni=', '&allowInsecure=1&sni=').replace('#Home', '#Lab')
        for shell in self.each_shell():
            self.fresh()
            r = self.vpn(shell, 'profile', 'import', '-', stdin=insecure)
            self.assertEqual(r.returncode, 0, r.stderr)
            pid = r.stdout.strip().splitlines()[-1]
            self.assertEqual(self.vpn(shell, 'profile', 'use', pid).returncode, 0)
            self.assertEqual(self.vpn(shell, 'killswitch', 'off').returncode, 0)
            # the VPN off: nothing to keep down, the setting is only stored
            self.conf.write_text('ENABLE=0\n')
            self.assertEqual(self.vpn(shell, 'killswitch', 'on').returncode, 0)
            self.assertEqual(self.vpn(shell, 'killswitch', 'off').returncode, 0)
            self.conf.write_text('ENABLE=1\n')
            for args in (('killswitch', 'on'), ('settings', 'set', 'KILL_SWITCH', '1'),
                         ('settings', 'set', 'KILL_SWITCH', '')):
                r = self.vpn(shell, *args)
                self.assertEqual(r.returncode, 1, args)
                self.assertIn('allowInsecure', r.stderr)
                self.no_secret(r.stdout, r.stderr)
                self.assertEqual(self.vpn(shell, 'settings', 'get', 'KILL_SWITCH').stdout.strip(), '0')
            self.assertEqual(self.vpn(shell, 'settings', 'set', 'KILL_SWITCH', '0').returncode, 0)
            r = self.vpn(shell, 'killswitch', 'on', '--force')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.vpn(shell, 'settings', 'get', 'KILL_SWITCH').stdout.strip(), '1')
            self.assertEqual(self.vpn(shell, 'killswitch', 'off', '--force').returncode, 2)

    def test_a_json_command_that_fails_says_so_in_json(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.vpn(shell, 'profile', 'show', 'nosuch', '--json')
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout), {'error': 'no such profile: nosuch'})
            r = self.vpn(shell, 'profile', 'show', 'Bad/Id', '--json')
            self.assertEqual(r.returncode, 2)
            self.assertIn('error', json.loads(r.stdout))

    def test_use_start_stop_aliases(self):
        for shell in self.each_shell():
            self.setup_profiles(shell)
            r = self.vpn(shell, 'use', 'tro')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((self.tmp / 'vpn/active').read_text().strip(), 'tro')
            r = self.vpn(shell, 'stop')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('ENABLE=0', self.conf.read_text())
            self.assertIn('nft delete table inet mu300_vpn', self.log('nft.log'))
            self.assertIn('nft delete table inet mu300_vpn_v6', self.log('nft.log'))


class Ipv6(Base):
    def loaded(self):
        """the rulesets nft -f was given, in order"""
        return [x for x in self.log('nft.log').split('-- loaded\n') if x.strip()]

    def test_the_kill_switch_rejects_ipv6_before_its_drop(self):
        for shell in self.each_shell():
            self.fresh()
            self.assertEqual(self.lib(shell, 'killswitch_on').returncode, 0)
            rs = self.loaded()[0]
            for chain in ('output', 'forward'):
                body = rs.split(f'chain {chain} {{')[1].split('}')[0]
                lines = [l.strip() for l in body.splitlines() if l.strip().startswith('oifname')]
                for i in ('sipa_eth*', 'wlan0'):
                    mine = [l for l in lines if l.startswith(f'oifname "{i}"')]
                    self.assertEqual(mine[-3:], [
                        f'oifname "{i}" meta nfproto ipv6 meta l4proto tcp reject with tcp reset',
                        f'oifname "{i}" meta nfproto ipv6 reject with icmpv6 type admin-prohibited',
                        f'oifname "{i}" counter drop'], (chain, i))
                    if chain == 'output':
                        self.assertIn(f'oifname "{i}" meta nfproto ipv6 icmpv6 type nd-neighbor-solicit accept', mine)
                        self.assertIn(f'oifname "{i}" meta nfproto ipv6 udp sport 546 udp dport 547 accept', mine)
                        # the engine's own marked sockets go first
                        self.assertEqual(mine[0], f'oifname "{i}" meta mark 0x2d0 accept')

    def guard(self, shell, setup, v6addr):
        (self.tmp / 'nft.log').unlink(missing_ok=True)
        if v6addr:
            self.stub('ip', 'case "$*" in "-6 addr show"*) echo "    inet6 2001:db8::2/64 scope global" ;; '
                            '"link show"*) exit 1 ;; esac; exit 0')
        else:
            self.stub('ip', 'case "$*" in "link show"*|"-6 addr show"*) exit 1 ;; esac; exit 0')
        r = self.lib(shell, setup + '; ipv6_guard')
        self.assertEqual(r.returncode, 0, r.stderr)
        log = self.log('nft.log')
        if 'table inet mu300_vpn_v6 {' in log:
            return 'on'
        return 'off' if 'nft delete table inet mu300_vpn_v6' in log else 'none'

    def test_the_guard_per_engine_and_setting(self):
        cases = [
            # (setup, the tunnel has a global IPv6 address, the guard)
            ('KILL_SWITCH=0; IPV6=auto; DRV_ROUTES=core; TUN=xtun', False, 'on'),     # xray, mihomo, dae: IPv4 only
            ('KILL_SWITCH=0; IPV6=auto; DRV_ROUTES=core; TUN=wg-mu300', True, 'off'),  # WireGuard with IPv6
            ('KILL_SWITCH=0; IPV6=0; DRV_ROUTES=core; TUN=wg-mu300', True, 'on'),      # IPv6 turned off
            ('KILL_SWITCH=0; IPV6=1; DRV_ROUTES=self; TUN=sbtun', False, 'off'),       # sing-box asked for IPv6
            ('KILL_SWITCH=0; IPV6=auto; DRV_ROUTES=self; TUN=sbtun', False, 'on'),     # sing-box, IPv4 only
            ('KILL_SWITCH=1; IPV6=auto; DRV_ROUTES=core; TUN=xtun', False, 'none'),    # the kill switch rejects it
        ]
        for shell in self.each_shell():
            self.fresh()
            for setup, v6, want in cases:
                self.assertEqual(self.guard(shell, setup, v6), want, setup)

    def test_the_guards_ruleset(self):
        for shell in self.each_shell():
            r = self.lib(shell, 'ipv6_guard_ruleset')
            rs = r.stdout
            self.assertIn('table inet mu300_vpn_v6 {', rs)
            out = rs.split('chain output {')[1].split('}')[0]
            fwd = rs.split('chain forward {')[1].split('}')[0]
            self.assertIn('meta mark 0x2d0 accept', out.splitlines()[2])
            for i in ('sipa_eth*', 'wlan0'):
                for body in (out, fwd):
                    self.assertIn(f'oifname "{i}" meta nfproto ipv6 reject with icmpv6 type admin-prohibited', body)
                    self.assertIn(f'oifname "{i}" meta nfproto ipv6 meta l4proto tcp reject with tcp reset', body)
            # nothing but IPv6 is touched: every rule but the mark names nfproto ipv6
            rules = [l.strip() for l in (out + fwd).splitlines() if l.strip().startswith('oifname')]
            self.assertTrue(all('meta nfproto ipv6' in l for l in rules))
            self.assertNotIn('drop', rs)

    def test_off_and_a_disabled_run_remove_it(self):
        for shell in self.each_shell():
            self.fresh()
            self.assertEqual(self.vpn(shell, 'run').returncode, 0)
            self.assertIn('nft delete table inet mu300_vpn_v6', self.log('nft.log'))


class Dae(Base):
    def kernel(self, rel, btf):
        b = self.tmp / 'btf'
        if btf:
            b.write_text('x')
        else:
            b.unlink(missing_ok=True)
        return dict(MU300_KREL=rel, MU300_BTF=b)

    def test_the_kernel_check(self):
        for shell in self.each_shell():
            for rel, btf, ok in (('5.4.210', True, False), ('6.18.3', False, False), ('6.18.3', True, True),
                                 ('5.17.0', True, True), ('5.16.9', True, False), ('7.2.0-mu300', True, True)):
                r = self.lib(shell, 'dae_kernel_ok', **self.kernel(rel, btf))
                self.assertEqual(r.returncode == 0, ok, (rel, btf, r.stdout))
                if not ok:
                    self.assertIn('dae needs', r.stdout)

    def test_import_sniffs_and_checks(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.vpn(shell, 'profile', 'import', '-', stdin=HY2)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'hy'), r.stderr)
            self.assertIn("TYPE='dae'", (self.tmp / 'vpn/profiles/hy/meta').read_text())
            self.assertTrue((self.tmp / 'vpn/profiles/hy/uri').exists())
            # several links in a file: one profile, all of them in a group
            f = self.tmp / 'nodes.txt'
            f.write_text(f'{VLESS}\n\n{TROJAN}\r\n{HY2}\n')
            r = self.vpn(shell, 'profile', 'add', 'dae', 'Nodes', f)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(len((self.tmp / 'vpn/profiles/nodes/links').read_text().splitlines()), 3)
            # a raw dae config is sniffed by its sections
            cfg = self.tmp / 'my.dae'
            cfg.write_text("global { lan_interface: eth0 }\nnode { a: 'ss://YWVzLTEyOC1nY206cA==@h.example:1' }\n"
                           "routing { fallback: proxy }\ngroup { proxy { policy: min } }\n")
            r = self.vpn(shell, 'profile', 'import', cfg)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'my'), r.stderr)
            self.assertIn("TYPE='dae'", (self.tmp / 'vpn/profiles/my/meta').read_text())
            # refused at import: an include, a file:// subscription, a section it does not know
            for bad in ('include { other.dae }\n', "subscription { 'file://x.sub' }\n", 'pprof { }\n'):
                cfg.write_text(bad + "node { a: 'ss://x@h:1' }\nrouting { fallback: proxy }\n")
                r = self.vpn(shell, 'profile', 'add', 'dae', 'Bad', cfg)
                self.assertEqual(r.returncode, 1, bad)
                self.assertFalse((self.tmp / 'vpn/profiles/bad').exists())
            self.no_secret(r.stdout, r.stderr)

    def rebuild(self, shell, setup):
        r = self.lib(shell, f'load_driver dae; PDIR="{self.tmp}/p"; {setup}; dae_rebuild "{self.tmp}/out.dae" && cat "{self.tmp}/out.dae"')
        return r

    def test_the_config_dae_gets(self):
        for shell in self.each_shell():
            p = self.tmp / 'p'
            shutil.rmtree(p, ignore_errors=True)
            p.mkdir()
            (p / 'meta').write_text("TYPE='dae'\n")
            (p / 'uri').write_text(VLESS + '\n')
            r = self.rebuild(shell, 'REMOTE_DNS=9.9.9.9; BOOTSTRAP_DNS=1.0.0.1')
            self.assertEqual(r.returncode, 0, r.stderr)
            c = r.stdout
            for want in ('so_mark_from_dae: 720', 'wan_interface: mu300dae', 'pprof_port: 0',
                         "bootstrap_resolver: '1.0.0.1:53'", "mu300_remote: 'tcp+udp://9.9.9.9:53'",
                         "mu300_bootstrap: 'udp://1.0.0.1:53'", "node(name_regex: '.') -> mu300_bootstrap",
                         f"mu300_1: '{VLESS.split('#')[0]}'", 'policy: fixed(0)', 'fallback: proxy'):
                self.assertIn(want, c)
            self.assertNotIn('lan_interface', c)     # no LAN interface here (the ip stub has none)
            self.assertEqual(c.count('global {'), 1)
            # the LAN from the profile, and a policy
            (p / 'meta').write_text("TYPE='dae'\nDAE_LAN='usb0,wlan0'\nDAE_POLICY='min'\n")
            (p / 'uri').unlink()
            (p / 'links').write_text(f'{VLESS}\n{TROJAN}\n')
            c = self.rebuild(shell, 'true').stdout
            self.assertIn('lan_interface: usb0,wlan0', c)
            self.assertIn('policy: min\n', c)
            self.assertIn("mu300_2: '" + TROJAN.split('#')[0] + "'", c)
            # a raw config: its global goes, ours is the only one; a listener in dns goes; its sections stay
            (p / 'links').unlink()
            (p / 'config.dae').write_text(
                "global { wan_interface: auto\n so_mark_from_dae: 0\n pprof_port: 6060 }\n"
                "dns { bind: '0.0.0.0:53'\n upstream { g: 'udp://8.8.8.8:53' }\n routing { request { fallback: g } } }\n"
                "node { a: 'ss://YWVzLTEyOC1nY206cA==@h.example:1' }\n# a comment { with braces }\n"
                "group { proxy { policy: min } }\nrouting {\n  dip(geoip:private) -> direct\n  fallback: proxy\n}\n")
            r = self.rebuild(shell, 'true')
            self.assertEqual(r.returncode, 0, r.stderr)
            c = r.stdout
            self.assertEqual(c.count('global {'), 1)
            self.assertNotIn('6060', c)
            self.assertNotIn('bind', c)
            self.assertNotIn('wan_interface: auto', c)
            # its dns section is replaced by ours (REMOTE_DNS through the proxy): nothing of it is left
            self.assertNotIn('8.8.8.8:53', c.split('dns {')[1].split('\nnode {')[0])
            self.assertEqual(c.count('dns {'), 1)
            self.assertIn('dip(geoip:private) -> direct', c)
            self.assertNotIn('comment', c)
            self.assertIn('so_mark_from_dae: 720', c)

    def test_the_raw_readers_refusals(self):
        bad = {
            'include { a.dae }': 'an include',
            'foo { }': 'not node, group or routing',
            "subscription { 'file://x.sub' }": 'a subscription section',
            "node { a: 'x' ": 'a { without its }',
            '}': 'a } without its {',
            'stray words': 'text at the top level',
            "node { a: 'open }": 'not closed on its line',
            'node { }\nnode { }': 'the section node twice',
        }
        for shell in self.each_shell():
            for text, why in bad.items():
                f = self.tmp / 'c.dae'
                f.write_text(text + "\nnode { b: 'ss://y@h:2' }\nrouting { fallback: proxy }\n")
                r = self.lib(shell, f'load_driver dae; dae_read check "{f}" || echo REFUSED')
                self.assertIn('REFUSED', r.stdout, text)
                self.assertIn(why, r.stdout, text)
                # a refusal names a rule, never the file's text
                self.assertNotIn("ss://y@h:2", r.stdout)

    def test_no_btf_fails_closed(self):
        """on a kernel without BTF the service puts the kill switch up and goes no further"""
        for shell in self.each_shell():
            self.fresh()
            self.assertEqual(self.vpn(shell, 'profile', 'import', '-', stdin=HY2).returncode, 0)
            self.assertEqual(self.vpn(shell, 'profile', 'use', 'hy').returncode, 0)
            self.put('vpn-dae', 'dae')
            self.conf.write_text('ENABLE=1\n')
            r = self.vpn(shell, 'run', **self.kernel('5.4.210', True))
            self.assertEqual(r.returncode, 1)
            self.assertIn('dae needs Linux 5.17', r.stderr)
            nft = self.log('nft.log')
            self.assertIn('table inet mu300_vpn {', nft)
            self.assertNotIn('delete table inet mu300_vpn\n', nft.split('-- loaded')[-1])
            # and on: refused before ENABLE=1 is written
            self.conf.write_text('ENABLE=0\n')
            r = self.vpn(shell, 'on', **self.kernel('5.4.210', True))
            self.assertEqual(r.returncode, 1)
            self.assertIn('ENABLE=0', self.conf.read_text())

    def test_a_missing_engine_fails_closed(self):
        """the active profile's engine extra is gone and cannot be had: the kill switch stays, nothing runs"""
        for shell in self.each_shell():
            self.fresh()
            self.assertEqual(self.vpn(shell, 'profile', 'import', '-', stdin=HY2).returncode, 0)
            self.assertEqual(self.vpn(shell, 'profile', 'use', 'hy').returncode, 0)
            self.conf.write_text('ENABLE=1\n')
            r = self.vpn(shell, 'run', EXTRA_RC='1', FETCH_REFRESH='1', **self.kernel('6.18.3', True))
            self.assertEqual(r.returncode, 1)
            self.assertIn('mu300-extra install vpn-dae', r.stderr)
            self.assertIn('extra install vpn-dae', self.log('extra.log'))
            last = self.loaded()[-1] if hasattr(self, 'loaded') else self.log('nft.log').split('-- loaded')[-2]
            self.assertIn('oifname "sipa_eth*" counter drop', last)

    def loaded(self):
        return [x for x in self.log('nft.log').split('-- loaded\n') if x.strip()]


class Subscriptions(Base):
    def serve(self, body):
        (self.tmp / 'sub.body').write_bytes(body)
        # curl, as http_get calls it: the body for every URL (and the URL noted, to check it was the one stored)
        # (the URL comes as curl's config on stdin, never as an argument; the arguments are noted to check that)
        self.stub('curl', 'echo "$*" >> "$STUBLOG/argv"; u=$(sed -n \'s/^url = "\\(.*\\)"$/\\1/p\'); '
                          'echo "$u" >> "$STUBLOG/urls"; cat "$STUBLOG/sub.body"')

    def test_links_base64_add_refresh_remove(self):
        url = f'https://panel.example.com/api/sub/{TOKEN}?flag=1'
        for shell in self.each_shell():
            self.fresh()
            (self.tmp / 'urls').unlink(missing_ok=True)
            self.serve(base64.b64encode(f'{VLESS}\n{TROJAN}\n'.encode()))
            r = self.vpn(shell, 'subscription', 'add', 'Work', '-', stdin=url + '\n')
            self.assertEqual((r.returncode, r.stdout.strip().splitlines()[-1]), (0, 'work'), r.stderr)
            self.assertEqual(self.log('urls').strip(), url)
            self.no_secret(r.stdout, r.stderr)
            ps = {p['id']: p for p in json.loads(self.vpn(shell, 'profile', 'list', '--json').stdout)}
            self.assertEqual(sorted(ps), ['home', 'tro'])
            self.assertTrue(all(p['source'] == 'subscription' and p['subscription'] == 'work' for p in ps.values()))
            r = self.vpn(shell, 'subscription', 'list', '--json')
            self.no_secret(r.stdout)
            s = json.loads(r.stdout)[0]
            self.assertEqual((s['id'], s['name'], s['host'], s['count'], s['format'], sorted(s['profiles'])),
                             ('work', 'Work', 'https://panel.example.com', 2, 'links', ['home', 'tro']))
            r = self.vpn(shell, 'subscription', 'show', 'work', '--json', '--reveal')
            if os.geteuid() == 0:
                self.assertEqual(json.loads(r.stdout)['url'], url)
            # refresh: Home changes (same id), Tro is gone, a new one comes
            changed = VLESS.replace('vpn.example.com:443', 'vpn2.example.com:8443')
            self.serve(f'{changed}\n{HY2}\nnot a link\n'.encode())
            r = self.vpn(shell, 'subscription', 'refresh', 'work')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('0 added, 1 updated, 1 removed, 1 skipped', r.stdout)   # no dae engine: hy2 skipped (a line that is no link is not counted)
            ps = {p['id']: p for p in json.loads(self.vpn(shell, 'profile', 'list', '--json').stdout)}
            self.assertEqual(sorted(ps), ['home'])
            self.assertEqual(ps['home']['server'], {'host': 'vpn2.example.com', 'port': 8443})
            # with the dae engine there, the hysteria2 link becomes a dae profile
            self.put('vpn-dae', 'dae')
            r = self.vpn(shell, 'subscription', 'refresh')
            self.assertIn('1 added', r.stdout)
            ps = {p['id']: p for p in json.loads(self.vpn(shell, 'profile', 'list', '--json').stdout)}
            self.assertEqual(ps['hy']['type'], 'dae')
            # the active one is not removed while the VPN is on: it is kept, stale
            self.assertEqual(self.vpn(shell, 'profile', 'use', 'home').returncode, 0)
            self.conf.write_text('ENABLE=1\n')
            self.serve(f'{HY2}\n'.encode())
            self.vpn(shell, 'subscription', 'refresh', 'work')
            ps = {p['id']: p for p in json.loads(self.vpn(shell, 'profile', 'list', '--json').stdout)}
            self.assertTrue(ps['home']['stale'])
            r = self.vpn(shell, 'subscription', 'remove', 'work')
            self.assertEqual(r.returncode, 1)
            self.conf.write_text('ENABLE=0\n')
            r = self.vpn(shell, 'subscription', 'remove', 'work')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(self.vpn(shell, 'profile', 'list', '--json').stdout), [])
            self.assertFalse((self.tmp / 'vpn/subscriptions/work').exists())

    def test_a_clash_subscription_is_one_mihomo_profile(self):
        for shell in self.each_shell():
            self.fresh()
            self.serve(MH_CONF.encode())
            r = self.vpn(shell, 'subscription', 'add', 'Clash', 'https://c.example.org/x')
            self.assertEqual(r.returncode, 0, r.stderr)
            ps = json.loads(self.vpn(shell, 'profile', 'list', '--json').stdout)
            self.assertEqual([(p['id'], p['type']) for p in ps], [('clash', 'mihomo')])
            # the same name, refreshed: the same profile
            self.assertEqual(self.vpn(shell, 'subscription', 'refresh', 'clash').returncode, 0)
            self.assertEqual(len(json.loads(self.vpn(shell, 'profile', 'list', '--json').stdout)), 1)

    def test_what_is_refused(self):
        for shell in self.each_shell():
            self.fresh()
            self.serve(b'')
            for url in ('ftp://x/y', 'file:///etc/shadow', "https://x/'a", 'http://x.example/plain', 'https://x/a\\b'):
                r = self.vpn(shell, 'subscription', 'add', 'X', url)
                self.assertEqual(r.returncode, 2, url)
            r = self.vpn(shell, 'subscription', 'add', 'X', 'https://x.example/empty')
            self.assertEqual(r.returncode, 1)
            self.assertFalse((self.tmp / 'vpn/subscriptions/x').exists())
            self.serve(b'hello world\n')
            r = self.vpn(shell, 'subscription', 'add', 'X', 'https://x.example/junk')
            self.assertEqual(r.returncode, 1)
            self.assertIn('neither a Clash/mihomo YAML nor a list of links', r.stderr)


class Latency(Base):
    def test_tcp_connect_time(self):
        for shell in self.each_shell():
            self.fresh()
            self.stub('curl', 'case "$*" in *vpn.example.com*) printf 0.048213 ;; *) printf 0.000000; exit 7 ;; esac')
            for link in (VLESS, TROJAN):
                self.assertEqual(self.vpn(shell, 'profile', 'import', '-', stdin=link).returncode, 0)
            wg = self.tmp / 'w.conf'
            wg.write_text(WG_CONF)
            self.assertEqual(self.vpn(shell, 'profile', 'import', wg, 'Wg').returncode, 0)
            r = self.vpn(shell, 'latency', 'home', '--json')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout), {'id': 'home', 'host': 'vpn.example.com', 'port': 443, 'ms': 48,
                                                    'via': 'direct', 'error': None})
            r = self.vpn(shell, 'latency', '--all', '--json')
            got = {x['id']: x for x in json.loads(r.stdout)}
            self.assertEqual((got['tro']['ms'], got['tro']['error']), (None, 'unreachable'))
            self.assertEqual(got['wg']['error'], 'udp')
            self.no_secret(r.stdout, r.stderr)
            r = self.vpn(shell, 'latency', 'home')
            self.assertEqual(r.stdout.strip(), 'home\t48 ms\tdirect')


class Logs(Base):
    def test_logs_by_engine(self):
        for shell in self.each_shell():
            self.stub('journalctl', 'printf "a mu300-vpn[1]: start\\nb sing-box[2]: WARN x\\nc xray[3]: up\\n"')
            r = self.vpn(shell, 'logs', 'xray', '-n', '5')
            self.assertEqual(r.stdout.splitlines(), ['c xray[3]: up'])
            r = self.vpn(shell, 'logs', '-n', '2')
            self.assertEqual(len(r.stdout.splitlines()), 2)
            self.assertEqual(self.vpn(shell, 'logs', 'nope').returncode, 2)
