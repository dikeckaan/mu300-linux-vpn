"""mu300-vpn, sourced for its functions (MU300_LIB=1): the VLESS URI parser, JSON helpers, which networks stay out of
the tunnel, and the sing-box config it writes. Ubuntu and OpenWrt both run it (dash, bash, busybox ash)."""
import json
import os
import re
import shutil
import signal
import subprocess
import time
import unittest

from helpers import BIN, ShellTest


class Vpn(ShellTest):
    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('')
        self.root = self.tmp / 'root'
        (self.root / 'run/mu300').mkdir(parents=True)
        self.brlan = None
        self.stub('ip', 'if [ "$*" = "-4 -o addr show br-lan" ] && [ -s "$STUBLOG/br-lan" ]; then '
                        'echo "5: br-lan    inet $(cat "$STUBLOG/br-lan") brd x scope global br-lan"; fi')

    def vpn(self, shell, code, conf='', device='f50', brlan=None):
        self.conf.write_text(conf)
        (self.root / 'run/mu300/device').write_text(device + '\n')
        (self.tmp / 'br-lan').write_text(brlan or '')
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', MU300_LIB=1, MU300_VPN_CONF=self.conf,
                       MU300_VPN_RUN=self.tmp / 'run-vpn', MU300_LAN_CONF=self.tmp / 'no-lan.conf',
                       MU300_BIN=BIN, MU300_SYSROOT=self.root)

    def test_own_lan_always_local(self):
        cases = [
            # (vpn.conf, device, br-lan address, LAN_CIDRS wanted)
            ('', 'f50', '192.168.77.1/24', '192.168.77.0/24'),
            ('', 'u30air', '192.168.78.1/24', '192.168.78.0/24'),
            # a vpn.conf copied from an F50 onto a U30 Air: its own network is added, not replaced
            ('LAN_CIDRS=192.168.77.0/24\n', 'u30air', '192.168.78.1/24', '192.168.77.0/24,192.168.78.0/24'),
            ('LAN_CIDRS=192.168.78.0/24\n', 'u30air', '192.168.78.1/24', '192.168.78.0/24'),
            # br-lan not up yet: the device's default address
            ('', 'u30air', None, '192.168.78.0/24'),
            ('', 'f50', None, '192.168.77.0/24'),
            # an address set in lan.conf / UCI, as br-lan has it
            ('LAN_CIDRS=10.0.0.0/8\n', 'f50', '192.168.5.1/24', '10.0.0.0/8,192.168.5.0/24'),
        ]
        for shell in self.each_shell():
            for conf, device, brlan, want in cases:
                r = self.vpn(shell, 'echo "$LAN_CIDRS"', conf, device, brlan)
                self.assertEqual(r.stdout.strip(), want, (conf, device, brlan, r.stderr))

    def test_urldecode(self):
        for shell in self.each_shell():
            r = self.vpn(shell, "urldecode 'a%20b%2Fc'; echo; urldecode 'k%C3%BCt%C3%BCk'; echo; urldecode plain; echo")
            self.assertEqual(r.stdout.split('\n')[:3], ['a b/c', 'kütük', 'plain'])

    def test_json_helpers(self):
        for shell in self.each_shell():
            r = self.vpn(shell, """json_str 'a"b\\c'; echo; json_list 'x,y"z,w'; echo""")
            a, b = r.stdout.split('\n')[:2]
            self.assertEqual(json.loads(a), 'a"b\\c')
            self.assertEqual(json.loads(b), ['x', 'y"z', 'w'])

    URIS = [
        ('vless://11111111-2222-3333-4444-555555555555@vpn.example.com:8443?type=ws&security=tls&sni=cdn.example.com'
         '&path=%2Fws%3Fed%3D2048&host=h.example.com#name',
         dict(UUID='11111111-2222-3333-4444-555555555555', HOST='vpn.example.com', PORT='8443', TYPE='ws',
              SECURITY='tls', SNI='cdn.example.com', WSPATH='/ws?ed=2048', WSHOST='h.example.com')),
        ('vless://uuid@[2001:db8::1]:443?security=reality&pbk=KEY&sid=ab&fp=chrome&type=grpc&serviceName=svc',
         dict(UUID='uuid', HOST='2001:db8::1', PORT='443', TYPE='grpc', SECURITY='reality', PBK='KEY', SID='ab',
              FP='chrome', SVC='svc')),
        ('vless://uuid@host.example', dict(HOST='host.example', PORT='443', TYPE='tcp', SECURITY='none')),
        ('vless://uuid@1.2.3.4:80/?type=tcp&peer=p.example', dict(HOST='1.2.3.4', PORT='80', SNI='p.example')),
    ]

    def test_parse_uri(self):
        for shell in self.each_shell():
            for uri, want in self.URIS:
                code = f"VLESS_URI='{uri}'; parse_uri; " + '; '.join(f'echo "{k}=${k}"' for k in want)
                r = self.vpn(shell, code)
                self.assertEqual(r.returncode, 0, r.stderr)
                got = dict(line.split('=', 1) for line in r.stdout.splitlines())
                self.assertEqual(got, want, uri)

    def test_parse_uri_rejects(self):
        for shell in self.each_shell():
            for uri in ('vmess://abc@h:1', 'vless://@host:443', 'https://x'):
                r = self.vpn(shell, f"VLESS_URI='{uri}'; parse_uri; echo PARSED")
                self.assertNotEqual(r.returncode, 0, uri)
                self.assertNotIn('PARSED', r.stdout)

    def test_outbound_json(self):
        for shell in self.each_shell():
            for uri, _ in self.URIS:
                r = self.vpn(shell, f"VLESS_URI='{uri}'; UPSTREAM_HTTP_PROXY=; parse_uri; outbound_json")
                o = json.loads(r.stdout)
                self.assertEqual(o['type'], 'vless')
                self.assertIsInstance(o['server_port'], int)
            r = self.vpn(shell, f"VLESS_URI='{self.URIS[1][0]}'; UPSTREAM_HTTP_PROXY=; parse_uri; outbound_json")
            o = json.loads(r.stdout)
            self.assertEqual(o['tls']['reality'], {'enabled': True, 'public_key': 'KEY', 'short_id': 'ab'})
            self.assertEqual(o['transport'], {'type': 'grpc', 'service_name': 'svc'})

    def test_singbox_config(self):
        self.stub('sing-box', 'echo "$*" >> "$STUBLOG/sb.args"')
        conf = f"VLESS_URI='{self.URIS[0][0]}'\nLAN_CIDRS=192.168.77.0/24\nENGINE=sing-box\n"
        for shell in self.each_shell():
            code = f'BIN="{self.stubs}/sing-box"; UPSTREAM_HTTP_PROXY=; gen_singbox'
            r = self.vpn(shell, code, conf, 'u30air', '192.168.78.1/24')
            self.assertEqual(r.returncode, 0, r.stderr)
            cfg = json.loads((self.tmp / 'run-vpn' / 'config.json').read_text())
            tun = cfg['inbounds'][0]
            self.assertEqual(tun['type'], 'tun')
            self.assertEqual(tun['route_exclude_address'], ['192.168.77.0/24', '192.168.78.0/24'])
            self.assertEqual(cfg['outbounds'][0]['server'], 'vpn.example.com')
            self.assertIn('check -c', (self.tmp / 'sb.args').read_text())


class Engines(ShellTest):
    """where mu300-vpn finds its engines: the vpn extra on the Linux partition first, an older image's own second;
    and what it does when there are none"""

    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.disk = self.tmp / 'disk'
        self.opt = self.tmp / 'opt'
        (self.opt / 'bin').mkdir(parents=True)
        self.extra = self.disk / 'extra/vpn/bin'
        self.stub('ip', 'exit 0')
        self.stub('nft', '[ "$1" = -f ] && cat >> "$STUBLOG/nft"; echo "--- $*" >> "$STUBLOG/nft"')

    def put(self, d, names):
        d.mkdir(parents=True, exist_ok=True)
        for n in names:
            (d / n).write_text('#!/bin/sh\n')
            (d / n).chmod(0o755)

    def vpn(self, shell, code, conf='ENABLE=1\nENGINE=xray\n', **env):
        self.conf.write_text(conf)
        e = dict(MU300_LIB=1, MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run-vpn', MU300_BIN=BIN,
                 MU300_LAN_CONF=self.tmp / 'no-lan.conf', MU300_OPT=self.opt, MU300_DISK=self.disk,
                 MU300_EXTRA_CMD=self.stubs / 'extra')
        e.update(env)
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', **e)

    def reset(self):
        shutil.rmtree(self.disk, ignore_errors=True)
        shutil.rmtree(self.opt / 'bin')
        (self.opt / 'bin').mkdir()

    def test_the_extra_comes_first(self):
        names = ('xray', 'hev-socks5-tunnel', 'sing-box')
        for shell in self.each_shell():
            self.reset()
            self.put(self.opt / 'bin', names)
            r = self.vpn(shell, 'echo "$XRAY $HEV $BIN"')
            self.assertEqual(r.stdout.split(), [str(self.opt / 'bin' / n) for n in names])
            self.put(self.extra, names)
            r = self.vpn(shell, 'echo "$XRAY $HEV $BIN"; engines_ok && echo OK')
            self.assertEqual(r.stdout.split(), [str(self.extra / n) for n in names] + ['OK'])
            # vpn.conf may name its own
            r = self.vpn(shell, 'echo "$XRAY"', conf='ENABLE=1\nXRAY=/x/xray\n')
            self.assertEqual(r.stdout.strip(), '/x/xray')

    def test_missing_engines_are_reported(self):
        for shell in self.each_shell():
            self.reset()
            r = self.vpn(shell, 'engines_ok && echo OK || echo "$MISSING"')
            self.assertEqual(r.stdout.strip(), 'the VPN engines are not installed: run mu300-extra install vpn')
            r = self.vpn(shell, '(gen) && echo rc=0 || echo rc=1')
            self.assertIn('mu300-extra install vpn', r.stderr)
            self.assertNotIn('rc=0', r.stdout)

    def test_a_configured_vpn_gets_its_engines_back(self):
        for shell in self.each_shell():
            for adopt_ok, install_ok, want in ((True, False, 'adopt'), (False, True, 'adopt install'),
                                               (False, False, 'adopt install')):
                self.reset()
                (self.tmp / 'calls').unlink(missing_ok=True)
                self.stub('extra', f'echo "$1" >> "$STUBLOG/calls"; '
                                   f'case $1 in adopt) ok={int(adopt_ok)} ;; install) ok={int(install_ok)} ;; esac; '
                                   f'[ $ok = 1 ] || exit 1; d="{self.extra}"; mkdir -p "$d"; '
                                   'for n in xray hev-socks5-tunnel sing-box; do printf "#!/bin/sh\\n" > "$d/$n"; chmod 755 "$d/$n"; done')
                r = self.vpn(shell, 'ensure_engines && echo rc=0 || echo rc=1; echo "$XRAY"')
                self.assertEqual((self.tmp / 'calls').read_text().split(), want.split(), (adopt_ok, install_ok))
                if adopt_ok or install_ok:
                    self.assertEqual(r.stdout.split()[-2:], ['rc=0', str(self.extra / 'xray')], r.stderr)
                else:
                    self.assertIn('rc=1', r.stdout)
                    self.assertIn('mu300-extra install vpn', r.stderr)
            # engines that are there: nothing is fetched
            self.put(self.extra, ('xray', 'hev-socks5-tunnel', 'sing-box'))
            (self.tmp / 'calls').unlink(missing_ok=True)
            r = self.vpn(shell, 'ensure_engines && echo rc=0 || echo rc=1')
            self.assertIn('rc=0', r.stdout)
            self.assertFalse((self.tmp / 'calls').exists())

    def test_without_the_kill_switch_nothing_is_left_up_while_fetching(self):
        for shell in self.each_shell():
            self.reset()
            (self.tmp / 'nft').unlink(missing_ok=True)
            self.stub('extra', 'exit 1')
            r = self.vpn(shell, 'ensure_engines; true', conf='ENABLE=1\nENGINE=sing-box\nKILL_SWITCH=0\n')
            self.assertNotIn('chain output', (self.tmp / 'nft').read_text() if (self.tmp / 'nft').exists() else '')

    def test_an_adopt_without_engines_still_downloads(self):
        for shell in self.each_shell():
            self.reset()
            (self.tmp / 'calls').unlink(missing_ok=True)
            self.stub('extra', f'echo "$1" >> "$STUBLOG/calls"; [ "$1" = adopt ] && exit 0; d="{self.extra}"; mkdir -p "$d"; '
                               'for n in xray hev-socks5-tunnel sing-box; do printf "#!/bin/sh\n" > "$d/$n"; chmod 755 "$d/$n"; done')
            r = self.vpn(shell, 'ensure_engines && echo rc=0 || echo rc=1')
            self.assertEqual((self.tmp / 'calls').read_text().split(), ['adopt', 'install'])
            self.assertIn('rc=0', r.stdout, r.stderr)

    def test_run_puts_the_kill_switch_up_before_anything_else(self):
        src = (BIN / 'mu300-vpn').read_text()
        run = src[src.index('    run)'):src.index('    off)')]
        self.assertLess(run.index('ENABLE'), run.index('killswitch_on'))
        self.assertLess(run.index('killswitch_on'), run.index('ensure_engines'))
        self.assertLess(run.index('ensure_engines'), run.index('gen'))

class KillSwitch(ShellTest):
    """KILL_SWITCH=1 fails closed: `mu300-vpn run` puts the full kill switch up first, and nothing that goes wrong
    after that - engines missing (an update or `mu300-extra remove vpn --force` took them), a failed or corrupt
    download, a signal or the deadline in the middle of it, a config the engine rejects, a crashed engine - takes it
    down. The download in between gets a window that lets only the device itself out, only to the release hosts,
    and only with timeouts. The nft stub keeps the ruleset that is in force (nft.state) and a log of every call,
    in order with the engines' and mu300-extra's own calls (events)."""

    URI = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?security=tls&type=tcp'
    ENGINES = ('xray', 'hev-socks5-tunnel', 'sing-box')

    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.disk = self.tmp / 'disk'
        self.opt = self.tmp / 'opt'
        self.extra = self.disk / 'extra/vpn/bin'
        self.ev = self.tmp / 'events'
        self.state = self.tmp / 'nft.state'
        self.stub('ip', 'exit 0')
        # the ruleset in force: an nft -f transaction replaces it whole; a lone delete of the table empties it
        self.stub('nft', 'case "$1" in\n'
                         '  -f) r=$(cat); printf "%s\\n" "$r" > "$STUBLOG/nft.state.new"; mv "$STUBLOG/nft.state.new" "$STUBLOG/nft.state"\n'
                         '      { echo "nft -f"; printf "%s\\n" "$r" | sed "s/^/  | /"; } >> "$STUBLOG/events" ;;\n'
                         '  list) [ -s "$STUBLOG/nft.state" ] ;;\n'
                         '  *) echo "nft $*" >> "$STUBLOG/events"\n'
                         '     [ "$*" = "delete table inet mu300_vpn" ] && : > "$STUBLOG/nft.state"; exit 0 ;;\n'
                         'esac')
        self.stub('getent', 'case $2 in\n'
                            '  github.com) echo "140.82.121.3     STREAM github.com" ;;\n'
                            '  api.github.com) echo "140.82.121.6     STREAM api.github.com" ;;\n'
                            '  *.githubusercontent.com) echo "185.199.108.133 STREAM $2"; echo "2606:50c0:8000::154 STREAM $2" ;;\n'
                            '  release.example) echo "203.0.113.7     STREAM $2" ;;\n'
                            'esac')
        self.mkengines = (f'd="{self.extra}"; mkdir -p "$d"; for n in {" ".join(self.ENGINES)}; do '
                          f'cp "{self.tmp}/engine" "$d/$n"; chmod 755 "$d/$n"; done')
        # every engine: notes how it was called; "check" fails when the engine is corrupt
        # the bearer's resolvers, as systemd-resolved / netifd write them; loopback ones are not the bearer's
        (self.tmp / 'resolv.conf').write_text('nameserver 127.0.0.53\nnameserver 10.177.0.34\nnameserver 2001:db8:53::1\n')
        (self.tmp / 'engine').write_text('#!/bin/sh\necho "engine ${0##*/} $*" >> "$STUBLOG/events"\n'
                                         '[ "$1" = check ] && [ -e "$STUBLOG/corrupt" ] && exit 1\nexit 0\n')

    def extra_cmd(self, adopt=False, install='ok'):
        """the mu300-extra stub: adopt works or not; install is ok, fail, or hang (a download that does not end)"""
        body = 'echo "extra $1" >> "$STUBLOG/events"\n'
        body += 'if [ "$1" = adopt ]; then ' + (self.mkengines if adopt else 'exit 1') + '; exit 0; fi\n'
        body += {'ok': self.mkengines,
                 'fail': 'echo "downloading mu300-extra-vpn.tar.gz failed" >&2; exit 1',
                 'hang': 'echo started > "$STUBLOG/started"; sleep 30; exit 1'}[install]
        self.stub('extra', body)

    def fresh(self, engines=()):
        for p in (self.ev, self.state, self.tmp / 'corrupt', self.tmp / 'started'):
            p.unlink(missing_ok=True)
        shutil.rmtree(self.disk, ignore_errors=True)
        shutil.rmtree(self.opt, ignore_errors=True)
        (self.opt / 'bin').mkdir(parents=True)
        if engines:
            self.extra.mkdir(parents=True)
            for n in engines:
                shutil.copy(self.tmp / 'engine', self.extra / n)
                (self.extra / n).chmod(0o755)

    def envs(self, **extra):
        e = dict(MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run-vpn', MU300_BIN=BIN,
                 MU300_LAN_CONF=self.tmp / 'no-lan.conf', MU300_OPT=self.opt, MU300_DISK=self.disk,
                 MU300_EXTRA_CMD=self.stubs / 'extra', FETCH_REFRESH=1, MU300_RESOLV_FILES=self.tmp / 'resolv.conf')
        e.update(extra)
        return e

    def run_vpn(self, shell, conf, **env):
        self.conf.write_text(conf)
        return self.script(shell, BIN / 'mu300-vpn', 'run', **self.envs(**env))

    def conf_ks(self, engine='sing-box'):
        return f"ENABLE=1\nENGINE={engine}\nKILL_SWITCH=1\nVLESS_URI='{self.URI}'\n"

    def events(self):
        return self.ev.read_text() if self.ev.exists() else ''

    def rulesets(self):
        """every ruleset applied, in order"""
        out = []
        for chunk in self.events().split('nft -f\n')[1:]:
            out.append('\n'.join(l[4:] for l in chunk.splitlines() if l.startswith('  | ')))
        return out

    def assertFull(self, ruleset, msg=None):
        """the full kill switch: device and clients dropped on the modem, nothing open for a download"""
        self.assertIn('chain output', ruleset, msg)
        self.assertIn('chain forward', ruleset, msg)
        self.assertRegex(ruleset, r'chain output \{[^}]*oifname "sipa_eth\*" counter drop', msg)
        self.assertRegex(ruleset, r'chain forward \{[^}]*oifname "sipa_eth\*" counter drop', msg)
        # the Wi-Fi client is an uplink too (wifi-client shares it with the LAN): the same for wlan0, except the
        # device's DHCP to that network, which keeps the address the engine's own connection goes out on
        self.assertRegex(ruleset, r'chain output \{[^}]*oifname "wlan0" udp sport 68 udp dport 67 accept'
                                  r'[^}]*oifname "wlan0" counter drop', msg)
        self.assertRegex(ruleset, r'chain forward \{[^}]*oifname "wlan0" counter drop', msg)
        self.assertNotIn('fetch', ruleset, msg)
        self.assertNotIn('dport 53', ruleset, msg)

    def assertClosed(self, msg=None):
        self.assertTrue(self.state.exists(), msg)
        self.assertFull(self.state.read_text(), msg)
        # never a moment without it: the table is only ever replaced in one transaction, never deleted on its own
        self.assertNotIn('nft delete table inet mu300_vpn', self.events(), msg)

    def test_the_kill_switch_is_up_before_anything_can_fail(self):
        for shell in self.each_shell():
            self.fresh()
            self.extra_cmd(install='fail')
            r = self.run_vpn(shell, self.conf_ks())
            self.assertNotEqual(r.returncode, 0)
            ev = self.events()
            self.assertTrue(ev.startswith('nft -f'), ev)
            self.assertFull(self.rulesets()[0])
            self.assertLess(ev.index('nft -f'), ev.index('extra adopt'))

    def test_a_failed_download_leaves_the_full_kill_switch(self):
        # also a corrupt download: mu300-extra checks it against SHA256SUMS and installs nothing, which is this
        for shell in self.each_shell():
            self.fresh()
            self.extra_cmd(install='fail')
            r = self.run_vpn(shell, self.conf_ks())
            self.assertNotEqual(r.returncode, 0, shell)
            self.assertIn('mu300-extra install vpn', r.stderr)
            self.assertClosed(r.stderr)
            self.assertEqual([('fetch4' in x) for x in self.rulesets()], [False, True, False], self.events())
            self.assertNotIn('engine', self.events())

    def test_the_download_window(self):
        for shell in self.each_shell():
            self.fresh()
            self.extra_cmd(install='hang')
            self.conf.write_text(self.conf_ks())
            p = subprocess.Popen(shell + [str(BIN / 'mu300-vpn'), 'run'], env=self.env(**self.envs(FETCH_TIME=60)),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                self.wait_for(self.tmp / 'started')
                window = self.state.read_text()
                # clients: everything to the modem dropped, and their DNS to the device too (dnsmasq would carry it)
                self.assertRegex(window, r'chain forward \{[^}]*oifname "sipa_eth\*" counter drop')
                self.assertRegex(window, r'chain forward \{[^}]*oifname "wlan0" counter drop')
                self.assertRegex(window, r'chain input \{[^}]*iifname != "lo" meta l4proto \{ tcp, udp \} th dport 53 drop')
                # the device: the engine's marked connections, NTP, DNS and the release hosts - everything else dropped
                out = window.split('chain output {')[1].split('chain ')[0]
                rules = [l.strip() for l in out.splitlines() if l.strip().startswith('oifname')]
                self.assertEqual(rules, [
                    'oifname "sipa_eth*" meta mark 0x2d0 accept',
                    'oifname "sipa_eth*" udp dport 123 accept',
                    'oifname "sipa_eth*" ip daddr @dns4 meta l4proto { tcp, udp } th dport 53 accept',
                    'oifname "sipa_eth*" ip6 daddr @dns6 meta l4proto { tcp, udp } th dport 53 accept',
                    'oifname "sipa_eth*" ip daddr @fetch4 tcp dport { 80, 443 } accept',
                    'oifname "sipa_eth*" ip6 daddr @fetch6 tcp dport { 80, 443 } accept',
                    'oifname "sipa_eth*" counter drop',
                    'oifname "wlan0" meta mark 0x2d0 accept',
                    'oifname "wlan0" udp dport 123 accept',
                    'oifname "wlan0" udp sport 68 udp dport 67 accept',
                    'oifname "wlan0" ip daddr @dns4 meta l4proto { tcp, udp } th dport 53 accept',
                    'oifname "wlan0" ip6 daddr @dns6 meta l4proto { tcp, udp } th dport 53 accept',
                    'oifname "wlan0" ip daddr @fetch4 tcp dport { 80, 443 } accept',
                    'oifname "wlan0" ip6 daddr @fetch6 tcp dport { 80, 443 } accept',
                    'oifname "wlan0" counter drop'])
                # every allowance runs out by itself
                for name in ('dns4', 'dns6', 'fetch4', 'fetch6'):
                    self.assertIn('flags timeout', re.search(r'set %s \{[^}]*' % name, window).group(0))
                adds = [l for l in self.events().splitlines() if l.startswith('nft add element')]
                self.assertTrue(adds)
                got4 = set(re.findall(r'(\d+\.\d+\.\d+\.\d+) timeout (\d+)s', ' '.join(adds)))
                self.assertEqual({a for a, _ in got4}, {'140.82.121.3', '140.82.121.6', '185.199.108.133', '10.177.0.34'})
                self.assertIn('dns4 { 10.177.0.34 timeout', ' '.join(adds))
                self.assertIn('dns6 { 2001:db8:53::1 timeout', ' '.join(adds))
                self.assertNotIn('127.0.0.53', ' '.join(adds))
                self.assertTrue(all(0 < int(t) <= 60 for _, t in got4))
                self.assertIn('fetch6 { 2606:50c0:8000::154 timeout', ' '.join(adds))
            finally:
                self.reap(p)

    def test_a_signal_mid_download_closes_the_window(self):
        for shell in self.each_shell():
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                with self.subTest(sig=sig.name):
                    self.fresh()
                    self.extra_cmd(install='hang')
                    self.conf.write_text(self.conf_ks())
                    # a shell cannot trap a signal that was ignored when it started (POSIX), and test runners can start
                    # us with SIGINT/SIGHUP ignored (GitHub's macOS runner does): the script gets the defaults, as from
                    # systemd or procd
                    p = subprocess.Popen(shell + [str(BIN / 'mu300-vpn'), 'run'], env=self.env(**self.envs()),
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                         preexec_fn=self.default_signals)
                    try:
                        self.wait_for(self.tmp / 'started')
                        self.assertIn('fetch4', self.state.read_text())
                        t = time.monotonic()
                        # only the script itself is signalled, as procd does (systemd signals the whole group)
                        os.kill(p.pid, sig)
                        _, err = p.communicate(timeout=10)
                        self.assertLess(time.monotonic() - t, 5, 'waited for the download')
                        self.assertNotEqual(p.returncode, 0)
                        self.assertClosed((sig, err))
                        # the refresher is gone with it: nothing is opened again afterwards
                        n = len(self.events())
                        time.sleep(2.5)
                        self.assertEqual(len(self.events()), n, self.events()[n:])
                        self.assertClosed(sig)
                    finally:
                        self.reap(p)

    def test_sigkill_mid_download_leaves_only_what_runs_out(self):
        # SIGKILL cannot be caught: the window stays, but every allowance in it has a timeout, and the refresher
        # stops when the script is gone, so nothing renews them
        for shell in self.each_shell():
            self.fresh()
            self.extra_cmd(install='hang')
            self.conf.write_text(self.conf_ks())
            p = subprocess.Popen(shell + [str(BIN / 'mu300-vpn'), 'run'], env=self.env(**self.envs(FETCH_TIME=60)),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                self.wait_for(self.tmp / 'started')
                os.kill(p.pid, signal.SIGKILL)
                p.wait(timeout=10)
                time.sleep(2.5)
                n = len(self.events())
                time.sleep(2.5)
                self.assertEqual(len(self.events()), n, 'the refresher outlived the script')
                adds = [l for l in self.events().splitlines() if l.startswith('nft add element')]
                for a in adds:
                    for el in a.split('{', 1)[1].rstrip('} ').split(','):
                        self.assertRegex(el.strip(), r'^\S+ timeout \d+s$')
            finally:
                self.reap(p)

    def test_a_download_past_the_deadline_is_ended(self):
        for shell in self.each_shell():
            self.fresh()
            self.extra_cmd(install='hang')
            t = time.monotonic()
            r = self.run_vpn(shell, self.conf_ks(), FETCH_TIME=2)
            self.assertLess(time.monotonic() - t, 15)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('longer than 2s', r.stderr)
            self.assertClosed(r.stderr)

    def test_a_good_download_closes_the_window_before_the_engine_starts(self):
        for shell in self.each_shell():
            self.fresh()
            self.extra_cmd(install='ok')
            r = self.run_vpn(shell, self.conf_ks())
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertClosed(r.stderr)
            ev = self.events()
            self.assertIn('engine sing-box run -c', ev)
            before = ev[:ev.index('engine sing-box run -c')]
            self.assertFull(before[before.rindex('nft -f'):])

    def test_a_corrupt_or_rejected_engine_fails_closed(self):
        for shell in self.each_shell():
            self.fresh(self.ENGINES)
            (self.tmp / 'corrupt').write_text('')
            r = self.run_vpn(shell, self.conf_ks())
            self.assertNotEqual(r.returncode, 0)
            self.assertClosed(r.stderr)
            self.assertIn('engine sing-box check', self.events())
            self.assertNotIn('engine sing-box run', self.events())
            # not even a link that does not parse opens it
            self.fresh(self.ENGINES)
            r = self.run_vpn(shell, 'ENABLE=1\nENGINE=sing-box\nKILL_SWITCH=1\nVLESS_URI=garbage\n')
            self.assertNotEqual(r.returncode, 0)
            self.assertClosed(r.stderr)

    def test_engines_removed_from_under_it_fail_closed(self):
        # mu300-extra remove vpn --force, or an update between its two renames: the next start finds none
        for shell in self.each_shell():
            self.fresh(self.ENGINES)
            self.extra_cmd(install='ok')
            self.assertEqual(self.run_vpn(shell, self.conf_ks()).returncode, 0)
            shutil.rmtree(self.extra)
            self.extra_cmd(install='fail')
            r = self.run_vpn(shell, self.conf_ks())
            self.assertNotEqual(r.returncode, 0)
            self.assertClosed(r.stderr)
            r = self.script(shell, BIN / 'mu300-vpn', 'status', **self.envs())
            self.assertIn('kill switch: 1 (active)', r.stdout)
            self.assertIn('not installed', r.stdout)

    def test_restarts_never_leave_a_gap(self):
        for shell in self.each_shell():
            self.fresh(self.ENGINES)
            for _ in range(3):
                self.assertEqual(self.run_vpn(shell, self.conf_ks()).returncode, 0)
            self.assertClosed()
            self.assertEqual(len(self.rulesets()), 3)
            for x in self.rulesets():
                self.assertFull(x)

    def test_xray_never_runs_without_the_kill_switch(self):
        for shell in self.each_shell():
            # sing-box is there: it runs instead, behind the kill switch
            self.fresh(self.ENGINES)
            r = self.run_vpn(shell, self.conf_ks('xray'))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertClosed(r.stderr)
            self.assertIn('engine sing-box run -c', self.events())
            self.assertNotIn('engine xray run', self.events())
            # only xray: nothing runs, and the kill switch stays
            self.fresh(('xray', 'hev-socks5-tunnel'))
            r = self.run_vpn(shell, self.conf_ks('xray'))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('the kill switch stays up', r.stderr)
            self.assertClosed(r.stderr)
            self.assertNotIn('engine xray run', self.events())
            self.assertNotIn('engine hev', self.events())

    def test_xray_with_allowinsecure_is_not_moved_to_an_unchecked_sing_box(self):
        # xray pins the certificate of an allowInsecure link; sing-box would take any: nothing runs instead
        for shell in self.each_shell():
            self.fresh(self.ENGINES)
            conf = self.conf_ks('xray').replace("type=tcp'", "type=tcp&allowInsecure=1'")
            r = self.run_vpn(shell, conf)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('allowInsecure', r.stderr)
            self.assertClosed(r.stderr)
            self.assertNotIn('engine sing-box run', self.events())

    def test_a_kill_switch_value_not_understood_is_on(self):
        for shell in self.each_shell():
            for v in ('yes', 'true', '', '2'):
                self.fresh(self.ENGINES)
                r = self.run_vpn(shell, self.conf_ks().replace('KILL_SWITCH=1', f'KILL_SWITCH={v}'))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertClosed((v, r.stderr))

    def test_guard_puts_it_up_before_the_bearer(self):
        for shell in self.each_shell():
            for conf, up in ((self.conf_ks(), True), (self.conf_ks().replace('KILL_SWITCH=1', 'KILL_SWITCH=0'), False),
                             (self.conf_ks().replace('ENABLE=1', 'ENABLE=0'), False), ('', False)):
                self.fresh()
                self.conf.write_text(conf)
                r = self.script(shell, BIN / 'mu300-vpn', 'guard', **self.envs())
                self.assertEqual(r.returncode, 0, r.stderr)
                if up:
                    self.assertClosed()
                else:
                    self.assertFalse(self.state.exists() and self.state.read_text().strip(), conf)
        # mobile-data calls it before it attaches
        src = (BIN / 'mobile-data').read_text()
        up = src[src.index('up_locked() {'):]
        self.assertLess(up.index('mu300-vpn}" guard'), up.index('AT+CGACT'))

    def test_release_url_host_is_checked(self):
        for shell in self.each_shell():
            r = self.sh(shell, f'. "{BIN}/mu300-vpn"; fetch_hosts', **self.envs(
                MU300_LIB=1, MU300_RELEASE_URL='https://user@release.example:8443/x/y', FETCH_HOSTS='github.com'))
            self.assertEqual(r.stdout.split(), ['github.com', 'release.example'])
            r = self.sh(shell, f'. "{BIN}/mu300-vpn"; fetch_hosts', **self.envs(
                MU300_LIB=1, MU300_RELEASE_URL='http://a;b}/x', FETCH_HOSTS='github.com'))
            self.assertEqual(r.stdout.split(), ['github.com'])

    @staticmethod
    def default_signals():
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_DFL)

    def reap(self, p):
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.communicate()

    def wait_for(self, path, timeout=15):
        end = time.monotonic() + timeout
        while not path.exists():
            if time.monotonic() > end:
                self.fail(f'{path.name} did not appear: {self.events()}')
            time.sleep(0.05)


if __name__ == '__main__':
    unittest.main()
