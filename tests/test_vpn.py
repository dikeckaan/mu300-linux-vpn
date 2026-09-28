"""mu300-vpn, sourced for its functions (MU300_LIB=1): the VLESS URI parser, JSON helpers, which networks stay out of
the tunnel, and the sing-box config it writes. Ubuntu and OpenWrt both run it (dash, bash, busybox ash)."""
import json
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


if __name__ == '__main__':
    unittest.main()
