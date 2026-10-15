"""A VLESS link as each engine gets it (#202, docs/FINDINGS.md 26o): the sing-box outbound the sing-box driver writes
for a link - the table below, every row of which tools/vless-matrix.sh ran against a real Xray server - the links
sing-box cannot run, refused with a reason that never repeats the link's secrets, Xray's streamSettings for the
variants v2.0.2 wrote wrongly, where such a link runs behind the kill switch, Xray's geodata, and the line the log
gets when a tunnel is up and nothing gets through it."""
import json
import subprocess
import time

from helpers import BIN, LIB, SYSBIN, ShellTest

U = '0a1b2c3d-1111-4222-8333-444455556666'   # (a throwaway id: none of these links has a server)
H = 'vpn.example'


def link(query, port=443):
    return f'vless://{U}@{H}:{port}?{query}#t'


def base(port=443, **extra):
    o = {'type': 'vless', 'tag': 'proxy', 'server': H, 'server_port': port, 'uuid': U}
    if 'flow' in extra:
        o['flow'] = extra.pop('flow')
    o.update({'packet_encoding': 'xudp', 'domain_resolver': 'bootstrap'})
    o.update(extra)
    return o


def tls(sni=H, **extra):
    t = {'enabled': True, 'server_name': sni}
    t.update(extra)
    return t


CHROME = {'enabled': True, 'fingerprint': 'chrome'}

# link -> the sing-box outbound (what changed since v2.0.2 is said beside it)
OUTBOUNDS = [
    (link('type=tcp&security=none', 80), base(80)),
    # ?ed=N on a WebSocket path is early data, not part of the path: Xray's server takes it off, and sent with the
    # path sing-box got "failed to validate path" and EOF
    (link('type=ws&path=%2Fws%3Fed%3D2048&host=h.example'),
     base(transport={'type': 'ws', 'path': '/ws', 'headers': {'Host': 'h.example'}, 'max_early_data': 2048,
                     'early_data_header_name': 'Sec-WebSocket-Protocol'})),
    # ... wherever it is in the query, and only when it is a number
    (link('type=ws&path=%2Fws%3Fx%3D1%26ed%3D512'),
     base(transport={'type': 'ws', 'path': '/ws?x=1', 'max_early_data': 512,
                     'early_data_header_name': 'Sec-WebSocket-Protocol'})),
    (link('type=ws&path=%2Fws%3Fed%3Dabc'), base(transport={'type': 'ws', 'path': '/ws?ed=abc'})),
    # h2 in the ALPN of a WebSocket link: a server that accepts h2 read the upgrade request as an HTTP/2 preface
    (link('type=ws&security=tls&sni=cdn.example&path=%2Fws&alpn=h2%2Chttp%2F1.1&fp=chrome'),
     base(tls=tls('cdn.example', alpn=['http/1.1'], utls=CHROME), transport={'type': 'ws', 'path': '/ws'})),
    (link('type=ws&security=tls&path=%2Fws&alpn=h2'), base(tls=tls(), transport={'type': 'ws', 'path': '/ws'})),
    # HTTPUpgrade: ed off the path, and no early data (sing-box has none for it; Xray's server waits for none)
    (link('type=httpupgrade&path=%2Fhu%3Fed%3D2048&host=hu.example'),
     base(transport={'type': 'httpupgrade', 'path': '/hu', 'host': 'hu.example'})),
    # gRPC keeps h2 (it is HTTP/2); h3 never (VLESS here is TCP)
    (link('type=grpc&serviceName=svc&security=tls&alpn=h3%2Ch2&fp=firefox'),
     base(tls=tls(alpn=['h2'], utls={'enabled': True, 'fingerprint': 'firefox'}),
          transport={'type': 'grpc', 'service_name': 'svc'})),
    (link('type=grpc&serviceName=svc&mode=multi'), base(transport={'type': 'grpc', 'service_name': 'svc'})),
    (link('type=tcp&security=tls&sni=other.example&allowInsecure=1'), base(tls=tls('other.example', insecure=True))),
    # Xray's randomizednoalpn, which sing-box does not know ("unknown uTLS fingerprint"): chrome
    (link('type=tcp&security=tls&fp=randomizednoalpn'), base(tls=tls(utls=CHROME))),
    (link('type=tcp&security=tls&fp=chrome&flow=xtls-rprx-vision'),
     base(flow='xtls-rprx-vision', tls=tls(utls=CHROME))),
    # Xray's vision that lets UDP/443 through ("unsupported flow"): sing-box's vision does that anyway
    (link('type=tcp&security=tls&fp=chrome&flow=xtls-rprx-vision-udp443'),
     base(flow='xtls-rprx-vision', tls=tls(utls=CHROME))),
    (link('type=tcp&security=tls&flow=xtls-rprx-vision&packetEncoding=xudp'),
     base(flow='xtls-rprx-vision', tls=tls())),
    (link('type=tcp&security=reality&sni=r.example&pbk=PUBKEY&sid=a1b2&fp=safari&flow=xtls-rprx-vision&spx=%2F'),
     base(flow='xtls-rprx-vision', tls=tls('r.example', utls={'enabled': True, 'fingerprint': 'safari'},
                                           reality={'enabled': True, 'public_key': 'PUBKEY', 'short_id': 'a1b2'}))),
    # REALITY without fp: Xray's client defaults to chrome, sing-box refused to start ("uTLS is required by reality
    # client")
    (link('type=grpc&serviceName=svc&security=reality&sni=r.example&pbk=PUBKEY'),
     base(tls=tls('r.example', utls=CHROME, reality={'enabled': True, 'public_key': 'PUBKEY', 'short_id': ''}),
          transport={'type': 'grpc', 'service_name': 'svc'})),
]

# link -> what the refusal says: what sing-box cannot do (it would come up and every connection would end at once)
REFUSED = [
    (link('type=tcp&encryption=mlkem768x25519plus.native.0rtt.SECRETKEYMATERIAL'), 'VLESS Encryption'),
    (link('type=tcp&security=tls&encryption=mlkem768x25519plus.xorpub.1rtt.SECRETKEYMATERIAL'), 'VLESS Encryption'),
    (link('type=xhttp&path=%2Fxh&mode=auto'), 'no XHTTP transport'),
    (link('type=splithttp&path=%2Fxh'), 'no XHTTP transport'),
    (link('type=xhttp&security=reality&pbk=PUBKEY&sid=ab&fp=chrome'), 'no XHTTP transport'),
    (link('type=h2&security=tls&path=%2Fh2'), 'HTTP/2'),
    (link('type=http&security=tls&path=%2Fh2'), 'HTTP/2'),
    (link('type=tcp&headerType=http&host=h.example&path=%2Fh', 80), 'HTTP header'),
    (link('type=kcp'), "no 'kcp' transport"),
    (link('type=tcp&security=tls&flow=xtls-rprx-direct'), 'flow'),
    (link('type=tcp&security=tls&fp=hellochrome_120'), 'fingerprint'),
    (link('type=tcp&security=reality&sid=ab'), 'public key'),
]


class VlessLinks(ShellTest):
    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('')
        (self.tmp / 'root/run/mu300').mkdir(parents=True)
        (self.tmp / 'root/run/mu300/device').write_text('f50\n')

    def vpn(self, shell, code, **env):
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', MU300_LIB=1, MU300_VPN_CONF=self.conf,
                       MU300_VPN_RUN=self.tmp / 'run', MU300_LAN_CONF=self.tmp / 'no-lan.conf', MU300_BIN=SYSBIN,
                       MU300_SYSROOT=self.tmp / 'root', MU300_VPN_LIB=LIB, MU300_DISK=self.tmp / 'disk',
                       MU300_OPT=self.tmp / 'opt', **env)

    def outbound(self, shell, uri):
        return self.vpn(shell, f"VLESS_URI='{uri}'; UPSTREAM_HTTP_PROXY=; load_driver sing-box; parse_uri; "
                               'outbound_json')

    def test_the_sing_box_outbound_of_each_link(self):
        for shell in self.each_shell():
            for uri, want in OUTBOUNDS:
                with self.subTest(link=uri):
                    r = self.outbound(shell, uri)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(json.loads(r.stdout), want)

    def test_links_sing_box_cannot_run_are_refused(self):
        for shell in self.each_shell():
            for uri, why in REFUSED:
                with self.subTest(link=uri):
                    # at import and check (a sing-box profile: the driver's drv_check) ...
                    r = self.vpn(shell, f"VLESS_URI='{uri}'; load_driver sing-box; drv_check")
                    self.assertNotEqual(r.returncode, 0)
                    self.assertIn('sing-box cannot run this link', r.stderr)
                    self.assertIn(why, r.stderr)
                    # ... and when a config is written: never a tunnel that comes up and carries nothing
                    r = self.outbound(shell, uri)
                    self.assertNotEqual(r.returncode, 0)
                    self.assertEqual(r.stdout, '')
                    for secret in (U, 'SECRETKEYMATERIAL', 'PUBKEY'):
                        self.assertNotIn(secret, r.stderr)

    def test_xray_writes_what_the_server_reads(self):
        cases = [
            # the TCP header: without it the server read the VLESS header as a broken HTTP request (v2.0.2 dropped it)
            (link('type=tcp&headerType=http&host=a.example%2Cb.example&path=%2Fa%2C%2Fb', 80),
             {'network': 'raw', 'rawSettings': {'header': {'type': 'http', 'request': {
                 'path': ['/a', '/b'], 'headers': {'Host': ['a.example', 'b.example']}}}}}),
            (link('type=tcp&headerType=none'), {'network': 'raw'}),
            # splithttp is XHTTP's earlier name (v2.0.2: "not supported")
            (link('type=splithttp&path=%2Fxh'), {'network': 'xhttp', 'xhttpSettings': {'path': '/xh'}}),
            # Xray's HTTPUpgrade client with early data never dialled (the server takes ed off its own path)
            (link('type=httpupgrade&path=%2Fhu%3Fed%3D2048'),
             {'network': 'httpupgrade', 'httpupgradeSettings': {'path': '/hu'}}),
            # its WebSocket client does early data itself: the path is the link's
            (link('type=ws&path=%2Fws%3Fed%3D2048'), {'network': 'ws', 'wsSettings': {'path': '/ws?ed=2048'}}),
        ]
        for shell in self.each_shell():
            for uri, want in cases:
                with self.subTest(link=uri):
                    r = self.vpn(shell, f"parse_link '{uri}' && PIN= && VCN= && load_driver xray && xray_stream_json")
                    self.assertEqual(r.returncode, 0, r.stderr)
                    got = json.loads('{' + r.stdout + '}')['streamSettings']
                    got.pop('sockopt', None)
                    self.assertEqual(got, want)
            for t in ('h2', 'http'):
                r = self.vpn(shell, f"VLESS_URI='{link('type=' + t)}'; load_driver xray; drv_check")
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('HTTP/2', r.stderr)

    def test_check_says_where_a_link_sing_box_cannot_run_goes(self):
        """an xray profile (where VLESS links are imported): the link is fine for Xray, so it is not refused, but
        check says that sing-box cannot run it and what that means behind the kill switch"""
        for shell in self.each_shell():
            r = self.vpn(shell, f"PTYPE=xray; PURI='{link('type=xhttp&path=%2Fx')}'; vless_sb_note")
            self.assertEqual(r.returncode, 0)
            self.assertIn('sing-box cannot run this link', r.stderr)
            self.assertIn('runs on xray only, behind the kill switch too', r.stderr)
            r = self.vpn(shell, f"PTYPE=xray; PURI='{link('type=ws&path=%2Fws')}'; vless_sb_note")
            self.assertEqual((r.returncode, r.stderr), (0, ''))

    def test_xray_finds_its_geodata(self):
        for i, shell in enumerate(self.each_shell()):
            d = self.tmp / f'x{i}'
            (d / 'bin').mkdir(parents=True, exist_ok=True)
            (d / 'share/xray').mkdir(parents=True, exist_ok=True)
            code = f'load_driver xray; XRAY="{d}/bin/xray"; xray_assets; echo "${{XRAY_LOCATION_ASSET:-none}}"'
            r = self.vpn(shell, code)
            self.assertEqual(r.stdout.strip(), 'none')
            for f in ('geoip.dat', 'geosite.dat'):
                (d / 'share/xray' / f).write_text('x')
            r = self.vpn(shell, code)
            self.assertEqual(r.stdout.strip(), f'{d}/share/xray')
            # one set elsewhere is left alone
            r = self.vpn(shell, code, XRAY_LOCATION_ASSET='/usr/share/xray')
            self.assertEqual(r.stdout.strip(), '/usr/share/xray')

    def watch(self, shell, probe, engine_for=None):
        """exit_watch ENGINE PID with MU300_EXIT_PROBE=PROBE, checks without a pause; the engine (a sleep) is
        stopped after ENGINE_FOR seconds, else when the watch ends. Its stderr."""
        engine = subprocess.Popen(['sleep', '60'])
        try:
            p = subprocess.Popen(shell + ['-c', f'. "{BIN}/mu300-vpn"; exit_watch sing-box {engine.pid}'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env(
                                     MU300_LIB=1, MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run',
                                     MU300_LAN_CONF=self.tmp / 'no-lan.conf', MU300_BIN=SYSBIN,
                                     MU300_SYSROOT=self.tmp / 'root', MU300_VPN_LIB=LIB, MU300_EXIT_PROBE=probe,
                                     MU300_EXIT_EVERY=0))
            if engine_for is not None:
                time.sleep(engine_for)
                # (reaped: a zombie still answers kill -0)
                engine.kill()
                engine.wait()
            _, err = p.communicate(timeout=30)
            self.assertEqual(p.returncode, 0, err)
            return err
        finally:
            engine.kill()
            engine.wait()

    def asked(self):
        f = self.tmp / 'asked'
        n = len(f.read_text().splitlines()) if f.exists() else 0
        f.unlink(missing_ok=True)
        return n

    def test_a_tunnel_that_carries_nothing_is_named_once(self):
        """exit_watch: after EXIT_CHECKS exit checks in a row that got nothing, one line that names the engine and
        the likely causes; a line again when connections get through. A tunnel that works is asked once."""
        self.stub('probe-yes', 'echo x >> "$STUBLOG/asked"; echo 203.0.113.9')
        # nothing for four checks, then an address
        self.stub('probe-later', 'n=$(cat "$STUBLOG/asked" 2>/dev/null | grep -c x); echo x >> "$STUBLOG/asked"; '
                                 '[ "$n" -ge 4 ] && echo 203.0.113.9; exit 0')
        # a captive portal's page is not an exit address
        self.stub('probe-portal', 'echo "<html>login</html>"')
        for shell in self.each_shell():
            self.assertEqual(self.watch(shell, 'probe-yes'), '')
            self.assertEqual(self.asked(), 1)
            err = self.watch(shell, 'probe-later')
            self.assertEqual(self.asked(), 5)
            warn = [l for l in err.splitlines() if 'nothing gets through' in l]
            self.assertEqual(len(warn), 1, err)
            self.assertTrue(warn[0].startswith('sing-box: the tunnel is up, but nothing gets through it (3 checks'))
            for cause in ('mu300-vpn check', 'VLESS Encryption', 'REMOTE_DNS (1.1.1.1)', 'mu300-vpn logs sing-box'):
                self.assertIn(cause, warn[0])
            self.assertIn('sing-box: connections get through the tunnel again', err)
            # the engine goes: so does the watch, having said it once
            err = self.watch(shell, 'probe-portal', engine_for=1)
            self.assertEqual(len([l for l in err.splitlines() if 'nothing gets through' in l]), 1, err)
