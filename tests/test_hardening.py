"""The security review's findings, each with a test: nothing from a link reaches dae's config but URL characters; no
link that turns the certificate check off runs on dae (dae cannot pin the certificate, as the xray driver does); a raw
dae config only in the subset its reader parses exactly as dae does; secret URLs over verified HTTPS and never on a
command line; no temporary file of a fixed name; and the CLI contract additions (latency, since, --due)."""
import base64
import json
import re
import shutil

from helpers import BIN, LIB
from test_v2 import Base, HY2, TOKEN, TROJAN, UUID, VLESS

HOSTILE = [
    "vless://" + UUID + "@h.example:443?type=tcp#x'\ninclude { /etc/x }",
    "trojan://p'w@h.example:443?sni=a#n",
    'trojan://pw@h.example:443?sni=a"b',
    'vless://' + UUID + '@h.example:443?path=/a\\b',
    'vless://' + UUID + '@h.example:443?path=/a b',
    'vless://' + UUID + '@h.example:443?x={y}',
    'trojan://pw@h.example:443?sni=a`id`',
]
INSECURE = [
    'vless://' + UUID + '@h.example:443?security=tls&allowInsecure=1',
    'trojan://pw@h.example:443?allowInsecure=true',
    'hysteria2://pw@h.example:443/?insecure=1',
    'tuic://' + UUID + ':pw@h.example:443?allow_insecure=1',
    'vmess://' + base64.b64encode(json.dumps({'v': '2', 'add': 'h.example', 'port': '443', 'id': UUID, 'net': 'tcp',
                                             'tls': 'tls', 'allowInsecure': True}).encode()).decode(),
]


class Hardening(Base):
    def serve(self, body):
        (self.tmp / 'sub.body').write_bytes(body)
        self.stub('curl', 'echo "$*" >> "$STUBLOG/argv"; u=$(sed -n \'s/^url = "\\(.*\\)"$/\\1/p\'); '
                          'echo "$u" >> "$STUBLOG/urls"; cat "$STUBLOG/sub.body"')

    def dae_link(self, shell, link):
        f = self.tmp / 'link'
        f.write_text(link)
        return self.lib(shell, f'load_driver dae; dae_link "$(cat "{f}")"')

    def test_hostile_links_never_reach_the_config(self):
        for shell in self.each_shell():
            for link in HOSTILE:
                r = self.dae_link(shell, link)
                self.assertNotEqual(r.returncode, 0, link)
                self.assertEqual(r.stdout, '', link)
            # the fragment (the display name) is never written
            r = self.dae_link(shell, VLESS)
            self.assertEqual(r.stdout.strip(), VLESS.split('#')[0])
            # a links file with one hostile line: refused whole at import
            self.fresh()
            f = self.tmp / 'nodes.txt'
            f.write_text(TROJAN + '\n' + HOSTILE[1] + '\n')
            r = self.vpn(shell, 'profile', 'add', 'dae', 'N', f)
            self.assertEqual(r.returncode, 1)
            self.assertFalse((self.tmp / 'vpn/profiles/n').exists())
            # a dae subscription: only the good links, one node line each, and nothing else
            self.serve('\n'.join([TROJAN, HY2] + HOSTILE[1:] + INSECURE).encode())
            r = self.vpn(shell, 'subscription', 'add', 'D', 'https://s.example/x', '--type', 'dae')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('1 added, 0 updated, 0 removed', r.stdout)
            p = self.tmp / 'vpn/profiles/d'
            self.assertEqual(sorted((p / 'links').read_text().splitlines()),
                             sorted([TROJAN.split('#')[0], HY2.split('#')[0]]))
            r = self.lib(shell, f'load_driver dae; PDIR="{p}"; dae_rebuild "{self.tmp}/out.dae" && cat "{self.tmp}/out.dae"')
            self.assertEqual(r.returncode, 0, r.stderr)
            nodes = r.stdout.split('node {\n')[1].split('}\n')[0].splitlines()
            self.assertEqual(len(nodes), 2)
            for n in nodes:
                self.assertRegex(n, r"^    mu300_\d+: '[A-Za-z0-9._~:/?@!$&()*+,;=%\[\]-]+'$")
            self.assertEqual(r.stdout.count('{'), r.stdout.count('}'))
            self.assertNotIn('include', r.stdout)

    def test_no_certificate_check_turned_off(self):
        for shell in self.each_shell():
            for link in INSECURE:
                r = self.dae_link(shell, link)
                self.assertNotEqual(r.returncode, 0, link)
                self.assertIn('certificate check off', r.stderr, link)
            self.fresh()
            r = self.vpn(shell, 'profile', 'import', '-', stdin=INSECURE[2])
            self.assertEqual(r.returncode, 1)
            self.assertIn('dae cannot pin', r.stderr)
            p = self.tmp / 'p'
            shutil.rmtree(p, ignore_errors=True)
            p.mkdir()
            (p / 'meta').write_text("TYPE='dae'\n")
            (p / 'uri').write_text(HY2 + '\n')
            r = self.lib(shell, f'load_driver dae; PDIR="{p}"; dae_rebuild "{self.tmp}/o.dae" && cat "{self.tmp}/o.dae"')
            self.assertIn('    allow_insecure: false\n', r.stdout)
            self.assertNotRegex(r.stdout.lower(), r'insecure=(1|true)|skip-cert-verify')
            (p / 'uri').unlink()
            (p / 'config.dae').write_text(f"node {{\n  a: '{INSECURE[0]}'\n}}\nrouting {{\n  fallback: proxy\n}}\n")
            r = self.lib(shell, f'load_driver dae; PDIR="{p}"; dae_rebuild "{self.tmp}/o.dae"')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('certificate check off', r.stderr)

    def test_raw_configs_outside_the_subset_are_refused(self):
        adversarial = [
            'node { a: "trojan://pw@h.example:1" }',
            "node { a: 'trojan://pw@h.example:1' } # include { x }",
            "node { a: 'trojan://pw@h.example:1\\' }\ninclude { x }",
            "node { a: 'trojan://pw@h.example:1' }\nsubscription { 'https://s.example/x' }",
            "global { x: 1 } include { y }",
            "node { a: 'trojan://pw@h.example:1'\n  b: 'x' }",
            "node { a: 'trojan://pw@h.example:1 -> vmess://x' }",
            "node { a: 'trojan://pw@h.example:1' }\nrouting { fallback: proxy\n x: 'a{b' }",
            "node { a: 'trojan://pw@h.example:1' }\nrouting { fallback: proxy }\nnode { b: 'ss://x@h:2' }",
            "node { a: 'trojan://pw@h.example:1' }\nrouting { fallback: proxy }\né",
            "node { a: 'trojan://pw@h.example:1' }\nrouting { fallback: proxy }\ndns { bind: '0.0.0.0:53' } x",
        ]
        for shell in self.each_shell():
            for text in adversarial:
                f = self.tmp / 'c.dae'
                f.write_text(text + ('\n' if 'routing' in text else "\nrouting { fallback: proxy }\n"))
                r = self.lib(shell, f'load_driver dae; dae_read check "{f}" >/dev/null || echo REFUSED')
                self.assertIn('REFUSED', r.stdout, text)
            # the subset itself is taken
            f.write_text("# whole-line comment\nnode {\n  a: 'trojan://pw@h.example:1#n'\n}\n"
                         "group { proxy { policy: min } }\nrouting {\n  dip(224.0.0.0/3, 'ff00::/8') -> direct\n  fallback: proxy\n}\n")
            r = self.lib(shell, f'load_driver dae; dae_read check "{f}" && echo OK')
            self.assertIn('OK', r.stdout, r.stdout + r.stderr)

    def test_secret_urls_https_only_and_never_in_argv(self):
        url = f'https://panel.example.com/sub/{TOKEN}'
        for shell in self.each_shell():
            self.fresh()
            (self.tmp / 'argv').unlink(missing_ok=True)
            self.serve(f'{VLESS}\n'.encode())
            r = self.vpn(shell, 'subscription', 'add', 'W', '-', stdin=url + '\n')
            self.assertEqual(r.returncode, 0, r.stderr)
            argv = self.log('argv')
            self.assertNotIn(TOKEN, argv)
            self.assertIn('--proto =https', argv)
            self.assertIn('-K -', argv)
            self.no_secret(r.stdout, r.stderr, self.vpn(shell, 'subscription', 'list', '--json').stdout,
                           self.vpn(shell, 'subscription', 'show', 'w', '--json').stdout)
            r = self.vpn(shell, 'subscription', 'add', 'P', 'http://p.example/x')
            self.assertEqual(r.returncode, 2)
            self.assertNotIn('p.example/x', r.stderr)
            r = self.vpn(shell, 'subscription', 'add', 'P', 'http://p.example/x', '--insecure')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('warning: plain http', r.stderr)
            self.assertIn('--proto =http,https', self.log('argv'))
            self.assertTrue(json.loads(self.vpn(shell, 'subscription', 'show', 'p', '--json').stdout)['insecure'])
            for p in (self.tmp / 'vpn/subscriptions').rglob('*'):
                self.assertEqual(p.stat().st_mode & 0o077, 0, p)
            # profile import --url: the same rules
            self.serve(f'{TROJAN}\n'.encode())
            self.assertEqual(self.vpn(shell, 'profile', 'import', '--url', 'http://p.example/c').returncode, 2)
            r = self.vpn(shell, 'profile', 'import', '--url', '-', 'Url', stdin=url + '\n')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(TOKEN, self.log('argv'))

    def test_no_temporary_file_of_a_fixed_name(self):
        src = (BIN / 'mu300-vpn').read_text() + ''.join(p.read_text() for p in LIB.glob('*.sh'))
        self.assertEqual(re.findall(r'/tmp/[A-Za-z0-9._-]*\$\$|/tmp/mu300[^"\s]*\.err', src), [])

    def test_subscription_interval_and_due(self):
        for shell in self.each_shell():
            self.fresh()
            self.serve(f'{VLESS}\n'.encode())
            r = self.vpn(shell, 'subscription', 'add', 'I', 'https://i.example/x', '--interval', '6')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(self.vpn(shell, 'subscription', 'show', 'i', '--json').stdout)['interval'], 6)
            (self.tmp / 'urls').unlink(missing_ok=True)
            self.vpn(shell, 'subscription', 'refresh', '--due')
            self.assertEqual(self.log('urls'), '')
            meta = self.tmp / 'vpn/subscriptions/i/meta'
            meta.write_text(''.join(l + '\n' for l in meta.read_text().splitlines() if not l.startswith('UPDATED='))
                            + "UPDATED='100'\n")
            self.vpn(shell, 'subscription', 'refresh', '--due')
            self.assertIn('i.example', self.log('urls'))

    def test_latency_contract(self):
        for shell in self.each_shell():
            self.fresh()
            self.stub('curl', 'printf 0.000000; exit 7')
            self.assertEqual(self.vpn(shell, 'profile', 'import', '-', stdin=VLESS).returncode, 0)
            r = self.vpn(shell, 'latency', 'home', '--json')
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout), {'error': 'unreachable'})
            r = self.vpn(shell, 'latency', '--all', '--json')
            self.assertEqual(r.returncode, 0)
            self.assertIsInstance(json.loads(r.stdout), list)

    def test_status_since(self):
        for shell in self.each_shell():
            self.fresh()
            s = json.loads(self.vpn(shell, 'status', '--json').stdout)
            self.assertIsNone(s['since'])
