"""mu300-vpn's profiles, settings and engine drivers, sourced for their functions (MU300_LIB=1) under every shell.

Store: the store under /etc/mu300/vpn (MU300_VPN_DIR, by default the directory of MU300_VPN_CONF + /vpn), its
settings with their validation, and the migration of a legacy vpn.conf into it."""
import os
import re
import shutil
import stat

from helpers import BIN, LIB, ShellTest

MARKER = ('# mu300-vpn: migrated to /etc/mu300/vpn (profile legacy); only ENABLE is read from this file now')
ID = re.compile(r'^[a-z0-9-]{1,32}$')


class Store(ShellTest):
    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.store = self.tmp / 'vpn'
        self.stub('ip', 'exit 0')
        self.stub('nft', 'cat >/dev/null')

    def vpn(self, shell, code, conf=None, confpath=None):
        """sources mu300-vpn with CONF (written first unless None) and runs CODE"""
        path = confpath or self.conf
        if conf is not None:
            path.write_text(conf)
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', MU300_LIB=1, MU300_VPN_CONF=path,
                       MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB, MU300_LAN_CONF=self.tmp / 'no',
                       MU300_BIN=BIN, MU300_OPT=self.tmp / 'opt', MU300_DISK=self.tmp / 'disk')

    def reset(self):
        shutil.rmtree(self.store, ignore_errors=True)
        self.conf.unlink(missing_ok=True)

    def files(self):
        """{relative path: (mode, mtime_ns, contents)} of the store and the conf"""
        out = {}
        for p in [self.conf] + sorted(self.store.rglob('*')) + [self.store]:
            st = p.stat()
            out[str(p.relative_to(self.tmp))] = (stat.S_IMODE(st.st_mode), st.st_mtime_ns,
                                                 None if p.is_dir() else p.read_bytes())
        return out

    def kv(self, path):
        """KEY=VALUE lines as a dict, single quotes undone as mu300-vpn writes them"""
        out = {}
        for line in path.read_text().splitlines():
            k, v = line.split('=', 1)
            if len(v) >= 2 and v[0] == v[-1] == "'":
                v = v[1:-1].replace("'\\''", "'")
            out[k] = v
        return out

    LEGACY = "ENABLE=1\nENGINE=xray\nKILL_SWITCH=0\nVLESS_URI='vless://u@h:443'\nREMOTE_DNS=9.9.9.9\nTLS_PIN_SHA256=ab\n"

    def test_first_migration(self):
        for shell in self.each_shell():
            self.reset()
            r = self.vpn(shell, 'echo "$KILL_SWITCH $REMOTE_DNS $PTYPE $ACTIVE $ENABLE"', self.LEGACY)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stderr, '')
            self.assertEqual(r.stdout.strip(), '0 9.9.9.9 xray legacy 1')
            self.assertEqual((self.store / 'active').read_text().strip(), 'legacy')
            prof = self.store / 'profiles/legacy'
            self.assertEqual((prof / 'uri').read_text().strip(), 'vless://u@h:443')
            meta = self.kv(prof / 'meta')
            self.assertEqual(meta['TYPE'], 'xray')
            self.assertEqual(meta['TLS_PIN_SHA256'], 'ab')
            self.assertEqual(meta['NAME'], 'legacy')
            self.assertEqual(meta['SOURCE'], 'manual')
            self.assertRegex(meta['CREATED'], r'^[0-9]+$')
            settings = self.kv(self.store / 'settings')
            self.assertEqual(settings['KILL_SWITCH'], '0')
            self.assertEqual(settings['REMOTE_DNS'], '9.9.9.9')
            for p in [self.store] + list(self.store.rglob('*')):
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700 if p.is_dir() else 0o600, p)
            lines = self.conf.read_text().split('\n')
            self.assertEqual(lines[0], MARKER)
            self.assertEqual('\n'.join(lines[1:]), self.LEGACY)
            # the code below still finds the link where it always did
            r = self.vpn(shell, 'echo "$VLESS_URI $ENGINE $TLS_PIN_SHA256"')
            self.assertEqual(r.stdout.strip(), 'vless://u@h:443 xray ab')

    def test_migration_is_idempotent(self):
        for shell in self.each_shell():
            self.reset()
            self.vpn(shell, 'true', self.LEGACY)
            before = self.files()
            r = self.vpn(shell, 'echo "$KILL_SWITCH $REMOTE_DNS $PTYPE"')
            self.assertEqual(r.stdout.strip(), '0 9.9.9.9 xray', r.stderr)
            self.assertEqual(self.files(), before)
            self.assertEqual(self.conf.read_text().count(MARKER), 1)

    def test_an_edited_conf_wins_for_changed_keys(self):
        for shell in self.each_shell():
            self.reset()
            r = self.vpn(shell, 'kv_set "$SETTINGS" TAILSCALE 0', self.LEGACY)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.conf.write_text(self.conf.read_text().replace('REMOTE_DNS=9.9.9.9', 'REMOTE_DNS=8.8.8.8'))
            r = self.vpn(shell, 'echo "$REMOTE_DNS $TAILSCALE $KILL_SWITCH"')
            self.assertEqual(r.stdout.strip(), '8.8.8.8 0 0', r.stderr)
            self.conf.write_text(self.conf.read_text().replace('REMOTE_DNS=8.8.8.8\n', ''))
            r = self.vpn(shell, 'echo "$REMOTE_DNS $TAILSCALE"')
            self.assertEqual(r.stdout.strip(), '1.1.1.1 0', r.stderr)
            # a new pin in the conf (an older image's save_pin) reaches the profile
            self.conf.write_text(self.conf.read_text().replace('TLS_PIN_SHA256=ab', 'TLS_PIN_SHA256=cd'))
            r = self.vpn(shell, 'echo "$TLS_PIN_SHA256"')
            self.assertEqual(r.stdout.strip(), 'cd', r.stderr)

    def test_engine_default_follows_kill_switch(self):
        uri = "VLESS_URI='vless://u@h:443'\n"
        for shell in self.each_shell():
            for conf, want in ((uri, 'sing-box'), ('KILL_SWITCH=0\n' + uri, 'xray'),
                               ('KILL_SWITCH=yes\n' + uri, 'sing-box'), ('ENGINE=foo\n' + uri, 'sing-box')):
                self.reset()
                r = self.vpn(shell, 'echo "$PTYPE"', conf)
                self.assertEqual(self.kv(self.store / 'profiles/legacy/meta')['TYPE'], want, conf)
                self.assertEqual(r.stdout.strip(), want, conf)

    def test_no_link_no_profile(self):
        for shell in self.each_shell():
            self.reset()
            r = self.vpn(shell, 'echo "[$ACTIVE] [$PTYPE] $ENGINE"', 'ENABLE=1\nKILL_SWITCH=1\n')
            self.assertEqual(r.stdout.strip(), '[] [] sing-box', r.stderr)
            self.assertEqual(list((self.store / 'profiles').iterdir()), [])
            self.assertFalse((self.store / 'active').exists())
            # the link added later makes the profile, and it is the active one
            r = self.vpn(shell, 'echo "$ACTIVE $PTYPE"', "ENABLE=1\nKILL_SWITCH=1\nVLESS_URI='vless://u@h:443'\n")
            self.assertEqual(r.stdout.strip(), 'legacy sing-box', r.stderr)

    def test_not_writable_reads_in_memory(self):
        if os.geteuid() == 0:
            self.skipTest('root can write anywhere')
        d = self.tmp / 'ro'
        d.mkdir()
        conf = d / 'vpn.conf'
        conf.write_text("ENABLE=1\nKILL_SWITCH=0\nVLESS_URI='vless://u@h:443'\nREMOTE_DNS=9.9.9.9\n")
        d.chmod(0o555)
        try:
            for shell in self.each_shell():
                r = self.vpn(shell, 'echo "$PTYPE $KILL_SWITCH $REMOTE_DNS $ENABLE $VLESS_URI [$ACTIVE]"', confpath=conf)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stderr, '')
                self.assertEqual(r.stdout.strip(), 'xray 0 9.9.9.9 1 vless://u@h:443 []')
                self.assertEqual(sorted(p.name for p in d.iterdir()), ['vpn.conf'])
                self.assertNotIn(MARKER, conf.read_text())
        finally:
            d.chmod(0o755)

    def test_meta_never_executes(self):
        name = "a$(touch pwned)'b `touch pwned2` \"c\" kütük"
        for shell in self.each_shell():
            self.reset()
            code = (f"cd '{self.tmp}'; id=$(profile_new xray '{name.replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))}') "
                    '|| exit 1; echo "$id"; kv_get "$PROFILES/$id/meta" NAME; kv_get "$PROFILES/$id/meta" TYPE')
            r = self.vpn(shell, code, '')
            self.assertEqual(r.returncode, 0, r.stderr)
            pid, got, typ = r.stdout.split('\n')[:3]
            self.assertRegex(pid, ID)
            self.assertEqual(got, name)
            self.assertEqual(typ, 'xray')
            self.assertFalse((self.tmp / 'pwned').exists())
            self.assertFalse((self.tmp / 'pwned2').exists())
            pdir = self.store / 'profiles' / pid
            self.assertEqual(stat.S_IMODE(pdir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((pdir / 'meta').stat().st_mode), 0o600)

    def test_profile_ids(self):
        for shell in self.each_shell():
            self.reset()
            r = self.vpn(shell, "profile_new wireguard 'My VPN!'; profile_new wireguard 'my vpn'; "
                                "profile_new openvpn '***'; profile_new xray Legacy; "
                                f"profile_new xray '{'x' * 40}'; profile_new xray '{'x' * 40}'", '')
            self.assertEqual(r.stdout.split(), ['my-vpn', 'my-vpn-2', 'openvpn', 'legacy-2', 'x' * 32,
                                                'x' * 30 + '-2'], r.stderr)

    def test_settings_validation(self):
        good = [('KILL_SWITCH', '0'), ('KILL_SWITCH', '1'), ('TAILSCALE', '0'), ('IPV6', '1'),
                ('REMOTE_DNS', '1.1.1.1'), ('REMOTE_DNS', '2606:4700::1111'), ('BOOTSTRAP_DNS', '8.8.4.4'),
                ('LAN_CIDRS', '10.0.0.0/8,fd00::/8'), ('LAN_CIDRS', ''), ('LAN_CIDRS', '192.168.1.0/24'),
                ('MIHOMO_CONTROLLER', '127.0.0.1:9090'), ('MIHOMO_CONTROLLER', '[::1]:9090'),
                ('MIHOMO_CONTROLLER', ''), ('XRAY', '/x/xray'), ('HEV', '/x/hev'), ('SING_BOX', '/x/sb'),
                ('MIHOMO', '/x/m'), ('OPENVPN', '/usr/sbin/openvpn'), ('XRAY', '')]
        bad = [('KILL_SWITCH', 'yes'), ('KILL_SWITCH', ''), ('IPV6', '2'), ('REMOTE_DNS', 'a;b'),
               ('REMOTE_DNS', '1.1.1.256'), ('REMOTE_DNS', '1.1.1'), ('REMOTE_DNS', ''), ('LAN_CIDRS', '10.0.0.0'),
               ('LAN_CIDRS', '10.0.0.0/33'), ('LAN_CIDRS', '10.0.0.0/8,'), ('LAN_CIDRS', 'fd00::/129'),
               ('MIHOMO_CONTROLLER', '0.0.0.0:9090'), ('MIHOMO_CONTROLLER', '127.0.0.1:99999'),
               ('MIHOMO_CONTROLLER', '127.0.0.1'), ('XRAY', 'relative/xray'), ('UNKNOWN', 'x')]
        for shell in self.each_shell():
            self.reset()
            code = '; '.join(f"setting_valid {k} '{v}' && echo 1 || echo 0" for k, v in good + bad)
            r = self.vpn(shell, code, '')
            self.assertEqual(r.stdout.split(), ['1'] * len(good) + ['0'] * len(bad), r.stderr)
            # on read, an invalid value counts as the default
            (self.store / 'settings').write_text("KILL_SWITCH=yes\nREMOTE_DNS='a;b'\nIPV6=2\nTAILSCALE=0\n"
                                                 "LAN_CIDRS=10.0.0.0\nXRAY=xray\nHEV='/x/h e v'\n")
            r = self.vpn(shell, 'echo "$KILL_SWITCH $REMOTE_DNS $IPV6 $TAILSCALE [$_xray] [$_hev]"; '
                                'setting LAN_CIDRS; echo "[$(setting XRAY)]"')
            self.assertEqual(r.stdout.split('\n')[:3], ['1 1.1.1.1 0 0 [] [/x/h e v]', '', '[]'], r.stderr)

    def test_kv_round_trip(self):
        values = ["plain", "it's", "a'\\''b", "$(x) `y` \"z\"", "", "  spaced  ", "x=y=z"]
        for shell in self.each_shell():
            self.reset()
            f = self.tmp / 'kv'
            code = '; '.join(f"kv_set '{f}' K{i} '{v.replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))}'"
                             for i, v in enumerate(values))
            code += '; ' + '; '.join(f"kv_get '{f}' K{i}" for i in range(len(values)))
            # a key that is not there prints nothing at all
            code += f"; kv_set '{f}' K0 again; kv_del '{f}' K1; kv_get '{f}' K0; kv_get '{f}' K1; echo"
            code += f"; kv_set '{f}' K2 'a\nb' && echo set || echo refused"
            r = self.vpn(shell, code, '')
            self.assertEqual(r.stdout.split('\n')[:len(values) + 3], values + ['again', '', 'refused'], r.stderr)
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
            self.assertEqual(self.kv(f)['K2'], values[2])
            # kv_var, the shell's own reader the start-up uses, reads the same
            code = '; '.join(f"kv_var v '{f}' K{i}; printf '%s\\n' \"$v\"" for i in range(len(values)))
            r = self.vpn(shell, code)
            self.assertEqual(r.stdout.split('\n')[:len(values)], ['again', ''] + values[2:], r.stderr)

    def test_valid_id(self):
        good = ['a', 'my-vpn-2', 'a' * 32, '0']
        bad = ['', 'a' * 33, 'A', 'a/b', '..', 'a b', 'a_b', 'é']
        for shell in self.each_shell():
            code = '; '.join(f"valid_id '{v}' && echo 1 || echo 0" for v in good + bad)
            r = self.vpn(shell, code, '')
            self.assertEqual(r.stdout.split(), ['1'] * len(good) + ['0'] * len(bad), r.stderr)

    def test_set_enable(self):
        for shell in self.each_shell():
            self.reset()
            self.vpn(shell, 'true', self.LEGACY)
            before = self.conf.read_text()
            self.conf.chmod(0o640)
            r = self.vpn(shell, 'set_enable 0; echo "$ENABLE"')
            self.assertEqual(r.stdout.strip(), '0', r.stderr)
            self.assertEqual(self.conf.read_text(), before.replace('ENABLE=1', 'ENABLE=0'))
            self.assertEqual(stat.S_IMODE(self.conf.stat().st_mode), 0o640)
            r = self.vpn(shell, 'echo "$ENABLE"; set_enable 1; echo "$ENABLE"')
            self.assertEqual(r.stdout.split(), ['0', '1'], r.stderr)
            self.assertEqual(self.conf.read_text(), before)
            # no ENABLE line yet: one is added, after a last line without its newline
            self.conf.write_text('KILL_SWITCH=0')
            self.vpn(shell, 'set_enable 1')
            self.assertEqual(self.conf.read_text().split('\n')[-3:], ['KILL_SWITCH=0', 'ENABLE=1', ''])
            # no vpn.conf at all: one with just the switch
            self.reset()
            r = self.vpn(shell, 'set_enable 1; echo "$ENABLE"')
            self.assertEqual(r.stdout.strip(), '1', r.stderr)
            self.assertEqual(self.conf.read_text(), 'ENABLE=1\n')
            self.assertEqual(stat.S_IMODE(self.conf.stat().st_mode), 0o600)
            r = self.vpn(shell, 'echo "$ENABLE"')
            self.assertEqual(r.stdout.strip(), '1', r.stderr)
