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


class Contract(ShellTest):
    """The driver loader and what every driver in /opt/mu300/lib/vpn provides; the routing the core installs for
    drivers that leave it to the core (DRV_ROUTES=core); and the resolve window, which lets the device's own DNS out
    past the kill switch for as long as server names are looked up."""

    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('ENABLE=1\nKILL_SWITCH=1\n')
        self.ev = self.tmp / 'events'
        self.rules = self.tmp / 'rules'

    def vpn(self, shell, code, **env):
        e = dict(MU300_LIB=1, MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB,
                 MU300_LAN_CONF=self.tmp / 'no', MU300_BIN=BIN, MU300_OPT=self.tmp / 'opt',
                 MU300_DISK=self.tmp / 'disk')
        e.update(env)
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', **e)

    def test_reserved_types(self):
        self.stub('ip', 'exit 0')
        for shell in self.each_shell():
            for t in ('l2tp', 'pptp', 'ikev2', 'tailscale-exit'):
                r = self.vpn(shell, f'load_driver {t}; echo LOADED')
                self.assertNotEqual(r.returncode, 0, t)
                self.assertNotIn('LOADED', r.stdout)
                self.assertIn(f'{t}: not available in this version', r.stderr)
            # nothing but a name of [a-z-] ever becomes a path, and a type without a driver is refused too
            for t in ('../x', 'x/y', 'X', '', 'nosuch'):
                r = self.vpn(shell, f"load_driver '{t}'; echo LOADED")
                self.assertNotEqual(r.returncode, 0, t)
                self.assertNotIn('LOADED', r.stdout, t)

    def test_only_complete_drivers_load(self):
        self.stub('ip', 'exit 0')
        lib = self.tmp / 'lib'
        shutil.copytree(LIB, lib)
        # a driver that lacks drv_alive: refused, and xray's (loaded before it) is not used in its place
        (lib / 'broken.sh').write_text('drv_engines() { :; }\ndrv_engines_ok() { :; }\ndrv_check() { :; }\n'
                                       'drv_gen() { :; }\ndrv_start() { :; }\ndrv_stop() { :; }\n'
                                       'drv_import() { :; }\n')
        for shell in self.each_shell():
            for t in ('uri', 'common', 'common-x'):
                r = self.vpn(shell, f'load_driver {t}; echo LOADED', MU300_VPN_LIB=lib)
                self.assertNotIn('LOADED', r.stdout, t)
                self.assertIn(f'{t}: invalid type', r.stderr)
            r = self.vpn(shell, 'load_driver xray || exit 9; load_driver broken && echo LOADED; '
                                'command -v drv_alive >/dev/null && echo STALE; echo "[$DRIVER]"', MU300_VPN_LIB=lib)
            self.assertNotIn('LOADED', r.stdout)
            self.assertNotIn('STALE', r.stdout)
            self.assertIn('[]', r.stdout)
            self.assertIn('broken: the driver is incomplete (no drv_alive)', r.stderr)

    def test_a_signal_closes_the_resolve_window(self):
        import signal
        import subprocess
        import time
        self.stub('nft', 'case "$1" in\n'
                         '  -f) r=$(cat); printf "%s\\n" "$r" > "$STUBLOG/nft.state"; echo "nft -f" >> "$STUBLOG/events" ;;\n'
                         '  *) echo "nft $*" >> "$STUBLOG/events" ;;\n'
                         'esac; exit 0')
        # a slow resolver: the service is stopped while it is looking the server up
        self.stub('getent', 'touch "$STUBLOG/resolving"; sleep 2; echo "203.0.113.5     STREAM srv.example"')
        self.stub('ip', 'exit 0')
        (self.tmp / 'resolv.conf').write_text('nameserver 10.177.0.34\n')
        for shell in self.each_shell():
            for p in ('events', 'resolving', 'nft.state'):
                (self.tmp / p).unlink(missing_ok=True)
            e = dict(MU300_LIB=1, MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB,
                     MU300_LAN_CONF=self.tmp / 'no', MU300_BIN=BIN, MU300_OPT=self.tmp / 'opt',
                     MU300_DISK=self.tmp / 'disk', MU300_RESOLV_FILES=self.tmp / 'resolv.conf')
            p = subprocess.Popen(shell + ['-c', f'. "{BIN}/mu300-vpn"; vpn_resolve srv.example; echo DONE'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env(**e))
            deadline = time.time() + 20
            while not (self.tmp / 'resolving').exists() and time.time() < deadline:
                time.sleep(0.05)
            p.send_signal(signal.SIGTERM)
            out, err = p.communicate(timeout=30)
            self.assertNotEqual(p.returncode, 0, err)
            self.assertNotIn('DONE', out)
            # the window went up and the full kill switch came back over it
            self.assertEqual((self.tmp / 'events').read_text().count('nft -f'), 2, err)
            state = (self.tmp / 'nft.state').read_text()
            self.assertIn('counter drop', state)
            self.assertNotIn('dns4', state)

    def test_every_driver_defines_the_contract(self):
        self.stub('ip', 'exit 0')
        names = sorted(p.stem for p in LIB.glob('*.sh') if p.name != 'uri.sh' and not p.name.startswith('common'))
        self.assertIn('xray', names)
        self.assertIn('sing-box', names)
        funcs = 'drv_engines drv_engines_ok drv_check drv_gen drv_start drv_alive drv_stop drv_status drv_import'
        for shell in self.each_shell():
            for n in names:
                r = self.vpn(shell, f'load_driver {n}; for f in {funcs}; do command -v "$f" >/dev/null || '
                                    'echo "missing $f"; done; echo "extra=[$DRV_EXTRA] routes=$DRV_ROUTES"')
                self.assertEqual(r.returncode, 0, (n, r.stderr))
                self.assertNotIn('missing', r.stdout, n)
                self.assertRegex(r.stdout, r'routes=(core|self)\n', n)

    # the Tailscale ip stub of test_vpn: rules kept as the kernel lists them
    IP = ('r="$STUBLOG/rules"; touch "$r"\n'
          'case "$1 $2" in\n'
          '  "rule add") shift 2; [ "$1" = pref ] || exit 2; grep -qxF "$*" "$r" && exit 2\n'
          '      [ -e "$STUBLOG/fail-$2" ] && exit 2; echo "$*" >> "$r" ;;\n'
          '  "rule del") [ "$3" = pref ] || exit 2\n'
          '      awk -v p="$4" \'!d && $2 == p {d = 1; next} {print} END {exit !d}\' "$r" > "$r.new" || { rm -f "$r.new"; exit 2; }\n'
          '      mv "$r.new" "$r" ;;\n'
          '  "rule show") sort -s -n -k2,2 "$r" | sed "s/^pref \\([0-9]*\\) /\\1: /" ;;\n'
          '  "link show") [ -e "$STUBLOG/tun" ]; exit ;;\n'
          'esac\nexit 0')

    def test_core_routes(self):
        self.stub('ip', self.IP)
        self.stub('nft', '[ "$1" = -f ] && cat > /dev/null; exit 0')
        for shell in self.each_shell():
            self.rules.unlink(missing_ok=True)
            r = self.vpn(shell, 'TUN=wg-mu300; mkdir -p "$RUN"; '
                                "printf '203.0.113.9\\n198.51.100.1\\n' > \"$RUN/server-ip\"; routes_up")
            self.assertEqual(r.returncode, 0, r.stderr)
            rules = self.rules.read_text().splitlines()
            for want in ('pref 9000 fwmark 0x2d0 lookup main', 'pref 9002 to 203.0.113.9 lookup main',
                         'pref 9002 to 198.51.100.1 lookup main', 'pref 9010 lookup 2022'):
                self.assertIn(want, rules)
            r = self.vpn(shell, 'TUN=wg-mu300; routes_down')
            self.assertEqual(r.returncode, 0, r.stderr)
            left = [l for l in self.rules.read_text().splitlines() if 9000 <= int(l.split()[1]) <= 9010]
            self.assertEqual(left, [])

    def test_resolve_window(self):
        # the KillSwitch nft stub of test_vpn: the ruleset in force, and every call in order
        self.stub('nft', 'case "$1" in\n'
                         '  -f) r=$(cat); printf "%s\\n" "$r" > "$STUBLOG/nft.state.new"; mv "$STUBLOG/nft.state.new" "$STUBLOG/nft.state"\n'
                         '      { echo "nft -f"; printf "%s\\n" "$r" | sed "s/^/  | /"; } >> "$STUBLOG/events" ;;\n'
                         '  list) [ -s "$STUBLOG/nft.state" ] ;;\n'
                         '  *) echo "nft $*" >> "$STUBLOG/events"\n'
                         '     [ "$*" = "delete table inet mu300_vpn" ] && : > "$STUBLOG/nft.state"; exit 0 ;;\n'
                         'esac')
        self.stub('getent', '[ "$2" = srv.example ] && echo "203.0.113.5     STREAM srv.example"; exit 0')
        self.stub('ip', 'exit 0')
        (self.tmp / 'resolv.conf').write_text('nameserver 127.0.0.53\nnameserver 10.177.0.34\n')
        for shell in self.each_shell():
            for code in ('resolve_window; vpn_resolve srv.example; resolve_close',
                         # by itself it opens and closes the window around the lookup
                         'vpn_resolve srv.example'):
                self.ev.unlink(missing_ok=True)
                r = self.vpn(shell, code, MU300_RESOLV_FILES=self.tmp / 'resolv.conf')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.strip(), '203.0.113.5')
                ev = self.ev.read_text()
                sets = ev.split('nft -f\n')[1:]
                self.assertEqual(len(sets), 2, ev)
                window, full = ('\n'.join(l[4:] for l in s.splitlines() if l.startswith('  | ')) for s in sets)
                self.assertIn('@dns4', window)
                self.assertNotIn('dns4', full)
                self.assertNotIn('fetch4', full)
                adds = [l for l in ev.splitlines() if l.startswith('nft add element')]
                self.assertTrue(any('dns4 { 10.177.0.34 timeout 30s }' in a for a in adds), adds)
                self.assertFalse(any('fetch' in a for a in adds), adds)
                self.assertNotIn('nft delete table', ev)
            # without the kill switch there is nothing to open
            self.ev.unlink(missing_ok=True)
            self.conf.write_text('ENABLE=1\nKILL_SWITCH=0\n')
            r = self.vpn(shell, 'vpn_resolve srv.example', MU300_RESOLV_FILES=self.tmp / 'resolv.conf')
            self.conf.write_text('ENABLE=1\nKILL_SWITCH=1\n')
            self.assertEqual(r.stdout.strip(), '203.0.113.5')
            self.assertFalse(self.ev.exists())

    def test_a_failed_drv_start_step_routes_nothing(self):
        # drv_start runs without set -e (drv_start || exit 1): an "ip link set xtun up" that fails must end it,
        # and the core must never route into that tunnel
        self.stub('ip', self.IP.replace('  "link show")', '  "link set") exit 1 ;;\n  "link show")'))
        self.stub('nft', '[ "$1" = -f ] && cat > /dev/null; exit 0')
        self.stub('ss', 'echo "LISTEN 0 4096 127.0.0.1:10808 0.0.0.0:*"')
        self.stub('getent', 'echo "203.0.113.9     STREAM $2"')
        self.stub('pgrep', 'exit 1')
        d = self.tmp / 'disk/extra/vpn/bin'
        d.mkdir(parents=True)
        (d / 'xray').write_text('#!/bin/sh\n[ "$2" = -test ] && exit 0\nexec sleep 30\n')
        (d / 'hev-socks5-tunnel').write_text('#!/bin/sh\nexec sleep 30\n')
        for n in ('xray', 'hev-socks5-tunnel'):
            (d / n).chmod(0o755)
        (self.tmp / 'tun').write_text('')
        uri = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?security=tls&type=tcp'
        for shell in self.each_shell():
            self.rules.unlink(missing_ok=True)
            self.conf.write_text(f"ENABLE=1\nENGINE=xray\nKILL_SWITCH=0\nVLESS_URI='{uri}'\n")
            r = self.script(shell, BIN / 'mu300-vpn', 'run', MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run',
                            MU300_VPN_LIB=LIB, MU300_LAN_CONF=self.tmp / 'no', MU300_BIN=BIN,
                            MU300_OPT=self.tmp / 'opt', MU300_DISK=self.tmp / 'disk')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('cannot bring xtun up', r.stderr)
            self.assertNotIn('tunnel up', r.stdout)
            rules = self.rules.read_text() if self.rules.exists() else ''
            self.assertNotIn('pref 9010', rules)
            self.assertFalse((self.tmp / 'run/iface').exists())

    def test_xray_runs_in_the_core_loop(self):
        # xray and hev-socks5-tunnel as stubs: the core routes the tunnel once both are up, keeps $RUN/iface while
        # it is, and takes it all down when one of them exits
        self.stub('ip', self.IP)
        self.stub('nft', '[ "$1" = -f ] && cat > /dev/null; exit 0')
        self.stub('ss', 'echo "LISTEN 0 4096 127.0.0.1:10808 0.0.0.0:*"')
        self.stub('getent', '[ "$2" = vpn.example.com ] && echo "203.0.113.9     STREAM vpn.example.com"; exit 0')
        self.stub('pgrep', 'exit 1')
        d = self.tmp / 'disk/extra/vpn/bin'
        d.mkdir(parents=True)
        (d / 'xray').write_text('#!/bin/sh\n[ "$2" = -test ] && exit 0\n'
                                'n=0; until [ -e "$MU300_VPN_RUN/iface" ] || [ $n -gt 100 ]; do sleep 0.1; n=$((n+1)); done\n'
                                'cp "$STUBLOG/rules" "$STUBLOG/rules-up"; cp "$MU300_VPN_RUN/iface" "$STUBLOG/iface-up"\n'
                                'echo "[Warning] gone"\n')
        (d / 'hev-socks5-tunnel').write_text('#!/bin/sh\nexec sleep 30\n')
        for n in ('xray', 'hev-socks5-tunnel'):
            (d / n).chmod(0o755)
        (self.tmp / 'tun').write_text('')
        uri = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?security=tls&type=tcp'
        for shell in self.each_shell():
            for p in ('rules', 'rules-up', 'iface-up'):
                (self.tmp / p).unlink(missing_ok=True)
            self.conf.write_text(f"ENABLE=1\nENGINE=xray\nKILL_SWITCH=0\nVLESS_URI='{uri}'\n")
            r = self.script(shell, BIN / 'mu300-vpn', 'run', MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run',
                            MU300_VPN_LIB=LIB, MU300_LAN_CONF=self.tmp / 'no', MU300_BIN=BIN,
                            MU300_OPT=self.tmp / 'opt', MU300_DISK=self.tmp / 'disk')
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn('tunnel up on xtun', r.stdout)
            self.assertIn('[Warning] gone', r.stdout)
            self.assertIn('xray exited, tearing the tunnel down', r.stderr)
            self.assertNotIn('11111111', r.stdout + r.stderr)
            up = (self.tmp / 'rules-up').read_text().splitlines()
            self.assertIn('pref 9002 to 203.0.113.9 lookup main', up)
            self.assertIn('pref 9010 lookup 2022', up)
            self.assertEqual((self.tmp / 'iface-up').read_text().strip(), 'xtun')
            self.assertEqual([l for l in self.rules.read_text().splitlines() if l.split()[1] >= '9000'], [])
            self.assertFalse((self.tmp / 'run/iface').exists())


VMESS = {"v": "2", "ps": "n", "add": "vm.example", "port": "8443", "id": "11111111-2222-3333-4444-555555555555",
         "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "h.example", "path": "/p", "tls": "tls",
         "sni": "s.example"}


def b64(s, urlsafe=False):
    import base64
    raw = s.encode()
    if urlsafe:
        return base64.urlsafe_b64encode(raw).decode().rstrip('=')
    return base64.b64encode(raw).decode()


def vmess_link(urlsafe=False, **over):
    import json
    d = dict(VMESS, **over)
    return 'vmess://' + b64(json.dumps(d), urlsafe)


class Uris(ShellTest):
    """parse_link for every kind of link the xray driver takes, and the outbound gen_xray writes from each: the
    right protocol, the server's resolved address, and the mark that lets it past the kill switch."""

    LINKS = [
        (vmess_link(), 'vmess',
         dict(PROTO='vmess', HOST='vm.example', PORT='8443', TYPE='ws', WSPATH='/p', WSHOST='h.example',
              SECURITY='tls', SNI='s.example', AID='0', METHOD='auto')),
        (vmess_link(urlsafe=True), 'vmess',
         dict(PROTO='vmess', HOST='vm.example', PORT='8443', TYPE='ws', WSPATH='/p', WSHOST='h.example',
              SECURITY='tls', SNI='s.example')),
        ('trojan://p%40ss@tr.example:443?type=grpc&serviceName=g&sni=x.example#t', 'trojan',
         dict(PROTO='trojan', PASSWORD='p@ss', HOST='tr.example', PORT='443', TYPE='grpc', SVC='g', SECURITY='tls',
              SNI='x.example')),
        ('ss://' + b64('aes-256-gcm:pw', urlsafe=True) + '@ss.example:8388#n', 'shadowsocks',
         dict(PROTO='ss', METHOD='aes-256-gcm', PASSWORD='pw', HOST='ss.example', PORT='8388', SECURITY='none')),
        ('ss://2022-blake3-aes-128-gcm:a%2Bb%3D@[2001:db8::2]:443', 'shadowsocks',
         dict(PROTO='ss', METHOD='2022-blake3-aes-128-gcm', PASSWORD='a+b=', HOST='2001:db8::2', PORT='443')),
        ('ss://' + b64('chacha20-ietf-poly1305:pw@1.2.3.4:8000') + '#legacy', 'shadowsocks',
         dict(PROTO='ss', METHOD='chacha20-ietf-poly1305', PASSWORD='pw', HOST='1.2.3.4', PORT='8000')),
        ('vless://11111111-2222-3333-4444-555555555555@vl.example:443?security=tls&type=tcp', 'vless',
         dict(PROTO='vless', HOST='vl.example', PORT='443', TYPE='tcp', SECURITY='tls')),
    ]
    BAD = ['ss://' + b64('aes-256-gcm:pw', urlsafe=True) + '@ss.example:8388/?plugin=obfs-local%3Bobfs%3Dhttp',
           'ss://' + b64('aes-256-gcm:pw') + '@ss.example:8388?plugin=obfs',
           'vmess://bm90IGpzb24',               # base64, but not JSON
           vmess_link(net='tcp', type='http'),   # TCP with an HTTP header: not something xray_stream_json writes
           vmess_link(port='x'),
           'trojan://@tr.example:443', 'trojan://pw@tr.example:99999', 'vless://u@h:443/?x\nmore',
           'ss://bm9jb2xvbg', 'https://example.com', 'vless://u@bad host:443']

    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('ENABLE=0\nKILL_SWITCH=0\n')
        self.stub('ip', 'exit 0')
        self.stub('nft', 'cat >/dev/null; exit 0')
        self.stub('getent', 'echo "203.0.113.10    STREAM $2"')
        self.stub('xray', 'echo "$*" >> "$STUBLOG/xray.args"')

    def vpn(self, shell, code):
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', MU300_LIB=1, MU300_VPN_CONF=self.conf,
                       MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB, MU300_LAN_CONF=self.tmp / 'no',
                       MU300_BIN=BIN, MU300_OPT=self.tmp / 'opt', MU300_DISK=self.tmp / 'disk')

    def test_parse_link(self):
        for shell in self.each_shell():
            for uri, _, want in self.LINKS:
                code = f"parse_link '{uri}' || exit 9; " + '; '.join(f'echo "{k}=${k}"' for k in want)
                r = self.vpn(shell, code)
                self.assertEqual(r.returncode, 0, (uri, r.stderr))
                got = dict(line.split('=', 1) for line in r.stdout.splitlines())
                self.assertEqual(got, want, uri)
            for uri in self.BAD:
                r = self.vpn(shell, f"parse_link '{uri}' && echo PARSED")
                self.assertNotIn('PARSED', r.stdout, uri)
                self.assertNotEqual(r.returncode, 0, uri)
            r = self.vpn(shell, "parse_link '" + self.BAD[0] + "'")
            self.assertIn('ss plugins are not supported', r.stderr)
            # the vless-only entry point the sing-box driver uses still refuses everything else
            r = self.vpn(shell, f"VLESS_URI='{self.LINKS[2][0]}'; parse_uri; echo PARSED")
            self.assertNotIn('PARSED', r.stdout)

    def test_b64d(self):
        for shell in self.each_shell():
            r = self.vpn(shell, "b64d 'YWVzLTI1Ni1nY206cHc'; b64d 'YWVzLTI1Ni1nY206cHc='; b64d 'Pz8_'")
            self.assertEqual(r.stdout.split('\n')[:3], ['aes-256-gcm:pw', 'aes-256-gcm:pw', '???'], r.stderr)

    def test_gen_xray_outbounds(self):
        import json
        for shell in self.each_shell():
            for uri, proto, want in self.LINKS:
                (self.tmp / 'xray.args').unlink(missing_ok=True)
                r = self.vpn(shell, f"PURI='{uri}'; load_driver xray; XRAY='{self.stubs}/xray'; gen_xray")
                self.assertEqual(r.returncode, 0, (uri, r.stderr))
                cfg = json.loads((self.tmp / 'run/xray.json').read_text())
                out = cfg['outbounds'][0]
                self.assertEqual(out['protocol'], proto, uri)
                server = (out['settings'].get('vnext') or out['settings'].get('servers'))[0]
                # a name is resolved; an address is used as it is
                addr = want['HOST'] if want['HOST'][0].isdigit() else '203.0.113.10'
                self.assertEqual(server['address'], addr, uri)
                self.assertEqual(server['port'], int(want['PORT']), uri)
                self.assertEqual(out['streamSettings']['sockopt']['mark'], 720, uri)
                self.assertEqual(cfg['outbounds'][1]['streamSettings']['sockopt']['mark'], 720)
                if proto == 'vmess':
                    self.assertEqual(server['users'][0]['alterId'], 0)
                    self.assertEqual(server['users'][0]['security'], 'auto')
                    self.assertEqual(out['streamSettings']['wsSettings'], {'path': '/p', 'host': 'h.example'})
                    self.assertEqual(out['streamSettings']['tlsSettings']['serverName'], 's.example')
                if proto == 'trojan':
                    self.assertEqual(server['password'], 'p@ss')
                    self.assertEqual(out['streamSettings']['grpcSettings'], {'serviceName': 'g'})
                if proto == 'shadowsocks':
                    self.assertEqual((server['method'], server['password']), (want['METHOD'], want['PASSWORD']))
                    self.assertNotIn('security', out['streamSettings'])
                self.assertEqual((self.tmp / 'run/server-ip').read_text().strip(), addr)
                self.assertIn(f'run -test -c {self.tmp}/run/xray.json', (self.tmp / 'xray.args').read_text())
                # what gen prints names the server, never the credentials
                for secret in ('11111111', 'p@ss', 'a+b='):
                    self.assertNotIn(secret, r.stdout + r.stderr, uri)


class Cli(ShellTest):
    """The commands: profile list/show/add/import/edit/set/remove/use/export, settings, on/off; run as the
    script, with the service manager a stub that notes what it was told (MU300_VPN_SVC)."""

    UUID = '11111111-2222-3333-4444-555555555555'
    LINK = f'vless://{UUID}@vpn.example.com:443?security=tls&type=tcp#Home'
    LINK2 = f'vless://{UUID}@other.example.com:443?security=tls&type=ws&path=%2Fw'

    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('ENABLE=0\n')
        self.store = self.tmp / 'vpn'
        self.svclog = self.tmp / 'svc.log'
        self.ev = self.tmp / 'events'
        self.stub('svc', 'echo "svc $*" >> "$STUBLOG/svc.log"')
        self.stub('ip', '[ "$1 $2" = "rule del" ] && exit 2; exit 0')
        self.stub('pgrep', 'exit 1')
        self.stub('getent', 'echo "203.0.113.10    STREAM $2"')
        self.stub('nft', 'case "$1" in\n'
                         '  -f) r=$(cat); printf "%s\\n" "$r" > "$STUBLOG/nft.state"\n'
                         '      { echo "nft -f"; printf "%s\\n" "$r" | sed "s/^/  | /"; } >> "$STUBLOG/events" ;;\n'
                         '  list) [ -s "$STUBLOG/nft.state" ] ;;\n'
                         '  *) echo "nft $*" >> "$STUBLOG/events"\n'
                         '     [ "$*" = "delete table inet mu300_vpn" ] && : > "$STUBLOG/nft.state"; exit 0 ;;\n'
                         'esac')

    def engines(self, names=('xray', 'hev-socks5-tunnel', 'sing-box')):
        d = self.tmp / 'disk/extra/vpn/bin'
        d.mkdir(parents=True, exist_ok=True)
        for n in names:
            (d / n).write_text('#!/bin/sh\necho "engine ${0##*/} $*" >> "$STUBLOG/events"\nexit 0\n')
            (d / n).chmod(0o755)

    def fresh(self):
        shutil.rmtree(self.store, ignore_errors=True)
        shutil.rmtree(self.tmp / 'disk', ignore_errors=True)
        for p in (self.svclog, self.ev, self.tmp / 'nft.state'):
            p.unlink(missing_ok=True)
        self.conf.write_text('ENABLE=0\n')

    def vpn(self, shell, *args):
        return self.script(shell, BIN / 'mu300-vpn', *args, MU300_VPN_CONF=self.conf,
                           MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB, MU300_LAN_CONF=self.tmp / 'no',
                           MU300_BIN=BIN, MU300_OPT=self.tmp / 'opt', MU300_DISK=self.tmp / 'disk',
                           MU300_VPN_SVC=self.stubs / 'svc', MU300_EXTRA_CMD=self.stubs / 'no-extra')

    def svc(self):
        return self.svclog.read_text().splitlines() if self.svclog.exists() else []

    def enable(self, v):
        self.conf.write_text(f'ENABLE={v}\n')

    def test_import_list_show_export(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.vpn(shell, 'profile', 'import', self.LINK, 'Home')
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'home'), r.stderr)
            r = self.vpn(shell, 'profile', 'import', self.LINK, 'Home')
            self.assertEqual(r.stdout.strip(), 'home-2', r.stderr)
            # without a name: the link's own tag
            r = self.vpn(shell, 'profile', 'import', vmess_link(ps='My VMess'))
            self.assertEqual(r.stdout.strip(), 'my-vmess', r.stderr)
            r = self.vpn(shell, 'profile', 'add', 'sing-box', 'SB', self.LINK2)
            self.assertEqual(r.stdout.strip(), 'sb', r.stderr)
            r = self.vpn(shell, 'profile', 'list')
            self.assertEqual(r.returncode, 0, r.stderr)
            lines = r.stdout.splitlines()
            self.assertIn(' \thome\txray\tHome', lines)
            self.assertIn(' \tsb\tsing-box\tSB', lines)
            self.assertIn(' \tmy-vmess\txray\tMy VMess', lines)
            pdir = self.store / 'profiles/home'
            self.assertEqual(stat.S_IMODE((pdir / 'uri').stat().st_mode), 0o600)
            r = self.vpn(shell, 'profile', 'show', 'home')
            self.assertEqual(r.returncode, 0, r.stderr)
            show = dict(l.split('\t', 1) for l in r.stdout.splitlines())
            self.assertEqual((show['id'], show['name'], show['type'], show['source'], show['server']),
                             ('home', 'Home', 'xray', 'manual', 'vpn.example.com:443'))
            self.assertRegex(show['created'], r'^[0-9]+$')
            for out in (r.stdout + r.stderr, self.vpn(shell, 'profile', 'list').stdout):
                self.assertNotIn(self.UUID, out)
                self.assertNotIn('vless://', out)
            r = self.vpn(shell, 'profile', 'export', 'home')
            self.assertEqual(r.stdout, self.LINK + '\n')

    def test_refused_imports_leave_nothing(self):
        for shell in self.each_shell():
            self.fresh()
            for args, msg in ((['import', 'ss://' + b64('aes-256-gcm:pw') + '@h:1?plugin=obfs'], 'ss plugins'),
                              (['import', 'https://example.com/x'], 'not a kind of link'),
                              (['add', 'sing-box', 'X', vmess_link()], 'not a link this profile type takes'),
                              (['add', 'l2tp', 'X', self.LINK], 'l2tp: not available in this version'),
                              (['add', 'nosuch', 'X', self.LINK], 'nosuch: no driver')):
                r = self.vpn(shell, 'profile', *args)
                self.assertNotEqual(r.returncode, 0, args)
                self.assertIn(msg, r.stderr, args)
                self.assertNotIn('pw@', r.stderr)
                self.assertEqual(list((self.store / 'profiles').iterdir()), [], args)

    def test_use_restarts_a_running_vpn(self):
        for shell in self.each_shell():
            self.fresh()
            self.vpn(shell, 'profile', 'import', self.LINK, 'Home')
            r = self.vpn(shell, 'profile', 'use', 'home')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((self.store / 'active').read_text(), 'home\n')
            self.assertEqual(self.svc(), [])
            self.enable(1)
            r = self.vpn(shell, 'profile', 'use', 'home')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.svc(), ['svc restart'])
            r = self.vpn(shell, 'profile', 'list')
            self.assertIn('*\thome\txray\tHome', r.stdout.splitlines())

    def test_invalid_ids(self):
        for shell in self.each_shell():
            self.fresh()
            for args in (['use', '../x'], ['show', 'A'], ['remove', 'a/b'], ['export', ''], ['set', '..', 'NAME', 'x']):
                r = self.vpn(shell, 'profile', *args)
                self.assertEqual(r.returncode, 2, args)
                self.assertIn('invalid profile id', r.stderr, args)
            r = self.vpn(shell, 'profile', 'show', 'nosuch')
            self.assertEqual(r.returncode, 1)

    def test_remove(self):
        for shell in self.each_shell():
            self.fresh()
            self.vpn(shell, 'profile', 'import', self.LINK, 'Home')
            self.vpn(shell, 'profile', 'use', 'home')
            self.enable(1)
            r = self.vpn(shell, 'profile', 'remove', 'home')
            self.assertNotEqual(r.returncode, 0)
            self.assertTrue((self.store / 'profiles/home').is_dir())
            r = self.vpn(shell, 'off')
            self.assertEqual(r.returncode, 0, r.stderr)
            r = self.vpn(shell, 'profile', 'remove', 'home')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse((self.store / 'profiles/home').exists())
            self.assertFalse((self.store / 'active').exists())

    def test_edit_and_set(self):
        for shell in self.each_shell():
            self.fresh()
            self.vpn(shell, 'profile', 'import', self.LINK, 'Home')
            uri = self.store / 'profiles/home/uri'
            # a link that does not parse leaves the old one
            r = self.vpn(shell, 'profile', 'edit', 'home', 'trojan://@x:1')
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(uri.read_text(), self.LINK + '\n')
            r = self.vpn(shell, 'profile', 'edit', 'home', vmess_link())
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(uri.read_text(), vmess_link() + '\n')
            self.assertEqual([p.name for p in (self.store / 'profiles').iterdir()], ['home'])
            r = self.vpn(shell, 'profile', 'set', 'home', 'TLS_PIN_SHA256', 'ab' * 32)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("TLS_PIN_SHA256='" + 'ab' * 32 + "'", (self.store / 'profiles/home/meta').read_text())
            for key, val in (('TLS_PIN_SHA256', 'zz'), ('UPSTREAM_HTTP_PROXY', 'h:x'), ('TYPE', 'sing-box'),
                             ('MIHOMO_STACK', 'gvisor')):
                r = self.vpn(shell, 'profile', 'set', 'home', key, val)
                self.assertEqual(r.returncode, 2, (key, r.stderr))
            r = self.vpn(shell, 'profile', 'set', 'home', 'NAME', 'Büro "1"')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('\thome\txray\tBüro "1"', self.vpn(shell, 'profile', 'list').stdout)

    def test_settings(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.vpn(shell, 'settings', 'set', 'KILL_SWITCH', 'yes')
            self.assertEqual(r.returncode, 2)
            r = self.vpn(shell, 'settings', 'set', 'NOPE', '1')
            self.assertEqual(r.returncode, 2)
            r = self.vpn(shell, 'settings', 'set', 'REMOTE_DNS', '9.9.9.9')
            self.assertEqual(r.returncode, 0, r.stderr)
            r = self.vpn(shell, 'settings', 'get', 'REMOTE_DNS')
            self.assertEqual(r.stdout, '9.9.9.9\n')
            r = self.vpn(shell, 'settings')
            got = dict(l.split('=', 1) for l in r.stdout.splitlines())
            self.assertEqual((got['REMOTE_DNS'], got['KILL_SWITCH'], got['LAN_CIDRS'], got['XRAY']),
                             ('9.9.9.9', '1', '', ''))
            self.assertEqual(len(got), 12)
            # empty: back to the default
            r = self.vpn(shell, 'settings', 'set', 'REMOTE_DNS', '')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.vpn(shell, 'settings', 'get', 'REMOTE_DNS').stdout, '1.1.1.1\n')

    def test_on_and_off(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.vpn(shell, 'on')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('no active profile', r.stderr)
            self.assertEqual(self.svc(), [])
            self.vpn(shell, 'profile', 'import', self.LINK, 'Home')
            self.vpn(shell, 'profile', 'use', 'home')
            # no engines: not turned on, with the command that gets them
            r = self.vpn(shell, 'on')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('mu300-vpn engines install', r.stderr)
            self.assertIn('ENABLE=0', self.conf.read_text())
            self.engines()
            r = self.vpn(shell, 'on')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('ENABLE=1', self.conf.read_text())
            self.assertEqual(self.svc(), ['svc enable', 'svc restart'])
            self.svclog.unlink()
            r = self.vpn(shell, 'restart')
            self.assertEqual(self.svc(), ['svc restart'])
            self.svclog.unlink()
            r = self.vpn(shell, 'off')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('ENABLE=0', self.conf.read_text())
            self.assertEqual(self.svc(), ['svc stop', 'svc disable'])
            self.assertIn('kill switch removed', r.stdout)
            self.assertIn('nft delete table inet mu300_vpn', self.ev.read_text())

    def test_switching_profiles_keeps_the_kill_switch(self):
        for shell in self.each_shell():
            self.fresh()
            self.engines()
            self.enable(1)
            self.assertEqual(self.vpn(shell, 'profile', 'add', 'sing-box', 'A', self.LINK).returncode, 0)
            self.assertEqual(self.vpn(shell, 'profile', 'add', 'xray', 'B', self.LINK2).returncode, 0)
            self.vpn(shell, 'profile', 'use', 'a')
            r = self.vpn(shell, 'run')
            self.assertEqual(r.returncode, 0, r.stderr)
            r = self.vpn(shell, 'profile', 'use', 'b')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.svc(), ['svc restart', 'svc restart'])
            # the service's next run, on B: an xray VLESS profile behind the kill switch runs on sing-box
            r = self.vpn(shell, 'run')
            self.assertEqual(r.returncode, 0, r.stderr)
            ev = self.ev.read_text()
            self.assertEqual(ev.count('nft -f\n'), 2, ev)
            self.assertNotIn('nft delete table inet mu300_vpn', ev)
            self.assertIn('other.example.com', (self.tmp / 'run/config.json').read_text())

    def test_nothing_secret_in_the_output(self):
        for shell in self.each_shell():
            self.fresh()
            self.engines()
            self.vpn(shell, 'settings', 'set', 'KILL_SWITCH', '0')
            links = [self.LINK, vmess_link(), f'trojan://{self.UUID}@tr.example:443?sni=x.example',
                     'ss://' + b64(f'aes-256-gcm:{self.UUID}') + '@ss.example:8388']
            for i, link in enumerate(links):
                r = self.vpn(shell, 'profile', 'import', link, f'p{i}')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.enable(1)
                self.vpn(shell, 'profile', 'use', f'p{i}')
                outs = [self.vpn(shell, *a) for a in (['run'], ['status'], ['profile', 'list'],
                                                      ['profile', 'show', f'p{i}'], ['check'], ['on'])]
                for r in outs:
                    self.assertNotIn(self.UUID, r.stdout + r.stderr, (link, r.args))
                self.enable(0)


XRAY_RAW = {
    "log": {"loglevel": "debug"},
    "inbounds": [{"port": 1080, "listen": "0.0.0.0", "protocol": "socks"}],
    "outbounds": [
        {"tag": "proxy", "protocol": "vless",
         "settings": {"vnext": [{"address": "srv.example", "port": 443,
                                 "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
         "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"alpn": ["h2"]}}},
        {"tag": "direct", "protocol": "freedom"}],
    "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]}}

SING_BOX_RAW = {
    "log": {"level": "info"},
    "dns": {"servers": [{"type": "tls", "tag": "dot", "server": "1.1.1.1"}]},
    "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080}],
    "outbounds": [{"type": "trojan", "tag": "proxy", "server": "tr.example", "server_port": 443,
                   "password": "11111111-2222-3333-4444-555555555555"},
                  {"type": "direct", "tag": "direct"}],
    "route": {"final": "proxy", "default_domain_resolver": "x"}}


class RawJson(ShellTest):
    """Raw Xray and sing-box configs: imported as they are, and rewritten at every start so that only the device's
    own inbound listens (no SOCKS port on the LAN), every connection the engine makes carries the mark the kill switch
    lets out, and server names are looked up by the core. Also "-" as the source: a link or a config on stdin."""

    UUID = '11111111-2222-3333-4444-555555555555'

    def setUp(self):
        super().setUp()
        import json
        self.json = json
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('ENABLE=0\nKILL_SWITCH=0\n')
        self.store = self.tmp / 'vpn'
        self.ev = self.tmp / 'events'
        self.stub('ip', 'exit 0')
        self.stub('svc', 'exit 0')
        self.stub('nft', 'case "$1" in -f) cat >/dev/null; echo "nft -f" >> "$STUBLOG/events" ;; esac; exit 0')
        self.stub('getent', 'echo "getent $2" >> "$STUBLOG/events"\n'
                            'case $2 in srv.example) echo "203.0.113.5     STREAM $2" ;;'
                            ' tr.example) echo "203.0.113.6     STREAM $2" ;; esac')
        self.stub('xray', 'echo "$*" >> "$STUBLOG/xray.args"')
        self.stub('sing-box', 'echo "$*" >> "$STUBLOG/sing-box.args"')
        self.xray = self.tmp / 'xray.json'
        self.xray.write_text(json.dumps(XRAY_RAW))
        self.sb = self.tmp / 'sb.json'
        self.sb.write_text(json.dumps(SING_BOX_RAW))

    def env(self, **extra):
        base = dict(MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB,
                    MU300_LAN_CONF=self.tmp / 'no', MU300_BIN=BIN, MU300_OPT=self.tmp / 'opt',
                    MU300_DISK=self.tmp / 'disk', MU300_VPN_SVC=self.stubs / 'svc')
        base.update(extra)
        return super().env(**base)

    def lib(self, shell, code):
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', MU300_LIB=1)

    def cli(self, shell, *args, stdin=None):
        return self.script(shell, BIN / 'mu300-vpn', *args, stdin=stdin)

    def fresh(self):
        shutil.rmtree(self.store, ignore_errors=True)
        shutil.rmtree(self.tmp / 'run', ignore_errors=True)
        for p in ('events', 'xray.args', 'sing-box.args'):
            (self.tmp / p).unlink(missing_ok=True)

    def gen(self, shell, pid, pre=''):
        return self.lib(shell, f'{pre}profile_load {pid}; load_driver "$PTYPE"; XRAY="{self.stubs}/xray"; '
                               f'BIN="{self.stubs}/sing-box"; drv_gen')

    def test_xray_config_is_rewritten(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.cli(shell, 'profile', 'import', self.xray, 'Raw')
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'raw'), r.stderr)
            pdir = self.store / 'profiles/raw'
            self.assertEqual(self.kv(pdir / 'meta')['TYPE'], 'xray')
            self.assertEqual(stat.S_IMODE((pdir / 'config.json').stat().st_mode), 0o600)
            self.assertFalse((pdir / 'uri').exists())
            r = self.gen(shell, 'raw')
            self.assertEqual(r.returncode, 0, r.stderr)
            cfg = self.json.loads((self.tmp / 'run/xray.json').read_text())
            self.assertEqual(cfg['inbounds'], [{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808,
                                                "protocol": "socks",
                                                "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}])
            self.assertEqual(cfg['log'], {"loglevel": "warning", "access": "none"})
            for out in cfg['outbounds']:
                self.assertEqual(out['streamSettings']['sockopt']['mark'], 720, out['tag'])
            proxy, direct = cfg['outbounds']
            self.assertEqual(proxy['settings']['vnext'][0]['address'], '203.0.113.5')
            self.assertNotIn('_name', proxy['settings']['vnext'][0])
            self.assertEqual(proxy['streamSettings']['tlsSettings'], {'alpn': ['h2'], 'serverName': 'srv.example'})
            # nothing is added to an outbound that has no servers
            self.assertNotIn('settings', direct)
            self.assertEqual(cfg['routing'], XRAY_RAW['routing'])
            self.assertEqual((self.tmp / 'run/server-ip').read_text().split(), ['203.0.113.5'])
            self.assertIn(f'run -test -c {self.tmp}/run/xray.json', (self.tmp / 'xray.args').read_text())
            self.assertTrue((self.tmp / 'run/hev.yml').exists())
            self.assertNotIn(self.UUID, r.stdout + r.stderr)
            r = self.cli(shell, 'profile', 'show', 'raw')
            self.assertIn('server\tsrv.example:443', r.stdout.splitlines())
            r = self.cli(shell, 'check', 'raw')
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'profile raw: OK'), r.stderr)
            self.assertNotIn(self.UUID, r.stdout + r.stderr)

    def test_xray_names_kept_literals_and_the_resolve_window(self):
        raw = dict(XRAY_RAW)
        raw['outbounds'] = [
            {"protocol": "vless", "settings": {"vnext": [{"address": "srv.example", "port": 443, "users": []}]},
             "streamSettings": {"security": "reality", "realitySettings": {"serverName": "cover.example"}}},
            {"protocol": "trojan", "settings": {"servers": [{"address": "tr.example", "port": 443, "password": "x"},
                                                            {"address": "198.51.100.7", "port": 443,
                                                             "password": "y"}]},
             "streamSettings": {"security": "tls"}}]
        self.xray.write_text(self.json.dumps(raw))
        for shell in self.each_shell():
            self.fresh()
            self.assertEqual(self.cli(shell, 'profile', 'import', self.xray, 'Raw').returncode, 0)
            # behind the kill switch: one window around both lookups
            r = self.gen(shell, 'raw', 'ENABLE=1; KILL_SWITCH=1; ')
            self.assertEqual(r.returncode, 0, r.stderr)
            ev = self.ev.read_text().splitlines()
            self.assertEqual(ev, ['nft -f', 'getent srv.example', 'getent tr.example', 'nft -f'])
            cfg = self.json.loads((self.tmp / 'run/xray.json').read_text())
            vl, tr = cfg['outbounds']
            # a serverName the config has is its own
            self.assertEqual(vl['streamSettings']['realitySettings']['serverName'], 'cover.example')
            self.assertEqual(tr['streamSettings']['tlsSettings']['serverName'], 'tr.example')
            self.assertEqual([s['address'] for s in tr['settings']['servers']], ['203.0.113.6', '198.51.100.7'])
            self.assertEqual(sorted((self.tmp / 'run/server-ip').read_text().split()),
                             ['198.51.100.7', '203.0.113.5', '203.0.113.6'])
            # a name that does not resolve: nothing is written to run, and the kill switch is back
            self.fresh()
            raw2 = dict(XRAY_RAW, outbounds=[{"protocol": "vless", "settings": {"vnext": [
                {"address": "nx.example", "port": 1, "users": []}]}}])
            self.xray.write_text(self.json.dumps(raw2))
            self.assertEqual(self.cli(shell, 'profile', 'import', self.xray, 'Raw').returncode, 0)
            r = self.gen(shell, 'raw', 'ENABLE=1; KILL_SWITCH=1; ')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('cannot resolve the VPN server nx.example', r.stderr)
            self.assertEqual(self.ev.read_text().splitlines(), ['nft -f', 'getent nx.example', 'nft -f'])
            self.xray.write_text(self.json.dumps(raw))

    def test_sing_box_config_is_rewritten(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.cli(shell, 'profile', 'import', self.sb, 'SB')
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'sb'), r.stderr)
            self.assertEqual(self.kv(self.store / 'profiles/sb/meta')['TYPE'], 'sing-box')
            r = self.gen(shell, 'sb')
            self.assertEqual(r.returncode, 0, r.stderr)
            cfg = self.json.loads((self.tmp / 'run/config.json').read_text())
            self.assertEqual(cfg['inbounds'], [{"type": "tun", "tag": "tun-in", "stack": "gvisor",
                                                "interface_name": "sbtun", "address": ["172.19.0.1/30"],
                                                "mtu": 1400, "auto_route": True, "strict_route": True,
                                                "route_exclude_address": ["192.168.77.0/24"]}])
            self.assertEqual(cfg['route']['default_mark'], 720)
            self.assertIs(cfg['route']['auto_detect_interface'], True)
            self.assertEqual(cfg['route']['final'], 'proxy')
            # the config's own resolver is kept
            self.assertEqual(cfg['route']['default_domain_resolver'], 'x')
            self.assertEqual(cfg['dns']['servers'], SING_BOX_RAW['dns']['servers'] +
                             [{"type": "udp", "tag": "mu300-bootstrap", "server": "1.1.1.1"}])
            self.assertEqual(cfg['outbounds'], SING_BOX_RAW['outbounds'])
            self.assertIn(f'check -c {self.tmp}/run/config.json', (self.tmp / 'sing-box.args').read_text())
            self.assertNotIn(self.UUID, r.stdout + r.stderr)
            # without a resolver of its own, ours
            raw = dict(SING_BOX_RAW, route={"final": "proxy"})
            raw.pop('dns')
            self.sb.write_text(self.json.dumps(raw))
            self.assertEqual(self.cli(shell, 'profile', 'edit', 'sb', self.sb).returncode, 0)
            self.assertEqual(self.gen(shell, 'sb').returncode, 0)
            cfg = self.json.loads((self.tmp / 'run/config.json').read_text())
            self.assertEqual(cfg['route']['default_domain_resolver'], 'mu300-bootstrap')
            self.assertEqual(cfg['dns']['servers'], [{"type": "udp", "tag": "mu300-bootstrap", "server": "1.1.1.1"}])
            self.sb.write_text(self.json.dumps(SING_BOX_RAW))

    def test_sing_box_control_apis_are_removed(self):
        raw = dict(SING_BOX_RAW, experimental={"clash_api": {"external_controller": "0.0.0.0:9090", "secret": "s"},
                                               "v2ray_api": {"listen": "0.0.0.0:8080"},
                                               "cache_file": {"enabled": True}})
        self.sb.write_text(self.json.dumps(raw))
        for shell in self.each_shell():
            self.fresh()
            self.assertEqual(self.cli(shell, 'profile', 'import', self.sb, 'SB').returncode, 0)
            self.assertEqual(self.gen(shell, 'sb').returncode, 0)
            text = (self.tmp / 'run/config.json').read_text()
            cfg = self.json.loads(text)
            self.assertEqual(cfg['experimental'], {"cache_file": {"enabled": True}})
            self.assertNotIn('9090', text)
            self.assertNotIn('8080', text)
        self.sb.write_text(self.json.dumps(SING_BOX_RAW))

    def test_import_sniffing(self):
        bad = self.tmp / 'bad.json'
        bad.write_text('{"outbounds": [ {"protocol": ')
        noout = self.tmp / 'noout.json'
        noout.write_text('{"inbounds": []}')
        for shell in self.each_shell():
            self.fresh()
            r = self.cli(shell, 'profile', 'import', self.xray)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'xray'), r.stderr)
            r = self.cli(shell, 'profile', 'import', self.sb)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'sb'), r.stderr)
            lines = self.cli(shell, 'profile', 'list').stdout.splitlines()
            self.assertIn(' \txray\txray\txray', lines)
            self.assertIn(' \tsb\tsing-box\tsb', lines)
            for f, args in ((bad, ['import']), (noout, ['import']), (bad, ['add', 'xray', 'B']),
                            (bad, ['add', 'sing-box', 'B']), (self.xray, ['add', 'sing-box', 'B']),
                            (noout, ['add', 'xray', 'B'])):
                r = self.cli(shell, 'profile', *args, f)
                self.assertNotEqual(r.returncode, 0, (f, args))
                self.assertEqual(sorted(p.name for p in (self.store / 'profiles').iterdir()), ['sb', 'xray'],
                                 (f, args))
            # a raw profile is never run on sing-box in xray's place, whatever the kill switch says
            r = self.lib(shell, 'profile_load xray; load_driver xray; KILL_SWITCH=1; ENGINE=sing-box; '
                                'vless_on_sing_box; echo "driver=$DRIVER"')
            self.assertIn('driver=xray', r.stdout, r.stderr)

    def test_stdin(self):
        link = f'vless://{self.UUID}@vpn.example.com:443?security=tls&type=tcp#Home'
        for shell in self.each_shell():
            self.fresh()
            r = self.cli(shell, 'profile', 'import', '-', stdin=link + '\n')
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'home'), r.stderr)
            self.assertEqual((self.store / 'profiles/home/uri').read_text(), link + '\n')
            r = self.cli(shell, 'profile', 'import', '-', 'Raw', stdin=self.xray.read_text())
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'raw'), r.stderr)
            self.assertEqual(self.json.loads((self.store / 'profiles/raw/config.json').read_text()), XRAY_RAW)
            # with no name: the type, not the name of a temporary file
            r = self.cli(shell, 'profile', 'import', '-', stdin=self.sb.read_text())
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'sing-box'), r.stderr)
            r = self.cli(shell, 'profile', 'add', 'xray', 'Two', '-', stdin='  \r\n' + link + '\r\n\n')
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'two'), r.stderr)
            self.assertEqual((self.store / 'profiles/two/uri').read_text(), link + '\n')
            # edit from stdin: the link replaced by a config, and back
            r = self.cli(shell, 'profile', 'edit', 'home', '-', stdin=self.xray.read_text())
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((self.store / 'profiles/home/config.json').exists())
            self.assertFalse((self.store / 'profiles/home/uri').exists())
            r = self.cli(shell, 'profile', 'edit', 'home', '-', stdin=link)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((self.store / 'profiles/home/uri').read_text(), link + '\n')
            self.assertFalse((self.store / 'profiles/home/config.json').exists())
            # refused: nothing on stdin, two links, garbage - and nothing of it left anywhere
            for data in ('', link + '\n' + link + '\n', 'garbage\n'):
                r = self.cli(shell, 'profile', 'import', '-', stdin=data)
                self.assertNotEqual(r.returncode, 0, repr(data))
                self.assertNotIn(self.UUID, r.stdout + r.stderr)
            self.assertEqual(sorted(p.name for p in (self.store / 'profiles').iterdir()),
                             ['home', 'raw', 'sing-box', 'two'])
            self.assertEqual([p.name for p in (self.tmp / 'run').iterdir()] if (self.tmp / 'run').exists() else [],
                             [])

    def kv(self, path):
        out = {}
        for line in path.read_text().splitlines():
            k, _, v = line.partition('=')
            out[k] = v.strip("'")
        return out


WG_PRIV = 'P' * 43 + '='
WG_PUB = 'B' * 43 + '='
WG_PSK = 'S' * 43 + '='
WG_CONF = f"""[Interface]
PrivateKey = {WG_PRIV}
Address = 10.7.0.2/32, fd00:7::2/128
DNS = 10.7.0.1, example.org
MTU = 1380
PostUp = iptables -A FORWARD -i %i -j ACCEPT
Table = off

[Peer]
PublicKey = {WG_PUB}
PresharedKey = {WG_PSK}
Endpoint = wg.example:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""


class WireGuard(ShellTest):
    """The wireguard driver: the wg-quick file is reduced to what wg setconf takes, the Endpoint name is looked up
    by the core, the interface is made with ip and marked with wg, and no key is ever printed."""

    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('ENABLE=0\nKILL_SWITCH=0\n')
        self.store = self.tmp / 'vpn'
        self.ev = self.tmp / 'events'
        self.ip_stub()
        self.stub('wg', 'echo "$*" >> "$STUBLOG/wg.log"\n'
                        'case "$*" in\n'
                        f'  "show wg-mu300 latest-handshakes") printf "{WG_PUB}\\t%s\\n" "$(( $(date +%s) - 30 ))" ;;\n'
                        f'  "show wg-mu300 transfer") printf "{WG_PUB}\\t100\\t200\\n" ;;\n'
                        'esac; exit 0')
        self.stub('svc', 'exit 0')
        self.stub('nft', 'case "$1" in -f) cat >/dev/null; echo "nft -f" >> "$STUBLOG/events" ;; esac; exit 0')
        self.stub('getent', 'echo "getent $2" >> "$STUBLOG/events"\n'
                            'case $2 in wg.example) echo "203.0.113.7     STREAM $2" ;; esac')
        self.src = self.tmp / 'x.conf'
        self.src.write_text(WG_CONF)

    def kv(self, path):
        out = {}
        for line in path.read_text().splitlines():
            k, _, v = line.partition('=')
            out[k] = v.strip("'")
        return out

    def iplog(self):
        # (sourcing mu300-vpn asks ip about the LAN too: only what the driver does is of interest)
        return [l for l in (self.tmp / 'ip.log').read_text().splitlines() if l.split()[0] in ('link', 'addr')]

    def ip_stub(self, kernel=True):
        # "link show" finds nothing (no tunnel yet); "link add ... type wireguard" works only on a kernel that has it
        add = 'exit 0' if kernel else 'exit 2'
        self.stub('ip', 'echo "$*" >> "$STUBLOG/ip.log"\n'
                        'case "$*" in\n'
                        '  "link show"*) exit 1 ;;\n'
                        f'  "link add"*) {add} ;;\n'
                        'esac; exit 0')

    def env(self, **extra):
        base = dict(MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB,
                    MU300_LAN_CONF=self.tmp / 'no', MU300_BIN=BIN, MU300_OPT=self.tmp / 'opt',
                    MU300_DISK=self.tmp / 'disk', MU300_VPN_SVC=self.stubs / 'svc',
                    MU300_WG_SYSMOD=self.tmp / 'no-module')
        base.update(extra)
        return super().env(**base)

    def lib(self, shell, code):
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', MU300_LIB=1)

    def cli(self, shell, *args, stdin=None):
        return self.script(shell, BIN / 'mu300-vpn', *args, stdin=stdin)

    def fresh(self):
        shutil.rmtree(self.store, ignore_errors=True)
        shutil.rmtree(self.tmp / 'run', ignore_errors=True)
        for p in ('events', 'ip.log', 'wg.log'):
            (self.tmp / p).unlink(missing_ok=True)

    def setup_profile(self, shell, text=WG_CONF):
        self.fresh()
        self.src.write_text(text)
        r = self.cli(shell, 'profile', 'import', self.src, 'Wg')
        self.assertEqual((r.returncode, r.stdout.strip()), (0, 'wg'), r.stderr)

    def run_lib(self, shell, code, pre=''):
        return self.lib(shell, f'{pre}profile_load wg; load_driver "$PTYPE"; {code}')

    def no_keys(self, r):
        for secret in (WG_PRIV, WG_PSK, 'PPPPPPPP', 'SSSSSSSS'):
            self.assertNotIn(secret, r.stdout + r.stderr)

    def test_import_sniffs_and_stores_0600(self):
        for shell in self.each_shell():
            self.setup_profile(shell)
            pdir = self.store / 'profiles/wg'
            self.assertEqual(self.kv(pdir / 'meta')['TYPE'], 'wireguard')
            self.assertEqual(stat.S_IMODE((pdir / 'wg.conf').stat().st_mode), 0o600)
            self.assertEqual((pdir / 'wg.conf').read_text(), WG_CONF)
            r = self.cli(shell, 'profile', 'show', 'wg')
            self.assertIn('server\twg.example:51820', r.stdout.splitlines())
            self.no_keys(r)
            r = self.cli(shell, 'check', 'wg')
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'profile wg: OK'), r.stderr)
            self.no_keys(r)
            # the same from stdin, with the section and keys in any case
            self.fresh()
            r = self.cli(shell, 'profile', 'import', '-', 'Low',
                         stdin=WG_CONF.replace('[Interface]', '[interface]').replace('PrivateKey', 'PRIVATEKEY'))
            self.assertEqual((r.returncode, r.stdout.strip()), (0, 'low'), r.stderr)

    def test_gen_reduces_the_config(self):
        for shell in self.each_shell():
            self.setup_profile(shell)
            r = self.run_lib(shell, 'drv_gen')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.no_keys(r)
            run = self.tmp / 'run'
            gen = (run / 'wg.conf').read_text()
            for gone in ('Address', 'DNS', 'MTU', 'PostUp', 'Table', 'iptables', 'wg.example'):
                self.assertNotIn(gone, gen)
            self.assertIn('Endpoint = 203.0.113.7:51820', gen.splitlines())
            for kept in (f'PrivateKey = {WG_PRIV}', f'PublicKey = {WG_PUB}', f'PresharedKey = {WG_PSK}',
                         'AllowedIPs = 0.0.0.0/0, ::/0', 'PersistentKeepalive = 25', '[Peer]'):
                self.assertIn(kept, gen.splitlines())
            self.assertEqual(stat.S_IMODE((run / 'wg.conf').stat().st_mode), 0o600)
            self.assertEqual((run / 'wg.addr').read_text().split(), ['10.7.0.2/32', 'fd00:7::2/128'])
            self.assertEqual((run / 'wg.mtu').read_text().strip(), '1380')
            self.assertEqual((run / 'dns').read_text().strip(), '10.7.0.1')
            self.assertEqual((run / 'server-ip').read_text().split(), ['203.0.113.7'])

    def test_keys_spelled_differently(self):
        text = (WG_CONF.replace('Address = ', 'address=').replace('DNS = ', 'dns\t=\t')
                .replace('MTU = 1380', 'mtu = 1400   # tuned').replace('PostUp', 'POSTUP')
                .replace('Endpoint = wg.example:51820', 'endpoint=[2001:db8::7]:51820'))
        for shell in self.each_shell():
            self.setup_profile(shell, text)
            r = self.run_lib(shell, 'drv_gen')
            self.assertEqual(r.returncode, 0, r.stderr)
            run = self.tmp / 'run'
            gen = (run / 'wg.conf').read_text()
            for gone in ('ddress', 'dns', 'mtu', 'POSTUP', 'iptables'):
                self.assertNotIn(gone, gen)
            # a literal address is kept, and nothing is looked up
            self.assertIn('endpoint = [2001:db8::7]:51820', gen.splitlines())
            self.assertEqual((run / 'server-ip').read_text().split(), ['2001:db8::7'])
            self.assertFalse(self.ev.exists())
            self.assertEqual((run / 'wg.mtu').read_text().strip(), '1400')
            self.assertEqual((run / 'dns').read_text().strip(), '10.7.0.1')

    def test_start_alive_stop(self):
        for shell in self.each_shell():
            self.setup_profile(shell)
            self.assertEqual(self.run_lib(shell, 'drv_gen').returncode, 0)
            for p in ('ip.log', 'wg.log'):
                (self.tmp / p).unlink(missing_ok=True)
            r = self.run_lib(shell, 'drv_start && echo STARTED; echo "tun=$TUN"')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('tunnel up on wg-mu300', r.stdout)
            self.assertIn('tun=wg-mu300', r.stdout)
            self.no_keys(r)
            ip = self.iplog()
            wg = (self.tmp / 'wg.log').read_text().splitlines()
            self.assertEqual(ip, ['link del wg-mu300', 'link add wg-mu300 type wireguard',
                                  'addr add 10.7.0.2/32 dev wg-mu300', 'link set wg-mu300 mtu 1380 up'])
            self.assertEqual(wg, [f'setconf wg-mu300 {self.tmp}/run/wg.conf', 'set wg-mu300 fwmark 0x2d0'])
            # with IPV6=1 the IPv6 address goes on too
            (self.tmp / 'ip.log').unlink()
            r = self.run_lib(shell, 'IPV6=1; drv_start')
            self.assertIn('addr add fd00:7::2/128 dev wg-mu300', (self.tmp / 'ip.log').read_text())
            # alive follows the interface; stop removes it and the runtime copy of the config
            r = self.run_lib(shell, 'drv_alive || echo "alive=$?"')
            self.assertIn('alive=1', r.stdout)
            (self.tmp / 'ip.log').unlink()
            r = self.run_lib(shell, 'drv_stop; echo "stop=$?"')
            self.assertIn('stop=0', r.stdout)
            self.assertEqual(self.iplog(), ['link del wg-mu300'])
            self.assertFalse((self.tmp / 'run/wg.conf').exists())

    def test_start_fails_closed(self):
        for shell in self.each_shell():
            self.setup_profile(shell)
            self.assertEqual(self.run_lib(shell, 'drv_gen').returncode, 0)
            # a wg that rejects the config says so without quoting it
            self.stub('wg', f'echo "Key is not the correct length: {WG_PRIV}" >&2; exit 1')
            r = self.run_lib(shell, 'drv_start && echo STARTED')
            self.assertNotIn('STARTED', r.stdout)
            self.assertIn('wg setconf rejected the config', r.stderr)
            self.no_keys(r)
            self.stub('wg', 'exit 0')
            self.ip_stub(kernel=False)
            r = self.run_lib(shell, 'drv_start && echo STARTED')
            self.assertNotIn('STARTED', r.stdout)
            self.assertIn('cannot create wg-mu300', r.stderr)
            self.ip_stub()

    def test_check_warns_about_the_default_route(self):
        text = WG_CONF.replace('AllowedIPs = 0.0.0.0/0, ::/0', 'AllowedIPs = 10.0.0.0/8')
        for shell in self.each_shell():
            self.setup_profile(shell, text)
            r = self.cli(shell, 'check', 'wg')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('0.0.0.0/0', r.stderr)
            self.assertIn('warning', r.stderr)
            self.no_keys(r)

    def test_refused_imports(self):
        cases = {
            'no PrivateKey': (WG_CONF.replace(f'PrivateKey = {WG_PRIV}\n', ''), 'no PrivateKey'),
            'no [Interface]': ('[Peer]\n' + WG_CONF.split('[Peer]\n')[1], 'no [Interface]'),
            'no peer': (WG_CONF.split('[Peer]')[0], 'no [Peer]'),
            'no peer key': (WG_CONF.replace(f'PublicKey = {WG_PUB}\n', ''), 'without a PublicKey'),
            'no endpoint': (WG_CONF.replace('Endpoint = wg.example:51820\n', ''), 'without an Endpoint'),
            'bad endpoint': (WG_CONF.replace('wg.example:51820', 'wg.example'), 'Endpoint that is not'),
            'option as host': (WG_CONF.replace('wg.example:51820', '-x:51820'), 'Endpoint that is not'),
            'bad key': (WG_CONF.replace(WG_PRIV, 'short'), 'PrivateKey that is not a WireGuard key'),
            'bad mtu': (WG_CONF.replace('1380', '12'), 'MTU'),
            'bad address': (WG_CONF.replace('10.7.0.2/32', '10.7.0.2;reboot'), 'Address'),
        }
        for shell in self.each_shell():
            for name, (text, msg) in cases.items():
                self.fresh()
                self.src.write_text(text)
                r = self.cli(shell, 'profile', 'add', 'wireguard', 'X', self.src)
                self.assertNotEqual(r.returncode, 0, name)
                self.assertIn(msg, r.stderr, name)
                self.no_keys(r)
                profiles = self.store / 'profiles'
                self.assertEqual(list(profiles.iterdir()) if profiles.exists() else [], [], name)

    def test_a_kernel_without_wireguard_fails_the_check(self):
        self.ip_stub(kernel=False)
        for shell in self.each_shell():
            self.fresh()
            r = self.cli(shell, 'profile', 'import', self.src, 'Wg')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('this kernel has no WireGuard', r.stderr)
            # the module is loaded: the probe is not needed
            (self.tmp / 'no-module').mkdir(exist_ok=True)
            r = self.cli(shell, 'profile', 'import', self.src, 'Wg')
            self.assertEqual(r.returncode, 0, r.stderr)
            (self.tmp / 'no-module').rmdir()

    def test_engines(self):
        for shell in self.each_shell():
            r = self.lib(shell, 'load_driver wireguard; echo "[$DRV_EXTRA] [$DRV_PKG] [$TUN] [$DRV_ROUTES]"; '
                                'drv_engines; drv_engines_ok && echo "ok=$?"')
            self.assertIn('[] [wireguard-tools] [wg-mu300] [core]', r.stdout)
            self.assertIn(f'{self.stubs}/wg', r.stdout.splitlines())
            # wg is there and the probe's temporary interface can be made
            self.assertIn('ok=0', r.stdout)
            self.assertIn('link add wg-mu300-t type wireguard', (self.tmp / 'ip.log').read_text())
            self.assertIn('link del wg-mu300-t', (self.tmp / 'ip.log').read_text())
            # no wg: not ok, whatever the kernel says
            (self.stubs / 'wg').rename(self.tmp / 'wg.away')
            r = self.lib(shell, 'load_driver wireguard; drv_engines_ok || echo "ok=$?"')
            (self.tmp / 'wg.away').rename(self.stubs / 'wg')
            self.assertIn('ok=1', r.stdout)

    def test_status_shows_no_keys(self):
        for shell in self.each_shell():
            self.setup_profile(shell)
            r = self.run_lib(shell, 'drv_status')
            self.assertEqual(r.returncode, 0, r.stderr)
            lines = r.stdout.splitlines()
            self.assertEqual(len(lines), 2, r.stdout)
            self.assertRegex(lines[0], r'^handshake: (29|3\d)s ago$')
            self.assertEqual(lines[1], 'transfer: 100 bytes received, 200 bytes sent')
            self.no_keys(r)
            self.assertNotIn(WG_PUB, r.stdout + r.stderr)

    def test_names_are_looked_up_in_the_resolve_window(self):
        for shell in self.each_shell():
            self.setup_profile(shell)
            r = self.run_lib(shell, 'drv_gen', 'ENABLE=1; KILL_SWITCH=1; ')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.ev.read_text().splitlines(), ['nft -f', 'getent wg.example', 'nft -f'])
            # a name that does not resolve: nothing is written, and the kill switch is back
            self.fresh()
            self.src.write_text(WG_CONF.replace('wg.example', 'nx.example'))
            self.assertEqual(self.cli(shell, 'profile', 'import', self.src, 'Wg').returncode, 0)
            r = self.run_lib(shell, 'drv_gen', 'ENABLE=1; KILL_SWITCH=1; ')
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('cannot resolve the VPN server nx.example', r.stderr)
            self.assertEqual(self.ev.read_text().splitlines(), ['nft -f', 'getent nx.example', 'nft -f'])
            self.assertFalse((self.tmp / 'run/wg.conf').exists())
