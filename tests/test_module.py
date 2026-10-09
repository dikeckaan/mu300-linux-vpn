"""The module: tools/make-module.sh's tarballs (with fake engines, MU300_VPN_FAKE_ENGINES=1: no network), and
hooks/link and hooks/unlink against fake systems (Ubuntu with systemd, OpenWrt with procd), with and without an
older image's own mu300-vpn there, under every shell."""
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from helpers import SYSBIN, TOP, ShellTest

MAKE = TOP / 'tools' / 'make-module.sh'


def build(out, tag='v1.2.3', **env):
    e = dict(os.environ, MU300_VPN_FAKE_ENGINES='1', SOURCE_DATE_EPOCH='1700000000', **env)
    return subprocess.run(['sh', str(MAKE), str(out), tag], capture_output=True, text=True, env=e, timeout=120)


class Tarballs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='mu300-module-'))
        r = build(cls.tmp / 'out')
        assert r.returncode == 0, r.stderr
        cls.out = cls.tmp / 'out'

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def members(self, name):
        with tarfile.open(self.out / name) as t:
            return {m.name: m for m in t.getmembers()}, {m.name: t.extractfile(m).read() for m in t.getmembers()
                                                          if m.isfile()}

    def test_the_three_release_files(self):
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         ['SHA256SUMS', 'mu300-linux-vpn-mihomo.tar.gz', 'mu300-linux-vpn.tar.gz'])
        sums = {}
        for line in (self.out / 'SHA256SUMS').read_text().splitlines():
            h, name = line.split('  ')
            sums[name] = h
        self.assertEqual(set(sums), {'mu300-linux-vpn.tar.gz', 'mu300-linux-vpn-mihomo.tar.gz'})
        for name, h in sums.items():
            self.assertEqual(hashlib.sha256((self.out / name).read_bytes()).hexdigest(), h, name)

    def test_module_layout(self):
        m, data = self.members('mu300-linux-vpn.tar.gz')
        files = {n[2:] for n, ti in m.items() if ti.isfile()}
        drivers = {'lib/vpn/' + p.name for p in (TOP / 'lib/vpn').iterdir()}
        self.assertEqual(files, {'VERSION', 'components', 'requires', 'name', 'release', 'manifest', 'install.sh',
                                 'bin/mu300-vpn', 'bin/xray', 'bin/hev-socks5-tunnel', 'bin/sing-box',
                                 'etc/vpn.conf.example', 'service/systemd/mu300-vpn.service',
                                 'service/procd/mu300-vpn', 'hooks/link', 'hooks/unlink'} | drivers)
        self.assertEqual(data['./VERSION'], b'v1.2.3\n')
        self.assertEqual(data['./release'], b'v1.2.3\n')
        self.assertEqual(data['./name'], b'vpn\n')
        self.assertEqual(data['./requires'], b'mu300-linux v2026.10.16\n')
        comp = data['./components'].decode().splitlines()
        self.assertEqual([c.split()[0] for c in comp], ['mu300-linux-vpn', 'xray', 'hev-socks5-tunnel', 'sing-box'])
        self.assertEqual(comp[0], 'mu300-linux-vpn v1.2.3')
        for rel in ('bin/mu300-vpn', 'hooks/link', 'etc/vpn.conf.example', 'lib/vpn/uri.sh'):
            self.assertEqual(data['./' + rel], (TOP / rel).read_bytes(), rel)

    def test_mihomo_layout(self):
        m, data = self.members('mu300-linux-vpn-mihomo.tar.gz')
        self.assertEqual({n[2:] for n, ti in m.items() if ti.isfile()},
                         {'VERSION', 'components', 'requires', 'name', 'release', 'manifest', 'bin/mihomo'})
        self.assertEqual(data['./name'], b'vpn-mihomo\n')
        self.assertRegex(data['./components'].decode(), r'^mihomo \d+\.\d+\.\d+\n$')

    def test_entries_modes_and_owner(self):
        for name in ('mu300-linux-vpn.tar.gz', 'mu300-linux-vpn-mihomo.tar.gz'):
            m, _ = self.members(name)
            for n, ti in m.items():
                with self.subTest(tarball=name, entry=n):
                    self.assertTrue(n.startswith('./') and '..' not in n.split('/'))
                    self.assertTrue(ti.isfile() or ti.isdir())
                    self.assertEqual((ti.uid, ti.gid, ti.uname, ti.gname), (0, 0, 'root', 'root'))
                    rel = n[2:]
                    if ti.isdir():
                        want = 0o755
                    elif rel.startswith(('bin/', 'hooks/', 'service/procd/')) or rel in ('install.sh', 'lib/vpn/openvpn-up'):
                        want = 0o755
                    else:
                        want = 0o644
                    self.assertEqual(ti.mode, want)

    def test_manifest_lists_every_other_file(self):
        for name in ('mu300-linux-vpn.tar.gz', 'mu300-linux-vpn-mihomo.tar.gz'):
            _, data = self.members(name)
            lines = data['./manifest'].decode().splitlines()
            self.assertEqual(lines, sorted(lines, key=lambda l: l[66:]))
            have = {l[66:]: l[:64] for l in lines}
            self.assertEqual(set(have), set(data) - {'./manifest'})
            for n, h in have.items():
                self.assertEqual(hashlib.sha256(data[n]).hexdigest(), h, n)

    def test_the_same_bytes_again(self):
        r = build(self.tmp / 'again')
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ('mu300-linux-vpn.tar.gz', 'mu300-linux-vpn-mihomo.tar.gz', 'SHA256SUMS'):
            self.assertEqual((self.tmp / 'again' / name).read_bytes(), (self.out / name).read_bytes(), name)

    def test_what_mu300_extra_accepts(self):
        """mu300-extra's checks (mu300-linux's spec, As implemented): plain files and directories only, names of
        [A-Za-z0-9._+-] not starting with a dot, at most four levels deep; VERSION one line of [A-Za-z0-9._-]{1,40};
        requires exactly 'mu300-linux v2026.10.16'; bin/mu300-vpn and the hooks there (vpn-mihomo: a program)."""
        import re
        for name in ('mu300-linux-vpn.tar.gz', 'mu300-linux-vpn-mihomo.tar.gz'):
            m, data = self.members(name)
            for n, ti in m.items():
                with self.subTest(tarball=name, entry=n):
                    self.assertTrue(ti.isreg() or ti.isdir())
                    self.assertFalse(ti.islnk() or ti.issym())
                    parts = n[2:].rstrip('/').split('/') if n.startswith('./') else n.split('/')
                    self.assertLessEqual(len(parts), 4)
                    for c in parts:
                        self.assertRegex(c, r'^[A-Za-z0-9_+-][A-Za-z0-9._+-]*$')
            self.assertRegex(data['./VERSION'].decode(), r'^[A-Za-z0-9._-]{1,40}\n$')
            self.assertEqual(data['./requires'], b'mu300-linux v2026.10.16\n')
        m, data = self.members('mu300-linux-vpn.tar.gz')
        for rel in ('bin/mu300-vpn', 'hooks/link', 'hooks/unlink'):
            self.assertTrue(m['./' + rel].isreg() and m['./' + rel].mode & 0o111, rel)
        m, _ = self.members('mu300-linux-vpn-mihomo.tar.gz')
        self.assertTrue(m['./bin/mihomo'].isreg() and m['./bin/mihomo'].mode & 0o111)

    def test_tag_is_checked(self):
        r = build(self.tmp / 'bad', tag='1.0')
        self.assertNotEqual(r.returncode, 0)


def tree(root):
    """{relative path: ('l', target) | ('d', mode) | ('f', mode, sha256)} of everything under ROOT."""
    out = {}
    for d, ds, fs in os.walk(root):
        for n in ds + fs:
            p = Path(d) / n
            rel = str(p.relative_to(root))
            st = p.lstat()
            if p.is_symlink():
                out[rel] = ('l', os.readlink(p))
            elif p.is_dir():
                out[rel] = ('d', st.st_mode & 0o777)
            else:
                out[rel] = ('f', st.st_mode & 0o777, hashlib.sha256(p.read_bytes()).hexdigest())
    return out


class Hooks(ShellTest):
    @classmethod
    def setUpClass(cls):
        cls.build = Path(tempfile.mkdtemp(prefix='mu300-module-'))
        r = build(cls.build)
        assert r.returncode == 0, r.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.build, ignore_errors=True)

    def setUp(self):
        super().setUp()
        self.extra = self.tmp / 'disk/extra/vpn'
        self.extra.mkdir(parents=True)
        with tarfile.open(self.build / 'mu300-linux-vpn.tar.gz') as t:
            t.extractall(self.extra, **({'filter': 'tar'} if hasattr(tarfile, 'tar_filter') else {}))
        self.extra = Path(os.path.realpath(self.extra))
        self.disk = self.extra.parents[1]
        for name in ('systemctl', 'nft', 'ip'):
            self.stub(name, f'echo "{name} $*" >> "$STUBLOG/calls"; '
                            f'[ "$1" = is-active ] && [ -e "$STUBLOG/active" ] && exit 0; [ "$1" != is-active ]')

    def system(self, kind, enable=None, builtin=False):
        root = self.tmp / ('root-' + kind)
        shutil.rmtree(root, ignore_errors=True)
        (root / 'etc/mu300').mkdir(parents=True)
        if kind == 'openwrt':
            (root / 'etc/openwrt_release').write_text("DISTRIB_ID='OpenWrt'\n")
        if enable is not None:
            (root / 'etc/mu300/vpn.conf').write_text(enable)
        if builtin:
            for rel, text in (('opt/mu300/bin/mu300-vpn', '#!/bin/sh\necho builtin\n'),
                              ('opt/mu300/lib/vpn/uri.sh', '# builtin\n'),
                              ('etc/mu300/vpn.conf.example', 'ENABLE=0 # builtin\n')):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text)
            (root / 'opt/mu300/bin/mu300-vpn').chmod(0o755)
            if kind == 'openwrt':
                (root / 'etc/init.d').mkdir(parents=True)
                (root / 'etc/init.d/mu300-vpn').write_text('#!/bin/sh /etc/rc.common\n# builtin\nSTART=95\n')
                (root / 'etc/rc.d').mkdir(parents=True)
                (root / 'etc/rc.d/S95mu300-vpn').symlink_to('../init.d/mu300-vpn')
            else:
                (root / 'etc/systemd/system/multi-user.target.wants').mkdir(parents=True)
                (root / 'etc/systemd/system/mu300-vpn.service').write_text('[Service]\n# builtin\n')
                (root / 'etc/systemd/system/multi-user.target.wants/mu300-vpn.service').symlink_to(
                    '/etc/systemd/system/mu300-vpn.service')
        return root

    def hook(self, shell, name, root, live='0', **env):
        return self.script(shell, self.extra / 'hooks' / name, root, MU300_VPN_LIVE=live, MU300_DISK=self.disk,
                           MU300_EXTRA_DIR=self.extra, **env)

    def assertLinked(self, root, kind, wanted):
        self.assertEqual(os.readlink(root / 'opt/mu300/bin/mu300-vpn'), str(self.extra / 'bin/mu300-vpn'))
        self.assertEqual(os.readlink(root / 'opt/mu300/lib/vpn'), str(self.extra / 'lib/vpn'))
        self.assertEqual((root / 'etc/mu300/vpn.conf.example').read_bytes(), (TOP / 'etc/vpn.conf.example').read_bytes())
        if kind == 'openwrt':
            init = root / 'etc/init.d/mu300-vpn'
            self.assertEqual(init.read_bytes(), (TOP / 'service/procd/mu300-vpn').read_bytes())
            self.assertEqual(init.stat().st_mode & 0o777, 0o755)
            links = sorted(p.name for p in (root / 'etc/rc.d').glob('*mu300-vpn')) if (root / 'etc/rc.d').exists() else []
            self.assertEqual(links, ['S95mu300-vpn'] if wanted else [])
            if wanted:
                self.assertEqual(os.readlink(root / 'etc/rc.d/S95mu300-vpn'), '../init.d/mu300-vpn')
            self.assertFalse((root / 'etc/systemd').exists())
        else:
            unit = root / 'etc/systemd/system/mu300-vpn.service'
            self.assertEqual(unit.read_bytes(), (TOP / 'service/systemd/mu300-vpn.service').read_bytes())
            self.assertEqual(unit.stat().st_mode & 0o777, 0o644)
            w = root / 'etc/systemd/system/multi-user.target.wants/mu300-vpn.service'
            self.assertEqual(w.is_symlink(), wanted)
            if wanted:
                self.assertEqual(os.readlink(w), '/etc/systemd/system/mu300-vpn.service')
            self.assertFalse((root / 'etc/init.d').exists())

    def test_link_and_unlink_a_new_system(self):
        for shell in self.each_shell():
            for kind in ('ubuntu', 'openwrt'):
                for enable, wanted in (('ENABLE=1\n', True), ('ENABLE=0\n', False), (None, False)):
                    with self.subTest(kind=kind, enable=enable):
                        root = self.system(kind, enable)
                        before = tree(root)
                        r = self.hook(shell, 'link', root)
                        self.assertEqual(r.returncode, 0, r.stderr)
                        self.assertEqual(r.stderr, '')
                        self.assertLinked(root, kind, wanted)
                        self.assertEqual([p for p in tree(root) if 'builtin' in p], [])
                        linked = tree(root)
                        r = self.hook(shell, 'link', root)
                        self.assertEqual(r.returncode, 0, r.stderr)
                        self.assertEqual(tree(root), linked, 'link twice')
                        r = self.hook(shell, 'unlink', root)
                        self.assertEqual(r.returncode, 0, r.stderr)
                        left = {p: v for p, v in tree(root).items() if v[0] != 'd'}
                        self.assertEqual(left, {p: v for p, v in before.items() if v[0] != 'd'}, 'unlink')
                        r = self.hook(shell, 'unlink', root)
                        self.assertEqual(r.returncode, 0, r.stderr)
                        self.assertEqual({p: v for p, v in tree(root).items() if v[0] != 'd'}, left, 'unlink twice')

    def test_an_older_images_own_vpn_is_kept_aside_and_put_back(self):
        for shell in self.each_shell():
            for kind in ('ubuntu', 'openwrt'):
                with self.subTest(kind=kind):
                    root = self.system(kind, 'ENABLE=1\n', builtin=True)
                    before = tree(root)
                    r = self.hook(shell, 'link', root)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertLinked(root, kind, True)
                    service = 'etc/init.d/mu300-vpn' if kind == 'openwrt' else 'etc/systemd/system/mu300-vpn.service'
                    aside = sorted(p for p in tree(root) if p.endswith('.builtin'))
                    self.assertEqual(aside, sorted(['opt/mu300/bin/mu300-vpn.builtin', 'opt/mu300/lib/vpn.builtin',
                                                    'etc/mu300/vpn.conf.example.builtin', service + '.builtin']))
                    self.assertEqual((root / 'opt/mu300/bin/mu300-vpn.builtin').read_text(), '#!/bin/sh\necho builtin\n')
                    self.assertEqual((root / 'opt/mu300/lib/vpn.builtin/uri.sh').read_text(), '# builtin\n')
                    linked = tree(root)
                    r = self.hook(shell, 'link', root)
                    self.assertEqual(tree(root), linked, 'link twice')
                    r = self.hook(shell, 'unlink', root)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(tree(root), before, 'unlink puts it all back')
                    r = self.hook(shell, 'unlink', root)
                    self.assertEqual(tree(root), before, 'unlink twice')

    def test_the_builtin_is_never_overwritten(self):
        """A system that is linked, unlinked by hand and given its own mu300-vpn again keeps both."""
        shell = self.shells[0]
        root = self.system('ubuntu', 'ENABLE=0\n', builtin=True)
        self.assertEqual(self.hook(shell, 'link', root).returncode, 0)
        (root / 'opt/mu300/bin/mu300-vpn').unlink()
        (root / 'opt/mu300/bin/mu300-vpn').write_text('#!/bin/sh\necho second\n')
        r = self.hook(shell, 'link', root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((root / 'opt/mu300/bin/mu300-vpn.builtin').read_text(), '#!/bin/sh\necho builtin\n')
        self.assertEqual((root / 'opt/mu300/bin/mu300-vpn.builtin.1').read_text(), '#!/bin/sh\necho second\n')

    def test_a_system_with_its_own_vpn_is_left_by_unlink(self):
        for shell in self.each_shell():
            root = self.system('ubuntu', 'ENABLE=1\n', builtin=True)
            before = tree(root)
            r = self.hook(shell, 'unlink', root)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(tree(root), before)

    def test_wanted_is_what_mu300_vpn_enabled_answers(self):
        confs = ['ENABLE=1\n', 'ENABLE=0\n', '', 'ENABLE="1"\n', "ENABLE='1'  # on\n", 'ENABLE=1\nENABLE=0\n',
                 'ENABLE=0\nENABLE=1\n', '# ENABLE=1\n', ' ENABLE=1\n', 'ENABLE=yes\n', 'XENABLE=1\n']
        for shell in self.each_shell():
            for conf in confs:
                with self.subTest(conf=conf):
                    root = self.system('ubuntu', conf)
                    run = self.tmp / 'run'
                    r = self.script(shell, self.extra / 'bin/mu300-vpn', 'enabled',
                                    MU300_VPN_CONF=root / 'etc/mu300/vpn.conf', MU300_VPN_DIR=self.tmp / 'store',
                                    MU300_VPN_RUN=run, MU300_LAN_CONF=self.tmp / 'no-lan.conf', MU300_BIN=SYSBIN,
                                    MU300_SYSROOT=root)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(self.hook(shell, 'link', root).returncode, 0)
                    w = root / 'etc/systemd/system/multi-user.target.wants/mu300-vpn.service'
                    self.assertEqual(w.is_symlink(), r.stdout.strip() == '1', conf)

    def test_the_running_system_reloads_and_starts_a_wanted_vpn(self):
        for shell in self.each_shell():
            for enable, active, want in (('ENABLE=1\n', False, ['systemctl daemon-reload', 'systemctl is-active --quiet mu300-vpn',
                                                                  'systemctl --no-block start mu300-vpn']),
                                         ('ENABLE=1\n', True, ['systemctl daemon-reload', 'systemctl is-active --quiet mu300-vpn']),
                                         ('ENABLE=0\n', False, ['systemctl daemon-reload'])):
                with self.subTest(enable=enable, active=active):
                    (self.tmp / 'calls').unlink(missing_ok=True)
                    (self.tmp / 'active').unlink(missing_ok=True)
                    if active:
                        (self.tmp / 'active').write_text('')
                    root = self.system('ubuntu', enable)
                    r = self.hook(shell, 'link', root, live='1')
                    self.assertEqual(r.returncode, 0, r.stderr)
                    calls = (self.tmp / 'calls').read_text().splitlines() if (self.tmp / 'calls').exists() else []
                    self.assertEqual(calls, want)
            # another system's root: no service calls
            (self.tmp / 'calls').unlink(missing_ok=True)
            r = self.script(shell, self.extra / 'hooks/link', self.system('ubuntu', 'ENABLE=1\n'),
                            MU300_EXTRA_DIR=self.extra)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse((self.tmp / 'calls').exists())

    def test_unlink_on_the_running_system_turns_the_vpn_off(self):
        """Nothing would be left that could take the kill switch down: mu300-vpn off first (ENABLE=0, the service
        stopped and disabled, the kill switch removed)."""
        self.stub('svc', 'echo "svc $*" >> "$STUBLOG/calls"')
        for shell in self.each_shell():
            (self.tmp / 'calls').unlink(missing_ok=True)
            root = self.system('ubuntu', 'ENABLE=1\nKILL_SWITCH=1\n')
            self.assertEqual(self.hook(shell, 'link', root).returncode, 0)
            r = self.hook(shell, 'unlink', root, live='1', MU300_VPN_CONF=root / 'etc/mu300/vpn.conf',
                          MU300_VPN_DIR=self.tmp / 'store', MU300_VPN_RUN=self.tmp / 'run',
                          MU300_LAN_CONF=self.tmp / 'no-lan.conf', MU300_BIN=SYSBIN, MU300_SYSROOT=root,
                          MU300_VPN_SVC=self.stubs / 'svc')
            self.assertEqual(r.returncode, 0, r.stderr)
            calls = (self.tmp / 'calls').read_text().splitlines()
            self.assertIn('svc stop', calls)
            self.assertIn('svc disable', calls)
            self.assertIn('nft delete table inet mu300_vpn', calls)
            self.assertIn('ENABLE=0', (root / 'etc/mu300/vpn.conf').read_text().splitlines())
            self.assertFalse((root / 'opt/mu300/bin/mu300-vpn').exists())
            self.assertFalse((root / 'etc/systemd/system/mu300-vpn.service').exists())
            self.assertFalse((root / 'etc/systemd/system/multi-user.target.wants/mu300-vpn.service').is_symlink())

    def test_mu300_vpn_finds_its_library_through_the_link(self):
        for shell in self.each_shell():
            root = self.system('ubuntu', 'ENABLE=0\n')
            self.assertEqual(self.hook(shell, 'link', root).returncode, 0)
            env = dict(MU300_LIB='1', MU300_VPN_CONF=self.tmp / 'vpn.conf', MU300_VPN_DIR=self.tmp / 'store',
                       MU300_VPN_RUN=self.tmp / 'run', MU300_LAN_CONF=self.tmp / 'no-lan.conf', MU300_BIN=SYSBIN,
                       MU300_SYSROOT=root)
            for via in (root / 'opt/mu300/bin/mu300-vpn', self.extra / 'bin/mu300-vpn'):
                r = subprocess.run(shell + ['-c', '. "$0"; echo "$LIB"', str(via)], capture_output=True, text=True,
                                   env=self.env(**env), timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(os.path.realpath(r.stdout.strip()), str(self.extra / 'lib/vpn'), via)
            # a copy with no lib/vpn next to it: the system's
            alone = self.tmp / 'alone/bin'
            alone.mkdir(parents=True, exist_ok=True)
            shutil.copy(self.extra / 'bin/mu300-vpn', alone)
            r = subprocess.run(shell + ['-c', '. "$0"; echo "$LIB"', str(alone / 'mu300-vpn')], capture_output=True,
                               text=True, env=self.env(**env), timeout=60)
            self.assertEqual(r.stdout.strip(), '/opt/mu300/lib/vpn')

    def test_links_go_to_the_extra_dir_mu300_extra_names(self):
        """mu300-extra runs the hooks with MU300_DISK and MU300_EXTRA_DIR; without them the links go to the
        device's own $DISK/extra/vpn, whichever directory the hook runs from."""
        for shell in self.each_shell():
            for env, want in (({'MU300_DISK': '/d', 'MU300_EXTRA_DIR': '/d/extra/vpn'}, '/d/extra/vpn'),
                              ({'MU300_DISK': '/d'}, '/d/extra/vpn'), ({}, '/mnt/mu300-disk/extra/vpn')):
                root = self.system('ubuntu', 'ENABLE=0\n')
                r = self.script(shell, self.extra / 'hooks/link', root, MU300_VPN_LIVE='0', **env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(os.readlink(root / 'opt/mu300/bin/mu300-vpn'), want + '/bin/mu300-vpn')
                self.assertEqual(os.readlink(root / 'opt/mu300/lib/vpn'), want + '/lib/vpn')

    def test_not_the_module(self):
        for shell in self.each_shell():
            d = self.tmp / 'x/hooks'
            d.mkdir(parents=True, exist_ok=True)
            shutil.copy(self.extra / 'hooks/link', d)
            root = self.system('ubuntu', 'ENABLE=1\n')
            r = self.script(shell, d / 'link', root)
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse((root / 'opt').exists())

    def test_hooks_are_posix(self):
        for name in ('link', 'unlink'):
            text = (TOP / 'hooks' / name).read_text()
            for bashism in (' [[ ', 'local ', 'function ', '$(<', 'echo -e', '==', 'pushd'):
                self.assertNotIn(bashism, text, (name, bashism))


if __name__ == '__main__':
    unittest.main()
