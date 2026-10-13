"""IPV6=auto on the proxy engines (docs/FINDINGS.md 26n): the tunnel is asked at every start whether IPv6 works
through it, and IPv6 is routed into it only after a yes. Both answers, for an engine the core routes for (xray,
mihomo) and for the one that is exec'd and routes itself (sing-box); the order of the routing and of the nft
transactions around the question (IPv6 is rejected or in the tunnel, never neither); what status says about it;
and the question itself against a real HTTP server on ::1.
"""
import http.server
import json
import shutil
import socket
import threading
import time
import unittest

from helpers import BIN, LIB, SYSBIN, ShellTest

URI = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?security=tls&type=tcp'
HOSTS = ['2606:4700:4700::1111', '2620:119:35::35']

# ip: every call noted; the IPv6 rules kept in a file ("PREF: ..." lines, as ip -6 rule show prints them); the TUN is
# there while $STUBLOG/tun-up is, and has a global IPv6 address while $STUBLOG/tun-v6 is
IP = r'''echo "ip $*" >> "$STUBLOG/events"
r="$STUBLOG/rules6"; touch "$r"
case "$*" in
  "link show "*) [ -e "$STUBLOG/tun-up" ]; exit ;;
  "-6 addr show dev "*) [ -e "$STUBLOG/tun-v6" ] && echo "    inet6 fdfe:dcba:9876::1/126 scope global"; exit 0 ;;
  "-6 addr flush dev "*) rm -f "$STUBLOG/tun-v6"; exit 0 ;;
  "-6 rule add pref "*) shift 4; p=$1; shift; echo "$p: $*" >> "$r"; exit 0 ;;
  "-6 rule del pref "*)
      awk -v p="$5:" '!d && $1 == p {d = 1; next} {print} END {exit !d}' "$r" > "$r.new" || { rm -f "$r.new"; exit 2; }
      mv "$r.new" "$r"; exit 0 ;;
  "-6 rule show"*) cat "$r"; exit 0 ;;
  "rule del "*) exit 2 ;;
esac
exit 0'''
NFT = ('case "$1" in\n'
       '  -f) r=$(cat); { echo "nft -f"; printf "%s\\n" "$r" | sed "s/^/  | /"; } >> "$STUBLOG/events" ;;\n'
       '  list) exit 1 ;;\n'
       '  *) echo "nft $*" >> "$STUBLOG/events" ;;\n'
       'esac; exit 0')
# the far end's place: the addresses in $STUBLOG/v6-answers answer; every question is noted
PROBE = 'echo "probe $1" >> "$STUBLOG/events"; grep -qxF "$1" "$STUBLOG/v6-answers" 2>/dev/null'
# sing-box: every call noted, every config it is run with kept (config.1, config.2, ...). Run without auto_route it
# is the instance that is only asked: its TUN is there (with an IPv6 address when its config has one) until it is
# told to go. Run with it, it is the one the service exec's: the test ends there.
ENGINE = r'''#!/bin/sh
echo "engine ${0##*/} $*" >> "$STUBLOG/events"
[ "$1" = run ] || exit 0
n=$(ls "$STUBLOG" | grep -c '^config\.[0-9]')
cp "$3" "$STUBLOG/config.$((n + 1))"
cp "$MU300_VPN_RUN/ipv6" "$STUBLOG/note.$((n + 1))" 2>/dev/null
grep -q '"auto_route":false' "$3" || exit 0
trap 'rm -f "$STUBLOG/tun-up" "$STUBLOG/tun-v6"; exit 0' TERM INT
if grep -q 'fdfe:dcba:9876::1/126' "$3"; then : > "$STUBLOG/tun-v6"; fi
: > "$STUBLOG/tun-up"
while :; do sleep 1 & wait $!; done
'''


class Base(ShellTest):
    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.run = self.tmp / 'run-vpn'
        self.disk = self.tmp / 'disk'
        self.ev = self.tmp / 'events'
        self.stub('ip', IP)
        self.stub('nft', NFT)
        self.stub('probe', PROBE)
        self.stub('pgrep', 'exit 1')
        # (status asks for the exit address when a tunnel is up: never the real network)
        self.stub('wget', 'echo 203.0.113.1')
        self.stub('curl', 'echo 203.0.113.1')
        (self.tmp / 'resolv.conf').write_text('nameserver 10.177.0.34\n')

    def fresh(self, answers=(), tun_v6=False):
        for p in self.tmp.glob('config.*'):
            p.unlink()
        for p in self.tmp.glob('note.*'):
            p.unlink()
        for n in ('events', 'rules6', 'tun-up', 'tun-v6'):
            (self.tmp / n).unlink(missing_ok=True)
        for d in (self.tmp / 'vpn', self.run, self.disk):
            shutil.rmtree(d, ignore_errors=True)
        (self.tmp / 'v6-answers').write_text(''.join(a + '\n' for a in answers))
        if tun_v6:
            (self.tmp / 'tun-v6').write_text('')
        d = self.disk / 'extra/vpn/bin'
        d.mkdir(parents=True)
        for n in ('xray', 'hev-socks5-tunnel', 'sing-box'):
            (d / n).write_text(ENGINE)
            (d / n).chmod(0o755)

    def envs(self, **extra):
        e = dict(MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.run, MU300_BIN=SYSBIN, MU300_VPN_LIB=LIB,
                 MU300_LAN_CONF=self.tmp / 'no-lan.conf', MU300_OPT=self.tmp / 'opt', MU300_DISK=self.disk,
                 MU300_EXTRA_CMD='true', MU300_VPN_SVC='true', MU300_RESOLV_FILES=self.tmp / 'resolv.conf',
                 MU300_V6_PROBE=self.stubs / 'probe')
        e.update(extra)
        return e

    def conf_text(self, engine, ks='0', extra=''):
        return f"ENABLE=1\nENGINE={engine}\nKILL_SWITCH={ks}\nVLESS_URI='{URI}'\n{extra}"

    def vpn(self, shell, *args, conf=None, **env):
        if conf is not None:
            self.conf.write_text(conf)
        return self.script(shell, BIN / 'mu300-vpn', *args, **self.envs(**env))

    def lib(self, shell, code, conf=None, **env):
        if conf is not None:
            self.conf.write_text(conf)
        return self.sh(shell, f'. "{BIN}/mu300-vpn"; {code}', **self.envs(MU300_LIB=1, **env))

    def events(self):
        return self.ev.read_text() if self.ev.exists() else ''

    def note(self):
        p = self.run / 'ipv6'
        return p.read_text().rstrip('\n').split('\t') if p.exists() else None

    def configs(self):
        return [p.read_text() for p in sorted(self.tmp.glob('config.*'))]


class SingBox(Base):
    """The engine that is exec'd: asked in a run of its own before the config it will serve with is written."""

    def test_a_yes_and_the_tunnel_gets_ipv6(self):
        for shell in self.each_shell():
            self.fresh(answers=HOSTS[:1])
            r = self.vpn(shell, 'run', conf=self.conf_text('sing-box'))
            self.assertEqual(r.returncode, 0, r.stderr)
            ev = self.events()
            asked, served = self.configs()
            # asked: the config it would serve IPv6 with, but no routing of its own and nothing in the log
            self.assertIn('"auto_route":false', asked)
            self.assertIn('"fdfe:dcba:9876::1/126"', asked)
            self.assertIn('"level":"panic"', asked)
            # served: IPv6 on the TUN, AAAA answered, its own routing
            self.assertIn('"auto_route":true', served)
            self.assertIn('"address":["172.19.0.1/30","fdfe:dcba:9876::1/126"]', served)
            self.assertIn('"strategy":"prefer_ipv4"', served)
            self.assertIn('"level":"warn"', served)
            # the question: its own table, the engine's marked sockets kept out of it, only the device's own
            # packets to the addresses that are asked - and all of it gone before the engine that serves starts
            first, last = ev.index('engine sing-box run'), ev.rindex('engine sing-box run')
            order = [first,
                     ev.index('ip -6 route replace default dev sbtun table 2023'),
                     ev.index('ip -6 rule add pref 9003 fwmark 0x2d0 lookup main'),
                     ev.index(f'ip -6 rule add pref 9004 iif lo to {HOSTS[0]} lookup 2023'),
                     ev.index(f'ip -6 rule add pref 9004 iif lo to {HOSTS[1]} lookup 2023'),
                     ev.index(f'probe {HOSTS[0]}'),
                     ev.index('ip -6 rule del pref 9003'),
                     # (the first flush of that table is routes_down's, before anything started)
                     ev.index('ip -6 route flush table 2023', first),
                     last]
            self.assertEqual(order, sorted(order), ev)
            self.assertLess(first, last)
            self.assertEqual((self.tmp / 'rules6').read_text(), '')
            self.assertFalse((self.tmp / 'tun-up').exists(), 'the instance that was asked is still running')
            self.assertEqual(self.note(), ['yes', 'probe', f'{HOSTS[0]} answered through the tunnel'])
            # what status had to go by while the instance that was asked ran (its TUN has an IPv6 address)
            self.assertEqual((self.tmp / 'note.1').read_text(), 'no\tprobe\tthe tunnel is being asked\n')
            self.assertIn(f'IPv6: through the tunnel - {HOSTS[0]} answered through the tunnel', r.stdout)
            self.assertEqual(r.stdout.count('IPv6: '), 1, r.stdout)

    def test_a_no_and_everything_is_as_it_was(self):
        for shell in self.each_shell():
            self.fresh()
            r = self.vpn(shell, 'run', conf=self.conf_text('sing-box'))
            self.assertEqual(r.returncode, 0, r.stderr)
            ev = self.events()
            asked, served = self.configs()
            self.assertIn('"fdfe:dcba:9876::1/126"', asked)
            # the config v2.0.1 wrote for auto: no IPv6 address, A records only
            self.assertIn('"address":["172.19.0.1/30"]', served)
            self.assertIn('"strategy":"ipv4_only"', served)
            self.assertIn('"auto_route":true', served)
            for h in HOSTS:
                self.assertIn(f'probe {h}', ev)
            self.assertEqual((self.tmp / 'rules6').read_text(), '')
            self.assertEqual(self.note()[:2], ['no', 'probe'])
            self.assertIn('nothing answered over IPv6 through the tunnel', self.note()[2])
            self.assertIn('IPv6: not through the tunnel, rejected on the uplinks - nothing answered', r.stdout)

    def test_rejected_or_in_the_tunnel_never_neither(self):
        """Without the kill switch the guard goes up before the previous run's routing is taken away, and a run that
        asks never takes it down: whatever the answer, and whenever sing-box gets round to its IPv6 routes."""
        for shell in self.each_shell():
            for answers in ((), HOSTS[:1]):
                self.fresh(answers=answers)
                r = self.vpn(shell, 'run', conf=self.conf_text('sing-box'))
                self.assertEqual(r.returncode, 0, r.stderr)
                ev = self.events()
                guard = ev.index('  | table inet mu300_vpn_v6 {')
                # (routes_down begins with the DNS redirect; the rule deletes follow)
                self.assertLess(guard, ev.index('nft delete table ip mu300_vpn_dns'))
                self.assertLess(guard, ev.index('ip -6 rule show'))
                self.assertLess(guard, ev.index('engine sing-box run'))
                self.assertNotIn('nft delete table inet mu300_vpn_v6', ev)
                # loaded again before the exec, in one transaction as ever (delete and create in the same nft -f)
                self.assertLess(ev.rindex('  | table inet mu300_vpn_v6 {'), ev.rindex('engine sing-box run'))

    def test_behind_the_kill_switch_nothing_is_opened_for_it(self):
        """The kill switch rejects IPv6 on the uplinks itself. The question adds no nft transaction: the kill switch
        and the resolve window of the bootstrap resolver are done before sing-box is first run, and the kill
        switch is never taken down."""
        for shell in self.each_shell():
            for answers in ((), HOSTS[:1]):
                self.fresh(answers=answers)
                r = self.vpn(shell, 'run', conf=self.conf_text('sing-box', ks='1'))
                self.assertEqual(r.returncode, 0, r.stderr)
                ev = self.events()
                self.assertNotIn('mu300_vpn_v6', ev)
                first = ev.index('engine sing-box run')
                ks = [i for i in range(len(ev)) if ev.startswith('  | table inet mu300_vpn {', i)]
                self.assertTrue(ks)
                self.assertLess(max(ks), first, ev)
                self.assertNotIn('nft delete table inet mu300_vpn\n', ev)
                # the last ruleset loaded on its table is the full kill switch, not a window
                self.assertNotIn('set dns4', ev[max(ks):])
                self.assertEqual(len(self.configs()), 2)
                self.assertEqual(self.note()[0], 'yes' if answers else 'no')

    def test_ipv6_0_and_1_do_not_ask(self):
        for shell in self.each_shell():
            for v, addr, note, guard_off in (('1', True, ['yes', 'setting', 'IPV6=1'], True),
                                             ('0', False, ['no', 'setting', 'IPV6=0'], False)):
                self.fresh(answers=HOSTS)
                r = self.vpn(shell, 'run', conf=self.conf_text('sing-box', extra=f'IPV6={v}\n'))
                self.assertEqual(r.returncode, 0, r.stderr)
                ev = self.events()
                cfg = self.configs()
                self.assertEqual(len(cfg), 1, ev)
                self.assertEqual('"fdfe:dcba:9876::1/126"' in cfg[0], addr)
                self.assertIn('"auto_route":true', cfg[0])
                self.assertNotIn('probe ', ev)
                self.assertNotIn('table 2023', ev.replace('ip -6 route flush table 2023', ''))
                self.assertNotIn('IPv6: ', r.stdout)
                self.assertEqual(self.note(), note)
                # the guard as v2.0.1 had it: off for a tunnel the setting says carries IPv6, on otherwise
                self.assertEqual('nft delete table inet mu300_vpn_v6' in ev, guard_off)
                self.assertEqual('  | table inet mu300_vpn_v6 {' in ev, not guard_off)

    def test_gen_outside_a_run_writes_the_ipv4_config(self):
        for shell in self.each_shell():
            self.fresh(answers=HOSTS)
            r = self.vpn(shell, 'gen', conf=self.conf_text('sing-box'))
            self.assertEqual(r.returncode, 0, r.stderr)
            cfg = (self.run / 'config.json').read_text()
            self.assertIn('"address":["172.19.0.1/30"]', cfg)
            self.assertIn('"auto_route":true', cfg)
            self.assertNotIn('probe ', self.events())

    def test_an_engine_that_does_not_come_up_for_the_question_is_a_no(self):
        for shell in self.each_shell():
            self.fresh(answers=HOSTS)
            # a sing-box that exits at once, as one with a bad server would not, but a broken binary does
            p = self.disk / 'extra/vpn/bin/sing-box'
            p.write_text('#!/bin/sh\necho "engine sing-box $*" >> "$STUBLOG/events"\n'
                         '[ "$1" = run ] && cp "$3" "$STUBLOG/config.$(ls "$STUBLOG" | grep -c "^config")"\nexit 0\n')
            r = self.vpn(shell, 'run', conf=self.conf_text('sing-box'))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn('probe ', self.events())
            self.assertEqual(self.note(), ['no', 'probe', 'the engine did not come up for the question'])
            self.assertIn('"address":["172.19.0.1/30"]', self.configs()[-1])


class CoreRouted(Base):
    """The engines the core routes for (xray behind hev-socks5-tunnel, mihomo): asked once the tunnel is up and IPv4
    is routed into it."""

    TUNNEL = ('mkdir -p "$RUN"; drv_start() { echo "drv_start" >> "$STUBLOG/events"; }; drv_stop() { :; }; '
              'drv_alive() { return 1; }; ( run_tunnel ) && rc=0 || rc=$?; echo "rc=$rc"')

    def tunnel(self, shell, driver='xray', answers=(), tun_v6=True, extra='', pre=''):
        self.fresh(answers=answers, tun_v6=tun_v6)
        r = self.lib(shell, f'load_driver {driver}; {pre}{self.TUNNEL}', conf=self.conf_text('xray', extra=extra))
        # (the engine "exits" at once: the run ends with 1 after the teardown)
        self.assertIn('rc=1', r.stdout, r.stderr)
        ev = self.events()
        # what was in place while the tunnel ran: everything up to the teardown
        return r, ev[:ev.index('nft delete table ip mu300_vpn_dns')] if 'nft delete table ip mu300_vpn_dns' in ev else ev

    def test_a_yes_routes_ipv6_after_the_answer(self):
        for shell in self.each_shell():
            for drv, tun in (('xray', 'xtun'), ('mihomo', 'mh-mu300')):
                r, ev = self.tunnel(shell, drv, answers=HOSTS[1:])
                order = [ev.index('drv_start'),
                         # IPv4 first: clients do not wait for the question
                         ev.index('ip rule add pref 9010 lookup 2022'),
                         ev.index(f'ip -6 route replace default dev {tun} table 2023'),
                         ev.index('ip -6 rule add pref 9003 fwmark 0x2d0 lookup main'),
                         ev.index(f'ip -6 rule add pref 9004 iif lo to {HOSTS[1]} lookup 2023'),
                         ev.index(f'probe {HOSTS[1]}'),
                         ev.index('ip -6 rule del pref 9004'),
                         ev.index('ip -6 route flush table 2023'),
                         # and only now IPv6 for everyone
                         ev.index('ip -6 rule add pref 9000 fwmark 0x2d0 lookup main'),
                         ev.index('ip -6 rule add pref 9001 lookup main suppress_prefixlength 0'),
                         ev.index(f'ip -6 route replace default dev {tun} table 2022'),
                         ev.index('ip -6 rule add pref 9010 lookup 2022'),
                         ev.index('  | table inet mu300_vpn_v6 {')]
                self.assertEqual(order, sorted(order), ev)
                self.assertNotIn('nft delete table inet mu300_vpn_v6', ev)
                self.assertNotIn('addr flush', ev)
                self.assertIn(f'IPv6: through the tunnel - {HOSTS[1]} answered through the tunnel', r.stdout)

    def test_a_no_routes_nothing_and_takes_the_address_away(self):
        for shell in self.each_shell():
            for drv, tun in (('xray', 'xtun'), ('mihomo', 'mh-mu300')):
                r, ev = self.tunnel(shell, drv)
                self.assertIn('ip rule add pref 9010 lookup 2022', ev)
                for h in HOSTS:
                    self.assertIn(f'probe {h}', ev)
                self.assertNotIn('-6 rule add pref 9000', ev)
                self.assertNotIn('-6 rule add pref 9010', ev)
                self.assertNotIn(f'-6 route replace default dev {tun} table 2022', ev)
                self.assertLess(ev.index('ip -6 route flush table 2023'),
                                ev.index(f'ip -6 addr flush dev {tun} scope global'))
                self.assertIn('  | table inet mu300_vpn_v6 {', ev)
                self.assertNotIn('nft delete table inet mu300_vpn_v6', ev)
                self.assertIn('IPv6: not through the tunnel, rejected on the uplinks - nothing answered', r.stdout)
                self.assertFalse((self.tmp / 'tun-v6').exists())

    def test_an_engine_that_gave_its_tun_no_address_is_not_asked(self):
        for shell in self.each_shell():
            r, ev = self.tunnel(shell, 'xray', answers=HOSTS, tun_v6=False)
            self.assertNotIn('probe ', ev)
            self.assertNotIn('table 2023', ev.replace('ip -6 route flush table 2023', ''))
            self.assertNotIn('-6 rule add pref 9010', ev)
            self.assertIn('the engine gave xtun no IPv6 address to ask through', r.stdout)

    def test_the_setting_and_a_config_with_its_own_address_do_not_ask(self):
        for shell in self.each_shell():
            # IPV6=1: routed as soon as the tunnel is up, the guard off, as before
            r, ev = self.tunnel(shell, 'xray', answers=HOSTS, extra='IPV6=1\n')
            self.assertNotIn('probe ', ev)
            self.assertLess(ev.index('ip -6 rule add pref 9010 lookup 2022'), ev.index('nft delete table inet mu300_vpn_v6'))
            self.assertNotIn('IPv6: ', r.stdout)
            # IPV6=0: nothing, whatever address the tunnel has
            r, ev = self.tunnel(shell, 'xray', answers=HOSTS, extra='IPV6=0\n')
            self.assertNotIn('probe ', ev)
            self.assertNotIn('-6 rule add', ev)
            self.assertIn('  | table inet mu300_vpn_v6 {', ev)
            # WireGuard, OpenVPN, dae with auto: the tunnel's own address decides, nobody is asked
            for drv in ('wireguard', 'openvpn', 'dae'):
                for v6 in (True, False):
                    r, ev = self.tunnel(shell, drv, answers=HOSTS, tun_v6=v6)
                    self.assertNotIn('probe ', ev, drv)
                    self.assertNotIn('table 2023', ev.replace('ip -6 route flush table 2023', ''), drv)
                    self.assertEqual('ip -6 rule add pref 9010 lookup 2022' in ev, v6, drv)
                    self.assertEqual('nft delete table inet mu300_vpn_v6' in ev, v6, drv)
                    self.assertNotIn('IPv6: ', r.stdout)

    def test_what_a_killed_run_left_of_the_question_goes_with_the_routing(self):
        for shell in self.each_shell():
            self.fresh()
            (self.tmp / 'rules6').write_text('9000: from all fwmark 0x2d0 lookup main\n'
                                             '9003: from all fwmark 0x2d0 lookup main\n'
                                             f'9004: from all to {HOSTS[0]} iif lo lookup 2023\n'
                                             f'9004: from all to {HOSTS[1]} iif lo lookup 2023\n'
                                             '32766: from all lookup main\n')
            r = self.lib(shell, 'routes_down', conf=self.conf_text('xray'))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((self.tmp / 'rules6').read_text(), '32766: from all lookup main\n')
            self.assertIn('ip -6 route flush table 2023', self.events())


class Drivers(Base):
    def test_which_drivers_ask(self):
        for shell in self.each_shell():
            self.fresh()
            for drv, want in (('xray', '1'), ('sing-box', '1'), ('mihomo', '1'), ('dae', ''), ('wireguard', ''),
                              ('openvpn', '')):
                r = self.lib(shell, f'load_driver {drv}; v6_asks && a=asks || a=no; echo "[$DRV_V6ASK] $a"',
                             conf=self.conf_text('xray'))
                self.assertEqual(r.stdout.strip(), f'[{want}] {"asks" if want else "no"}', (drv, r.stderr))
                # only with auto
                for v in ('0', '1'):
                    r = self.lib(shell, f'load_driver {drv}; v6_asks && echo asks || echo no',
                                 conf=self.conf_text('xray', extra=f'IPV6={v}\n'))
                    self.assertEqual(r.stdout.strip(), 'no', (drv, v))

    def test_the_tun_gets_an_ipv6_address_for_the_question_and_after_a_yes(self):
        cases = [
            # (IPV6, what the run knows, an IPv6 address)
            ('0', '', False), ('0', 'V6_ASKING=1; ', False), ('1', '', True),
            ('auto', '', False),                      # outside a run (gen, check): the IPv4 config
            ('auto', 'V6_ASKING=1; ', True),          # written for the question
            ('auto', 'V6_ON=1; ', True),              # sing-box, after a yes
            ('auto', 'V6_ON=0; ', False),             # and after a no
        ]
        for shell in self.each_shell():
            self.fresh()
            for v, pre, want in cases:
                conf = self.conf_text('xray', extra=f'IPV6={v}\n')
                r = self.lib(shell, f'load_driver sing-box; {pre}singbox_addrs', conf=conf)
                self.assertEqual('"fdfe:dcba:9876::1/126"' in r.stdout, want, (v, pre, r.stderr))
                self.assertIn('"172.19.0.1/30"', r.stdout)
                r = self.lib(shell, f'load_driver xray; {pre}mkdir -p "$RUN"; xray_hev_yml; cat "$RUN/hev.yml"', conf=conf)
                self.assertEqual("  ipv6: 'fdfe:dcba:9875::1'\n" in r.stdout, want, (v, pre, r.stderr))
                self.assertIn('  ipv4: 198.18.0.1\n', r.stdout)
                self.assertIn('socks5:\n  port: 10808\n', r.stdout)
                r = self.lib(shell, f'load_driver mihomo; {pre}mihomo_ours system', conf=conf)
                self.assertEqual('  inet6-address: []\n' not in r.stdout, want, (v, pre, r.stderr))

    def test_the_guard_stays_for_a_run_that_asks(self):
        cases = [
            ('KILL_SWITCH=0; IPV6=auto; DRV_V6ASK=1; DRV_ROUTES=core; TUN=xtun; V6_ON=1', 'on'),
            ('KILL_SWITCH=0; IPV6=auto; DRV_V6ASK=1; DRV_ROUTES=core; TUN=xtun; V6_ON=0', 'on'),
            ('KILL_SWITCH=0; IPV6=auto; DRV_V6ASK=1; DRV_ROUTES=self; TUN=sbtun; V6_ON=1', 'on'),
            ('KILL_SWITCH=0; IPV6=1; DRV_V6ASK=1; DRV_ROUTES=self; TUN=sbtun', 'off'),
            ('KILL_SWITCH=1; IPV6=auto; DRV_V6ASK=1; DRV_ROUTES=core; TUN=xtun; V6_ON=1', 'none'),
        ]
        for shell in self.each_shell():
            for setup, want in cases:
                self.fresh(tun_v6=True)
                r = self.lib(shell, setup + '; ipv6_guard', conf=self.conf_text('xray'))
                self.assertEqual(r.returncode, 0, r.stderr)
                ev = self.events()
                got = 'on' if 'table inet mu300_vpn_v6 {' in ev else ('off' if 'nft delete table inet mu300_vpn_v6' in ev else 'none')
                self.assertEqual(got, want, setup)

    def test_carried_only_after_the_answer(self):
        for shell in self.each_shell():
            self.fresh(tun_v6=True)
            for pre, want in (('', 'no'), ('V6_ON=0; ', 'no'), ('V6_ON=1; ', 'yes')):
                # (the TUN has its address from the start: it must not count before the answer)
                r = self.lib(shell, f'load_driver xray; {pre}tunnel_carries_v6 && echo yes || echo no',
                             conf=self.conf_text('xray'))
                self.assertEqual(r.stdout.strip(), want, pre)


class Status(Base):
    def status(self, shell, note, **kw):
        self.fresh(**kw)
        self.run.mkdir()
        (self.run / 'iface').write_text('sbtun\n')
        (self.run / 'since').write_text('1791828033\n')
        (self.tmp / 'tun-up').write_text('')
        if note is not None:
            (self.run / 'ipv6').write_text(note)
        r = self.vpn(shell, 'status', '--json')
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)['ipv6']

    def test_what_the_run_wrote(self):
        for shell in self.each_shell():
            self.conf.write_text(self.conf_text('sing-box'))
            why = f'{HOSTS[0]} answered through the tunnel'
            self.assertEqual(self.status(shell, f'yes\tprobe\t{why}\n'),
                             {'setting': 'auto', 'tunnel': True, 'guard': False, 'source': 'probe', 'reason': why})
            v6 = self.status(shell, 'no\tprobe\tnothing answered over IPv6 through the tunnel, asked for 5s at most: a b\n')
            self.assertEqual((v6['tunnel'], v6['source']), (False, 'probe'))
            self.assertIn('nothing answered', v6['reason'])
            # the words of a human's status
            (self.run / 'ipv6').write_text(f'yes\tprobe\t{why}\n')
            r = self.vpn(shell, 'status')
            self.assertIn(f'IPv6: through the tunnel (probe: {why})', r.stdout, r.stderr)
            (self.run / 'ipv6').write_text('no\tsetting\tIPV6=0\n')
            self.assertIn('IPv6: not through the tunnel (setting: IPV6=0)', self.vpn(shell, 'status').stdout)

    def test_a_tunnel_that_is_down_says_nothing(self):
        for shell in self.each_shell():
            self.fresh()
            self.conf.write_text(self.conf_text('sing-box'))
            self.run.mkdir()
            (self.run / 'ipv6').write_text('yes\tprobe\tleft behind\n')
            v6 = json.loads(self.vpn(shell, 'status', '--json').stdout)['ipv6']
            self.assertEqual(v6, {'setting': 'auto', 'tunnel': False, 'guard': False, 'source': None, 'reason': None})
            self.assertNotIn('IPv6:', self.vpn(shell, 'status').stdout)

    def test_a_tunnel_an_older_module_brought_up(self):
        """No $RUN/ipv6: from the setting and the tunnel's addresses, as v2.0.1 reported it."""
        for shell in self.each_shell():
            for conf_v6, tun_v6, want in (
                    ('', False, (False, 'config')),      # sing-box with auto: IPv4
                    ('IPV6=1\n', False, (True, 'setting')),  # sing-box routes itself: the setting is the answer
                    ('IPV6=0\n', True, (False, 'setting'))):
                self.conf.write_text(self.conf_text('sing-box', extra=conf_v6))
                v6 = self.status(shell, None, tun_v6=tun_v6)
                self.assertEqual((v6['tunnel'], v6['source']), want, conf_v6)
                self.assertTrue(v6['reason'])
            # and a file that is not ours to read is not believed
            self.conf.write_text(self.conf_text('sing-box'))
            v6 = self.status(shell, 'yes\tsomething\telse\n')
            self.assertEqual((v6['tunnel'], v6['source']), (False, 'config'))


class _Silent(http.server.BaseHTTPRequestHandler):
    """accepts, reads the request and says nothing (a proxy's TUN whose server cannot deliver)"""

    def handle(self):
        try:
            self.connection.settimeout(8)
            self.connection.recv(1024)
            time.sleep(6)
        except OSError:
            pass


class _Answers(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(301)
        self.send_header('Location', 'https://example.invalid/')
        self.end_headers()

    def log_message(self, *a):
        pass


class _Server6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True


class Fetch(ShellTest):
    """The question itself, against servers on ::1: with curl, and as OpenWrt asks it (nc, MU300_NO_CURL)."""

    def setUp(self):
        super().setUp()
        self.conf = self.tmp / 'vpn.conf'
        self.conf.write_text('ENABLE=0\n')
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        super().tearDown()

    def serve(self, handler):
        try:
            s = _Server6(('::1', 0), handler)
        except OSError:
            self.skipTest('no ::1 here')
        self.servers.append(s)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        return s.server_address[1]

    def probe(self, shell, port, **env):
        e = dict(MU300_LIB=1, MU300_VPN_CONF=self.conf, MU300_VPN_RUN=self.tmp / 'run', MU300_VPN_LIB=LIB,
                 MU300_LAN_CONF=self.tmp / 'no', MU300_BIN=SYSBIN, MU300_OPT=self.tmp / 'opt',
                 MU300_DISK=self.tmp / 'disk', MU300_V6_PROBE='', MU300_V6_HOSTS='::1', MU300_V6_PORT=port,
                 MU300_V6_TIME=3)
        e.update(env)
        t = time.time()
        r = self.sh(shell, f'. "{BIN}/mu300-vpn"; v6_probe && rc=0 || rc=$?; echo "rc=$rc by=$V6_BY"', **e)
        return r.stdout.strip(), time.time() - t, r

    def tools(self):
        t = []
        if shutil.which('curl'):
            t.append({})
        if shutil.which('nc'):
            t.append({'MU300_NO_CURL': 1})
        if not t:
            self.skipTest('neither curl nor nc')
        return t

    def test_an_http_reply_is_a_yes(self):
        port = self.serve(_Answers)
        for shell in self.each_shell():
            for env in self.tools():
                out, took, r = self.probe(shell, port, **env)
                self.assertEqual(out, 'rc=0 by=::1', (env, r.stderr))
                self.assertLess(took, 3, env)
                self.assertFalse((self.tmp / 'run/.v6ask').exists())

    def test_nothing_listening_is_a_no_at_once(self):
        s = socket.socket(socket.AF_INET6)
        try:
            s.bind(('::1', 0))
        except OSError:
            self.skipTest('no ::1 here')
        port = s.getsockname()[1]
        s.close()
        for shell in self.each_shell():
            for env in self.tools():
                out, took, r = self.probe(shell, port, **env)
                self.assertEqual(out, 'rc=1 by=', (env, r.stderr))
                self.assertLess(took, 3, env)

    def test_a_far_end_that_says_nothing_is_a_no_in_time(self):
        """What a proxy's TUN does for a server without IPv6: the connect is answered on the device, and then
        nothing comes."""
        port = self.serve(_Silent)
        for shell in self.each_shell():
            for env in self.tools():
                out, took, r = self.probe(shell, port, **env)
                self.assertEqual(out, 'rc=1 by=', (env, r.stderr))
                self.assertLess(took, 6, env)
                self.assertFalse((self.tmp / 'run/.v6ask').exists())


if __name__ == '__main__':
    unittest.main()
