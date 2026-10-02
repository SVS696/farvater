"""No root, kernel, launchd, PF or routing mutations: deterministic mocked boundary tests."""
import ast
import base64
import copy
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

import mac_gateway as m


def sample():
    return {'lan_interface': 'en7', 'upstream_interface': 'en0',
            'lan_cidr': '192.168.77.0/24', 'lan_address': '192.168.77.1',
            'management_cidrs': ['192.168.1.0/24'],
            'upstream': {'type': 'shadowsocks', 'method': '2022-blake3-aes-128-gcm', 'server': '192.168.1.20', 'server_port': 8388, 'password': base64.b64encode(b'x' * 16).decode()},
            'dns_server': '1.1.1.1', 'system_dns_service': 'Wi-Fi', 'tun_interface': 'utun231', 'tun_address': '198.18.231.1/30'}


class FakeSystem:
    def __init__(self):
        self.calls = []
        self.boot_id = 'boot-one'
        self.rows = [{'destination': '0.0.0.0/0', 'gateway': '192.168.1.1', 'interface': 'en0', 'flags': 'UGSc'},
                     {'destination': '192.168.77.0/24', 'gateway': 'link#7', 'interface': 'en7', 'flags': 'UC'}]
        self.process = None
        self.states = ''
        self.main = 'anchor "com.apple/*" all\n'
        self.anchor = ''
        self.siblings = ''
        self.lan_ipv6 = False
        self.stop_count = 0
        self.fail_add = False

    def run(self, args, check=True):
        self.calls.append(args)
        if args[:2] == ['/sbin/ifconfig', '-l']:
            return 'lo0 en0 en7' + (' utun231' if self.process else '')
        if args[:2] == ['/sbin/ifconfig', 'en7']:
            return 'en7: flags=UP\ninet 192.168.77.1 netmask 0xffffff00\nstatus: active\n' + ('inet6 fe80::1\n' if self.lan_ipv6 else '')
        if args[:2] == ['/sbin/ifconfig', 'en0']:
            return 'en0: flags=UP\ninet 192.168.1.3 netmask 0xffffff00\nstatus: active\n'
        if args == ['/sbin/pfctl', '-sr']:
            return self.main
        if args == ['/sbin/pfctl', '-a', m.ANCHOR, '-sr']:
            return self.anchor
        if args == ['/sbin/pfctl', '-a', 'com.apple', '-s', 'Anchors']:
            return self.siblings
        if args == ['/sbin/pfctl', '-ss']:
            return self.states
        if args == ['/usr/sbin/sysctl', '-n', 'net.inet.ip.forwarding']:
            return '0'
        if args == ['/usr/sbin/networksetup', '-listnetworkserviceorder']:
            return '(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n'
        if args == ['/usr/sbin/networksetup', '-getdnsservers', 'Wi-Fi']:
            return '192.168.1.1\n'
        if args[:3] == ['/sbin/route', '-n', 'add']:
            if self.fail_add:
                raise m.GatewayError('test add failure')
            self.rows.append({'destination': args[4], 'interface': args[6], 'gateway': 'link#231', 'flags': 'US'})
        if args[:3] == ['/sbin/route', '-n', 'delete']:
            self.rows = [r for r in self.rows if r['destination'] != args[4]]
        return ''

    def routes(self):
        return copy.deepcopy(self.rows)

    def boot(self):
        return self.boot_id

    def core_pid(self):
        return self.process['pid'] if self.process else None

    def identity(self, pid):
        return copy.deepcopy(self.process) if self.process and pid == self.process['pid'] else None

    def start(self):
        self.process = {'pid': 987, 'birth': '0 Fri Oct 2 18:00:00 2026', 'executable': str(m.ROOT / 'sing-box')}
        return copy.deepcopy(self.process)

    def stop(self):
        self.stop_count += 1
        self.process = None

    def enable_pf(self):
        self.calls.append(['/sbin/pfctl', '-E'])
        (m.ROOT / 'pf-enable.log').write_text('Token : 12345\n')
        return 'Token : 12345\n'


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(m, 'ROOT', self.root), patch.object(m, 'verify_runtime'),
                        patch.object(m, 'register_watchdog'), patch.object(m, 'protected', side_effect=lambda p, directory=False: Path(p))]
        for p in self.patches:
            p.start()
        (self.root / 'sing-box').write_bytes(b'verified mock core')
        self.system = FakeSystem()
        self.value = sample()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def activate(self):
        return m.apply(self.value, 120, self.system)

    def networking(self):
        return [args for args in self.system.calls if
                args[0] == '/sbin/route' or '-w' in args or
                args[0] == '/sbin/pfctl' and ('-E' in args or '-X' in args or '-f' in args and '-n' not in args)]

    def test_configuration_fixed_schema_no_paths_and_python39(self):
        ast.parse(Path(m.__file__).read_text(), feature_version=(3, 9))
        config = m.config(self.value)
        self.assertFalse(config['inbounds'][0]['auto_route'])
        self.assertEqual(config['outbounds'][0]['bind_interface'], 'en0')
        self.assertEqual(config['dns']['servers'][0]['detour'], 'upstream')
        self.assertEqual({i['listen'] for i in config['inbounds'][1:]}, {'127.0.0.1', '192.168.77.1'})
        self.value['upstream']['tls'] = {'certificate_path': '/etc/private'}
        with self.assertRaises(m.GatewayError):
            m.config(self.value)

    def test_same_interface_refused_before_mutation(self):
        self.value['lan_interface'] = 'en0'
        with self.assertRaises(m.GatewayError):
            self.activate()
        self.assertEqual(self.networking(), [])

    def test_nonprivate_lan_refused(self):
        self.value.update(lan_cidr='8.8.8.0/24', lan_address='8.8.8.1')
        with self.assertRaises(m.GatewayError):
            self.activate()
        self.assertEqual(self.networking(), [])

    def test_route_collision_refused_before_mutation(self):
        self.system.rows.append({'destination': str(m.route_ranges(self.value)[0]), 'gateway': '1.2.3.4', 'interface': 'en0', 'flags': 'UGS'})
        with self.assertRaises(m.GatewayError):
            self.activate()
        self.assertEqual(self.networking(), [])

    def test_more_specific_route_and_host_refused_before_mutation(self):
        for destination in ('8.8.8.0/24', '8.8.8.8/32'):
            with self.subTest(destination=destination):
                self.system = FakeSystem()
                (self.root / 'receipt.json').unlink(missing_ok=True)
                self.system.rows.append({'destination': destination, 'gateway': '192.168.1.1',
                                         'interface': 'en0', 'flags': 'UGS'})
                with self.assertRaises(m.GatewayError):
                    self.activate()
                self.assertEqual(self.networking(), [])
                self.assertTrue(any(r['destination'] == destination for r in self.system.rows))
                self.system.rows.pop()

    def test_more_specific_route_created_during_core_start_refused(self):
        original_start = self.system.start

        def start_with_foreign_route():
            identity = original_start()
            self.system.rows.append({'destination': '8.8.8.0/24', 'gateway': '192.168.1.1',
                                     'interface': 'en0', 'flags': 'UGS'})
            return identity

        with patch.object(self.system, 'start', side_effect=start_with_foreign_route):
            with self.assertRaises(m.GatewayError):
                self.activate()
        self.assertEqual(m.receipt()['phase'], 'rolled-back')
        self.assertTrue(any(r['destination'] == '8.8.8.0/24' for r in self.system.rows))
        self.assertFalse(any(args[0] == '/sbin/route' for args in self.system.calls))
        self.assertNotIn(['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1'], self.system.calls)

    def test_explicit_management_host_and_broader_mixed_routes_preserved(self):
        # /16 includes excluded management+LAN and covered destinations. The added
        # TUN prefixes win on covered addresses; a host wholly excluded stays direct.
        foreign = [{'destination': '192.168.1.10/32', 'gateway': '192.168.1.1', 'interface': 'en0', 'flags': 'UGS'},
                   {'destination': '192.168.0.0/16', 'gateway': '192.168.1.1', 'interface': 'en0', 'flags': 'UGS'}]
        self.system.rows.extend(foreign)
        self.activate()
        m.rollback(m.receipt(), self.system)
        for row in foreign:
            self.assertIn(row, self.system.rows)

    def test_tun_subnet_overlap_refused_before_mutation(self):
        self.system.rows.append({'destination': '198.18.0.0/16', 'gateway': 'link#1', 'interface': 'en0', 'flags': 'US'})
        with self.assertRaises(m.GatewayError):
            self.activate()
        self.assertEqual(self.networking(), [])

    def test_missing_anchor_refused_before_mutation(self):
        self.system.main = 'pass quick all\nanchor "com.apple/*" all\n'
        with self.assertRaises(m.GatewayError):
            self.activate()
        self.assertEqual(self.networking(), [])

    def test_existing_states_refused_before_mutation(self):
        self.system.states = 'existing connection'
        with self.assertRaises(m.GatewayError):
            self.activate()
        self.assertEqual(self.networking(), [])

    def test_ipv6_lan_refused_before_mutation(self):
        self.system.lan_ipv6 = True
        with self.assertRaises(m.GatewayError):
            self.activate()
        self.assertEqual(self.networking(), [])

    def test_watchdog_registration_failure_precedes_mutation(self):
        with patch.object(m, 'register_watchdog', side_effect=m.GatewayError('launchd unavailable')):
            with self.assertRaises(m.GatewayError):
                self.activate()
        self.assertEqual(self.networking(), [])
        self.assertFalse((self.root / 'receipt.json').exists())

    def test_apply_persists_snapshot_and_installs_filter_before_forwarding(self):
        before = self.system.routes()
        self.assertEqual(self.activate()['phase'], 'pending')
        record = m.receipt()
        self.assertEqual(record['original']['routes'], before)
        self.assertEqual(record['original']['system_dns'], ['192.168.1.1'])
        self.assertIn(['/usr/sbin/networksetup', '-setdnsservers', 'Wi-Fi', '127.0.0.1'], self.system.calls)
        self.assertTrue(record['forwarding_intent'])
        operations = self.networking()
        self.assertEqual(operations[0][1:3], ['-a', m.ANCHOR])
        self.assertEqual(operations[-1], ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1'])

    def test_manual_ranges_exclude_management_upstream_and_lan(self):
        ranges = m.route_ranges(self.value)
        self.assertFalse(any(m.network('192.168.77.0/24').overlaps(n) for n in ranges))
        self.assertFalse(any(m.network('192.168.1.0/24').overlaps(n) for n in ranges))
        self.assertTrue(any(m.ipaddress.IPv4Address('8.8.8.8') in n for n in ranges))
        self.assertNotIn(m.network('0.0.0.0/0'), ranges)

    def test_system_and_lan_failclosed_pf(self):
        rules = m.pf_rules(self.value).decode()
        self.assertIn('block drop out quick inet6 all', rules)
        self.assertIn('proto { tcp udp } to 192.168.1.20 port 8388', rules)
        self.assertIn('block drop out quick on en0 inet from 192.168.77.0/24 to any', rules)
        self.assertTrue(rules.endswith('block drop out quick all\n'))
        self.assertNotIn('nat ', rules)

    def test_rollback_only_owned_anchor_routes_and_enable_token(self):
        self.activate()
        self.system.calls.clear()
        m.rollback(m.receipt(), self.system)
        self.assertEqual(self.system.stop_count, 1)
        self.assertEqual(m.receipt()['phase'], 'rolled-back')
        self.assertEqual(self.system.calls[0], ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=0'])
        self.assertIn(['/sbin/pfctl', '-X', '12345'], self.system.calls)
        self.assertIn(['/usr/sbin/networksetup', '-setdnsservers', 'Wi-Fi', '192.168.1.1'], self.system.calls)
        for args in self.system.calls:
            self.assertNotIn('-F', args)
            self.assertNotIn('-d', args)
            if args[0] == '/sbin/pfctl' and '-f' in args:
                self.assertEqual(args[1:3], ['-a', m.ANCHOR])
        self.assertEqual(len(self.system.rows), 2)

    def test_repeated_manual_rollback_preserves_later_administrator_state(self):
        self.activate()
        m.rollback(m.receipt(), self.system)
        before = (self.root / 'receipt.json').read_bytes()
        foreign = {'destination': '8.8.8.8/32', 'gateway': '192.168.1.1', 'interface': 'en0', 'flags': 'UGS'}
        self.system.rows.append(foreign)
        self.system.main = 'new administrator rules'
        self.system.calls.clear()
        m.rollback(m.receipt(), self.system)
        self.assertEqual(self.system.calls, [])
        self.assertEqual((self.root / 'receipt.json').read_bytes(), before)
        self.assertIn(foreign, self.system.rows)
        self.assertEqual(self.system.main, 'new administrator rules')
        self.assertEqual(self.system.stop_count, 1)

    def test_dns_operation_expiry_never_enables_forwarding(self):
        clock = [1000]
        original_run = self.system.run

        def slow_dns(args, check=True):
            if args == ['/usr/sbin/networksetup', '-setdnsservers', 'Wi-Fi', '127.0.0.1']:
                clock[0] += 121
            return original_run(args, check)

        with patch.object(m.time, 'time', side_effect=lambda: clock[0]), patch.object(self.system, 'run', side_effect=slow_dns):
            with self.assertRaises(m.GatewayError):
                self.activate()
        self.assertNotIn(['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1'], self.system.calls)
        self.assertEqual(m.receipt()['phase'], 'rolled-back')
        self.assertIn(['/usr/sbin/networksetup', '-setdnsservers', 'Wi-Fi', '192.168.1.1'], self.system.calls)
        self.assertEqual(self.system.stop_count, 1)

    def test_forwarding_operation_expiry_rolls_back_before_return(self):
        clock = [1000]
        original_run = self.system.run

        def slow_forwarding(args, check=True):
            if args == ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1']:
                clock[0] += 121
            return original_run(args, check)

        with patch.object(m.time, 'time', side_effect=lambda: clock[0]), patch.object(self.system, 'run', side_effect=slow_forwarding):
            with self.assertRaises(m.GatewayError):
                self.activate()
        self.assertEqual(m.receipt()['phase'], 'rolled-back')
        self.assertIn(['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=0'], self.system.calls)
        self.assertEqual(self.system.stop_count, 1)

    def test_foreign_pid_never_stopped_and_filter_retained(self):
        self.activate()
        self.system.process['birth'] = '0 changed PID birth'
        with self.assertRaises(m.GatewayError):
            m.rollback(m.receipt(), self.system)
        self.assertEqual(self.system.stop_count, 0)
        self.assertEqual(m.receipt()['phase'], 'rolling-back')
        self.assertNotIn(['/sbin/pfctl', '-X', '12345'], self.system.calls)

    def test_corrupt_receipt_no_commands(self):
        self.activate()
        record = m.receipt()
        record['routes_added'].append('8.8.8.8/32')
        m.write_receipt(record)
        self.system.calls.clear()
        with self.assertRaises(m.GatewayError):
            m.watchdog(self.system)
        self.assertEqual(self.system.calls, [])

    def test_route_add_failure_rolls_back(self):
        self.system.fail_add = True
        with self.assertRaises(m.GatewayError):
            self.activate()
        self.assertEqual(m.receipt()['phase'], 'rolled-back')
        self.assertEqual(self.system.stop_count, 1)

    def test_deadline_independent_watchdog(self):
        self.activate()
        record = m.receipt()
        record['deadline'] = 1
        m.write_receipt(record)
        m.watchdog(self.system)
        self.assertEqual(m.receipt()['phase'], 'rolled-back')

    def test_confirmed_core_death_rolls_back(self):
        self.activate()
        record = m.receipt()
        record['phase'] = 'confirmed'
        m.write_receipt(record)
        self.system.process = None
        m.watchdog(self.system)
        self.assertEqual(m.receipt()['phase'], 'rolled-back')

    def test_reboot_pending_does_not_reactivate(self):
        self.activate()
        self.system.boot_id = 'boot-two'
        self.system.process = None
        self.system.rows = self.system.rows[:2]
        self.system.calls.clear()
        m.watchdog(self.system)
        self.assertEqual(m.receipt()['phase'], 'rolled-back')
        self.assertEqual(self.system.stop_count, 0)
        self.assertNotIn(['/sbin/pfctl', '-X', '12345'], self.system.calls)
        self.assertFalse(any('bootstrap' in args for args in self.system.calls))

    def test_start_crash_before_pid_receipt_unloads_exact_owned_job(self):
        self.activate()
        record = m.receipt()
        record['process'] = None
        record['phase'] = 'prepared'
        m.write_receipt(record)
        m.watchdog(self.system)
        self.assertEqual(self.system.stop_count, 1)
        self.assertEqual(m.receipt()['phase'], 'rolled-back')

    def test_pf_reference_journal_recovers_unpersisted_token(self):
        self.activate()
        record = m.receipt()
        record['pf_token'] = None
        m.rollback(record, self.system)
        self.assertIn(['/sbin/pfctl', '-X', '12345'], self.system.calls)


class OwnershipTests(unittest.TestCase):
    def test_user_writable_or_user_owned_source_rejected(self):
        import types
        for uid, mode in [(501, stat_mode()) , (0, stat_mode() | 0o020)]:
            info = types.SimpleNamespace(st_uid=uid, st_mode=mode)
            with patch.object(Path, 'lstat', return_value=info):
                with self.assertRaises(m.GatewayError):
                    m.protected(Path('/protected/helper.py'))

    def test_symlink_rejected(self):
        import types
        import stat
        with patch.object(Path, 'lstat', return_value=types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o700)):
            with self.assertRaises(m.GatewayError):
                m.protected(Path('/protected/helper.py'))


def stat_mode():
    import stat
    return stat.S_IFREG | 0o700


if __name__ == '__main__':
    unittest.main()
