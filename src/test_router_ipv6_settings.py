import unittest
from router_ipv6_settings import validate, compile_settings


class RouterIPv6SettingsTests(unittest.TestCase):
    def setUp(self):
        self.value = dict(policy='Trial', server_connection='Wireguard1', provider_connection='ISP',
                          prefixes=['2000::/3', 'fc00::/7', '200::/7'], health_address='10.9.0.1',
                          health_port=18082, probe_seconds=2, interval_seconds=3, failures=3, recovery_seconds=60)

    def test_settings_reject_command_injection_and_local_prefix_capture(self):
        for key, value in [('policy', 'Trial;reboot'), ('server_connection', 'Wireguard1\nreboot'),
                           ('health_address', '10.9.0.1;reboot'), ('health_address', '::1'),
                           ('health_address', 'fe80::1%wg0'), ('prefixes', ['::/0']),
                           ('prefixes', ['ff00::/8']), ('prefixes', ['fe80::/10']),
                           ('prefixes', ['2000::/3', '2001:db8::/32']), ('prefixes', [True]),
                           ('interval_seconds', 16), ('probe_seconds', 5), ('health_port', True)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate(self.value | {key: value})

    def test_every_behavior_setting_changes_revision(self):
        initial = compile_settings(self.value)
        changes = dict(policy='Other', server_connection='Wireguard2', provider_connection='Backup',
                       prefixes=['2000::/3'], health_address='fd42::1', health_port=18083,
                       probe_seconds=3, interval_seconds=4, failures=4, recovery_seconds=120)
        revision = lambda content: content.decode().split('REVISION=')[1].strip()
        for key, value in changes.items():
            with self.subTest(key=key):
                self.assertNotEqual(revision(initial), revision(compile_settings(self.value | {key: value})))

    def test_no_kernel_interface_or_table_parameters(self):
        for key in ('table', 'device', 'command'):
            with self.assertRaises(ValueError):
                validate(self.value | {key: 'nwg1'})


if __name__ == '__main__':
    unittest.main()
