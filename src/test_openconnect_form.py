import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from candidate_bundle import build_bundle, validate_bundle
from candidate_config import build_candidate_config
from native_endpoints import openconnect_host
from safe_apply import Backend
from test_candidate_config import CandidateConfigTests
from test_candidate_web import CandidateWebTests
from tunnel_form import parse_outbound


def fields():
    return {'type': 'openconnect', 'name': 'Work VPN', 'scope': 'work',
            'oc_server': 'https://vpn.example.com:443/group', 'oc_flavor': 'anyconnect',
            'oc_domain_resolver': 'isp', 'oc_username': 'owner', 'oc_password': 'test-secret',
            'oc_no_udp': 'on', 'oc_reconnect_timeout': '86400s'}


class OpenConnectTests(unittest.TestCase):
    def policy(self):
        return CandidateConfigTests().base()

    def configured(self):
        policy = self.policy()
        policy['exits']['work'] = parse_outbound(fields(), {}, 'work', policy)
        return policy

    def test_form_preserves_secret_and_unexposed_options_without_mutation(self):
        policy = self.configured()
        previous = policy['exits']['work']
        previous['native']['token'] = {'mode': 'totp', 'secret': 'existing-token'}
        before = copy.deepcopy(previous)
        result = parse_outbound({**fields(), 'oc_password': ''}, previous, 'work', policy)
        self.assertEqual(result['native']['password'], 'test-secret')
        self.assertEqual(result['native']['token'], previous['native']['token'])
        self.assertEqual(previous, before)
        self.assertFalse(result['native']['system'])

    def test_replace_clear_and_switch_do_not_reuse_wrong_protocol_credentials(self):
        previous = self.configured()['exits']['work']
        cleared = parse_outbound({**fields(), 'clear_oc_password': 'on'}, previous, 'work', self.policy())
        self.assertNotIn('password', cleared['native'])
        changed = parse_outbound({**fields(), 'oc_password': ''}, {'native': {'type': 'socks', 'password': 'old'}}, 'work', self.policy())
        self.assertNotIn('password', changed['native'])

    def test_server_url_matches_pinned_client_constraints(self):
        self.assertEqual(openconnect_host('https://[2001:db8::1]:443/group'), '2001:db8::1')
        self.assertEqual(openconnect_host('vpn.example.com/group'), 'vpn.example.com')
        for value in ('http://vpn.test', 'https://u:p@vpn.test', 'https://vpn.test/?group',
                      'https://vpn.test/#group', 'https://vpn.test?', 'https://vpn.test:0',
                      'https://vpn.test:65536', 'https://vpn.test/\n', 'https://vpn.test\\path'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                openconnect_host(value)

    def test_invalid_form_fields_are_rejected(self):
        for change in ({'oc_flavor': 'unknown'}, {'oc_mtu': '20'}, {'oc_mtu': '９００'},
                       {'oc_reconnect_timeout': '999999s'}, {'oc_dpd_interval': '-1s'},
                       {'oc_password': 'a\nb'}, {'oc_ca': 'not a certificate'},
                       {'oc_domain_resolver': 'missing'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                parse_outbound({**fields(), **change}, {}, 'work', self.policy())

    def test_compiler_places_endpoint_and_preserves_dns_and_route_references(self):
        policy = self.configured()
        policy['dns']['private']['native']['detour'] = 'work'
        files = build_bundle(policy, api_secret='x' * 32)
        validate_bundle(files)
        config = json.loads(files['config.json'])
        self.assertEqual([e['tag'] for e in config['endpoints']], ['work'])
        self.assertNotIn('work', [e['tag'] for e in config['outbounds']])
        self.assertEqual(next(e for e in config['dns']['servers'] if e['tag'] == 'private')['detour'], 'work')
        self.assertNotIn('endpoints', build_candidate_config(self.policy(), api_secret='x' * 32, default_filtering=False)['config'])

    def test_compiler_blocks_host_interfaces_commands_and_bootstrap_cycles(self):
        for change in ({'system': True}, {'name': 'rtl0'}, {'csd': {'wrapper_path': '/tmp/run'}}, {'tncc': 'invalid'}):
            policy = self.configured()
            policy['exits']['work']['native'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                build_bundle(policy, api_secret='x' * 32)
        for via_selector in (False, True):
            policy = self.configured()
            policy['dns']['isp']['native']['detour'] = 'queue' if via_selector else 'work'
            if via_selector:
                policy['exits']['queue'] = {'scope': 'work', 'native': {'type': 'selector', 'outbounds': ['work']}}
            with self.subTest(via_selector=via_selector), self.assertRaisesRegex(ValueError, 'этого же VPN'):
                build_bundle(policy, api_secret='x' * 32)

    def test_native_apply_requires_the_reproduced_endpoint(self):
        files = build_bundle(self.configured(), api_secret='x' * 32)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = json.loads(files['config.json'])
            config['experimental']['cache_file']['path'] = str(root/'cache.db')
            path = root/'candidate.json'
            path.write_text(json.dumps(config))
            backend = Backend(root)
            with patch('safe_apply.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError, 'validated complete bundle'):
                    backend.validate(path)
                run.assert_not_called()
                backend.validate_bundle(files)
                run.return_value.returncode = 0
                backend.validate(path)
                run.assert_called_once()
                config['endpoints'][0]['server'] = 'https://changed.test'
                path.write_text(json.dumps(config))
                with self.assertRaisesRegex(ValueError, 'validated complete bundle'):
                    backend.validate(path)


class OpenConnectWebTests(unittest.TestCase):
    def setUp(self):
        self.fixture = CandidateWebTests()
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def test_draft_form_does_not_call_remote_or_echo_password_or_cookie(self):
        fixture = self.fixture
        response = fixture.client.post('/tunnels/save', data={**fixture.fields(), **fields(), 'id': 'work', 'oc_cookie': 'private-cookie'})
        self.assertEqual(response.status_code, 302)
        html = fixture.client.get('/tunnels/work/edit').text
        self.assertIn('oc_server', html)
        self.assertIn('oc_domain_resolver', html)
        self.assertNotIn('test-secret', html)
        self.assertNotIn('private-cookie', html)
        fixture.remote.call.assert_not_called()

    def test_stale_or_invalid_draft_does_not_change_original(self):
        fixture = self.fixture
        original = (fixture.root/'policy.json').read_bytes()
        for change, code in (({'oc_server': 'https://vpn.test/?unsupported'}, 400), ({'revision': 'old'}, 409), ({'csrf': 'bad'}, 403)):
            response = fixture.client.post('/tunnels/save', data={**fixture.fields(), **fields(), 'id': 'work', **change})
            self.assertEqual(response.status_code, code)
            self.assertEqual((fixture.root/'policy.json').read_bytes(), original)
        fixture.remote.call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
