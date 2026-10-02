"""Read-only and accessible contextual help in existing Flask forms."""

import json
import unittest
from html.parser import HTMLParser

import test_web as base


class HelpMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.described = []
        self.help_details = 0

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if attrs.get('id'):
            self.ids.add(attrs['id'])
        if attrs.get('aria-describedby'):
            self.described.extend(attrs['aria-describedby'].split())
        if tag == 'details' and 'context-help' in attrs.get('class', '').split():
            self.help_details += 1
            assert 'open' not in attrs


class ContextualHelpTests(unittest.TestCase):
    setUp = base.WebTests.setUp
    tearDown = base.WebTests.tearDown
    login = base.WebTests.login

    def test_main_sections_have_distinct_read_only_help(self):
        self.login()
        before = (self.path / 'policy.json').read_bytes()
        pages = {
            '/overview': 'Действующий выход',
            '/health': 'старый результат',
            '/rules': 'сверху вниз',
            '/tunnels': 'назначение выхода',
            '/dns': 'начальный DNS',
            '/filtering': 'режим',
            '/devices': 'профили устройств WireGuard',
            '/changes': 'весь сохранённый черновик',
            '/backups': 'не восстанавливает систему',
            '/help': 'последовательность настройки',
        }
        for url, phrase in pages.items():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertIn('<details class="context-help">', response.text)
                self.assertIn('<summary>О странице</summary>', response.text)
                self.assertIn(phrase, response.text)
                markup = HelpMarkup()
                markup.feed(response.text)
                self.assertEqual(markup.help_details, 1)
                self.assertTrue(all(value in markup.ids for value in markup.described))
        self.assertEqual((self.path / 'policy.json').read_bytes(), before)

    def test_editor_fields_keep_values_and_descriptions(self):
        self.policy['exits']['proxy'] = {'name': 'Proxy', 'scope': 'public', 'native': {
            'type': 'socks', 'server': '127.0.0.1', 'server_port': 1080,
            'password': 'hidden-proxy-secret'}}
        (self.path / 'policy.json').write_text(json.dumps(self.policy))
        self.login()
        before = (self.path / 'policy.json').read_bytes()
        editors = {
            '/rules/new': {'help-rule-source', 'help-rule-domains', 'help-rule-ports', 'help-rule-exit', 'help-rule-dns', 'help-rule-reserve'},
            '/rules/default': {'help-rule-exit', 'help-rule-dns', 'help-rule-reserve'},
            '/dns/new': {'help-dns-detour', 'help-dns-bootstrap'},
            '/tunnels/proxy/edit': {'help-tunnel-password', 'help-tunnel-uuid', 'help-tunnel-ca', 'help-tunnel-short-id', 'help-tunnel-headers'},
            '/lan': {'help-lan-clients', 'help-lan-targets', 'help-vpn-clients', 'help-vpn-bypass', 'help-vpn-clients-v6', 'help-vpn-bypass-v6'},
            '/devices/incoming/new?protocol=socks': set(),
        }
        for url, expected in editors.items():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                markup = HelpMarkup()
                markup.feed(response.text)
                self.assertEqual(markup.help_details, 1)
                self.assertTrue(expected <= markup.ids)
                self.assertTrue(all(value in markup.ids for value in markup.described))
        tunnel = self.client.get('/tunnels/proxy/edit').text
        self.assertIn('value="Proxy"', tunnel)
        self.assertNotIn('hidden-proxy-secret', tunnel)
        self.assertEqual((self.path / 'policy.json').read_bytes(), before)

    def test_guest_sees_no_context_help(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('context-help', response.text)
        self.assertEqual(self.client.get('/changes').status_code, 302)

    def test_client_and_service_help_does_not_conflate_operations(self):
        self.policy['exits']['work'] = {'name': 'Work VPN', 'scope': 'work',
                                        'protocol': 'OpenConnect',
                                        'native': {'type': 'direct', 'tag': 'work', 'bind_interface': 'vpn0'}}
        (self.path / 'policy.json').write_text(json.dumps(self.policy))
        self.login()
        for url, phrase in {
            '/devices/trusttunnel': 'входящему TrustTunnel',
            '/wireguard': 'отдельной службой',
            '/amnezia': 'отдельной службой',
            '/tunnels/work/edit': 'автозапуск меняется отдельно',
        }.items():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertIn(phrase, response.text)


if __name__ == '__main__':
    unittest.main()
