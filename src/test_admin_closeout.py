"""Regression checks for admin input boundaries and native confirmation."""

import json
import time
import unittest
from unittest.mock import patch

import test_web
from web import create_app, token_equal
from health_settings import new_check, read_settings
from monitor_control import control
import test_monitor_settings as monitor_tests


class AdminInputTests(unittest.TestCase):
    setUp = test_web.WebTests.setUp
    tearDown = test_web.WebTests.tearDown
    login = test_web.WebTests.login
    revision = test_web.WebTests.revision

    def test_unicode_form_boundaries_refuse_without_write(self):
        before = (self.path / 'policy.json').read_bytes()
        self.client.get('/login')
        with self.client.session_transaction() as session:
            csrf = session['csrf']
        self.assertEqual(self.client.post('/login', data={
            'csrf': 'не-ASCII', 'username': 'owner', 'password': 'test-password'}).status_code, 403)
        self.assertEqual(self.client.post('/login', data={
            'csrf': csrf, 'username': 'владелец', 'password': 'test-password'}).status_code, 200)
        csrf = self.login()
        self.assertEqual(self.client.post('/rules/save', data={
            'csrf': csrf, 'revision': 'не-ASCII', 'name': 'Rule', 'kind': 'public',
            'domains': 'example.com', 'exit': 'direct', 'dns': 'isp'}).status_code, 409)
        (self.path / 'policy-import.json').write_text(json.dumps({
            'token': 'ascii-preview', 'draft_revision': self.revision(),
            'created_at': time.time(), 'policy': self.policy}))
        self.assertEqual(self.client.post('/configuration/confirm', data={
            'csrf': csrf, 'revision': self.revision(), 'confirm': 'on',
            'token': 'не-ASCII'}).status_code, 409)
        self.assertEqual((self.path / 'policy.json').read_bytes(), before)

    def test_unicode_revision_rejected_by_export_and_candidate_apply(self):
        self.assertFalse(token_equal('не-ASCII', 'ascii'))
        self.assertTrue(token_equal('ascii', 'ascii'))
        csrf = self.login()
        before = (self.path / 'policy.json').read_bytes()
        for url, data in [
            ('/openvpn/export', {'id': 'direct'}),
            ('/tunnels/direct/export-ss', {}),
            ('/tunnels/direct/export-vless', {}),
        ]:
            with self.subTest(url=url):
                self.assertEqual(self.client.post(url, data={
                    'csrf': csrf, 'revision': 'не-ASCII', **data}).status_code, 409)
        self.assertEqual((self.path / 'policy.json').read_bytes(), before)
        from unittest.mock import Mock
        remote = Mock()
        self.app = create_app(self.path, candidate=remote)
        self.app.testing = True
        self.client = self.app.test_client()
        csrf = self.login()
        self.assertEqual(self.client.post('/candidate/apply', data={
            'csrf': csrf, 'revision': 'не-ASCII', 'candidate_revision': 'a' * 64}).status_code, 409)
        remote.call.assert_not_called()

    def test_failures_are_limited_by_trusted_source_not_foreign_header(self):
        self.client.get('/login')
        with self.client.session_transaction() as session:
            csrf = session['csrf']
        a = {'REMOTE_ADDR': '192.0.2.10'}
        b = {'REMOTE_ADDR': '192.0.2.11'}
        wrong = {'csrf': csrf, 'username': 'owner', 'password': 'wrong'}
        for _ in range(5):
            self.assertEqual(self.client.post('/login', data=wrong, environ_overrides=a).status_code, 200)
        self.assertEqual(self.client.post('/login', data=wrong, environ_overrides=a).status_code, 429)
        self.assertEqual(self.client.post('/login', data=wrong, environ_overrides=a,
            headers={'X-Forwarded-For': '192.0.2.99'}).status_code, 429)
        self.assertEqual(self.client.post('/login', data={
            'csrf': csrf, 'username': 'owner', 'password': 'test-password'},
            environ_overrides=b).status_code, 302)
        with self.client.session_transaction() as session:
            renewed_csrf = session['csrf']
        self.assertEqual(self.client.post('/login', data={**wrong, 'csrf': renewed_csrf},
                                          environ_overrides=a).status_code, 429)

    def test_unknown_source_is_bounded_and_global_pressure_does_not_lock_fresh_owner(self):
        self.client.get('/login')
        with self.client.session_transaction() as session:
            csrf = session['csrf']
        wrong = {'csrf': csrf, 'username': 'owner', 'password': 'wrong'}
        unknown = {'REMOTE_ADDR': ''}
        with patch('web.check_password_hash', side_effect=lambda _hash, value: value == 'test-password'):
            for _ in range(5):
                self.assertEqual(self.client.post('/login', data=wrong,
                    environ_overrides=unknown).status_code, 200)
            self.assertEqual(self.client.post('/login', data=wrong,
                environ_overrides=unknown, headers={'X-Forwarded-For': '192.0.2.99'}).status_code, 429)
            for index in range(1, 61):
                self.assertEqual(self.client.post('/login', data=wrong,
                    environ_overrides={'REMOTE_ADDR': f'198.51.100.{index}'}).status_code, 200)
            self.assertEqual(self.client.post('/login', data={
                'csrf': csrf, 'username': 'owner', 'password': 'test-password'},
                environ_overrides={'REMOTE_ADDR': '203.0.113.5'}).status_code, 302)


class NativeDeleteTests(unittest.TestCase):
    setUp = monitor_tests.MonitorWebTests.setUp
    tearDown = monitor_tests.MonitorWebTests.tearDown
    login = monitor_tests.MonitorWebTests.login

    def test_list_requires_editor_confirmation_without_javascript(self):
        csrf = self.login()
        fields = monitor_tests.values(new_check('dns', ''))
        fields.update(name='Custom check', domain='example.com')
        result = control({'version': 1, 'action': 'monitor-add', 'kind': 'dns',
                          'revision': read_settings(self.monitor)[1], 'values': fields}, self.monitor)
        identifier = result['selected']['id']
        html = self.client.get('/health/settings').text
        self.assertNotIn('name="confirm" value="on"', html)
        self.assertIn('Изменить или удалить', html)
        revision = read_settings(self.monitor)[1]
        url = '/health/settings/server:' + identifier + '/remove'
        self.assertEqual(self.client.post(url, data={'csrf': csrf, 'revision': revision}).status_code, 400)
        self.assertIn(identifier, {check['id'] for check in read_settings(self.monitor)[0]['checks']})
        editor = self.client.get('/health/settings/server:' + identifier).text
        self.assertIn('name="confirm" required', editor)
        self.assertEqual(self.client.post(url, data={
            'csrf': csrf, 'revision': revision, 'confirm': 'on'}).status_code, 302)
        self.assertNotIn(identifier, {check['id'] for check in read_settings(self.monitor)[0]['checks']})
        system_id = monitor_tests.CHECK['id']
        self.assertEqual(self.client.post('/health/settings/server:' + system_id + '/remove', data={
            'csrf': csrf, 'revision': read_settings(self.monitor)[1], 'confirm': 'on'}).status_code, 302)
        self.assertIn(system_id, {check['id'] for check in read_settings(self.monitor)[0]['checks']})


class NavigationTests(unittest.TestCase):
    setUp = test_web.WebTests.setUp
    tearDown = test_web.WebTests.tearDown
    login = test_web.WebTests.login

    def test_nine_sections_and_native_subpages_keep_urls(self):
        self.login()
        for url, parent, child in [
            ('/dns', '/dns', 'DNS-профили'),
            ('/filtering', '/dns', 'Фильтрация'),
            ('/devices', '/devices', 'Клиенты VPN'),
            ('/lan', '/devices', 'Подключение сетей'),
        ]:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                nav = response.text.split('id="panel-navigation"', 1)[1].split('</nav>', 1)[0]
                self.assertEqual(nav.count('<a href='), 9)
                self.assertIn('href="' + parent + '" aria-current="page"', nav)
                self.assertIn(child, response.text)
        self.assertIn('href="/filtering" aria-current="page"', self.client.get('/filtering').text)
        self.assertIn('href="/lan" aria-current="page"', self.client.get('/lan').text)
        self.assertIn('Подключения', self.client.get('/tunnels').text)


if __name__ == '__main__':
    unittest.main()
