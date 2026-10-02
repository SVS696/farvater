"""Backup copy must reflect the actual recovery capability and drill evidence."""

import unittest
from unittest.mock import Mock

import test_web as fixture
from web import create_app


class BackupHelpTests(unittest.TestCase):
    setUp = fixture.WebTests.setUp
    tearDown = fixture.WebTests.tearDown
    login = fixture.WebTests.login

    def page(self, available=False, drill=None):
        backend = Mock()
        backend.call.return_value = {
            'scope': 'Тестовый состав', 'exclusions': [], 'signing_fingerprint': 'a' * 64,
            'recipient': 'тестовый получатель', 'jobs': [{
                'id': 'b' * 32, 'kind': 'import', 'status': 'checked',
                'created_at': 1000, 'manifest_sha256': 'c' * 64}],
            'restore_application_available': available, 'last_drill': drill,
        }
        self.app = create_app(self.path, candidate=backend)
        self.app.testing = True
        self.client = self.app.test_client()
        self.login()
        return self.client.get('/backups').text

    def test_unavailable_and_unverified_are_not_presented_as_restored(self):
        html = self.page()
        self.assertIn('Полное восстановление из панели сейчас недоступно', html)
        self.assertIn('Последняя полная проверка восстановления: не проверено', html)
        self.assertNotIn('Последняя принятая проверка', html)
        self.assertNotIn('Открыть восстановление и статус', html)
        html = self.page(available=True)
        if 'backup_restore_page' in self.app.view_functions:
            self.assertIn('Защищённое восстановление доступно', html)
            self.assertIn('Открыть восстановление и статус', html)
            self.assertIn('href="/backups/recovery/help"', html)
        else:
            self.assertIn('действия панели ещё не подключены', html)
            self.assertNotIn('Открыть восстановление и статус', html)

    def test_drill_result_only_comes_from_backend_metadata(self):
        html = self.page(available=True, drill={
            'status': 'passed', 'at': 1000, 'platform': 'linux-amd64',
            'scope': 'isolated-full-systemd', 'evidence_sha256': 'd' * 64})
        self.assertIn('Последняя принятая проверка восстановления', html)
        self.assertIn('linux-amd64', html)
        failed = self.page(drill={
            'status': 'failed', 'at': 1000, 'platform': 'linux-amd64',
            'scope': 'isolated-full-systemd', 'evidence_sha256': 'e' * 64})
        self.assertIn('завершилась ошибкой', failed)
        self.assertNotIn('Последняя принятая проверка', failed)
        incomplete = self.page(drill={'status': 'passed', 'at': 1000})
        self.assertIn('не проверено', incomplete)
        self.assertNotIn('Последняя принятая проверка', incomplete)


if __name__ == '__main__':
    unittest.main()
