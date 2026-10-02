"""Display grouping must not alter health status or card identity."""

import json
import time
import unittest

import test_web as fixture
from monitor_view import group_cards


class GroupCardsTests(unittest.TestCase):
    def test_problems_first_and_unknown_kind_stays_other(self):
        rows = [
            {'id': 'a', 'status': 'up', 'kind': 'dns'},
            {'id': 'b', 'status': 'down', 'kind': 'service'},
            {'id': 'c', 'status': 'up'},
            {'id': 'd', 'status': 'stale', 'kind': 'dns'},
        ]
        grouped = group_cards(rows)
        self.assertEqual([(name, [item['id'] for item in cards]) for name, cards in grouped],
                         [('Проблемы', ['b', 'd']), ('DNS', ['a']), ('Прочее', ['c'])])


class GroupPageTests(unittest.TestCase):
    setUp = fixture.WebTests.setUp
    tearDown = fixture.WebTests.tearDown
    login = fixture.WebTests.login

    def test_cards_keep_original_ids_and_overall_failure(self):
        self.login()
        now = time.time()
        checks = [
            {'id': 'dns-check', 'name': 'DNS check', 'scope': 'DNS', 'kind': 'dns',
             'status': 'up', 'observed_at': now, 'duration_ms': 1,
             'detail': 'ok', 'action': 'Check'},
            {'id': 'service-check', 'name': 'Service check', 'scope': 'Core', 'kind': 'service',
             'status': 'down', 'observed_at': now, 'duration_ms': 1,
             'detail': 'down', 'action': 'Restart'},
        ]
        (self.path / 'health.json').write_text(json.dumps({
            'version': 1, 'generated_at': now, 'checks': checks}))
        page = self.client.get('/health').text
        self.assertIn('Требуют внимания: 1', page)
        self.assertLess(page.index('<h2>Проблемы</h2>'), page.index('<h2>DNS</h2>'))
        self.assertIn('id="check-dns-check"', page)
        self.assertIn('id="check-service-check"', page)


if __name__ == '__main__':
    unittest.main()
