"""Fixed, value-free policy section summaries for the changes screen."""

import hashlib
import json
import unittest

import test_candidate_web as candidate_fixture
import test_web as web_fixture
from policy_sections import changed_section_labels, section_hashes


class SectionDigestTests(unittest.TestCase):
    def test_reordered_objects_have_same_hash_and_only_changed_label_appears(self):
        policy = {'dns': {'private': {'name': 'Secret', 'password': 'private-value'}},
                  'exits': {'direct': {'name': 'Direct'}}, 'profiles': []}
        reordered = {'profiles': [], 'exits': {'direct': {'name': 'Direct'}},
                     'dns': {'private': {'password': 'private-value', 'name': 'Secret'}}}
        before = section_hashes(policy)
        self.assertEqual(before, section_hashes(reordered))
        reordered['dns']['private']['name'] = 'Changed'
        self.assertEqual(changed_section_labels(section_hashes(reordered), before), ['DNS-профили'])
        self.assertNotIn('private-value', json.dumps(before))
        self.assertIsNone(changed_section_labels(before, {'dns': 'bad'}))


class ChangesScreenTests(unittest.TestCase):
    setUp = candidate_fixture.CandidateWebTests.setUp
    tearDown = candidate_fixture.CandidateWebTests.tearDown

    def test_equal_changed_and_unknown_applied_sections(self):
        policy = json.loads((self.root / 'policy.json').read_text())
        original = section_hashes(policy)
        original_hash = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
        self.state.update(policy_sha256=original_hash, policy_section_sha256=original)
        html = self.client.get('/changes').text
        self.assertIn('Изменений нет', html)
        self.assertIn('Повторное применение без изменений', html)
        self.assertNotIn('>Применить настройки</button>', html)
        self.state['transaction']['status'] = 'pending'
        html = self.client.get('/changes').text
        self.assertIn('временно применённым пакетом', html)
        self.assertNotIn('совпадает с подтверждённой действующей политикой', html)
        self.state['transaction']['status'] = 'confirmed'
        policy['dns']['isp']['name'] = 'Changed DNS'
        (self.root / 'policy.json').write_text(json.dumps(policy))
        html = self.client.get('/changes').text
        self.assertIn('Изменены разделы:', html)
        self.assertIn('DNS-профили', html)
        self.assertIn('>Применить настройки</button>', html)
        self.state.pop('policy_section_sha256')
        html = self.client.get('/changes').text
        self.assertIn('Состав изменений не подтверждён', html)
        self.assertNotIn('action="/candidate/apply"', html)


class PrimaryPairTests(unittest.TestCase):
    setUp = web_fixture.WebTests.setUp
    tearDown = web_fixture.WebTests.tearDown
    login = web_fixture.WebTests.login
    revision = web_fixture.WebTests.revision

    def test_new_rule_requires_explicit_pair_even_when_dictionary_reordered(self):
        self.policy['exits'] = {'proxy': {'name': 'Proxy', 'scope': 'public'}, **self.policy['exits']}
        self.policy['dns'] = {'bootstrap': {'name': 'Bootstrap', 'scope': 'public'}, **self.policy['dns']}
        (self.path / 'policy.json').write_text(json.dumps(self.policy))
        csrf = self.login()
        page = self.client.get('/rules/new').text
        self.assertIn('<option value="" selected disabled>Выберите выход</option>', page)
        self.assertIn('<option value="" selected disabled>Выберите DNS</option>', page)
        self.assertNotIn('<option value="proxy" selected', page)
        before = (self.path / 'policy.json').read_bytes()
        fields = {'csrf': csrf, 'revision': self.revision(), 'name': 'Rule',
                  'kind': 'public', 'domains': 'example.com', 'exit': '', 'dns': ''}
        for exit_id, dns_id in [('', ''), ('direct', ''), ('', 'isp'), ('unknown', 'isp')]:
            with self.subTest(exit=exit_id, dns=dns_id):
                fields.update(exit=exit_id, dns=dns_id)
                self.assertEqual(self.client.post('/rules/save', data=fields).status_code, 400)
                self.assertEqual((self.path / 'policy.json').read_bytes(), before)
        fields.update(exit='direct', dns='isp')
        self.assertEqual(self.client.post('/rules/save', data=fields).status_code, 302)
        saved = json.loads((self.path / 'policy.json').read_text())['profiles'][0]
        self.assertEqual((saved['exit'], saved['dns']), ('direct', 'isp'))
        self.assertIn('<option value="direct" selected', self.client.get('/rules/' + saved['id'] + '/edit').text)
        self.assertIn('<option value="direct" selected', self.client.get('/rules/default').text)


if __name__ == '__main__':
    unittest.main()
