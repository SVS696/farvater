import copy
import unittest
from werkzeug.datastructures import MultiDict
from policy import validate_policy
from policy import explain
from policy_modes import compile_policy_modes
from rule_fallback import parse_pairs
import test_rule_compiler as fixtures


class PolicyModeTests(unittest.TestCase):
    def base(self):
        policy = fixtures.GeneralRuleTests().base()
        policy['exits']['vpn'] = {'scope': 'public'}
        policy['dns']['vpn-dns'] = {'scope': 'public'}
        policy['profiles'][0].update(exit='vpn', dns='vpn-dns',
                                    fallback_pairs=[{'exit': 'direct', 'dns': 'isp'}])
        policy['failover'] = {'priority': ['vpn', 'direct'], 'dns_by_exit': {'vpn': 'vpn-dns', 'direct': 'isp'}}
        return policy

    def compile(self, policy, **kwargs):
        return compile_policy_modes(policy, default_filtering=False, **kwargs)

    def test_primary_and_backup_pairs_cover_all_atomic_combinations(self):
        policy = self.base(); before = copy.deepcopy(policy); result = self.compile(policy)
        self.assertEqual(len(result['modes']), 4)
        self.assertEqual(len({m['name'] for m in result['modes']}), 4)
        for mode in result['modes']:
            domain_dns = next(r for r in result['dns_rules'] if r.get('type') == 'logical'
                              and {'clash_mode': mode['name']} in r['rules'])
            domain_route = next(r for r in result['route_rules'] if r.get('type') == 'logical'
                                and {'clash_mode': mode['name']} in r['rules'])
            self.assertEqual(domain_dns['server'], mode['pairs']['rule:arbitrary']['dns'])
            self.assertEqual(domain_route['outbound'], mode['pairs']['rule:arbitrary']['exit'])
        self.assertEqual(policy, before)

    def test_unknown_mode_ends_in_dns_and_route_reject(self):
        result = self.compile(self.base())
        self.assertEqual(result['dns_rules'][-1], {'action': 'reject', 'no_drop': True})
        self.assertEqual(result['route_rules'][-1], {'action': 'reject'})

    def test_protected_fallback_cannot_be_public_on_either_half(self):
        for pair in [{'exit': 'direct', 'dns': 'private'}, {'exit': 'work', 'dns': 'isp'}]:
            policy = self.base()
            policy['profiles'][0].update(kind='work', exit='work', dns='private', fallback_pairs=[pair])
            with self.subTest(pair=pair), self.assertRaisesRegex(ValueError, 'защищённого'):
                self.compile(policy)

    def test_queue_errors_are_reported_before_generation(self):
        for value in [None, ['direct'], [{'exit': 'direct'}], [{'exit': 'missing', 'dns': 'isp'}],
                      [{'exit': 'vpn', 'dns': 'vpn-dns'}], [{'exit': 'direct', 'dns': 'isp', 'extra': True}]]:
            policy = self.base(); policy['profiles'][0]['fallback_pairs'] = value
            with self.subTest(value=value):
                self.assertTrue(any(i['severity'] == 'error' for i in validate_policy(policy)))
                with self.assertRaises(ValueError): self.compile(policy)

    def test_independent_queues_are_bounded_before_expansion(self):
        policy = self.base(); original = policy['profiles'][0]
        policy['profiles'] = [{**copy.deepcopy(original), 'id': 'p'+str(i), 'domains': [str(i)+'.test']} for i in range(6)]
        with self.assertRaisesRegex(ValueError, '64'): self.compile(policy)

    def test_filtered_resolver_is_required_for_every_selected_pair(self):
        policy = self.base()
        with self.assertRaisesRegex(ValueError, 'AdGuard'):
            compile_policy_modes(policy, default_filtering=True, filtered_resolvers={'vpn-dns': 'filtered-vpn'})

    def test_special_response_and_source_scope_survive_mode_guard(self):
        policy = self.base()
        policy['profiles'][0].update(source_networks=['192.168.2.82/32'],
            dns_response={'mode': 'nodata', 'query_types': ['HTTPS']})
        with self.assertRaisesRegex(ValueError, 'исходный IP'): self.compile(policy)
        result = self.compile(policy, source_identity=True)
        predefined = [r for r in result['dns_rules'] if r['action'] == 'predefined']
        self.assertEqual(len(predefined), 4)
        self.assertTrue(all(r['rcode'] == 'NOERROR' and r['type'] == 'logical' for r in predefined))

    def test_names_do_not_influence_mode_or_rules(self):
        policy = self.base(); before = self.compile(policy)
        policy['profiles'][0]['name'] = 'Совершенно произвольное новое имя'
        self.assertEqual(before, self.compile(policy))

    def test_default_explanation_uses_actual_queue_head(self):
        p=self.base()
        self.assertEqual(explain(p,'unmatched.test')['exit'],'vpn')
        self.assertEqual(explain(p,'unmatched.test')['dns'],'vpn-dns')

    def test_pair_form_requires_complete_rows_and_preserves_order(self):
        pairs = parse_pairs(MultiDict([('fallback_exit','vpn'),('fallback_dns','vpn-dns'),
                    ('fallback_exit','direct'),('fallback_dns','isp'),('fallback_exit',''),('fallback_dns','')]))
        self.assertEqual(pairs, [{'exit':'vpn','dns':'vpn-dns'},{'exit':'direct','dns':'isp'}])
        with self.assertRaisesRegex(ValueError, 'выберите'):
            parse_pairs(MultiDict([('fallback_exit','direct'),('fallback_dns','')]))
