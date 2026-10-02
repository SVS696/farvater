import copy
import unittest
from policy import domain_matches, explain, singbox_match, validate_policy


class PolicyTests(unittest.TestCase):
    def base(self):
        return {'exits':{'work':{'scope':'work'},'direct':{'scope':'public'}},
                'dns':{'private':{'scope':'work'},'isp':{'scope':'public'}},
                'default_exit':'direct','default_dns':'isp','profiles':[
                    {'id':'work','name':'Работа','kind':'work','domains':['*.company.example'],'exit':'work','dns':'private'}]}

    def test_domain_caches_are_bounded_and_keep_invalid_inputs_invalid(self):
        from policy import normalized_domain,domain_pattern
        for fn in (normalized_domain,domain_pattern):
            fn.cache_clear()
            for i in range(4100):fn('host'+str(i)+'.example')
            self.assertLessEqual(fn.cache_info().currsize,4096)
            for _ in range(2):
                with self.assertRaises(ValueError):fn('https://invalid.example/path')
        self.assertEqual(domain_pattern('*.ПРИМЕР.РФ'),('subdomains','xn--e1afmkfd.xn--p1ai'))
        self.assertEqual(domain_pattern('ПРИМЕР.РФ'),('exact','xn--e1afmkfd.xn--p1ai'))

    def test_wildcard_does_not_include_apex_or_similar_suffix(self):
        self.assertTrue(domain_matches('*.example.com','a.b.example.com'))
        self.assertFalse(domain_matches('*.example.com','example.com'))
        self.assertFalse(domain_matches('*.example.com','notexample.com'))
        self.assertFalse(domain_matches('*.example.com','example.com.attacker.test'))

    def test_exact_idn_case_and_trailing_dot(self):
        self.assertTrue(domain_matches('ПРИМЕР.РФ','xn--e1afmkfd.xn--p1ai.'))
        self.assertFalse(domain_matches('example.com','a.example.com'))

    def test_domain_and_subnet_match_are_explicit_union(self):
        m=singbox_match(['example.com'],['10.0.0.0/24'])
        self.assertEqual(m['mode'],'or');self.assertEqual(len(m['rules']),2)

    def test_work_public_fallback_blocks_apply(self):
        p=self.base();p['profiles'][0]['fallback']=['direct']
        self.assertTrue(any(i['severity']=='error' for i in validate_policy(p)))

    def test_public_rule_above_work_is_blocked(self):
        p=self.base();p['profiles'].insert(0,{'id':'all','name':'Все example','kind':'public','domains':['*.example'],'exit':'direct','dns':'isp'})
        self.assertTrue(any('перекрывает' in i['message'] and i['severity']=='error' for i in validate_policy(p)))

    def test_resolver_cycle_is_detected(self):
        p=self.base();p['dns']['private']['bootstrap']='isp';p['dns']['isp']['bootstrap']='private'
        self.assertTrue(any('Цикл' in i['message'] for i in validate_policy(p)))

    def test_native_bootstrap_cycle_is_also_detected(self):
        p=self.base();p['dns']['isp']['native']={'type':'https','server':'dns.example','domain_resolver':{'server':'isp'}}
        self.assertTrue(any('Цикл' in i['message'] for i in validate_policy(p)))

    def test_private_label_does_not_make_public_dns_safe(self):
        p=self.base();p['dns']['private']['native']={'type':'udp','server':'1.1.1.1'}
        self.assertTrue(any('защищённого DNS' in i['message'] for i in validate_policy(p)))
        p['dns']['private']['native']['detour']='work'
        self.assertEqual(validate_policy(p),[])

    def test_explanation_respects_order(self):
        p=self.base();self.assertEqual(explain(p,'jira.company.example')['exit'],'work')
        self.assertEqual(explain(p,'company.example')['exit'],'direct')

    def test_validation_does_not_mutate_source(self):
        p=self.base();old=copy.deepcopy(p);self.assertEqual(validate_policy(p),[]);self.assertEqual(p,old)

    def test_public_site_exception_keeps_private_subnet_protected(self):
        p=self.base();p['profiles'][0]['exclude_domains']=['www.company.example'];p['profiles'][0]['networks']=['10.20.0.0/16']
        self.assertEqual(explain(p,'www.company.example')['exit'],'direct')
        self.assertEqual(explain(p,'10.20.1.2')['exit'],'work')
        match=singbox_match(['*.company.example'],['10.20.0.0/16'],['www.company.example'])
        self.assertEqual(match['mode'],'or');self.assertEqual(match['rules'][0]['mode'],'and')

    def test_unknown_fallback_is_not_silently_accepted(self):
        p=self.base();p['profiles'][0]['fallback']=['missing']
        self.assertTrue(any(i['message']=='Неизвестный резервный выход' for i in validate_policy(p)))

    def test_disabled_work_profile_blocks_instead_of_falling_through(self):
        p=self.base();p['profiles'][0]['enabled']=False
        self.assertEqual(explain(p,'jira.company.example')['exit'],'blocked')

    def test_disabled_work_profile_still_detects_public_override(self):
        p=self.base();p['profiles'][0]['enabled']=False
        p['profiles'].insert(0,{'id':'all','name':'Публичное','kind':'public','domains':['*.example'],'exit':'direct','dns':'isp'})
        self.assertTrue(any(i['severity']=='error' and 'перекрывает' in i['message'] for i in validate_policy(p)))

    def test_disabled_work_profile_keeps_validating_block_conditions(self):
        p=self.base();p['profiles'][0].update(enabled=False,domains=['https://company.example'])
        self.assertTrue(any(i['severity']=='error' for i in validate_policy(p)))

    def test_exclusions_on_prior_profile_remove_false_overlap(self):
        p=self.base();p['profiles'][0]['exclude_domains']=['www.company.example']
        p['profiles'].append({'id':'site','name':'Сайт','kind':'public','domains':['www.company.example'],'exit':'direct','dns':'isp'})
        self.assertEqual(validate_policy(p),[])

    def test_wildcard_overlap_survives_finite_exclusions(self):
        p=self.base();p['profiles'][0]['exclude_domains']=['www.company.example']
        p['profiles'].insert(0,{'id':'all','name':'Публичное','kind':'public','domains':['*.company.example'],'exit':'direct','dns':'isp'})
        self.assertTrue(any(i['severity']=='error' for i in validate_policy(p)))

    def test_dns_only_profile_does_not_hide_later_route(self):
        p=self.base();p['profiles'][0].update(kind='special',dns_only=True)
        p['profiles'].append({'id':'route','name':'Маршрут','kind':'public','domains':['*.company.example'],'exit':'direct','dns':'isp'})
        answer=explain(p,'jira.company.example')
        self.assertEqual(answer['exit'],'direct');self.assertEqual(answer['dns'],'private')

    def test_protected_bootstrap_cannot_escape_through_public_chain(self):
        p=self.base()
        p['dns']['private']['native']={'type':'udp','server':'dns.company.example','detour':'work','domain_resolver':'isp'}
        self.assertTrue(any('Bootstrap защищённого' in i['message'] for i in validate_policy(p)))
        p['dns']['isp'].update(scope='work',native={'type':'udp','server':'10.0.0.53','detour':'work'})
        self.assertEqual(validate_policy(p),[])
        p['dns']['isp']['native']['type']='fakeip'
        self.assertTrue(any('FakeIP' in i['message'] for i in validate_policy(p)))

    def test_unknown_protection_scope_is_rejected(self):
        p=self.base();p['exits']['work']={};p['dns']['private']={}
        errors=validate_policy(p)
        self.assertTrue(any('не может уходить' in i['message'] for i in errors))
        self.assertTrue(any('не должны уходить' in i['message'] for i in errors))

    def test_bootstrap_metadata_cannot_hide_actual_public_resolver(self):
        p=self.base();p['dns']['private2']={'scope':'work','native':{'type':'udp','server':'10.0.0.53','detour':'work'}}
        p['dns']['private'].update(bootstrap='private2',native={'type':'udp','server':'dns.company.example','detour':'work','domain_resolver':'isp'})
        issues=validate_policy(p)
        self.assertTrue(any('не совпадает' in i['message'] for i in issues))
        self.assertTrue(any('Bootstrap защищённого' in i['message'] for i in issues))

    def test_selector_cycles_and_indirect_public_hop_are_rejected(self):
        p=self.base();p['exits']['work']['native']={'type':'selector','outbounds':['direct']}
        self.assertTrue(any('цепочка содержит' in i['message'] for i in validate_policy(p)))
        p['exits']['direct']['native']={'type':'selector','outbounds':['work']}
        self.assertTrue(any('Цикл выходов' in i['message'] for i in validate_policy(p)))

    def test_protected_plain_direct_is_not_made_safe_by_label(self):
        p=self.base();p['exits']['work']['native']={'type':'direct'}
        self.assertTrue(any('привязан' in i['message'] for i in validate_policy(p)))
        p['exits']['work']['native']['bind_interface']='wg-work'
        self.assertEqual(validate_policy(p),[])


if __name__=='__main__':unittest.main()
