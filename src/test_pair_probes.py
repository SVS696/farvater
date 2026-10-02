import copy,json,unittest
from candidate_config import build_candidate_config
from candidate_bundle import build_bundle,validate_bundle
from pair_probes import parse_target,validate_probe_inbounds
import test_candidate_config as fixtures

class PairProbeTests(unittest.TestCase):
    def setUp(self):
        self.policy=fixtures.CandidateConfigTests().base()
        self.target={'dns_name':'api.ipify.org','urls':['https://api.ipify.org','https://example.com/'],'codes':[200]}
        self.policy['health_probes']={'default':copy.deepcopy(self.target)}
    def build(self,**kwargs):return build_candidate_config(self.policy,api_secret='x'*32,default_filtering=False,pair_probes=True,**kwargs)
    def test_probes_bind_each_pair_without_a_mode_switch_or_main_policy_change(self):
        before=build_candidate_config(self.policy,api_secret='x'*32,default_filtering=False)
        after=self.build();self.assertEqual(after['modes'],before['modes'])
        self.assertEqual(after['config']['route']['rules'][-len(before['config']['route']['rules']):],before['config']['route']['rules'])
        self.assertEqual(len(after['probes']),len(after['queues']['default']))
        for record,pair in zip(after['probes'],after['queues']['default']):
            self.assertEqual((record['exit'],record['dns']),(pair['exit'],pair['dns']))
        self.assertTrue(all(i['listen']=='127.0.0.1' for i in after['config']['inbounds']))
    def test_probe_targets_cannot_send_protected_names_to_public_dns(self):
        self.policy['profiles'].append({'id':'secret','name':'Secret','kind':'work','domains':['*.secret.test'],'exit':'work','dns':'private'})
        for field,value in [('dns_name','api.secret.test'),('urls',['https://api.secret.test/'])]:
            self.policy['health_probes']['default']=dict(self.target,**{field:value})
            with self.assertRaisesRegex(ValueError,'Публичная проверка'):self.build()
    def test_all_unconfigured_queues_are_explicit(self):
        self.policy['health_probes']={};result=self.build()
        self.assertEqual(result['probes'],[]);self.assertEqual(set(result['unconfigured_probe_queues']),set(result['queues']))
    def test_more_than_eight_active_probe_pairs_are_refused(self):
        self.policy['profiles']=[]
        tags=['out-'+str(i) for i in range(9)]
        for tag in tags:self.policy['exits'][tag]={'scope':'public','native':{'type':'direct'}}
        self.policy['failover']={'priority':tags,'dns_by_exit':{tag:'isp' for tag in tags}}
        with self.assertRaisesRegex(ValueError,'до 8'):self.build()
    def test_unknown_queue_and_probe_port_collision_are_rejected(self):
        self.policy['health_probes']['missing']=self.target
        with self.assertRaises(ValueError):self.build()
        del self.policy['health_probes']['missing']
        for option in ('dns_port','proxy_port','api_port'):
            with self.subTest(option=option),self.assertRaises(ValueError):self.build(**{option:12000})
    def test_private_destination_guard_precedes_public_probe_route(self):
        rules=self.build()['config']['route']['rules']
        guard=next(i for i,r in enumerate(rules) if r.get('ip_is_private'))
        route=next(i for i,r in enumerate(rules) if r['action']=='route')
        self.assertLess(guard,route);self.assertEqual(rules[guard]['action'],'reject')
    def test_protected_queue_rejects_public_resolver_before_probe_generation(self):
        p=self.policy['profiles'][0]
        p.update(kind='work',exit='work',dns='private',fallback_pairs=[{'exit':'work','dns':'isp'}])
        self.policy['health_probes']['rule:'+p['id']]=self.target
        with self.assertRaisesRegex(ValueError,'защищённого'):self.build()
    def test_fakeip_check_is_explicitly_unqualified(self):
        self.policy['dns']['fake']={'scope':'public','native':{'type':'fakeip','inet4_range':'198.18.0.0/15'}}
        self.policy['exits']['vpn']['native']={'type':'socks','server':'127.0.0.1','server_port':15080}
        p=self.policy['profiles'][0];p['dns']='fake'
        self.policy['health_probes']['rule:'+p['id']]=self.target
        with self.assertRaisesRegex(ValueError,'проверка FakeIP пока'):self.build()
        # A UDP filtering wrapper is not evidence of real upstream resolution.
        p['adguard']='on'
        with self.assertRaisesRegex(ValueError,'проверка FakeIP пока'):
            self.build(filtered_resolvers={**{tag:tag for tag in self.policy['dns']},'fake':'isp'})
    def test_non_probe_traffic_is_rejected_before_main_policy_and_dns_cache_is_disabled(self):
        result=self.build();dns=result['config']['dns']['rules']
        self.assertTrue(dns[0]['disable_cache']);self.assertTrue(dns[0]['disable_optimistic_cache'])
        self.assertEqual(dns[1],{'inbound':['okopy-probe-dns-0','okopy-probe-proxy-0'],'action':'reject','no_drop':True})
        routes=result['config']['route']['rules'];terminal=next(i for i,r in enumerate(routes) if r=={'inbound':['okopy-probe-proxy-0'],'action':'reject'})
        self.assertTrue(all('inbound' in r for r in routes[:terminal]))
        allowed=[r for r in routes[:terminal] if r['action']=='route']
        self.assertEqual({(r['domain'][0],r['port'][0]) for r in allowed},{('api.ipify.org',443),('example.com',443)})
    def test_unsafe_url_shapes_and_invalid_codes_are_refused(self):
        for field,value in [('urls',['file:///etc/passwd']),('urls',['https://user:password@example.com']),('urls',['https://127.0.0.1/']),('dns_name','127.0.0.1'),('codes',[True]),('codes',[200,200])]:
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):parse_target(dict(self.target,**{field:value}))
    def test_listener_validator_refuses_other_ports_extra_fields_and_non_loopback(self):
        inbounds=self.build()['config']['inbounds'][2:];validate_probe_inbounds(inbounds)
        for field,value in [('listen','0.0.0.0'),('listen_port',53),('users',[])]:
            bad=copy.deepcopy(inbounds);bad[0][field]=value
            with self.assertRaises(ValueError):validate_probe_inbounds(bad)
    def test_bundle_rebuild_binds_probe_records_and_keeps_legacy_without_probes(self):
        files=build_bundle(self.policy,api_secret='x'*32,options={'default_filtering':False,'pair_probes':True})
        self.assertTrue(validate_bundle(files)['probes'])
        old=build_bundle(self.policy,api_secret='x'*32)
        self.assertNotIn('probes',validate_bundle(old));self.assertEqual(len(json.loads(old['config.json'])['inbounds']),2)
