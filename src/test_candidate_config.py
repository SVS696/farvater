import copy
import unittest
import test_policy_modes as fixtures
from candidate_config import build_candidate_config


class CandidateConfigTests(unittest.TestCase):
    def base(self):
        p=fixtures.PolicyModeTests().base()
        p['exits']={tag:{**entry,'native':{'type':'direct'}} for tag,entry in p['exits'].items()}
        p['exits']['work']['native']['bind_interface']='test-vpn'
        p['dns']={tag:{**entry,'native':{'type':'udp','server':'127.0.0.1','server_port':15353}}
                  for tag,entry in p['dns'].items()}
        return p

    def build(self,p,**kwargs):
        return build_candidate_config(p,api_secret='x'*32,default_filtering=False,**kwargs)

    def test_dhcp_auto_interface_monitor_is_only_added_when_needed(self):
        p=self.base()
        self.assertNotIn('auto_detect_interface',self.build(p)['config']['route'])
        p['dns']['isp']['native']={'type':'dhcp'}
        c=self.build(p)['config']
        self.assertTrue(c['route']['auto_detect_interface'])
        self.assertEqual(next(x for x in c['dns']['servers'] if x['tag']=='isp'),{'type':'dhcp','tag':'isp'})
        p['dns']['isp']['native']['interface']='eth0'
        self.assertNotIn('auto_detect_interface',self.build(p)['config']['route'])

    def test_full_config_has_only_loopback_ingress_and_guarded_default_mode(self):
        p=self.base();before=copy.deepcopy(p);r=self.build(p);c=r['config']
        self.assertTrue(all(i['listen']=='127.0.0.1' and i['type'] in ('direct','mixed') for i in c['inbounds']))
        self.assertEqual(c['experimental']['clash_api']['default_mode'],r['modes'][0]['name'])
        self.assertEqual(c['route']['rules'][0]['action'],'hijack-dns')
        self.assertEqual(c['route']['rules'][-1]['action'],'reject')
        self.assertEqual(p,before)

    def test_missing_native_or_tag_mismatch_blocks_whole_config(self):
        for patch in [{},{'type':'udp','server':'127.0.0.1','tag':'different'}]:
            p=self.base();p['dns']['isp']['native']=patch
            with self.subTest(patch=patch),self.assertRaises(ValueError):self.build(p)

    def test_port_collision_and_weak_control_secret_are_rejected(self):
        for kwargs in [{'dns_port':2082},{'proxy_port':53},{'api_port':True}]:
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.build(self.base(),**kwargs)
        with self.assertRaises(ValueError):build_candidate_config(self.base(),api_secret='weak',default_filtering=False)

    def test_filtered_resolver_must_exist_in_full_config(self):
        p=self.base()
        with self.assertRaisesRegex(ValueError,'отсутствует'):
            self.build(p,filtered_resolvers={'isp':'nonexistent'})

    def test_connection_resolution_uses_dns_rules_and_no_public_bootstrap(self):
        c=self.build(self.base())['config']
        self.assertEqual(c['route']['rules'][1],{'action':'resolve'})
        tag=c['route']['default_domain_resolver']
        self.assertEqual(next(s for s in c['dns']['servers'] if s['tag']==tag),
                         {'type':'hosts','tag':tag,'path':['/dev/null']})
        self.assertEqual(c['dns']['final'],tag)

    def test_loopback_source_can_be_simulated_but_lan_source_cannot(self):
        p=self.base();p['profiles'][0]['source_networks']=['127.0.0.2/32']
        self.build(p,source_identity=True)
        p['profiles'][0]['source_networks']=['192.168.2.82/32']
        with self.assertRaisesRegex(ValueError,'реальные устройства'):self.build(p,source_identity=True)

    def test_assembled_references_and_hostname_bootstrap_are_checked(self):
        for native in [{'domain_resolver':'missing'}, {'domain_resolver':{'server':'missing'}},
                       {'server':'endpoint.test'}]:
            p=self.base();p['exits']['direct']['native'].update(native)
            with self.subTest(native=native),self.assertRaises(ValueError):self.build(p)
        for extra in [{'type':'udp','tag':'extra','server':'127.0.0.1','detour':'missing'},
                      {'type':'udp','tag':'extra','server':'127.0.0.1','domain_resolver':'missing'}]:
            with self.subTest(extra=extra),self.assertRaises(ValueError):self.build(self.base(),additional_dns=[extra])

    def test_filter_adapter_cannot_map_protected_dns_to_public_or_unclassified_backend(self):
        for target in ('isp','extra'):
            p=self.base();p['profiles'].append({'id':'corp','name':'Corp','kind':'work','domains':['corp.test'],
                'exit':'work','dns':'private','adguard':'on'})
            with self.subTest(target=target),self.assertRaisesRegex(ValueError,'защищённым'):
                self.build(p,filtered_resolvers={'private':target},additional_dns=[
                    {'type':'udp','tag':'extra','server':'127.0.0.1','server_port':15354}])
        p['dns']['filtered-private']={'scope':'work','native':{'type':'udp','server':'127.0.0.1','server_port':15354}}
        self.build(p,filtered_resolvers={'private':'filtered-private'})

    def fake(self):
        p=self.base();p['dns']['fake']={'scope':'public','native':{'type':'fakeip','inet4_range':'198.18.0.0/15'}}
        p['profiles'][0].update(dns='fake',fallback_pairs=[])
        return p

    def test_fakeip_requires_remote_hostname_support_in_every_selected_exit(self):
        p=self.fake()
        with self.assertRaisesRegex(ValueError,'FakeIP'):self.build(p)
        p['exits']['remote']={'scope':'public','native':{'type':'socks','server':'127.0.0.1','server_port':15080}}
        p['profiles'][0]['exit']='remote';self.build(p)
        p['exits']['selector']={'scope':'public','native':{'type':'selector','outbounds':['remote','direct']}}
        p['profiles'][0]['exit']='selector'
        with self.assertRaisesRegex(ValueError,'FakeIP'):self.build(p)
        p['exits']['direct']['native']['domain_resolver']='isp';self.build(p)
        p['exits']['direct']['native']['domain_resolver']='okopy-bootstrap-deny'
        with self.assertRaisesRegex(ValueError,'FakeIP'):self.build(p)

    def test_fakeip_dns_only_and_incompatible_backup_are_rejected(self):
        p=self.fake();p['exits']['remote']={'scope':'public','native':{'type':'socks','server':'127.0.0.1','server_port':15080}}
        p['profiles'][0].update(exit='remote',dns_only=True)
        with self.assertRaisesRegex(ValueError,'FakeIP'):self.build(p)
        p['profiles'][0].update(dns_only=False,fallback_pairs=[{'exit':'direct','dns':'fake'}])
        with self.assertRaisesRegex(ValueError,'FakeIP'):self.build(p)

    def test_extra_fakeip_and_default_pair_receive_the_same_compatibility_check(self):
        p=self.base();p['profiles'][0].update(adguard='on',fallback_pairs=[])
        with self.assertRaisesRegex(ValueError,'FakeIP'):
            self.build(p,filtered_resolvers={'vpn-dns':'extra'},additional_dns=[
                {'type':'fakeip','tag':'extra','inet4_range':'198.18.0.0/15'}])
        p=self.fake();p['profiles']=[];p.pop('failover');p['default_dns']='fake'
        with self.assertRaisesRegex(ValueError,'FakeIP'):self.build(p)

    def test_filter_wrapper_cannot_hide_incompatible_original_fakeip(self):
        p=self.fake();p['profiles'][0]['adguard']='on'
        with self.assertRaisesRegex(ValueError,'FakeIP'):
            self.build(p,filtered_resolvers={'fake':'isp'})
        p['profiles']=[];p.pop('failover');p['default_dns']='fake'
        with self.assertRaisesRegex(ValueError,'FakeIP'):
            build_candidate_config(p,api_secret='x'*32,default_filtering=True,
                                   filtered_resolvers={'fake':'isp'})
