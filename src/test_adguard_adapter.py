import copy
import json
import unittest
from adguard_adapter import compile_adapter,runtime_config,settings,validate_inbounds,PREFIX
from candidate_bundle import build_bundle,validate_bundle
from candidate_config import build_candidate_config
import test_candidate_config as fixtures


class AdGuardAdapterTests(unittest.TestCase):
    def base(self):
        p=fixtures.CandidateConfigTests().base()
        p['filtering']={'default_enabled':True,'blocklists':[],'allowlists':[],'rules':['||blocked.test^']}
        p['profiles'].append({'id':'corp','name':'Corp','kind':'work','domains':['*.corp.test'],
                              'exit':'work','dns':'private','adguard':'on'})
        return p

    def test_mapping_preserves_each_resolver_scope_and_has_no_fallback(self):
        p=self.base();original=copy.deepcopy(p);a=compile_adapter(p)
        self.assertEqual(p,original)
        self.assertTrue({'private','vpn-dns','isp'}<=set(a['mapping']))
        for r in a['records']:
            self.assertEqual(a['policy']['dns'][r['filtered_dns']]['scope'],p['dns'][r['dns']]['scope'])
            route=next(x for x in a['dns_rules'] if x.get('inbound')==[r['inbound']] and x['action']=='route')
            self.assertEqual(route['server'],r['dns']);self.assertTrue(route['disable_cache'])
        validate_inbounds(a['inbounds'])
        a['inbounds'][0]['listen']='0.0.0.0'
        with self.assertRaises(ValueError):validate_inbounds(a['inbounds'])

    def test_global_off_and_rule_off_do_not_create_filtering_paths(self):
        p=self.base();p['filtering']['default_enabled']=False
        for profile in p['profiles']:profile['adguard']='off'
        self.assertEqual(compile_adapter(p)['records'],[])
        p['profiles'][0]['adguard']='on'
        a=compile_adapter(p)
        self.assertEqual(set(a['mapping']),{p['profiles'][0]['dns'],*(pair['dns'] for pair in p['profiles'][0].get('fallback_pairs',[]))})

    def test_fakeip_keeps_filtering_and_adds_private_name_recovery(self):
        p=self.base();p['dns']['private']['native']={'type':'fakeip','inet4_range':'198.18.0.0/15'}
        p['exits']['work']['native']={'type':'socks','server':'127.0.0.1','server_port':15080}
        result=build_candidate_config(p,api_secret='x'*32,default_filtering=False,adguard_adapter=True)
        self.assertEqual([r['exit'] for r in result['unmapping']],['work'])
        self.assertIn('private',compile_adapter(p)['mapping'])

    def test_three_file_bundle_reproduces_settings_mapping_and_native_config(self):
        p=self.base();files=build_bundle(p,api_secret='x'*32,options={'default_filtering':False,'adguard_adapter':True})
        manifest=validate_bundle(files);self.assertEqual(len(files),3)
        self.assertEqual(manifest['adguard'],compile_adapter(p)['records'])
        self.assertEqual(json.loads(files['applied-policy.json']),p)
        native=json.loads(files['config.json'])
        self.assertTrue(any(i['tag'].startswith(PREFIX) for i in native['inbounds']))

    def test_no_mixing_with_manual_backend_and_no_reserved_id_collision(self):
        with self.assertRaisesRegex(ValueError,'смешивать'):
            build_candidate_config(self.base(),api_secret='x'*32,default_filtering=False,
                                   adguard_adapter=True,filtered_resolvers={'isp':'arbitrary'})
        p=self.base();p['dns'][PREFIX+'spoof']=p['dns']['isp']
        with self.assertRaisesRegex(ValueError,'зарезервирован'):compile_adapter(p)

    def test_filter_settings_validate_unique_lists_and_device_scope(self):
        p=self.base()
        for change in [{'default_enabled':1},{'rules':['||x.test^$client=1.2.3.4']},
                       {'rules':['line\nline']},{'rules':'string'},
                       {'blocklists':[{'id':1,'name':'Bad','url':'file:///etc/passwd','enabled':True}]}]:
            v=copy.deepcopy(p);v['filtering'].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):settings(v)

    def test_native_runtime_disables_cross_client_caches_and_external_lookups(self):
        base={'http':{},'dns':{},'filtering':{},'dhcp':{},'tls':{},'querylog':{}}
        a=compile_adapter(self.base());cfg=runtime_config(base,a)
        self.assertFalse(cfg['dns']['cache_enabled']);self.assertEqual(cfg['dns']['fallback_dns'],[])
        self.assertFalse(any(cfg['clients']['runtime_sources'].values()))
        self.assertEqual(cfg['dns']['allowed_clients'],[r['source'] for r in a['records']])
        self.assertTrue(all(not c['upstreams_cache_enabled'] for c in cfg['clients']['persistent']))
        self.assertEqual(cfg['filtering']['blocking_mode'],'nxdomain')


if __name__=='__main__':unittest.main()
