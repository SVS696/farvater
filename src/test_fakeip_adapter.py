import copy,json,unittest
from candidate_bundle import build_bundle,validate_bundle
from candidate_config import build_candidate_config
from fakeip_adapter import PREFIX,BASE_PORT,validate_inbounds
import test_candidate_config as fixtures


class FakeIPAdapterTests(unittest.TestCase):
    def base(self):
        p=fixtures.CandidateConfigTests().base()
        p['dns']['fake']={'scope':'special','native':{'type':'fakeip','inet4_range':'198.18.0.0/15'}}
        p['exits']['special']={'scope':'special','native':{'type':'socks','server':'127.0.0.1','server_port':9050}}
        p['profiles'].append({'id':'onion','name':'Special network','kind':'special','domains':['*.onion'],
                              'exit':'special','dns':'fake','adguard':'on'})
        p['filtering']={'default_enabled':False,'blocklists':[],'allowlists':[],'rules':[]}
        return p

    def build(self,p=None,**kwargs):
        return build_candidate_config(p or self.base(),api_secret='x'*32,default_filtering=False,adguard_adapter=True,**kwargs)

    def test_original_policy_is_unchanged_and_listener_is_authenticated(self):
        p=self.base();before=copy.deepcopy(p);built=self.build(p);c=built['config'];record=built['unmapping'][0]
        self.assertEqual(p,before)
        inbound=next(i for i in c['inbounds'] if i['tag']==record['inbound']);validate_inbounds([inbound])
        outbound=next(o for o in c['outbounds'] if o['tag']=='special')
        self.assertEqual(outbound['password'],inbound['users'][0]['password'])
        raw=next(o for o in c['outbounds'] if o['tag']==record['native_exit'])
        self.assertEqual(raw,{**p['exits']['special']['native'],'tag':record['native_exit']})
        self.assertEqual(c['route']['rules'][0],{'inbound':[record['inbound']],'action':'route','outbound':record['native_exit']})
        self.assertNotIn('password',record)

    def test_all_queues_and_rule_backups_receive_recovery_only_when_needed(self):
        p=self.base();p['profiles'][-1]['adguard']='off'
        self.assertNotIn('unmapping',self.build(p))
        p['profiles'][-1].update(adguard='on',dns='private',exit='work',fallback_pairs=[{'exit':'special','dns':'fake'}])
        self.assertEqual([r['exit'] for r in self.build(p)['unmapping']],['special'])
        p=self.base();p['profiles']=[];p.pop('failover');p.update(default_dns='fake',default_exit='special')
        p['dns']['fake']['scope']='public';p['exits']['special']['scope']='public';p['filtering']['default_enabled']=True
        self.assertEqual([r['exit'] for r in self.build(p)['unmapping']],['special'])

    def test_unsafe_listener_shapes_and_collisions_are_refused(self):
        inbound=self.build()['config']['inbounds'][-1]
        for change in ({'listen':'0.0.0.0'},{'users':[]},{'listen_port':53},{'tag':'other'}):
            with self.subTest(change=change),self.assertRaises(ValueError):validate_inbounds([{**inbound,**change}])
        with self.assertRaisesRegex(ValueError,'занят'):self.build(api_port=BASE_PORT)
        p=self.base();p['exits'][PREFIX+'native-0']={'scope':'public','native':{'type':'direct'}}
        with self.assertRaisesRegex(ValueError,'зарезервирован'):self.build(p)

    def test_bundle_records_recovery_without_exposing_authentication(self):
        files=build_bundle(self.base(),api_secret='x'*32,options={'default_filtering':False,'adguard_adapter':True})
        m=validate_bundle(files);self.assertEqual(m['unmapping'][0]['exit'],'special')
        self.assertNotIn('password',json.dumps(m))


if __name__=='__main__':unittest.main()
