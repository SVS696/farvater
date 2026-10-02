import copy,json,unittest
import lan_ingress as lan
import lan_runtime
from candidate_bundle import build_bundle,validate_bundle
import test_lan_ingress as fixtures

class GatewayProbeTests(unittest.TestCase):
    def value(self):return {**copy.deepcopy(fixtures.LAN),'gateway_probe_domains':['api.ipify.org','example.com'],'transparent_targets':['0.0.0.0/0']}

    def test_gateway_is_separate_from_devices_and_never_a_transparent_source(self):
        v=lan.settings({'lan_ingress':self.value()})
        self.assertNotIn(v['gateway']+'/32',v['clients'])
        self.assertIn(v['gateway']+'/32',lan.admitted_sources(v))
        route,dns=lan.gateway_guards(v)
        self.assertEqual(route[0]['rules'][0],{'inbound':['okopy-lan-transparent']})
        self.assertEqual(route[0]['rules'][1],{'source_ip_cidr':['192.168.2.1/32']})
        self.assertEqual(route[0]['action'],'reject')
        self.assertEqual(route[1]['rules'][2]['rules'],[{'domain':v['gateway_probe_domains'],'invert':True},{'port':[443],'invert':True},{'network':'udp'}])
        self.assertEqual(dns[0]['rcode'],'REFUSED')
        self.assertEqual(len(lan_runtime.specs(v)[2]),2) # Only client return + local transparent route.

    def test_generated_bundle_enforces_gateway_dns_before_all_other_resolvers(self):
        p=fixtures.LanTests().policy();p['lan_ingress']=self.value()
        files=build_bundle(p,api_secret='x'*32,options={'default_filtering':False,'lan_adapter':True});validate_bundle(files)
        config=json.loads(files['config.json']);value=lan.settings(p);lan.validate_config(config,value)
        self.assertEqual(config['dns']['rules'][0],lan.gateway_guards(value)[1][0])
        config['dns']['rules'].pop(0)
        with self.assertRaisesRegex(ValueError,'Gateway DNS'):lan.validate_config(config,value)

    def test_names_are_bounded_exact_normalized_and_do_not_accept_ips(self):
        v={**self.value(),'gateway_probe_domains':['Example.COM','example.com']}
        self.assertEqual(lan.settings({'lan_ingress':v})['gateway_probe_domains'],['example.com'])
        for domains in ('example.com',['*.example.com'],['example.com;command'],['127.0.0.1'],['a'],['example.com']*9):
            with self.subTest(domains=domains),self.assertRaises(ValueError):lan.settings({'lan_ingress':{**v,'gateway_probe_domains':domains}})

    def test_disabling_or_emptying_probe_access_does_not_admit_gateway(self):
        v={**self.value(),'gateway_probe_domains':[]}
        self.assertEqual(lan.admitted_sources(v),v['clients']);self.assertEqual(lan.gateway_guards(v),([],[]))
        p=fixtures.LanTests().policy();p['lan_ingress']={**self.value(),'enabled':False}
        files=build_bundle(p,api_secret='x'*32,options={'default_filtering':False,'lan_adapter':True})
        config=json.loads(files['config.json']);self.assertFalse(any(i['tag'].startswith('okopy-lan-') for i in config['inbounds']))
        self.assertNotEqual(config['dns']['rules'][0],lan.gateway_guards(lan.settings(p))[1][0])

class GatewayWebTests(unittest.TestCase):
    setUp=fixtures.LanWebTests.setUp
    tearDown=fixtures.LanWebTests.tearDown
    login=fixtures.LanWebTests.login
    revision=fixtures.LanWebTests.revision

    def test_gateway_domain_form_roundtrip_and_invalid_name(self):
        csrf=self.login()
        data={'csrf':csrf,'revision':self.revision(),**fixtures.LAN,'enabled':'on',
              'clients':'192.168.2.82/32','gateway_probe_domains':'api.ipify.org\nexample.com'}
        self.assertEqual(self.client.post('/lan/save',data=data).status_code,302)
        stored=json.loads((self.path/'policy.json').read_text())
        self.assertEqual(stored['lan_ingress']['gateway_probe_domains'],['api.ipify.org','example.com'])
        self.assertIn('api.ipify.org\nexample.com',self.client.get('/lan').text)
        data.update(revision=self.revision(),gateway_probe_domains='*.example.com')
        self.assertEqual(self.client.post('/lan/save',data=data).status_code,400)
        self.assertEqual(stored,json.loads((self.path/'policy.json').read_text()))

if __name__=='__main__':unittest.main()
