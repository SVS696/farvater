import copy,json,unittest
from vpn_ingress import settings,nft_script
from test_vpn_ingress import VPN
from test_web import WebTests

class DnsCaptureTests(unittest.TestCase):
 def test_local_dns_precedes_management_bypass_for_both_families(self):
  v={**VPN,'dns_before_bypass':True,'clients_v6':['fd42::/64'],'bypass_v6':['fd42::/64']}
  for version,subnet in [(4,'10.9.0.0/24'),(6,'fd42::/64')]:
   text=nft_script(v,True,version)
   self.assertLess(text.index('th dport 53 tproxy'),text.index(subnet,text.index('chain selected')))
   closed=nft_script(v,False,version)
   self.assertIn('th dport 53 drop',closed);self.assertNotIn('tproxy to',closed)
 def test_legacy_and_explicit_off_are_identical(self):
  self.assertEqual(nft_script(VPN,True),nft_script({**VPN,'dns_before_bypass':False},True))
  self.assertEqual(settings({'vpn_ingress':VPN}),VPN)
 def test_validation_preserves_explicit_setting(self):
  for value in [True,False]:self.assertIs(settings({'vpn_ingress':{**VPN,'dns_before_bypass':value}})['dns_before_bypass'],value)
  for value in [1,'on',None]:
   with self.assertRaises(ValueError):settings({'vpn_ingress':{**VPN,'dns_before_bypass':value}})
 def test_web_roundtrip_and_old_form_cannot_erase_setting(self):
  f=WebTests();f.setUp()
  try:
   csrf=f.login();d={'csrf':csrf,'revision':f.revision(),'enabled':'on','interface':'wg0','clients':'10.9.0.2/32','bypass':'10.9.0.0/24','dns_before_bypass_present':'1','dns_before_bypass':'on'}
   self.assertEqual(f.client.post('/vpn-ingress/save',data=d).status_code,302)
   p=json.loads((f.path/'policy.json').read_text());self.assertTrue(p['vpn_ingress']['dns_before_bypass'])
   self.assertIn('name="dns_before_bypass" checked',f.client.get('/lan').text)
   d['revision']=f.revision();d.pop('dns_before_bypass_present');d.pop('dns_before_bypass')
   self.assertEqual(f.client.post('/vpn-ingress/save',data=d).status_code,409)
   d['dns_before_bypass_present']='1';self.assertEqual(f.client.post('/vpn-ingress/save',data=d).status_code,302)
   self.assertFalse(json.loads((f.path/'policy.json').read_text())['vpn_ingress']['dns_before_bypass'])
  finally:f.tearDown()

 def test_empty_disabled_form_remains_supported(self):
  f=WebTests();f.setUp()
  try:
   d={'csrf':f.login(),'revision':f.revision(),'dns_before_bypass_present':'1'}
   self.assertEqual(f.client.post('/vpn-ingress/save',data=d).status_code,302)
   self.assertEqual(json.loads((f.path/'policy.json').read_text())['vpn_ingress'],{'enabled':False})
  finally:f.tearDown()
