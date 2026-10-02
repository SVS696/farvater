import io,json,copy,unittest
import test_web as base
from test_openvpn_format import BASIC
from openvpn_format import parse
from openvpn_profile import form_view
from candidate_config import build_candidate_config
from native_endpoints import validate_bootstrap
from dns_form import parse_dns

class OpenVPNWebTests(unittest.TestCase):
 login=base.WebTests.login
 revision=base.WebTests.revision
 tearDown=base.WebTests.tearDown
 def fields(self,**kw):
  return {'csrf':self.csrf,'revision':self.revision(),'name':'Test VPN','scope':'public',**kw}
 def setUp(self):
  base.WebTests.setUp(self);self.csrf=self.login()
 def import_profile(self,raw=BASIC,**kw):
  return self.client.post('/openvpn/import',data=self.fields(connection_file=(io.BytesIO(raw.encode()),'profile.ovpn'),**kw))
 def test_native_import_export_edit_and_secrets(self):
  self.assertEqual(self.client.get('/openvpn-new').status_code,200)
  r=self.import_profile(BASIC+'auth-user-pass auth.txt\n',related_files=(io.BytesIO(b'user\n PRIVATE pass \n'),'auth.txt'))
  self.assertEqual(r.status_code,302)
  identifier=r.location.split('/')[-2];html=self.client.get(r.location).text
  self.assertIn('OpenVPN',html);self.assertNotIn('PRIVATE pass',html)
  before=(self.path/'policy.json').read_bytes()
  r=self.client.post('/openvpn/export',data=self.fields(id=identifier))
  self.assertEqual(r.status_code,200);self.assertEqual(r.headers['Cache-Control'],'no-store')
  native=parse(r.text)['native'];self.assertEqual(native['password'],' PRIVATE pass ')
  self.assertEqual(before,(self.path/'policy.json').read_bytes())
  form=self.fields(id=identifier)
  for _,rows in form_view(native):
   for row in rows:
    if row['kind']=='bool':
     if row['value']:form['ov_'+row['path']]='on'
    else:form['ov_'+row['path']]=str(row['value'])
  r=self.client.post('/openvpn/save',data=form);self.assertEqual(r.status_code,302)
  saved=json.loads((self.path/'policy.json').read_text())['exits'][identifier]
  self.assertEqual(saved['native']['password'],native['password'])
 def test_bad_profile_revision_csrf_and_paths_do_not_mutate(self):
  before=(self.path/'policy.json').read_bytes()
  for extra,kw in [('up /tmp/run\n',{}),('auth-user-pass\n',{}),('',{'revision':'stale'}),('',{'csrf':'bad'}),('ca other.pem\n',{'related_files':(io.BytesIO(b'no'),'../other.pem')})]:
   r=self.import_profile(BASIC+extra,**kw);self.assertIn(r.status_code,[400,403,409])
   self.assertEqual(before,(self.path/'policy.json').read_bytes())
 def test_hostname_requires_independent_dns(self):
  raw=BASIC.replace('192.0.2.1','vpn.example.com')
  self.assertEqual(self.import_profile(raw).status_code,400)
  self.assertEqual(self.import_profile(raw,domain_resolver='isp').status_code,302)

class CompileTests(unittest.TestCase):
 def policy(self):
  return {'default_exit':'vpn','default_dns':'vpn-dns','exits':{'vpn':{'name':'VPN','scope':'public',**parse(BASIC)}},'dns':{'isp':{'name':'ISP','scope':'public','native':{'type':'udp','server':'192.0.2.53'}},'vpn-dns':{'name':'VPN DNS','scope':'public','native':{'type':'openvpn','endpoint':'vpn'}}},'profiles':[]}
 def test_endpoint_placement_and_dns_reference(self):
  p=self.policy();r=build_candidate_config(p,api_secret='x'*32,default_filtering=False)['config']
  self.assertEqual(r['endpoints'][0]['type'],'openvpn-client')
  self.assertFalse(any(x['type']=='openvpn-client' for x in r['outbounds']))
  p['dns']['vpn-dns']['native']['endpoint']='missing'
  with self.assertRaises(ValueError):build_candidate_config(p,api_secret='x'*32,default_filtering=False)
 def test_bootstrap_cycle_and_fakeip_are_rejected(self):
  p=self.policy();native=p['exits']['vpn']['native'];native['domain_resolver']='vpn-dns'
  with self.assertRaisesRegex(ValueError,'этого же VPN'):validate_bootstrap(p)
  native['domain_resolver']='isp';validate_bootstrap(p)
  p['dns']['isp']['native']={'type':'fakeip'}
  with self.assertRaises(ValueError):validate_bootstrap(p)
 def test_pushed_dns_form_requires_openvpn(self):
  p=self.policy();form={'type':'openvpn','scope':'public','name':'VPN DNS','endpoint':'vpn','accept_default_resolvers':'on'}
  result=parse_dns(form,{},'vpn-dns',p)
  self.assertEqual(result['native']['endpoint'],'vpn');self.assertTrue(result['native']['accept_default_resolvers'])
  form['endpoint']='missing'
  with self.assertRaises(ValueError):parse_dns(form,{},'vpn-dns',p)

if __name__=='__main__':unittest.main()
