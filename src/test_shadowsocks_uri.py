import base64,copy,io,json,unittest
from urllib.parse import quote
from shadowsocks_uri import parse,render
from web import create_app
import test_web as base

class UriTests(unittest.TestCase):
 def setUp(self):self.outbound={'name':'VPN + Япония','native':{'type':'shadowsocks','server':'2001:db8::1','server_port':443,'method':'aes-256-gcm','password':'private:@/% пароль'}}
 def test_aead_and_plain_userinfo_roundtrip_ipv6_unicode_reserved(self):
  uri=render(self.outbound);self.assertTrue(uri.startswith('ss://'));self.assertNotIn(self.outbound['native']['password'],uri)
  self.assertEqual(parse(uri)['native'],self.outbound['native']);self.assertEqual(parse(uri)['name'],self.outbound['name'])
  plain='ss://aes-256-gcm:'+quote(self.outbound['native']['password'],safe='')+'@[2001:db8::1]:443#'+quote(self.outbound['name'],safe='')
  self.assertEqual(parse(plain)['native'],self.outbound['native'])
  padded=quote(base64.urlsafe_b64encode(b'aes-256-gcm:hello').decode(),safe='')
  self.assertEqual(parse('ss://'+padded+'@vpn.test:443')['native']['password'],'hello')
 def test_2022_uses_percent_encoding_and_checks_keys(self):
  for method,length in [('2022-blake3-aes-128-gcm',16),('2022-blake3-aes-256-gcm',32),('2022-blake3-chacha20-poly1305',32)]:
   p=copy.deepcopy(self.outbound);p['native'].update(method=method,password=base64.b64encode(bytes([251])*length).decode())
   uri=render(p);self.assertTrue(uri.startswith('ss://2022-'));self.assertEqual(parse(uri)['native'],p['native'])
   encoded=base64.urlsafe_b64encode((method+':'+p['native']['password']).encode()).decode()
   with self.assertRaises(ValueError):parse('ss://'+encoded+'@vpn.test:443')
   p['native']['password']='short'
   with self.assertRaises(ValueError):render(p)
 def test_unknown_or_unrepresentable_settings_are_never_lost(self):
  for field,value in [('bind_interface','wg0'),('plugin','obfs-local'),('network','tcp'),('multiplex',{'enabled':True}),('domain_resolver','internal')]:
   p=copy.deepcopy(self.outbound);p['native'][field]=value
   with self.assertRaises(ValueError):render(p)
  baseuri=render(self.outbound).split('#')[0]
  for suffix in ['/?plugin=obfs-local','?unknown=value','?','/bad']:
   with self.assertRaises(ValueError):parse(baseuri+suffix)
 def test_malformed_links_rejected_without_echoing_secret(self):
  cases=['ss://%%%SECRET@host:443','ss://aes-256-gcm:SECRET@host:0','ss://aes-256-gcm:SECRET@host','ss://aes-256-gcm:SECRET@host:443#%ff','ss://aes-256-gcm:SECRET@host:443#%zz','ss://aes-256-gcm:SECRET@host:443#bad name','https://x','ss://aes-256-gcm:SECRET@x@host:443','ss://aes-256-gcm:SECRET@host:443#%0a']
  for uri in cases:
   with self.subTest(uri=uri):
    with self.assertRaises(ValueError) as caught:parse(uri)
    self.assertNotIn('SECRET',str(caught.exception))

class WebTests(unittest.TestCase):
 login=base.WebTests.login;revision=base.WebTests.revision
 def setUp(self):
  base.WebTests.setUp(self);self.outbound={'name':'Link import','native':{'type':'shadowsocks','server':'192.0.2.1','server_port':443,'method':'aes-256-gcm','password':'PRIVATE-link-password'}}
 def tearDown(self):base.WebTests.tearDown(self)
 def test_import_export_use_saved_draft_no_apply_no_secret_html(self):
  self.assertEqual(self.client.get('/shadowsocks-import').status_code,302);csrf=self.login();uri=render(self.outbound)
  r=self.client.post('/shadowsocks-import',data={'csrf':csrf,'revision':self.revision(),'uri':uri,'scope':'public'});self.assertEqual(r.status_code,302)
  policy=json.loads((self.path/'policy.json').read_text());key=next(k for k in policy['exits'] if k!='direct')
  self.assertEqual(policy['default_exit'],'direct');self.assertEqual(policy['profiles'],[])
  html=self.client.get(r.location);self.assertNotIn('PRIVATE-link-password',html.text)
  before=(self.path/'policy.json').read_bytes();r=self.client.post('/tunnels/'+key+'/export-ss',data={'csrf':csrf,'revision':self.revision()})
  self.assertEqual(r.status_code,200);self.assertEqual(r.text,uri);self.assertEqual(r.headers['Cache-Control'],'no-store');self.assertEqual(before,(self.path/'policy.json').read_bytes())
 def test_file_import_stale_revision_csrf_and_unknown_fields(self):
  csrf=self.login();uri=render(self.outbound);fields={'csrf':csrf,'revision':self.revision(),'scope':'work'}
  r=self.client.post('/shadowsocks-import',data={**fields,'connection_file':(io.BytesIO(uri.encode()),'ss.txt')});self.assertEqual(r.status_code,302)
  before=(self.path/'policy.json').read_bytes()
  r=self.client.post('/shadowsocks-import',data={**fields,'uri':uri});self.assertEqual(r.status_code,409)
  r=self.client.post('/shadowsocks-import',data={**fields,'csrf':'bad','uri':uri});self.assertEqual(r.status_code,403)
  r=self.client.post('/shadowsocks-import',data={**fields,'revision':self.revision(),'uri':uri.split('#')[0]+'?plugin=evil'});self.assertEqual(r.status_code,400)
  self.assertEqual(before,(self.path/'policy.json').read_bytes())

if __name__=='__main__':unittest.main()
