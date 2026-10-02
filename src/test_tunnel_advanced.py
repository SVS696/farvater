import base64,copy,json,unittest
from tunnel_form import parse_outbound
from tunnel_advanced import transport_hosts
import test_web as fixtures

KEY=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
FORM={'name':'VLESS','scope':'public','type':'vless','server':'127.0.0.1','server_port':'28443','uuid':'ab61cbe2-a43a-4c2f-9357-a4e5881aa001',
      'advanced_fields':'v1','tls_enabled':'on','server_name':'vpn.example.com','tls_alpn':'h2\nhttp/1.1','tls_min_version':'1.2','tls_max_version':'1.3',
      'tls_fingerprint':'','transport_type':'','packet_encoding':'default'}
POLICY={'exits':{}}
def parse(changes=None,previous=None):return parse_outbound({**FORM,**(changes or {})},previous or {},'custom',POLICY)['native']

class AdvancedTunnelTests(unittest.TestCase):
 def test_reality_compiles_and_preserves_short_id_on_empty_input(self):
  values={'tls_reality':'on','tls_fingerprint':'chrome','reality_public_key':KEY,'reality_short_id':'aabb','flow':'xtls-rprx-vision'}
  native=parse(values);self.assertEqual(native['tls']['reality'],{'enabled':True,'public_key':KEY,'short_id':'aabb'})
  previous={'native':native};before=copy.deepcopy(previous)
  self.assertEqual(parse({**values,'reality_short_id':''},previous)['tls']['reality']['short_id'],'aabb')
  self.assertEqual(parse({**values,'clear_reality_short_id':'on'},previous)['tls']['reality']['short_id'],'')
  self.assertEqual(previous,before)

 def test_invalid_reality_and_incompatible_modes_are_rejected(self):
  base={'tls_reality':'on','tls_fingerprint':'chrome','reality_public_key':KEY,'reality_short_id':'abcd'}
  for values in [{'reality_public_key':'wrong'},{'reality_short_id':'a'},{'reality_short_id':'a'*18},{'tls_fingerprint':''},{'tls_insecure':'on'},{'transport_type':'quic'},{'flow':'xtls-rprx-vision','transport_type':'ws'}]:
   with self.subTest(values=values),self.assertRaises(ValueError):parse({**base,**values})
  with self.assertRaises(ValueError):parse({'tls_enabled':'','flow':'xtls-rprx-vision'})

 def test_websocket_headers_and_early_data_round_trip_without_disclosing_secrets(self):
  values={'transport_type':'ws','transport_path':'/vpn?ed=2560','transport_hosts':'cdn.example.com:443','transport_headers':'{"Authorization":"Bearer secret"}','transport_early_data':'2560','transport_early_header':'Sec-WebSocket-Protocol'}
  native=parse(values)
  self.assertEqual(native['transport']['headers'],{'Authorization':'Bearer secret','Host':'cdn.example.com:443'})
  self.assertEqual(transport_hosts(native),'cdn.example.com:443')
  self.assertEqual(parse({**values,'transport_headers':''},{'native':native})['transport'],native['transport'])
  cleared=parse({**values,'transport_headers':'','clear_transport_headers':'on'},{'native':native})
  self.assertEqual(cleared['transport']['headers'],{'Host':'cdn.example.com:443'})

 def test_transport_change_discards_incompatible_old_fields_and_secret_headers(self):
  old={'native':parse({'transport_type':'ws','transport_headers':'{"Authorization":"secret"}','transport_early_data':'200'})}
  result=parse({'transport_type':'grpc','transport_service_name':'TunService'},old)
  self.assertEqual(result['transport'],{'type':'grpc','service_name':'TunService'})
  result=parse({'transport_type':''},old);self.assertNotIn('transport',result)

 def test_http_hosts_upgrade_and_quic(self):
  result=parse({'transport_type':'http','transport_hosts':'example.com\n[2001:db8::1]:443','transport_method':'PUT','transport_path':'/t'})
  self.assertEqual(result['transport']['host'],['example.com','[2001:db8::1]:443'])
  self.assertEqual(result['transport']['method'],'PUT')
  self.assertEqual(parse({'transport_type':'httpupgrade','transport_hosts':'example.com'})['transport']['host'],'example.com')
  self.assertEqual(parse({'transport_type':'quic'})['transport'],{'type':'quic'})

 def test_header_injection_bad_paths_alpn_and_versions_are_rejected(self):
  for values in [{'transport_type':'ws','transport_headers':'{"X-Test":"line\\r\\nBad: value"}'},{'transport_type':'ws','transport_headers':'{"Host":"example.com"}'},{'transport_type':'ws','transport_headers':'{"X-Test":"a","x-test":"b"}'},{'transport_type':'ws','transport_hosts':'https://example.com'},{'transport_type':'ws','transport_path':'not/a/path'},{'tls_alpn':'h2\nh2'},{'tls_min_version':'1.3','tls_max_version':'1.2'},{'tls_fingerprint':'unknown'},{'tls_certificate':'not a certificate'},{'packet_encoding':'unknown'}]:
   with self.subTest(values=values),self.assertRaises(ValueError):parse(values)

 def test_native_tls_extras_are_preserved_and_certificate_clear_is_explicit(self):
  previous={'native':parse()};previous['native']['tls'].update(certificate_path='/trusted/root.pem',handshake_timeout='12s')
  result=parse({},previous);self.assertEqual(result['tls']['certificate_path'],'/trusted/root.pem');self.assertEqual(result['tls']['handshake_timeout'],'12s')
  self.assertNotIn('certificate_path',parse({'clear_tls_certificate':'on'},previous)['tls'])
  self.assertNotIn('tls',parse({'tls_enabled':''},previous))

class AdvancedTunnelWebTests(unittest.TestCase):
 setUp=fixtures.WebTests.setUp;tearDown=fixtures.WebTests.tearDown;login=fixtures.WebTests.login;revision=fixtures.WebTests.revision
 def test_form_saves_advanced_fields_and_does_not_echo_credentials(self):
  csrf=self.login();data={**FORM,'csrf':csrf,'revision':self.revision(),'transport_type':'ws','transport_hosts':'cdn.example.com','transport_path':'/vpn','transport_headers':'{"Authorization":"hidden-header-value"}','tls_reality':'on','tls_fingerprint':'chrome','reality_public_key':KEY,'reality_short_id':'1234aabb'}
  response=self.client.post('/tunnels/save',data=data);self.assertEqual(response.status_code,302)
  policy=json.loads((self.path/'policy.json').read_text());identifier=next(k for k in policy['exits'] if k!='direct')
  html=self.client.get('/tunnels/'+identifier+'/edit').text
  for value in ['hidden-header-value','1234aabb',FORM['uuid']]:self.assertNotIn(value,html)
  for value in ['Reality','WebSocket','gRPC','Authorization',KEY,'cdn.example.com']:self.assertIn(value,html)
  self.assertEqual(policy['exits'][identifier]['native']['transport']['headers']['Authorization'],'hidden-header-value')

if __name__=='__main__':unittest.main()
