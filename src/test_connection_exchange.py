import copy,io,json,unittest
from openconnect_exchange import import_native,to_model,from_model,export_native
from openconnect_profile import DEFAULT
from native_exchange import decode
import test_web as fixture

class Formats(unittest.TestCase):
 def test_openconnect_standard_bundle_roundtrip(self):
  model={**copy.deepcopy(DEFAULT),'server':'https://vpn.example.com','username':'worker','password':'private','mtu':1300,'no_dtls':True}
  native=from_model(model,'isp');restored=import_native(export_native(native),'native-bundle','isp')
  self.assertEqual(to_model(restored),model)
  plain=import_native('server=https://vpn.example.com\nuser=worker\nno-dtls','conf','isp')
  self.assertEqual(plain['username'],'worker');self.assertNotIn('password',plain)
  xml='<AnyConnectProfile><ServerList><HostEntry><HostAddress>vpn.example.com</HostAddress><UserGroup>work</UserGroup></HostEntry></ServerList></AnyConnectProfile>'
  self.assertEqual(import_native(xml,'xml','isp')['server'],'https://vpn.example.com/work')
 def test_nonportable_native_or_oc_settings_rejected_without_loss(self):
  native=from_model({**copy.deepcopy(DEFAULT),'server':'https://vpn.example.com','username':'worker','password':'private'},'isp')
  for changed in [{**native,'tcp_keep_alive_enabled':True},{**native,'tls':{'insecure':True}},{**native,'unknown_extension':True}]:
   with self.assertRaises(ValueError):export_native(changed)
  for raw in [b'{}',b'{"outbounds":[]}',b'{"outbounds":[{"type":"http","tls":{"certificate_path":"/private"}}]}',b'{"endpoints":[{"type":"openconnect","server":"https://vpn.example","csd":{"wrapper_path":"/bin/x"}}]}']:
   with self.assertRaises(ValueError):decode(raw,'new')
 def test_invalid_basic_parameters_rejected(self):
  for native in [{'type':'http','server':'vpn.example','server_port':70000},{'type':'vless','server':'vpn.example','server_port':443,'uuid':'invalid'},{'type':'shadowsocks','server':'vpn.example','server_port':443,'method':'unknown','password':'x'},{'type':'selector','outbounds':['one','one']}]:
   with self.assertRaises(ValueError):decode(json.dumps({'outbounds':[native]}).encode(),'new')
 def test_native_fragment_preserves_all_fields(self):
  native={'type':'vless','tag':'old','server':'192.0.2.1','server_port':443,'uuid':'e34e7d31-58aa-4ccf-9706-42d3b17a93e2','tls':{'enabled':True,'server_name':'vpn.example'},'transport':{'type':'ws','path':'/proxy'}}
  restored=decode(json.dumps({'outbounds':[native]}).encode(),'new');self.assertEqual(restored,{**native,'tag':'new'})

class WebExchange(unittest.TestCase):
 setUp=fixture.WebTests.setUp
 tearDown=fixture.WebTests.tearDown
 login=fixture.WebTests.login
 revision=fixture.WebTests.revision
 def test_import_export_embedded_and_native_json_are_draft_only(self):
  token=self.login();revision=self.revision()
  response=self.client.post('/openconnect-import',data={'csrf':token,'revision':revision,'name':'Portable VPN','scope':'work','resolver':'isp','format':'conf','connection_file':(io.BytesIO(b'server=https://vpn.example.com\nuser=worker'),'vpn.conf')})
  self.assertEqual(response.status_code,302)
  policy=json.loads((self.path/'policy.json').read_text());key=next(k for k in policy['exits'] if k!='direct')
  policy['exits'][key]['native']['password']='not-in-html';(self.path/'policy.json').write_text(json.dumps(policy))
  response=self.client.get(response.location);self.assertNotIn('not-in-html',response.text)
  exported=self.client.post('/tunnels/'+key+'/export-native',data={'csrf':token,'revision':self.revision(),'format':'openconnect'})
  self.assertEqual(exported.status_code,200);self.assertTrue(exported.data.startswith(b'PK'))
  exported=self.client.post('/tunnels/'+key+'/export-native',data={'csrf':token,'revision':self.revision(),'format':'json'})
  self.assertIn('endpoints',json.loads(exported.data))
  response=self.client.post('/connections/import-native',data={'csrf':token,'revision':self.revision(),'name':'Copy VPN','scope':'work','connection_file':(io.BytesIO(exported.data),'vpn.json')})
  self.assertEqual(response.status_code,302);self.assertEqual(len(json.loads((self.path/'policy.json').read_text())['exits']),3)

if __name__=='__main__':unittest.main()
