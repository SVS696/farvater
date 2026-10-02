import copy,io,json,unittest
from policy_exchange import encode,decode,remove,references
import test_web as fixture

class ExchangeTests(unittest.TestCase):
 tearDown=fixture.WebTests.tearDown
 login=fixture.WebTests.login
 revision=fixture.WebTests.revision
 def setUp(self):
  fixture.WebTests.setUp(self);self.policy['failover']['dns_by_exit']={'direct':'isp'};(self.path/'policy.json').write_text(json.dumps(self.policy))
 def test_export_import_preview_is_private_and_does_not_change_until_confirm(self):
  token=self.login();self.policy['exits']['spare']={'name':'Spare','scope':'public','native':{'type':'socks','server':'192.0.2.4','server_port':1080,'password':'PRIVATE-FIXTURE'}}
  (self.path/'policy.json').write_text(json.dumps(self.policy))
  result=self.client.post('/configuration/export',data={'csrf':token,'revision':self.revision()})
  self.assertEqual(result.status_code,200);self.assertEqual(decode(result.data),self.policy)
  incoming=copy.deepcopy(self.policy);incoming['exits']['spare']['name']='Imported'
  before=(self.path/'policy.json').read_bytes();revision=self.revision()
  response=self.client.post('/configuration/import',data={'csrf':token,'revision':revision,'configuration':(io.BytesIO(encode(incoming).encode()),'settings.json')})
  self.assertEqual(response.status_code,200);self.assertNotIn('PRIVATE-FIXTURE',response.text);self.assertEqual((self.path/'policy.json').read_bytes(),before)
  preview=json.loads((self.path/'policy-import.json').read_text());self.assertEqual((self.path/'policy-import.json').stat().st_mode&0o777,0o600)
  fields={'csrf':token,'revision':revision,'token':preview['token'],'confirm':'on'}
  self.assertEqual(self.client.post('/configuration/confirm',data={**fields,'token':'wrong'}).status_code,409)
  self.assertEqual(self.client.post('/configuration/confirm',data=fields).status_code,302)
  self.assertEqual(json.loads((self.path/'policy.json').read_text()),incoming)
  self.assertEqual(json.loads((self.path/'policy.before-import.json').read_text()),self.policy)
 def test_invalid_file_stale_preview_and_deletion_references(self):
  token=self.login();revision=self.revision()
  for raw in [b'[]',b'{"format":"a","format":"b"}',b'{"x":NaN}',encode({**self.policy,'profiles':[{'id':['bad']}]}).encode()]:
   r=self.client.post('/configuration/import',data={'csrf':token,'revision':revision,'configuration':(io.BytesIO(raw),'bad.json')});self.assertEqual(r.status_code,400)
  self.assertEqual(self.client.post('/configuration/export',data={}).status_code,403)
  self.assertEqual(self.client.post('/configuration/import',data={'csrf':token,'revision':revision,'configuration':(io.BytesIO(encode(self.policy).encode()),'settings.json')}).status_code,200)
  preview=json.loads((self.path/'policy-import.json').read_text());self.policy['extra']='Changed';(self.path/'policy.json').write_text(json.dumps(self.policy))
  r=self.client.post('/configuration/confirm',data={'csrf':token,'revision':revision,'token':preview['token'],'confirm':'on'});self.assertEqual(r.status_code,409)
  for group,key in [('exits','direct'),('dns','isp')]:
   self.assertIn('используется',self.client.get(f'/configuration/{group}/{key}/delete').text)
   self.assertEqual(self.client.post(f'/configuration/{group}/{key}/delete',data={'csrf':token,'revision':self.revision(),'confirm':'on'}).status_code,409)
 def test_unused_entity_delete_and_disabled_rule_dependency(self):
  token=self.login();self.policy['dns']['unused']={'name':'Extra','scope':'public'}
  (self.path/'policy.json').write_text(json.dumps(self.policy))
  self.assertEqual(self.client.post('/configuration/dns/unused/delete',data={'csrf':token,'revision':self.revision(),'confirm':'on'}).status_code,302)
  self.assertNotIn('unused',json.loads((self.path/'policy.json').read_text())['dns'])
  self.policy['exits']['spare']={'name':'Spare','scope':'public'}
  self.policy['profiles']=[{'id':'rule','name':'Disabled','enabled':False,'exit':'spare','dns':'unused','fallback':[],'fallback_pairs':[]}]
  self.assertTrue(references(self.policy,'exits','spare'));self.assertTrue(references(self.policy,'dns','unused'))
  with self.assertRaises(ValueError):remove(self.policy,'exits','spare')
 def test_rule_delete_requires_confirmation_and_preserves_default(self):
  token=self.login();self.policy['profiles']=[{'id':'work','kind':'work','name':'Work','exit':'direct','dns':'isp','domains':['work.example']}]
  (self.path/'policy.json').write_text(json.dumps(self.policy))
  fields={'csrf':token,'revision':self.revision()}
  self.assertEqual(self.client.post('/rules/work/delete',data=fields).status_code,400)
  self.assertEqual(self.client.post('/rules/__default__/delete',data={**fields,'confirm':'on'}).status_code,400)
  self.assertEqual(self.client.post('/rules/work/delete',data={**fields,'confirm':'on'}).status_code,302)
  self.assertEqual(json.loads((self.path/'policy.json').read_text())['profiles'],[])
 def test_native_bootstrap_and_reserve_references(self):
  p=copy.deepcopy(self.policy);p['exits']['second']={'name':'Second','scope':'public','native':{'type':'socks','domain_resolver':{'server':'isp'}}}
  self.assertIn('Подключение «Second»',references(p,'dns','isp'))
  p['dns']['other']={'name':'Other','scope':'public','native':{'type':'udp','detour':'second'}}
  self.assertIn('DNS «Other»',references(p,'exits','second'))
  p['profiles']=[{'id':'rule','name':'Fallback','exit':'direct','dns':'isp','fallback_pairs':[{'exit':'second','dns':'other'}]}]
  self.assertIn('Правило «Fallback»',references(p,'exits','second'))

if __name__=='__main__':unittest.main()
