import copy
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from health_settings import edit_check,form_fields,read_settings,fingerprint
from monitor_control import control
from health_collect import checked,probe,main
import test_web
from web import create_app
from candidate_remote import RemoteError

CHECK={'id':'dns:test','name':'DNS test','scope':'Test','action':'Check DNS','kind':'dns',
       'server':'127.0.0.1','port':5301,'domain':'example.com'}

def values(check):
 return {f['key']:(f['value'] if f['type']=='bool' else str(f['value'])) for f in form_fields(check)}

class MonitorSettingsTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  (self.root/'checks.json').write_text(json.dumps({'checks':[CHECK]}))
  self.row={**{k:CHECK[k] for k in ('id','name','scope','action')},'status':'up','detail':'old',
            'observed_at':1000,'duration_ms':2,'definition_sha256':fingerprint(CHECK)}
  self.snapshot={'version':1,'generated_at':1000,'checks':[self.row]}
  (self.root/'health.json').write_text(json.dumps(self.snapshot));(self.root/'health.json').chmod(0o640)
 def tearDown(self):self.temp.cleanup()
 def status(self):return control({'version':1,'action':'monitor-status','check_id':CHECK['id']},self.root)
 def save(self,v,revision=None):
  return control({'version':1,'action':'monitor-set','check_id':CHECK['id'],'revision':revision or self.status()['revision'],'values':v},self.root)

 def test_edit_is_cas_and_invalidates_old_success_without_changing_file_access(self):
  old=(self.root/'checks.json').read_bytes();revision=self.status()['revision'];v=values(CHECK);v['domain']='changed.test'
  result=self.save(v,revision)
  self.assertNotEqual(result['revision'],revision)
  self.assertEqual((self.root/'checks.previous.json').read_bytes(),old)
  self.assertEqual((self.root/'health.json').stat().st_mode & 0o777,0o640)
  self.assertEqual(json.loads((self.root/'health.json').read_text())['checks'][0]['status'],'unknown')
  with self.assertRaises(ValueError):self.save(v,revision)

 def test_noop_does_not_invalidate_fresh_sample(self):
  self.save(values(CHECK))
  (self.root/'health.json').write_text(json.dumps(self.snapshot))
  current=read_settings(self.root)[0]['checks'][0]
  self.save(values(current))
  self.assertEqual(json.loads((self.root/'health.json').read_text())['checks'][0]['status'],'up')

 def test_invalid_edit_is_rejected_before_invalidation(self):
  old=(self.root/'checks.json').read_bytes();health=(self.root/'health.json').read_bytes()
  for key,value in [('server','@evil.test'),('domain','-f /secret'),('domain','x\ny'),('port','0'),('timeout_seconds','50'),('tcp','true')]:
   v=values(CHECK);v[key]=value
   with self.assertRaises(ValueError):self.save(v)
  v=values(CHECK);v['command']='anything'
  with self.assertRaises(ValueError):self.save(v)
  self.assertEqual((self.root/'checks.json').read_bytes(),old);self.assertEqual((self.root/'health.json').read_bytes(),health)

 def test_http_credentials_options_unsupported_schemes_and_inconsistent_timeouts_rejected(self):
  check={**CHECK,'kind':'https','url':'https://example.com','observe_ip':True}
  self.assertEqual(edit_check(check,values(check))['codes'],['200'])
  for key,value in [('url','file:///etc/shadow'),('url','http://example.com'),('url','https://user:secret@example.com'),('url','https://example.com/?token=secret'),('url','https://example.com/{one,two}'),('proxy','--config /secret'),('proxy','[[::1]]:1080'),('proxy','[127.0.0.1]:1080'),('proxy','::1:1080'),('codes','200,302'),('timeout_seconds','1')]:
   v=values(check);v[key]=value
   with self.assertRaises(ValueError):edit_check(check,v)
  v=values(check);v['proxy']='[::1]:1080';self.assertEqual(edit_check(check,v)['proxy'],'[::1]:1080')
  service={**CHECK,'kind':'service','unit':'example.service'}
  v=values(service);v['unit']='--all'
  with self.assertRaises(ValueError):edit_check(service,v)

 def test_inflight_old_measurement_cannot_publish_success_for_new_settings(self):
  def measure(checks,previous,**kwargs):
   updated={**CHECK,'domain':'changed.test'}
   (self.root/'checks.json').write_text(json.dumps({'checks':[updated]}))
   return copy.deepcopy(self.snapshot),[{'at':1000,'id':CHECK['id'],'name':CHECK['name'],'status':'up','detail':'old'}]
  with patch('sys.argv',['health_collect.py','--root',str(self.root)]),patch('health_collect.candidate_runtime_inputs',side_effect=OSError()),patch('health_collect.collect',side_effect=measure):main()
  result=json.loads((self.root/'health.json').read_text())
  self.assertEqual(result['checks'][0]['status'],'unknown');self.assertEqual(result['events'],[])

 def test_selected_timeouts_and_expectations_reach_probe(self):
  with patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,';; status: NOERROR\nx 5 IN A 192.0.2.1\n','')) as run:
   self.assertEqual(probe({**CHECK,'timeout_seconds':5})[0],'up')
   self.assertIn('+time=5',run.call_args.args[0]);self.assertEqual(run.call_args.args[1],7)
  with patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,'302\t0.001\t0.01\t0.05\t0.06\t0.07','')) as run:
   self.assertEqual(probe({'kind':'https','url':'https://example.com','timeout_seconds':4,'connect_timeout_seconds':3,'codes':['302']})[0],'up')
   args=run.call_args.args[0];self.assertEqual(args[args.index('--max-time')+1],'4');self.assertIn('--globoff',args)

 def test_resource_thresholds_and_plain_http_are_not_reported_as_tls(self):
  with patch('health_collect.os.statvfs',return_value=SimpleNamespace(f_bavail=10*2**30,f_frsize=1)),patch('health_collect.Path.read_text',return_value='MemAvailable: 128000 kB\n'):
   self.assertEqual(probe({'kind':'resources','disk_warning_gib':5,'memory_warning_mib':0})[0],'up')
   self.assertEqual(probe({'kind':'resources','disk_warning_gib':20,'memory_warning_mib':0})[0],'degraded')
   self.assertEqual(probe({'kind':'resources','disk_warning_gib':5,'memory_warning_mib':256})[0],'degraded')
  with patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,'200\t0.001\t0.01\t0.05\t0.06\t0.07','')):
   self.assertIn('не использует TLS',probe({'kind':'https','url':'http://example.com'})[1])

class MonitorWebTests(unittest.TestCase):
 login=test_web.WebTests.login
 tearDown=test_web.WebTests.tearDown
 def setUp(self):
  test_web.WebTests.setUp(self);self.monitor=self.path/'monitor';self.monitor.mkdir()
  (self.monitor/'checks.json').write_text(json.dumps({'checks':[CHECK]}))
  root=self.monitor
  class Remote:
   def call(self,action,**fields):
    try:return control({'version':1,'action':action,**fields},root)
    except ValueError as error:raise RemoteError(str(error))
  self.app=create_app(self.path,candidate=Remote());self.app.testing=True;self.client=self.app.test_client()
 def test_edit_page_auth_csrf_save_and_stale_revision(self):
  self.assertEqual(self.client.get('/health/settings').status_code,302)
  token=self.login();page=self.client.get('/health/settings/dns:test')
  self.assertIn('Проверочное имя',page.text);self.assertNotIn('http-equiv="refresh"',page.text)
  revision=read_settings(self.monitor)[1]
  data={**values(CHECK),'csrf':token,'revision':revision,'domain':'new.example'};data.pop('tcp')
  self.assertEqual(self.client.post('/health/settings/dns:test',data={}).status_code,403)
  self.assertEqual(self.client.post('/health/settings/dns:test',data=data).status_code,302)
  self.assertEqual(read_settings(self.monitor)[0]['checks'][0]['domain'],'new.example')
  data['domain']='stale.example'
  response=self.client.post('/health/settings/dns:test',data=data,follow_redirects=True)
  self.assertIn('уже изменились',response.text)
  self.assertEqual(read_settings(self.monitor)[0]['checks'][0]['domain'],'new.example')

if __name__=='__main__':unittest.main()
