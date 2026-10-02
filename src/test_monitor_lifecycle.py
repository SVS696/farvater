import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_monitor_settings as fixtures
from health_settings import edit_check,new_check,form_fields,read_settings,fingerprint
from health_collect import collect,main
from health_model import present_snapshot,validate_snapshot
from monitor_control import control

class LifecycleTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  self.check=copy.deepcopy(fixtures.CHECK)
  (self.root/'checks.json').write_text(json.dumps({'checks':[self.check]}))
 def tearDown(self):self.temp.cleanup()
 def call(self,action,**fields):return control({'version':1,'action':action,**fields},self.root)
 def revision(self):return read_settings(self.root)[1]
 def add(self):
  check=new_check('dns','')
  return self.call('monitor-add',kind='dns',revision=self.revision(),values={**fixtures.values(check),'domain':'example.com','interval_seconds':'60'})

 def test_create_edit_delete_cas_and_protected_checks(self):
  old=self.revision();result=self.add();identifier=result['selected']['id']
  self.assertTrue(result['selected']['removable']);self.assertEqual(len(result['checks']),2)
  stored=read_settings(self.root)[0]['checks'][-1];self.assertEqual(stored['interval_seconds'],60)
  for action,fields in [('monitor-remove',{'check_id':identifier}),('monitor-add',{'kind':'dns','values':fixtures.values(stored)})]:
   with self.assertRaisesRegex(ValueError,'уже изменились'):self.call(action,revision=old,**fields)
  with self.assertRaisesRegex(ValueError,'обязательные'):self.call('monitor-remove',check_id=self.check['id'],revision=self.revision())
  with self.assertRaisesRegex(ValueError,'нельзя добавить'):self.call('monitor-add',kind='runtime',revision=self.revision(),values={})
  self.call('monitor-remove',check_id=identifier,revision=self.revision())
  self.assertEqual(read_settings(self.root)[0]['checks'],[self.check])

 def test_new_check_is_unknown_immediately_and_deleted_check_disappears(self):
  (self.root/'health.json').write_text(json.dumps({'version':1,'generated_at':1000,'checks':[]}))
  result=self.add();identifier=result['selected']['id']
  snapshot=json.loads((self.root/'health.json').read_text());validate_snapshot(snapshot)
  self.assertEqual(snapshot['checks'][0]['status'],'unknown')
  self.call('monitor-remove',check_id=identifier,revision=self.revision())
  self.assertEqual(json.loads((self.root/'health.json').read_text())['checks'],[])

 def test_period_skips_network_without_refreshing_observation_and_rechecks_on_due_or_edit(self):
  check={**self.check,'interval_seconds':60}
  with patch('health_collect.time.time',return_value=1000),patch('health_collect.probe',return_value=('up','ok')):
   first,_=collect([check])
  with patch('health_collect.time.time',return_value=1020),patch('health_collect.probe') as probe:
   second,events=collect([check],first)
  probe.assert_not_called();self.assertEqual(events,[])
  self.assertEqual(second['checks'][0]['observed_at'],1000);self.assertTrue(second['checks'][0]['scheduled'])
  with patch('health_collect.time.time',return_value=1060),patch('health_collect.probe',return_value=('down','unreachable')) as probe:
   third,events=collect([check],second)
  probe.assert_called_once();self.assertEqual(third['checks'][0]['status'],'down');self.assertEqual(len(events),1)
  with patch('health_collect.time.time',return_value=1021),patch('health_collect.probe',return_value=('up','new')) as probe:
   fourth,_=collect([{**check,'domain':'changed.test'}],second)
  probe.assert_called_once();self.assertEqual(fourth['checks'][0]['observed_at'],1021)

 def test_long_period_preserves_time_but_stopped_collector_still_goes_stale(self):
  check={**self.check,'interval_seconds':300}
  with patch('health_collect.time.time',return_value=1000),patch('health_collect.probe',return_value=('up','ok')):snapshot,_=collect([check])
  path=self.root/'health.json';snapshot['generated_at']=1250;path.write_text(json.dumps(snapshot))
  self.assertEqual(present_snapshot(path,now=1250)['checks'][0]['status'],'up')
  snapshot['generated_at']=1400;path.write_text(json.dumps(snapshot))
  self.assertEqual(present_snapshot(path,now=1451)['checks'][0]['status'],'stale')
  snapshot['generated_at']=1050;path.write_text(json.dumps(snapshot))
  self.assertEqual(present_snapshot(path,now=1250)['checks'][0]['status'],'stale')
  for period in (True,0,301,'300'):
   snapshot['checks'][0]['interval_seconds']=period
   with self.assertRaises(ValueError):validate_snapshot(snapshot)

 def test_inflight_collection_cannot_resurrect_deleted_or_hide_new_check(self):
  identifier=self.add()['selected']['id'];checks=read_settings(self.root)[0]['checks']
  def measure(definitions,previous,**kwargs):
   self.call('monitor-remove',check_id=identifier,revision=self.revision())
   self.add()
   with patch('health_collect.probe',return_value=('up','old')):return collect(definitions)
  with patch('sys.argv',['collect','--root',str(self.root)]),patch('health_collect.candidate_runtime_inputs',side_effect=OSError()),patch('health_collect.collect',side_effect=measure):main()
  snapshot=json.loads((self.root/'health.json').read_text());rows={r['id']:r for r in snapshot['checks']}
  current=read_settings(self.root)[0]['checks'][-1]['id']
  self.assertNotIn(identifier,rows);self.assertEqual(rows[current]['status'],'unknown')
  self.assertFalse(any(e['id']==identifier for e in snapshot['events']))

 def test_new_boot_discards_scheduled_result_from_previous_boot(self):
  check={**self.check,'interval_seconds':300}
  (self.root/'checks.json').write_text(json.dumps({'checks':[check]}))
  with patch('health_collect.time.time',return_value=1000),patch('health_collect.probe',return_value=('up','before reboot')):snapshot,_=collect([check])
  snapshot['boot_id']='old-boot';(self.root/'health.json').write_text(json.dumps(snapshot))
  original=Path.read_text
  def read(path,*args,**kwargs):return 'new-boot' if str(path)=='/proc/sys/kernel/random/boot_id' else original(path,*args,**kwargs)
  with patch('sys.argv',['collect','--root',str(self.root)]),patch('health_collect.candidate_runtime_inputs',side_effect=OSError()),patch.object(Path,'read_text',read),patch('health_collect.time.time',return_value=1020),patch('health_collect.probe',return_value=('down','after reboot')) as probe:main()
  probe.assert_called_once();result=json.loads((self.root/'health.json').read_text())
  self.assertEqual(result['boot_id'],'new-boot');self.assertEqual(result['checks'][0]['status'],'down')

 def test_reboot_rechecks_without_emitting_unchanged_baseline_events(self):
  check={**self.check,'interval_seconds':300}
  with patch('health_collect.time.time',return_value=1000),patch('health_collect.probe',return_value=('up','same')):first,_=collect([check])
  with patch('health_collect.time.time',return_value=1010),patch('health_collect.probe',return_value=('up','same')) as probe:second,events=collect([check],first,reuse=False)
  probe.assert_called_once();self.assertEqual(second['checks'][0]['observed_at'],1010);self.assertEqual(events,[])

 def test_missed_long_period_probe_retries_and_tail_checks_get_their_turn(self):
  import time,threading
  checks=[{**self.check,'id':'test:'+str(i),'interval_seconds':300} for i in range(12)]
  calls=[];lock=threading.Lock()
  def slow(check):
   with lock:calls.append(check['id'])
   time.sleep(.03)
   return {**{k:check[k] for k in ('id','name','scope','action')},'status':'up','detail':'ok','observed_at':time.time(),'duration_ms':30,'definition_sha256':fingerprint(check)}
  with patch('health_collect.checked',side_effect=slow):first,_=collect(checks,deadline_seconds=.01)
  missed=[r for r in first['checks'] if r['id'] not in calls]
  self.assertTrue(missed);self.assertTrue(all('next_check_at' not in r and 'due_since' in r for r in first['checks']))
  # A normal full cycle gives the previously missed jobs priority over recent ones.
  first['checks'][0].pop('due_since');first['checks'][0]['next_check_at']=time.time()-0.001
  calls.clear()
  with patch('health_collect.checked',side_effect=slow):second,_=collect(checks,first,deadline_seconds=1)
  self.assertNotEqual(calls[0],checks[0]['id']);self.assertEqual(set(calls),{c['id'] for c in checks})
  self.assertTrue(all(r['status']=='up' for r in second['checks']))

class LifecycleWebTests(unittest.TestCase):
 setUp=fixtures.MonitorWebTests.setUp
 tearDown=fixtures.MonitorWebTests.tearDown
 login=fixtures.MonitorWebTests.login
 def test_generic_probe_survives_without_external_router_integration(self):
  from unittest.mock import Mock
  from router_settings import DEFAULT,status_view
  from web import create_app
  check={**fixtures.CHECK,'id':'router:giga','kind':'icmp','host':'192.168.2.1'}
  (self.monitor/'checks.json').write_text(json.dumps({'checks':[check]}))
  root=self.monitor
  class Remote:
   def call(self,action,**fields):return control({'version':1,'action':action,**fields},root)
  router_check={**DEFAULT,'id':'router:giga'}
  router=Mock();router.status.return_value=status_view({'check':router_check,'revision':fingerprint(router_check),'persistent_matches':True})
  self.app=create_app(self.path,candidate=Remote(),router_monitor=router);self.app.testing=True;self.client=self.app.test_client()
  token=self.login();page=self.client.get('/health/settings').text
  self.assertIn('/health/settings/server:router:giga',page);self.assertNotIn('href="/health/settings/router:giga"',page);router.status.assert_not_called()
  page=self.client.get('/health/settings/new?kind=dns').text
  self.assertIn('data-monitor-kind',page);self.assertNotIn('href="/health/settings/router:giga"',page)
  page=self.client.get('/health/settings/server:router:giga').text
  self.assertIn('IP узла',page);self.assertNotIn('LAN IPv4 кандидата',page)
  data={**fixtures.values(check),'csrf':token,'revision':read_settings(self.monitor)[1],'host':'192.168.2.2'}
  self.client.post('/health/settings/server:router:giga',data=data)
  router.save.assert_not_called();self.assertEqual(read_settings(self.monitor)[0]['checks'][0]['host'],'192.168.2.2')

 def test_create_and_remove_forms_require_auth_csrf_revision_and_confirmation(self):
  self.assertEqual(self.client.get('/health/settings/new').status_code,302)
  token=self.login();page=self.client.get('/health/settings/new?kind=dns')
  self.assertEqual(page.status_code,200);self.assertIn('Период проверки',page.text)
  values=fixtures.values(new_check('dns',''));values.pop('tcp')
  values.update(kind='dns',domain='example.com',revision=read_settings(self.monitor)[1],csrf=token)
  self.assertEqual(self.client.post('/health/settings/new',data={}).status_code,403)
  response=self.client.post('/health/settings/new',data=values,follow_redirects=True)
  self.assertIn('Датчик добавлен',response.text)
  identifier=read_settings(self.monitor)[0]['checks'][-1]['id'];route='/health/settings/'+identifier+'/remove'
  data={'revision':read_settings(self.monitor)[1],'csrf':token}
  self.assertEqual(self.client.post(route,data=data).status_code,400)
  self.assertEqual(self.client.post(route,data={**data,'confirm':'on'}).status_code,302)
  self.assertEqual(len(read_settings(self.monitor)[0]['checks']),1)

if __name__=='__main__':unittest.main()
