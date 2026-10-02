import copy,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from health_collect import main,collect,checked,slow_rows
from health_model import present_snapshot,validate_snapshot
from health_settings import new_check,form_fields,edit_check,read_settings
from monitor_control import control
import test_monitor_settings as fixtures

def values(c):return {f['key']:f['value'] if f['type']=='bool' else str(f['value']) for f in form_fields(c)}
def slow_check(identifier='custom:'+'a'*32):
 c=new_check('https_slow',identifier)
 return edit_check(c,{**values(c),'name':'Slow path','scope':'Special','action':'Check path','url':'http://example.test/','proxy':'127.0.0.1:2081'})

class SlowTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.slow=slow_check();self.fast=copy.deepcopy(fixtures.CHECK)
  (self.root/'checks.json').write_text(json.dumps({'checks':[self.fast,self.slow]}));(self.root/'settings.lock').touch()
 def tearDown(self):self.temp.cleanup()
 def write_slow(self,observed=1000,generated=1010,boot='boot'):
  with patch('health_collect.time.time',return_value=observed),patch('health_collect.probe',return_value=('up','slow success')):result,_=collect([self.slow])
  result.update(generated_at=generated,boot_id=boot);(self.root/'slow-health.json').write_text(json.dumps(result));return result
 def run_lane(self,lane,boot=True):
  original=Path.read_text
  def read(p,*a,**kw):
   if str(p)=='/proc/sys/kernel/random/boot_id':
    if not boot:raise OSError('unavailable')
    return 'boot'
   return original(p,*a,**kw)
  with patch.object(Path,'read_text',read),patch('sys.argv',['collect','--root',str(self.root),'--lane',lane]),patch('health_collect.candidate_runtime_inputs',side_effect=OSError()):main()
 def test_import_keeps_clocks_and_rejects_other_boot_or_definition(self):
  self.write_slow();row=slow_rows(self.root,[self.slow],'boot')[0]
  self.assertEqual((row['observed_at'],row['source_generated_at']),(1000,1010))
  for boot in ('other',None):self.assertEqual(slow_rows(self.root,[self.slow],boot)[0]['status'],'unknown')
  self.assertEqual(slow_rows(self.root,[{**self.slow,'url':'http://changed.test/'}],'boot')[0]['status'],'unknown')
 def test_stopped_slow_source_stales_despite_fresh_fast_snapshot(self):
  self.write_slow(observed=1000,generated=1000);row=slow_rows(self.root,[self.slow],'boot')[0];row['interval_seconds']=300
  p=self.root/'health.json';p.write_text(json.dumps({'version':1,'generated_at':1151,'checks':[row]}))
  self.assertEqual(present_snapshot(p,now=1151)['checks'][0]['status'],'stale')
  row['source_generated_at']=1151;p.write_text(json.dumps({'version':1,'generated_at':1151,'checks':[row]}))
  self.assertEqual(present_snapshot(p,now=1151)['checks'][0]['status'],'up')
  row['source_generated_at']='fresh'
  with self.assertRaises(ValueError):validate_snapshot({'version':1,'generated_at':1151,'checks':[row]})
 def test_fast_does_not_run_slow_network_or_rejuvenate_measurement(self):
  original=Path.read_text
  def read(p,*a,**kw):return 'boot' if str(p)=='/proc/sys/kernel/random/boot_id' else original(p,*a,**kw)
  self.write_slow()
  with patch.object(Path,'read_text',read),patch('health_collect.probe',return_value=('up','fast')) as probe:self.run_lane('fast')
  self.assertEqual([c.args[0]['id'] for c in probe.call_args_list],[self.fast['id']])
  row=next(r for r in json.loads((self.root/'health.json').read_text())['checks'] if r['id']==self.slow['id']);self.assertEqual(row['observed_at'],1000)
 def test_slow_lane_only_runs_slow_and_handles_empty_lane(self):
  with patch('health_collect.probe',return_value=('up','slow')) as probe,patch('health_collect.collect',wraps=collect) as collector:self.run_lane('slow')
  self.assertEqual(collector.call_args.kwargs['workers'],2);self.assertEqual(collector.call_args.kwargs['deadline_seconds'],68)
  self.assertEqual([c.args[0]['id'] for c in probe.call_args_list],[self.slow['id']]);self.assertFalse((self.root/'health.json').exists())
  (self.root/'checks.json').write_text(json.dumps({'checks':[self.fast]}))
  with patch('health_collect.probe') as probe:self.run_lane('slow')
  probe.assert_not_called();self.assertEqual(json.loads((self.root/'slow-health.json').read_text())['checks'],[])
 def test_missing_boot_id_does_not_repeatedly_probe_unusable_slow_results(self):
  with patch('health_collect.probe') as probe:self.run_lane('slow',boot=False)
  probe.assert_not_called();snapshot=json.loads((self.root/'slow-health.json').read_text())
  self.assertIsNone(snapshot['boot_id']);self.assertEqual(snapshot['checks'][0]['status'],'unknown')
 def test_edit_delete_invalidate_both_and_prevent_old_success(self):
  source=self.write_slow(observed=time.time());(self.root/'health.json').write_text(json.dumps(source))
  control({'version':1,'action':'monitor-set','check_id':self.slow['id'],'revision':read_settings(self.root)[1],'values':{**values(self.slow),'url':'http://changed.test/'}},self.root)
  for name in ('health.json','slow-health.json'):
   row=next(r for r in json.loads((self.root/name).read_text())['checks'] if r['id']==self.slow['id']);self.assertEqual(row['status'],'unknown')
  current=read_settings(self.root)[0]['checks'][-1];self.assertEqual(slow_rows(self.root,[current],'boot')[0]['status'],'unknown')
  control({'version':1,'action':'monitor-remove','check_id':self.slow['id'],'revision':read_settings(self.root)[1]},self.root)
  for name in ('health.json','slow-health.json'):self.assertFalse(any(r['id']==self.slow['id'] for r in json.loads((self.root/name).read_text())['checks']))
 def test_inflight_slow_delete_cannot_publish_old_success(self):
  def probe(check):
   control({'version':1,'action':'monitor-remove','check_id':self.slow['id'],'revision':read_settings(self.root)[1]},self.root);return 'up','old'
  with patch('health_collect.probe',side_effect=probe):self.run_lane('slow')
  self.assertEqual(json.loads((self.root/'slow-health.json').read_text())['checks'],[])
 def test_limits(self):
  self.assertEqual(self.slow['timeout_seconds'],30);self.assertEqual(self.slow['interval_seconds'],60)
  self.assertEqual(self.slow['connect_timeout_seconds'],30)
  for key,bad in [('interval_seconds','59'),('timeout_seconds','31'),('connect_timeout_seconds','31')]:
   with self.assertRaises(ValueError):edit_check(self.slow,{**values(self.slow),key:bad})
  (self.root/'checks.json').write_text(json.dumps({'checks':[self.fast]+[slow_check('custom:'+str(i)*32) for i in range(4)]}))
  with self.assertRaisesRegex(ValueError,'четырёх'):control({'version':1,'action':'monitor-add','kind':'https_slow','revision':read_settings(self.root)[1],'values':values(self.slow)},self.root)
 def test_network_uses_bounded_timeout_and_socks(self):
  import subprocess
  with patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,'200\t0.001\t0.01\t0.05\t0.06\t0.07','')) as run:row=checked(self.slow)
  self.assertEqual(row['status'],'up');args,timeout=run.call_args.args;self.assertEqual(timeout,32);self.assertIn('--socks5-hostname',args);self.assertEqual(args[args.index('--max-time')+1],'30')

if __name__=='__main__':unittest.main()
