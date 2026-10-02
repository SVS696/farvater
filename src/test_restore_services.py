import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import restore_files as r


def unit(name,active='active',kind='simple',triggers='',boot='static',load='loaded'):
 return {'Id':name,'ActiveState':active,'Type':kind,'TriggeredBy':triggers,'UnitFileState':boot,'LoadState':load,'SubState':'running' if active=='active' else 'dead'}


class ServiceModelTests(unittest.TestCase):
 def test_boot_barrier_allows_only_expected_absent_or_masked_stopped_units(self):
  for load in ['not-found','masked']:
   services={'before':{'app.service':{'mode':'stop','load':load}},'after':{}}
   capture={'recovery.service':unit('recovery.service','activating','oneshot')}
   output='Id=app.service\nLoadState='+load+'\nActiveState=inactive\nRequires=\nAfter=\n'
   with patch.object(r,'service_capture',return_value=capture),patch.object(r.subprocess,'run',return_value=SimpleNamespace(stdout=output)):
    r.verify_boot_gate(services,'recovery.service')
    services['before']['app.service']['load']='loaded'
    with self.assertRaises(ValueError):r.verify_boot_gate(services,'recovery.service')

 def test_boot_barrier_rejects_missing_dependency_or_running_units(self):
  services={'before':{'app.service':{'mode':'start','load':'loaded'}},'after':{}}
  capture={'recovery.service':unit('recovery.service','activating','oneshot')}
  for requires,after,state in [('recovery.service','','inactive'),('','recovery.service','inactive'),('recovery.service','recovery.service','active')]:
   output='Id=app.service\nLoadState=loaded\nActiveState='+state+'\nRequires='+requires+'\nAfter='+after+'\n'
   with patch.object(r,'service_capture',return_value=capture),patch.object(r.subprocess,'run',return_value=SimpleNamespace(stdout=output)):
    with self.assertRaises(ValueError):r.verify_boot_gate(services,'recovery.service')

 def test_inactive_masked_and_timer_workers_do_not_become_start_jobs(self):
  registry={'vpn.service':unit('vpn.service'),
            'disabled.service':unit('disabled.service','inactive',boot='masked',load='masked'),
            'check.timer':unit('check.timer',kind=''),
            'check.service':unit('check.service','activating','oneshot','check.timer')}
  actual=r.service_targets(registry)
  self.assertEqual([n for n,v in actual.items() if v['mode']=='start'],['vpn.service','check.timer'])
  self.assertEqual(actual['disabled.service']['mode'],'stop')
  self.assertEqual(actual['check.service']['mode'],'triggered')

 def test_external_activation_and_unstable_daemon_rejected(self):
  for value in [unit('app.service',triggers='outside.socket'),unit('app.service','activating'),unit('app.service',load='masked',boot='masked')]:
   with self.assertRaises(ValueError):r.service_targets({'app.service':value})
  for name in ['--all','../ssh.service','a.service;shutdown','network.target']:
   with self.assertRaises(ValueError):r.service_name(name)

 def test_health_input_does_not_allow_credentials_or_unbounded_operations(self):
  valid={'url':'https://example.test/health','codes':[200,302],'timeout':3}
  self.assertEqual(r.health_checks([valid]),[valid])
  for url in ['file:///etc/passwd','https://user:password@example.test/','https://example.test/?secret=1','http://example.test:99999/','https://example.test/#fragment','http://example.test/\nHeader: x']:
   with self.assertRaises(ValueError):r.health_checks([{**valid,'url':url}])
  with self.assertRaises(ValueError):r.health_checks([{**valid,'timeout':11}])
  with self.assertRaises(ValueError):r.health_checks([{**valid,'codes':[True]}])
  with self.assertRaises(ValueError):r.health_checks([valid]*21)


@unittest.skipUnless(sys.platform=='linux','Real journal needs Linux metadata support')
class ServiceJournalTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name).resolve();self.root=self.base/'root';self.source=self.base/'source';self.journal=self.base/'journal'
  for p in [self.root,self.source]:p.mkdir(mode=0o700)
  (self.root/'config').write_text('old');(self.source/'config').write_text('new')
  for p in [self.root,self.source]:(p/'cache').write_text('initial cache')
  r.prepare(self.root,self.source,['config','cache'],['config','cache'],self.journal)
  self.registry={'app.service':unit('app.service'),'off.service':unit('off.service','inactive')}
  self.checks=[{'url':'http://127.0.0.1:19001/health','codes':[200],'timeout':1}]

 def tearDown(self):self.temp.cleanup()

 def attach(self,mutable=()):
  with patch.object(r,'service_capture',return_value=self.registry):
   return r.attach_services(self.journal,self.registry,allowed_units=self.registry,before_checks=self.checks,after_checks=self.checks,mutable_paths=mutable)

 def test_unapproved_service_cannot_join_operation(self):
  with self.assertRaises(ValueError):r.attach_services(self.journal,self.registry,allowed_units=['off.service'],before_checks=self.checks,after_checks=self.checks)
  self.assertNotIn('services',json.loads((self.journal/'plan.json').read_text()))
  self.assertEqual((self.root/'config').read_text(),'old')

 def test_old_frozen_runtime_cannot_ignore_new_service_plan(self):
  (self.journal/'rollback.py').chmod(0o600);(self.journal/'rollback.py').write_text('# older file-only runtime')
  with patch.object(r,'service_capture',return_value=self.registry):
   with self.assertRaises(ValueError):r.attach_services(self.journal,self.registry,allowed_units=self.registry,before_checks=self.checks,after_checks=self.checks)
  self.assertNotIn('services',json.loads((self.journal/'plan.json').read_text()))

 def test_apply_checks_services_then_stops_before_files_and_starts_after(self):
  self.attach();events=[]
  def stop(s):events.append(('stop',(self.root/'config').read_text()))
  def start(s,side,*,pending=False):
   self.assertFalse(pending)  # This fixture has no deferred writer; preserve service ordering.
   events.append(('start-'+side,(self.root/'config').read_text()))
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'stop_services',side_effect=stop),patch.object(r,'start_services',side_effect=start),patch.object(r,'run_checks',return_value=[]):
   r.apply(self.journal);r.rollback(self.journal)
  self.assertEqual(events,[('stop','old'),('start-after','new'),('stop','new'),('start-before','old')])

 def test_unhealthy_new_service_keeps_recoverable_state(self):
  self.attach();calls=[]
  def check(values):
   calls.append((self.root/'config').read_text())
   if calls[-1]=='new':raise ValueError('fixture unavailable')
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'stop_services'),patch.object(r,'start_services'),patch.object(r,'run_checks',side_effect=check):
   with self.assertRaises(ValueError):r.apply(self.journal)
   self.assertEqual(json.loads((self.journal/'state.json').read_text())['status'],'starting_services')
   r.rollback(self.journal)
  self.assertEqual((self.root/'config').read_text(),'old');self.assertEqual(calls,['old','new','old'])

 def test_explicit_runtime_data_is_restored_even_if_snapshot_initially_identical(self):
  self.attach(['cache'])
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'stop_services'),patch.object(r,'start_services'),patch.object(r,'run_checks',return_value=[]):
   r.apply(self.journal);(self.root/'cache').write_text('updated by new service');r.rollback(self.journal)
  self.assertEqual((self.root/'cache').read_text(),'initial cache')

 def test_immutable_drift_during_final_health_blocks_confirmation(self):
  self.attach()
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'stop_services'),patch.object(r,'start_services'),patch.object(r,'run_checks',return_value=[]):r.apply(self.journal)
  def drift(values):(self.root/'config').write_text('external edit')
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'run_checks',side_effect=drift):
   with self.assertRaises(ValueError):r.confirm(self.journal)
  self.assertEqual(json.loads((self.journal/'state.json').read_text())['status'],'awaiting_confirmation')

 def test_deadline_is_rechecked_after_slow_final_probe(self):
  self.attach()
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'stop_services'),patch.object(r,'start_services'),patch.object(r,'run_checks',return_value=[]):r.apply(self.journal)
  token='a'*32;r.save(self.journal/'guard.json',{'token':token,'timer':'okopy-restore-undo-'+token,'worker':'okopy-restore-worker-'+token,'deadline':100})
  clock=[99]
  def probe(values):clock[0]=101
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'run_checks',side_effect=probe),patch.object(r.time,'monotonic',side_effect=lambda:clock[0]):
   with self.assertRaises(ValueError):r.confirm(self.journal)
  self.assertEqual(json.loads((self.journal/'state.json').read_text())['status'],'awaiting_confirmation')

 def test_prestart_recovery_never_recursively_starts_services(self):
  self.attach()
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'stop_services'),patch.object(r,'start_services'),patch.object(r,'run_checks',return_value=[]):r.apply(self.journal)
  with patch.object(r,'boot_id',return_value='other-boot'),patch.object(r,'stop_services') as stop,patch.object(r,'start_services') as start,patch.object(r,'verify_boot_gate'),patch.object(r,'queue_boot_services') as queue:
   r.recover_before_start(self.journal,'recovery.service');stop.assert_not_called();start.assert_not_called();queue.assert_called_once()
  self.assertEqual((self.root/'config').read_text(),'old')

 def test_prestart_requires_verified_barrier_before_replacing_files(self):
  self.attach()
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'stop_services'),patch.object(r,'start_services'),patch.object(r,'run_checks',return_value=[]):r.apply(self.journal)
  with patch.object(r,'boot_id',return_value='other-boot'):
   with self.assertRaises(ValueError):r.recover_before_start(self.journal)
  self.assertEqual((self.root/'config').read_text(),'new')

 def test_failed_boot_queue_keeps_retryable_state(self):
  self.attach()
  with patch.object(r,'service_matches',return_value=True),patch.object(r,'stop_services'),patch.object(r,'start_services'),patch.object(r,'run_checks',return_value=[]):r.apply(self.journal)
  with patch.object(r,'boot_id',return_value='other-boot'),patch.object(r,'verify_boot_gate'),patch.object(r,'queue_boot_services',side_effect=RuntimeError('reload failure')):
   with self.assertRaises(RuntimeError):r.recover_before_start(self.journal,'recovery.service')
  self.assertEqual((self.root/'config').read_text(),'old')
  self.assertEqual(json.loads((self.journal/'state.json').read_text())['status'],'rolling_back')


if __name__=='__main__':unittest.main()
