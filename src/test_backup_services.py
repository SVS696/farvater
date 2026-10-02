import unittest
from unittest.mock import patch
from types import SimpleNamespace
from backup_services import discover,capture,legacy_states


class BackupServiceTests(unittest.TestCase):
 def test_new_connections_and_timer_workers_are_discovered_from_saved_files(self):
  paths=['etc/systemd/system/new-vpn.service','etc/systemd/system/new-vpn.service.d/hardening.conf',
         'etc/systemd/system/scan.timer','etc/systemd/system/scan.service',
         'etc/systemd/system/multi-user.target.wants/linked-vpn.service','etc/systemd/system/unrelated.txt']
  self.assertEqual(discover(paths,['existing.service']),['existing.service','linked-vpn.service','new-vpn.service','scan.service','scan.timer'])

 def test_scoped_paths_do_not_pull_unrelated_loaded_services(self):
  paths=['etc/systemd/system/okopy-panel.service']
  self.assertEqual(discover(paths,[],['ssh.socket','systemd-networkd.service','rsyslog.service']),
                   ['okopy-panel.service'])

 def test_systemd_targets_are_not_started_or_stopped_as_recovery_workers(self):
  paths=['etc/systemd/system/remote-fs.target',
         'etc/systemd/system/multi-user.target.wants/okopy-panel.service']
  self.assertEqual(discover(paths,['remote-fs.target','okopy-candidate.service'],
                            ['remote-fs.target','okopy-panel.service']),
                   ['okopy-candidate.service','okopy-panel.service'])

 def test_template_instances_are_limited_to_backed_up_templates(self):
  paths=['etc/systemd/system/vpn@.service.d/hook.conf']
  loaded=['vpn@home.service','vpn@disabled.service','vpn@.service','mail@external.service','unrelated.service']
  self.assertEqual(discover(paths,[],loaded),['vpn@disabled.service','vpn@home.service'])

 def test_bad_configured_names_cannot_become_command_options(self):
  for name in ['--all','-evil.service','a.service\nOther=x','../evil.service','x.service;echo']:
   with self.assertRaises(ValueError):discover([],[name])

 def test_captures_dependencies_owners_and_mask_without_command_arguments(self):
  calls=[]
  def run(args,**kwargs):
   calls.append(args)
   if args[1]=='list-units':return SimpleNamespace(returncode=0,stdout='new.service loaded active running New\n')
   return SimpleNamespace(returncode=0,stdout='Id=new.service\nActiveState=inactive\nUnitFileState=masked\nRequires=dns.service\nDynamicUser=yes\nUser=new\n')
  with patch('backup_services.subprocess.run',side_effect=run):result=capture(['etc/systemd/system/new.service'],[])
  self.assertEqual(result['units'][0]['UnitFileState'],'masked');self.assertEqual(result['units'][0]['Requires'],'dns.service')
  self.assertNotIn('ExecStart',calls[-1][-1]);self.assertNotIn('Environment',calls[-1][-1])
  self.assertIn('UnitFileState=masked',legacy_states(result))

 def test_missing_or_unexpected_service_response_does_not_become_valid_registry(self):
  for output in ['', 'Id=other.service\nActiveState=active\n']:
   with patch('backup_services.subprocess.run',side_effect=[SimpleNamespace(returncode=0,stdout=''),SimpleNamespace(returncode=0,stdout=output)]):
    with self.assertRaises(ValueError):capture([],['expected.service'])

 def test_aliases_preserve_canonical_service_without_duplicate_activation(self):
  response='Id=main.service\nNames=main.service alias.service\nActiveState=active\nUnitFileState=enabled\n'
  with patch('backup_services.subprocess.run',side_effect=[SimpleNamespace(returncode=0,stdout=''),SimpleNamespace(returncode=0,stdout=response+'\n'+response)]):
   result=capture([],['main.service','alias.service'])
  self.assertEqual(len(result['units']),1);self.assertEqual(result['units'][0]['Id'],'main.service')


if __name__=='__main__':unittest.main()
