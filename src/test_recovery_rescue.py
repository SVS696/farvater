"""Independent rescue accepts only a fixed prepared job and no terminal mutation."""

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import recovery_rescue as rescue


class RescueCliTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
  self.job='a'*32;self.journal=self.root/self.job;self.journal.mkdir(mode=0o700)
  (self.journal/'rollback.py').write_text('# frozen fixture');(self.journal/'rollback.py').chmod(0o400)

 def context(self):
  return (patch.object(rescue,'ROOT',self.root),patch.object(rescue,'OWNER',os.geteuid()),
          patch.object(rescue.os,'geteuid',return_value=0))

 def test_old_admin_cannot_mutate_terminal_job(self):
  reply=SimpleNamespace(returncode=0,stdout='{"status":"confirmed"}')
  root,owner,euid=self.context()
  with root,owner,euid,patch.object(rescue.subprocess,'run',return_value=reply) as command:
   for action in ('start','confirm','rollback'):
    with self.assertRaisesRegex(ValueError,'только для чтения'):
     rescue.run(action,self.job)
  self.assertEqual(command.call_count,3)
  self.assertTrue(all(call.args[0][-2]=='status' for call in command.call_args_list))

 def test_start_requires_boot_guard_then_calls_only_frozen_start(self):
  prepared=SimpleNamespace(returncode=0,stdout='{"status":"prepared","boot_guard":"installed"}')
  started=SimpleNamespace(returncode=0,stdout='{"status":"started"}')
  root,owner,euid=self.context()
  with root,owner,euid,patch.object(rescue.subprocess,'run',side_effect=[prepared,started]) as command:
   self.assertEqual(rescue.run('start',self.job)['status'],'started')
  invocation=command.call_args_list[1].args[0]
  self.assertEqual(invocation[-2],'start-guarded')
  self.assertEqual(invocation[0],'/usr/bin/systemd-run')
  self.assertIn('--wait',invocation);self.assertIn('--pipe',invocation)
  self.assertIn('--property=RuntimeMaxSec=240s',invocation)

 def test_rollback_with_guard_uses_fenced_worker_stop(self):
  (self.journal/'guard.json').write_text('{}')
  prepared=SimpleNamespace(returncode=0,stdout='{"status":"recovery_required"}')
  restored=SimpleNamespace(returncode=0,stdout='{"status":"rolled_back"}')
  root,owner,euid=self.context()
  with (root,owner,euid,patch.object(rescue.subprocess,'run',side_effect=[prepared,restored]) as command,
        patch.object(rescue,'dispatch_terminal_cleanup',return_value={'status':'removed'}) as cleanup):
   self.assertEqual(rescue.run('rollback',self.job)['status'],'rolled_back')
  self.assertEqual(command.call_args_list[1].args[0][-2],'recover-guarded')
  cleanup.assert_called_once_with(self.job)

 def test_recovery_required_status_is_readable_in_frozen_rescue(self):
  reply=SimpleNamespace(returncode=0,stdout='{"status":"recovery_required"}')
  root,owner,euid=self.context()
  with root,owner,euid,patch.object(rescue.subprocess,'run',return_value=reply):
   self.assertEqual(rescue.run('status',self.job)['status'],'recovery_required')

 def test_terminal_status_retries_only_protected_boot_cleanup(self):
  reply=SimpleNamespace(returncode=0,stdout='{"status":"confirmed","boot_guard":"installed"}')
  root,owner,euid=self.context()
  with (root,owner,euid,patch.object(rescue.subprocess,'run',return_value=reply) as action,
        patch.object(rescue,'dispatch_terminal_cleanup',return_value={'status':'removed'}) as cleanup):
   result=rescue.run('status',self.job)
  self.assertEqual(result['status'],'confirmed')
  self.assertEqual(result['boot_guard'],'removed')
  action.assert_called_once();cleanup.assert_called_once_with(self.job)


if __name__=='__main__':unittest.main()
