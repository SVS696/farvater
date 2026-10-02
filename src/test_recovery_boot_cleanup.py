"""Protected rescue cleanup touches only a terminal journal's verified guard."""

from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import recovery_boot_cleanup as cleanup


class BootCleanupTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve()
  self.value='a'*32
  self.journal=self.root/self.value
  @contextmanager
  def locked(_):
   yield self.journal,{'services':{'boot_gate':'infrastructure-recovery-guard.service'}},Path('/'),{'status':'rolled_back'}
  self.files=SimpleNamespace(status=Mock(side_effect=[
      {'status':'rolled_back','boot_guard':'installed'},
      {'status':'rolled_back','boot_guard':'removed'}]),locked=locked,
      service_capture=Mock(return_value={'infrastructure-recovery-guard.service':
          {'ActiveState':'active','Type':'oneshot'}}),service_matches=Mock(return_value=True))
  self.boot=SimpleNamespace(capsule=Mock(),remove=Mock())

 def context(self):
  def load(path,name):return self.files if name=='restore_files' else self.boot
  return (patch.object(cleanup,'CODE_ROOT',self.root),patch.object(cleanup,'CAPSULE_ROOT',self.root),
          patch.object(cleanup,'OWNER',os.geteuid()),patch.object(cleanup.os,'geteuid',return_value=0),
          patch.object(cleanup,'protected_module',side_effect=load))

 def test_terminal_cleanup_removes_only_own_verified_guard(self):
  root,capsule,owner,euid,load=self.context()
  with root,capsule,owner,euid,load:
   self.assertEqual(cleanup.run(self.value),{'status':'removed'})
  self.boot.capsule.assert_called_once_with(self.journal)
  self.files.service_matches.assert_called_once()
  self.boot.remove.assert_called_once_with(self.journal)

 def test_nonterminal_or_activating_gate_is_not_removed(self):
  root,capsule,owner,euid,load=self.context()
  self.files.status=Mock(return_value={'status':'awaiting_confirmation','boot_guard':'installed'})
  with root,capsule,owner,euid,load:
   with self.assertRaisesRegex(ValueError,'только после завершения'):
    cleanup.run(self.value)
  self.boot.remove.assert_not_called()
  self.files.status=Mock(return_value={'status':'rolled_back','boot_guard':'installed'})
  self.files.service_capture.return_value['infrastructure-recovery-guard.service']['ActiveState']='activating'
  root,capsule,owner,euid,load=self.context()
  with root,capsule,owner,euid,load:
   with self.assertRaisesRegex(ValueError,'ещё завершает запуск'):
    cleanup.run(self.value)
  self.boot.remove.assert_not_called()


if __name__=='__main__':unittest.main()
