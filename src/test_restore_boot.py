import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import restore_boot as boot
import restore_files as files


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'Persistent systemd installer requires Linux root')
class BootInstallTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name).resolve()
  self.capsules=self.base/'capsules';self.capsules.mkdir(mode=0o700)
  self.units=self.base/'units';self.units.mkdir()
  self.root=self.base/'root';self.source=self.base/'source'
  for p in (self.root,self.source):p.mkdir(mode=0o700)
  (self.root/'config').write_text('old');(self.source/'config').write_text('new')
  self.journal=self.capsules/('b'*32)
  self.contexts=[patch.object(boot,'CAPSULE_ROOT',self.capsules),patch.object(boot,'UNIT_ROOT',self.units)]
  for context in self.contexts:context.start()
  files.prepare(self.root,self.source,['config'],['config'],self.journal)
  self.plan=json.loads((self.journal/'plan.json').read_text())
  state={'app.service':{'mode':'start','boot':'static','load':'loaded','triggers':[]}}
  self.plan['services']={'before':state,'after':state,'before_checks':[],'after_checks':[],'mutable_paths':[]}
  files.save(self.journal/'plan.json',self.plan)
  token='c'*32
  self.info={'version':1,'token':token,'gate':'infrastructure-recovery-'+token+'.service','dropin':'90-infrastructure-recovery-'+token+'.conf','unit_root':str(self.units),'status':'installing'}

 def tearDown(self):
  for context in reversed(self.contexts):context.stop()
  self.temp.cleanup()

 def write_barrier(self):
  files.save(self.journal/'boot-guard.json',self.info)
  wanted=boot.definitions(self.journal,self.plan,self.info)
  for path,body in wanted.items():boot.write_owned(path,body)
  return wanted

 def test_volatile_or_noncanonical_capsule_is_rejected(self):
  with self.assertRaises(ValueError):boot.capsule(self.root)
  link=self.capsules/('d'*32);link.symlink_to(self.journal)
  with self.assertRaises(ValueError):boot.capsule(link)

 def test_secure_directory_rejects_symlink_and_writable_parent(self):
  link=self.base/'link';link.symlink_to(self.units)
  with self.assertRaises(ValueError):boot.secure_directory(link/'child',create=True)
  self.units.chmod(0o777)
  with self.assertRaises(ValueError):boot.secure_directory(self.units/'child',create=True)

 def test_unit_write_is_idempotent_and_preserves_foreign_files(self):
  p=self.units/'probe.service';boot.write_owned(p,'owned');inode=p.stat().st_ino
  boot.write_owned(p,'owned');self.assertEqual(p.stat().st_ino,inode)
  with self.assertRaises(ValueError):boot.write_owned(p,'replacement')
  self.assertEqual(p.read_text(),'owned')
  p.unlink();p.symlink_to(self.root/'config')
  with self.assertRaises(ValueError):boot.write_owned(p,'owned')
  self.assertEqual((self.root/'config').read_text(),'old')

 def test_partial_or_removing_barrier_never_permits_target_writes(self):
  for state in ('installing','removing','removed'):
   files.save(self.journal/'boot-guard.json',{**self.info,'status':state})
   with self.assertRaises(ValueError):files.apply(self.journal)
   self.assertEqual((self.root/'config').read_text(),'old')

 def test_cannot_remove_barrier_during_unconfirmed_restore(self):
  wanted=self.write_barrier();files.save(self.journal/'state.json',{'status':'awaiting_confirmation'})
  with patch.object(boot.subprocess,'run') as command:
   with self.assertRaises(ValueError):boot.remove(self.journal)
   command.assert_not_called()
  self.assertTrue(all(p.exists() for p in wanted))

 def test_foreign_edit_blocks_removal_before_first_unlink(self):
  wanted=self.write_barrier();last=list(wanted)[-1];last.write_text('foreign')
  with patch.object(boot.subprocess,'run') as command:
   with self.assertRaises(ValueError):boot.remove(self.journal)
   command.assert_not_called()
  self.assertTrue(all(p.exists() for p in wanted))

 def test_removal_keeps_other_dropins_and_is_repeatable(self):
  wanted=self.write_barrier();dropin=list(wanted)[-1];other=dropin.parent/'custom.conf';other.write_text('[Service]\nNice=5\n')
  with patch.object(boot.subprocess,'run',return_value=SimpleNamespace(stdout='not-found\n')):
   boot.remove(self.journal);boot.remove(self.journal)
  self.assertFalse(any(p.exists() for p in wanted));self.assertTrue(other.exists())
  self.assertEqual(json.loads((self.journal/'boot-guard.json').read_text())['status'],'removed')

 def test_snapshot_cannot_replace_guard_directory(self):
  # Check an actual entry rooted at the destination, not an unrelated string.
  protected=self.root/'guard';protected.mkdir()
  self.plan['entries']['guard']={'before':{'kind':'directory','mode':0o755,'uid':0,'gid':0},'after':{'kind':'absent'}}
  files.save(self.journal/'plan.json',self.plan)
  with patch.object(boot,'UNIT_ROOT',protected),patch.object(boot.subprocess,'run',return_value=SimpleNamespace(stdout=str(protected)+'\n')):
   with self.assertRaises(ValueError):boot.install(self.journal)
  self.assertFalse((self.journal/'boot-guard.json').exists());self.assertTrue(protected.exists())


if __name__=='__main__':unittest.main()
