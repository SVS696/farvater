import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import restore_files as recovery


MODULE=Path(recovery.__file__).resolve()


@unittest.skipUnless(sys.platform=='linux','Real filesystem recovery is verified on Linux')
class RestoreFilesTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name).resolve()
  self.root=self.base/'target';self.source=self.base/'source';self.journal=self.base/'journal'
  for p in (self.root,self.source):p.mkdir(mode=0o700)
  (self.root/'etc').mkdir(mode=0o750);(self.source/'etc').mkdir(mode=0o750)
  (self.root/'etc/settings').write_bytes(b'old settings');(self.root/'etc/settings').chmod(0o640)
  (self.source/'etc/settings').write_bytes(b'new settings');(self.source/'etc/settings').chmod(0o600)
  (self.root/'etc/obsolete').write_bytes(b'keep for rollback')
  (self.source/'etc/added').write_bytes(b'new service')
  (self.root/'current').symlink_to('/old/release');(self.source/'current').symlink_to('/new/release')
  (self.source/'new-dir').mkdir(mode=0o750);(self.source/'new-dir/file').write_bytes(b'new subfile')
  (self.root/'retired-dir').mkdir();(self.root/'retired-dir/file').write_bytes(b'removed subtree')
  self.current=['etc','etc/settings','etc/obsolete','current','retired-dir','retired-dir/file']
  self.desired=['etc','etc/settings','etc/added','current','new-dir','new-dir/file']
  self.before=self.tree()

 def tearDown(self):self.temp.cleanup()

 def tree(self):
  return {str(p.relative_to(self.root)):recovery.inspect(p) for p in self.root.rglob('*')}

 def prepare(self):return recovery.prepare(self.root,self.source,self.current,self.desired,self.journal)

 def test_file_symlink_addition_removal_modes_and_independent_rollback(self):
  self.prepare();recovery.apply(self.journal)
  self.assertEqual((self.root/'etc/settings').read_bytes(),b'new settings')
  self.assertFalse((self.root/'etc/obsolete').exists());self.assertFalse((self.root/'retired-dir').exists())
  self.assertEqual(os.readlink(self.root/'current'),'/new/release')
  # Rollback still works after the source and original application module vanish.
  frozen=self.journal/'rollback.py';shutil.rmtree(self.source)
  result=subprocess.run([sys.executable,'-I',str(frozen),'rollback',str(self.journal)],capture_output=True,text=True,check=True)
  self.assertEqual(json.loads(result.stdout)['status'],'rolled_back');self.assertEqual(self.tree(),self.before)
  recovery.rollback(self.journal);self.assertEqual(self.tree(),self.before)

 def test_confirm_is_checked_and_prevents_late_rollback(self):
  self.prepare();recovery.apply(self.journal)
  (self.root/'etc/settings').write_bytes(b'changed unexpectedly')
  with self.assertRaises(ValueError):recovery.confirm(self.journal)
  (self.root/'etc/settings').write_bytes(b'new settings')
  recovery.confirm(self.journal);after=self.tree();recovery.rollback(self.journal)
  self.assertEqual(self.tree(),after)

 def test_destination_drift_stops_before_first_change(self):
  self.prepare();(self.root/'etc/settings').write_bytes(b'user edit')
  before=self.tree()
  with self.assertRaises(ValueError):recovery.apply(self.journal)
  self.assertEqual(self.tree(),before)
  recovery.rollback(self.journal);self.assertEqual(self.tree(),before)

 def test_corrupt_rollback_blob_blocks_apply_without_changes(self):
  self.prepare();name=hashlib.sha256(b'old settings').hexdigest()
  (self.journal/'objects'/name).write_bytes(b'corrupt')
  with self.assertRaises(ValueError):recovery.apply(self.journal)
  self.assertEqual(self.tree(),self.before)

 def test_unmanaged_file_in_removed_directory_blocks_prepare(self):
  (self.root/'retired-dir/precious').write_bytes(b'user data')
  before=self.tree()
  with self.assertRaises(ValueError):self.prepare()
  self.assertEqual(self.tree(),before);self.assertFalse(self.journal.exists())

 def test_parent_symlink_and_live_root_are_rejected(self):
  outside=self.base/'outside';outside.mkdir();(outside/'file').write_text('untouched')
  (self.root/'linked').symlink_to(outside,target_is_directory=True)
  for root,current in [(self.root,[*self.current,'linked/file']),(Path('/'),self.current)]:
   with self.assertRaises(ValueError):recovery.prepare(root,self.source,current,self.desired,self.journal)
  self.assertEqual((outside/'file').read_text(),'untouched')

 def test_ancestor_added_after_prepare_blocks_mutation(self):
  self.prepare();old=self.root/'etc';old.rename(self.root/'moved-etc');old.symlink_to(self.root/'moved-etc')
  with self.assertRaises(ValueError):recovery.apply(self.journal)
  self.assertEqual((self.root/'moved-etc/settings').read_bytes(),b'old settings')

 def test_unsupported_metadata_and_hardlink_block_prepare(self):
  os.link(self.root/'etc/settings',self.root/'second-link')
  with self.assertRaises(ValueError):self.prepare()
  (self.root/'second-link').unlink()
  with patch('restore_files.os.listxattr',return_value=['user.extra']):
   with self.assertRaises(ValueError):self.prepare()

 def test_type_change_and_scope_escape_rejected(self):
  (self.source/'current').unlink();(self.source/'current').mkdir()
  with self.assertRaises(ValueError):self.prepare()
  for name in ('../outside','/etc/passwd','a//b','a/./b'):
   with self.assertRaises(ValueError):recovery.prepare(self.root,self.source,[name],self.desired,self.journal)

 def test_reserved_atomic_name_is_not_deleted(self):
  self.prepare();reserved=self.root/'etc'/('.okopy-restore-'+hashlib.sha256(b'etc/settings').hexdigest())
  reserved.write_text('my file')
  with self.assertRaises(ValueError):recovery.apply(self.journal)
  self.assertEqual(reserved.read_text(),'my file')

 def test_implicit_parent_and_unmanaged_sibling_survive_removal(self):
  (self.root/'etc/unmanaged').write_bytes(b'outside scope')
  recovery.prepare(self.root,self.source,['etc/obsolete'],[],self.journal)
  recovery.apply(self.journal);recovery.confirm(self.journal)
  self.assertFalse((self.root/'etc/obsolete').exists())
  self.assertEqual((self.root/'etc/unmanaged').read_bytes(),b'outside scope')
  self.assertEqual((self.root/'etc/settings').read_bytes(),b'old settings')
  self.assertEqual(stat_mode(self.root/'etc'),0o750)

 def test_late_worker_cannot_write_after_guard_fence(self):
  self.prepare();recovery.save(self.journal/'cancel.json',{'cancelled':True})
  with self.assertRaises(ValueError):recovery.apply(self.journal)
  self.assertEqual(self.tree(),self.before)

 def expired_guard(self):
  token='a'*32
  recovery.save(self.journal/'guard.json',{'token':token,'timer':'okopy-restore-undo-'+token,'worker':'okopy-restore-worker-'+token,'deadline':0})

 def test_expired_window_cannot_be_confirmed_even_before_timer_gets_cpu(self):
  self.prepare();recovery.apply(self.journal);self.expired_guard()
  with self.assertRaises(ValueError):recovery.confirm(self.journal)
  self.assertEqual(json.loads((self.journal/'state.json').read_text())['status'],'awaiting_confirmation')
  recovery.rollback(self.journal);self.assertEqual(self.tree(),self.before)

 def test_late_start_after_expiration_cannot_touch_target(self):
  self.prepare();self.expired_guard()
  with self.assertRaises(ValueError):recovery.apply(self.journal)
  self.assertEqual(self.tree(),self.before)

 def test_identical_files_and_shared_directory_permissions_not_rewritten(self):
  for root in (self.root,self.source):(root/'etc/same').write_bytes(b'unchanged')
  self.current.append('etc/same');self.desired.append('etc/same');self.prepare()
  inode=(self.root/'etc/same').stat().st_ino
  def observe(name):self.assertEqual(stat_mode(self.root/'etc'),0o750)
  recovery.apply(self.journal,observe)
  self.assertEqual((self.root/'etc/same').stat().st_ino,inode)
  recovery.rollback(self.journal,observe)
  self.assertEqual((self.root/'etc/same').stat().st_ino,inode)

 def test_reserved_source_path_rejected_before_target_change(self):
  (self.source/'.okopy-restore-unrelated').write_text('bad namespace')
  with self.assertRaises(ValueError):recovery.prepare(self.root,self.source,self.current,[*self.desired,'.okopy-restore-unrelated'],self.journal)
  self.assertEqual(self.tree(),self.before)

 def test_previous_boot_cannot_be_confirmed_and_rolls_back_before_start(self):
  self.prepare();recovery.apply(self.journal)
  self.assertEqual(recovery.recover_before_start(self.journal)['status'],'not_needed')
  with patch('restore_files.boot_id',return_value='different-boot'):
   with self.assertRaises(ValueError):recovery.confirm(self.journal)
   self.assertEqual(recovery.recover_before_start(self.journal)['status'],'rolled_back')
  self.assertEqual(self.tree(),self.before)

 def test_confirmed_snapshot_survives_new_boot_and_prepared_job_expires(self):
  self.prepare();recovery.apply(self.journal);recovery.confirm(self.journal);after=self.tree()
  with patch('restore_files.boot_id',return_value='different-boot'):
   self.assertEqual(recovery.recover_before_start(self.journal)['status'],'not_needed')
  self.assertEqual(self.tree(),after)
  shutil.rmtree(self.journal);self.prepare()
  with patch('restore_files.boot_id',return_value='different-boot'):
   with self.assertRaises(ValueError):recovery.apply(self.journal)
   self.assertEqual(recovery.recover_before_start(self.journal)['status'],'rolled_back')
  self.assertEqual(self.tree(),after)

 def test_interruption_inside_atomic_copy_cleans_partial_sibling(self):
  self.prepare()
  def crash_rename(src,dst):
   if str(dst)==str(self.root/'etc/settings'):raise RuntimeError('simulated rename interruption')
   return real(src,dst)
  real=os.replace
  with patch('restore_files.os.replace',side_effect=crash_rename):
   with self.assertRaises(RuntimeError):recovery.apply(self.journal)
  # Simulate SIGKILL before the finally block of a newly introduced file.
  partial=self.root/'new-dir'/('.okopy-restore-'+hashlib.sha256(b'new-dir/file').hexdigest())
  partial.write_bytes(b'partial')
  recovery.rollback(self.journal);self.assertEqual(self.tree(),self.before)

 def test_real_death_before_atomic_rename_is_recoverable(self):
  self.prepare()
  program='''import os,sys
sys.path.insert(0,sys.argv[1])
import restore_files
original=os.replace
def crash(src,dst):
 if str(dst)==sys.argv[3]:os._exit(74)
 return original(src,dst)
os.replace=crash
restore_files.apply(sys.argv[2])
'''
  result=subprocess.run([sys.executable,'-I','-c',program,str(MODULE.parent),str(self.journal),str(self.root/'etc/settings')],capture_output=True)
  self.assertEqual(result.returncode,74,result.stderr.decode())
  self.assertTrue(list((self.root/'etc').glob('.okopy-restore-*')))
  subprocess.run([sys.executable,'-I',str(self.journal/'rollback.py'),'rollback',str(self.journal)],check=True,capture_output=True)
  self.assertEqual(self.tree(),self.before)

 @unittest.skipUnless(os.geteuid()==0,'Owner preservation requires the native root fixture')
 def test_distinct_owners_and_privileged_mode_preserved_both_ways(self):
  path=self.root/'etc/settings';new=self.source/'etc/settings'
  os.chown(path,23456,23457);os.chmod(path,0o2640)
  os.chown(new,23458,23459);os.chmod(new,0o4600)
  self.before=self.tree();self.prepare();recovery.apply(self.journal)
  self.assertEqual((path.stat().st_uid,path.stat().st_gid,stat_mode(path)),(23458,23459,0o4600))
  recovery.rollback(self.journal);self.assertEqual(self.tree(),self.before)

 def test_process_death_after_each_mutation_and_during_rollback(self):
  self.prepare();steps=[];recovery.apply(self.journal,steps.append);recovery.rollback(self.journal)
  steps_count=len(steps)
  # Real abrupt exits, not exceptions that run finally/cleanup in the worker.
  for action in ('apply','rollback'):
   for stop_after in range(1,steps_count+1):
    shutil.rmtree(self.journal);self.prepare()
    if action=='rollback':recovery.apply(self.journal)
    program='''import os,sys
sys.path.insert(0,sys.argv[1])
import restore_files
count=0
def step(name):
 global count
 count+=1
 if count==int(sys.argv[4]):os._exit(73)
getattr(restore_files,sys.argv[2])(sys.argv[3],step)
'''
    result=subprocess.run([sys.executable,'-I','-c',program,str(MODULE.parent),action,str(self.journal),str(stop_after)],capture_output=True)
    self.assertIn(result.returncode,(0,73),result.stderr.decode())
    recovery.rollback(self.journal)
    self.assertEqual(self.tree(),self.before,(action,stop_after))


def stat_mode(path):return path.stat().st_mode&0o7777


if __name__=='__main__':unittest.main()
