import json,os,shutil,subprocess,tempfile,unittest,uuid,fcntl
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
import system_backup as backup

@unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'),'age CLI is required for encryption interoperability')
class SystemBackupTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name);self.host=self.path/'host';self.host.mkdir();self.root=self.path/'backup';self.root.mkdir(mode=0o700);(self.root/'jobs').mkdir(mode=0o700)
  self.panel=self.host/'var/lib/okopy-panel';self.panel.mkdir(parents=True)
  for name in ['backup-downloads','backup-uploads']:(self.panel/name).mkdir()
  (self.host/'etc').mkdir();(self.host/'etc/vpn.conf').write_text('PRIVATE CONFIG');(self.host/'etc/vpn.conf').chmod(0o600)
  key=Ed25519PrivateKey.generate();(self.root/'signing.key').write_bytes(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
  self.identity=self.path/'recovery.agekey';subprocess.run(['age-keygen','-o',str(self.identity)],check=True,capture_output=True)
  recipient=subprocess.check_output(['age-keygen','-y',str(self.identity)],text=True).strip()
  (self.root/'settings.json').write_text(json.dumps({'version':1,'recipient':recipient,'host_id':'fixture','scope':'server','exclusions':['other-hosts'],'required':['etc/vpn.conf'],'trees':['etc']}))
 def tearDown(self):self.temp.cleanup()
 def call(self,action,**fields):return backup.control({'version':1,'action':action,**fields},root=self.root,panel=self.panel,host=self.host,age=shutil.which('age'))
 def export(self):
  value=uuid.uuid4().hex;result=self.call('backup-create',id=value);return value,result
 def inspect(self,exported,key=None):
  value=uuid.uuid4().hex;shutil.copyfile(self.panel/'backup-downloads'/(exported+'.age'),self.panel/'backup-uploads'/(value+'.age'))
  return value,self.call('backup-inspect',id=value,recovery_key=key or self.identity.read_text())
 def test_encrypted_roundtrip_preview_and_deletion_preserve_host(self):
  value,result=self.export();file=self.panel/'backup-downloads'/(value+'.age')
  self.assertEqual(result['status'],'ready');self.assertNotIn(b'PRIVATE CONFIG',file.read_bytes())
  self.assertEqual(self.call('backup-create',id=value)['sha256'],result['sha256'])
  imported,preview=self.inspect(value);self.assertEqual(preview['status'],'checked');self.assertEqual(preview['summary']['changed'],0)
  self.assertTrue(preview['summary']['signature_verified']);self.assertFalse(preview['summary']['working_system_changed'])
  self.assertFalse((self.root/'jobs'/imported/'identity.tmp').exists());self.assertFalse((self.panel/'backup-uploads'/(imported+'.age')).exists())
  self.assertEqual((self.host/'etc/vpn.conf').read_text(),'PRIVATE CONFIG')
  self.call('backup-delete',id=imported);self.call('backup-delete',id=value);self.assertEqual(self.call('backup-status')['jobs'],[])
 def test_changed_and_missing_required_files_can_still_be_inspected(self):
  value,_=self.export();(self.host/'etc/vpn.conf').write_text('NEW STATE')
  _,preview=self.inspect(value);self.assertEqual(preview['summary']['changed'],1)
  (self.host/'etc/vpn.conf').unlink();_,preview=self.inspect(value);self.assertEqual(preview['summary']['missing'],1)
  self.assertFalse((self.host/'etc/vpn.conf').exists())
 def test_wrong_recovery_key_fails_without_leaving_identity_or_plain_stage(self):
  value,_=self.export();other=self.path/'wrong.agekey';subprocess.run(['age-keygen','-o',str(other)],capture_output=True,check=True)
  with self.assertRaises(ValueError):self.inspect(value,other.read_text())
  jobs=self.call('backup-status')['jobs'];failed=next(x for x in jobs if x['status']=='failed');job=self.root/'jobs'/failed['id']
  self.assertFalse((job/'identity.tmp').exists());self.assertFalse((job/'staged').exists())
  self.assertNotIn(other.read_text(),json.dumps(jobs));self.assertEqual((self.host/'etc/vpn.conf').read_text(),'PRIVATE CONFIG')
 def test_active_transaction_and_parallel_writer_block_snapshot(self):
  tx=self.host/'var/lib/okopy-candidate';tx.mkdir();(tx/'transaction.json').write_text(json.dumps({'status':'pending'}))
  with self.assertRaisesRegex(ValueError,'неподтверждённое'):self.export()
  (tx/'transaction.json').unlink()
  with (self.panel/'draft.lock').open('a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX)
   with self.assertRaisesRegex(ValueError,'изменяются'):self.export()
 def test_foreign_signature_and_upload_symlink_rejected(self):
  value,_=self.export();(self.root/'signing.key').write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
  with self.assertRaises(ValueError):self.inspect(value)
  identifier=uuid.uuid4().hex;(self.panel/'backup-uploads'/(identifier+'.age')).symlink_to(self.host/'etc/vpn.conf')
  with self.assertRaises(ValueError):self.call('backup-inspect',id=identifier,recovery_key=self.identity.read_text())
  self.assertEqual((self.host/'etc/vpn.conf').read_text(),'PRIVATE CONFIG')
 def test_recovery_identity_is_an_inherited_pipe_not_a_disk_file(self):
  from unittest.mock import patch
  value,_=self.export();original=subprocess.Popen;seen=[]
  def checked(args,**kwargs):
   if '--decrypt' in args:
    identity=args[args.index('-i')+1];self.assertTrue(identity.startswith(('/proc/self/fd/','/dev/fd/')))
    self.assertEqual(len(kwargs['pass_fds']),1)
    self.assertFalse(any(self.root.glob('jobs/*/identity*')));seen.append(True)
   return original(args,**kwargs)
  with patch.object(backup.subprocess,'Popen',side_effect=checked):self.inspect(value)
  self.assertEqual(seen,[True])
 def test_plugin_identity_and_substituted_export_directory_rejected(self):
  value,_=self.export()
  with self.assertRaisesRegex(ValueError,'X25519'):self.inspect(value,'AGE-PLUGIN-ATTACKER-1abc')
  directory=self.panel/'backup-downloads';directory.rename(self.panel/'original-downloads');outside=self.path/'outside';outside.mkdir();directory.symlink_to(outside,target_is_directory=True)
  with self.assertRaises(ValueError):self.export()
  self.assertEqual(list(outside.iterdir()),[])
 def test_unrecognized_path_and_action_not_accepted(self):
  with self.assertRaises(ValueError):self.call('backup-create',id='../outside')
  with self.assertRaises(ValueError):self.call('backup-create',id=uuid.uuid4().hex,path='/etc/shadow')

if __name__=='__main__':unittest.main()
