import io,json,os,stat,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
import backup_archive as archive
from backup_restore_tree import materialize

class RestoreTreeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
  self.src=self.root/'source';self.src.mkdir();(self.src/'etc').mkdir();(self.src/'etc/private.conf').write_text('fixture secret');(self.src/'etc/private.conf').chmod(0o600)
  (self.src/'current').symlink_to('/absolute/original/release')
  self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  buffer=io.BytesIO();archive.write(buffer,['etc','etc/private.conf','current'],source_root=self.src,private_key=self.key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()),metadata={'scope':'fixture'})
  buffer.seek(0);self.staged=self.root/'staged';self.manifest=archive.read(buffer,public_key=self.pub,staging=self.staged);self.dest=self.root/'restored'
 def tearDown(self):self.tmp.cleanup()
 def restore(self):return materialize(self.staged,self.dest,self.pub)
 def test_exact_files_owners_modes_and_absolute_links_without_execution(self):
  result=self.restore();self.assertTrue(result['content_verified']);self.assertFalse(result['services_started'])
  for r in self.manifest['files']:
   path=self.dest/r['path'];st=path.lstat();self.assertEqual(st.st_uid,r['uid']);self.assertEqual(st.st_gid,r['gid'])
   if r['kind']=='file':self.assertEqual(path.read_text(),'fixture secret');self.assertEqual(stat.S_IMODE(st.st_mode),0o600)
   elif r['kind']=='symlink':self.assertEqual(os.readlink(path),r['target'])
 def test_existing_destination_and_live_root_are_never_overwritten(self):
  self.dest.mkdir();(self.dest/'keep').write_text('keep')
  with self.assertRaises(ValueError):self.restore()
  self.assertEqual((self.dest/'keep').read_text(),'keep')
  with self.assertRaises(ValueError):materialize(self.staged,'/',self.pub)
 def test_damaged_blob_never_publishes_partial_tree(self):
  r=next(r for r in self.manifest['files'] if r['kind']=='file');(self.staged/'objects'/r['sha256']).write_text('bad')
  with self.assertRaises(ValueError):self.restore()
  self.assertFalse(self.dest.exists());self.assertEqual(list(self.root.glob('.restore-*')),[])
 def test_blob_symlink_cannot_read_an_unrelated_file(self):
  r=next(r for r in self.manifest['files'] if r['kind']=='file');p=self.staged/'objects'/r['sha256'];p.unlink();p.symlink_to(self.src/'etc/private.conf')
  with self.assertRaises((OSError,ValueError)):self.restore()
  self.assertFalse(self.dest.exists())
 def test_mutated_manifest_and_wrong_signing_key_fail(self):
  raw=(self.staged/'manifest.json').read_bytes();(self.staged/'manifest.json').write_bytes(raw+b' ')
  with self.assertRaises(ValueError):self.restore()
  (self.staged/'manifest.json').write_bytes(raw);self.pub=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  with self.assertRaises(ValueError):self.restore()
 def test_signed_symlink_parent_and_traversal_still_rejected(self):
  for path in ['../escape','current/escape']:
   m=json.loads(json.dumps(self.manifest));m['files'].append({'path':path,'kind':'directory','mode':448,'uid':os.getuid(),'gid':os.getgid()})
   raw=archive.canonical(m);(self.staged/'manifest.json').write_bytes(raw);(self.staged/'manifest.sig').write_bytes(self.key.sign(raw))
   with self.assertRaises(ValueError):self.restore()
 def test_destination_under_symlink_or_shared_parent_rejected(self):
  link=self.root/'link';link.symlink_to(self.root);self.dest=link/'restored'
  with self.assertRaises(ValueError):self.restore()
  self.dest=self.root/'restored';self.root.chmod(0o755)
  with self.assertRaises(ValueError):self.restore()
  self.root.chmod(0o700)
