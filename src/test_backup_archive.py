import io,json,os,tarfile,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
import backup_archive as archive

class ArchiveTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir();(self.source/'private').mkdir(mode=0o700)
  (self.source/'private/key').write_bytes(b'PRIVATE FIXTURE');(self.source/'private/key').chmod(0o600);(self.source/'current').symlink_to('/opt/app/release')
  key=Ed25519PrivateKey.generate();self.private=key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption());self.public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  self.paths=['current','private','private/key']
 def tearDown(self):self.temp.cleanup()
 def encoded(self):
  out=io.BytesIO();manifest=archive.write(out,self.paths,source_root=self.source,private_key=self.private,metadata={'scope':'fixture'});return out.getvalue(),manifest
 def decode(self,data,key=None):return archive.read(io.BytesIO(data),public_key=key or self.public,staging=self.root/'staging')
 def rewrite(self,data,fn):
  source=tarfile.open(fileobj=io.BytesIO(data),mode='r:gz');out=io.BytesIO()
  with tarfile.open(fileobj=out,mode='w:gz') as target:
   for member in source:
    body=source.extractfile(member).read() if member.isfile() else None
    member,body=fn(member,body)
    if body is not None:member.size=len(body)
    target.addfile(member,io.BytesIO(body) if body is not None else None)
  return out.getvalue()
 def test_signed_roundtrip_keeps_modes_secrets_and_links_as_metadata(self):
  data,expected=self.encoded();actual=self.decode(data);self.assertEqual(actual,expected)
  self.assertEqual((self.root/'staging/objects'/archive.digest(b'PRIVATE FIXTURE')).read_bytes(),b'PRIVATE FIXTURE')
  self.assertFalse((self.root/'staging/current').exists());self.assertFalse((self.root/'staging/current').is_symlink())
  self.assertEqual(next(x for x in actual['files'] if x['path']=='private/key')['mode'],0o600)
 def test_changed_file_fails_signed_manifest(self):
  data,_=self.encoded()
  def change(member,body):return member,b'altered' if member.name=='files/private/key' else body
  with self.assertRaisesRegex(ValueError,'манифесту'):self.decode(self.rewrite(data,change))
 def test_changed_manifest_is_rejected(self):
  data,_=self.encoded()
  def change(member,body):
   if member.name=='manifest.json':body=body.replace(b'fixture',b'foreign')
   return member,body
  with self.assertRaisesRegex(ValueError,'Подпись'):self.decode(self.rewrite(data,change))
 def test_traversal_hardlink_and_unknown_member_rejected(self):
  data,_=self.encoded()
  for kind in ['traversal','hardlink','unknown']:
   stage=self.root/'staging'
   if stage.exists():import shutil;shutil.rmtree(stage)
   def change(member,body):
    if member.name=='files/private/key':
     if kind=='traversal':member.name='files/../../outside'
     elif kind=='unknown':member.name='command.py'
     else:member.type=tarfile.LNKTYPE;member.linkname='/etc/passwd';member.size=0;body=None
    return member,body
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.decode(self.rewrite(data,change))
   self.assertFalse((self.root/'outside').exists())
 def test_size_limit_checked_before_reading_body(self):
  from unittest.mock import patch
  data,_=self.encoded()
  with patch.object(archive,'MAX_FILE',3),self.assertRaises(ValueError):self.decode(data)
 def test_huge_pax_header_is_rejected_before_body_allocation(self):
  info=tarfile.TarInfo('pax');info.type=tarfile.XHDTYPE;info.size=512*1024*1024
  with self.assertRaisesRegex(ValueError,'заголовок'):archive.BoundedTarInfo.frombuf(info.tobuf(),encoding='utf-8',errors='strict')
 def test_foreign_key_cannot_validate_backup(self):
  data,_=self.encoded();other=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  with self.assertRaises(ValueError):self.decode(data,other)

if __name__=='__main__':unittest.main()
