"""TLS key custody stays outside the panel-writable socket directory."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import json
from datetime import datetime,timedelta,timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import recovery_access as access


class RecoveryAccessTests(unittest.TestCase):
 def test_rescue_auth_uses_same_password_hash_but_new_session_key(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp).resolve();ui=base/'ui';ui.mkdir(mode=0o750)
   source=base/'panel-auth.json'
   source.write_text(json.dumps({'username':'operator','password_hash':'synthetic-hash',
                                 'session_secret':'main-panel-secret'}));source.chmod(0o600)
   def account(name):
    return SimpleNamespace(pw_uid=os.geteuid(),pw_gid=os.getegid())
   with (patch.object(access,'OWNER',os.geteuid()),patch.object(access.pwd,'getpwnam',side_effect=account),
         patch.object(access.os,'fchown')):
    access.stage_auth(root=ui,source=source)
   copied=json.loads((ui/'auth.json').read_text())
   self.assertEqual(copied['username'],'operator')
   self.assertEqual(copied['password_hash'],'synthetic-hash')
   self.assertNotEqual(copied['session_secret'],'main-panel-secret')

 def test_tls_copies_only_to_root_private_recovery_tree(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp).resolve();ui=base/'recovery-ui';ui.mkdir(mode=0o750);tls=ui/'tls';tls.mkdir(mode=0o700)
   panel_sockets=base/'panel-sockets';panel_sockets.mkdir(mode=0o750)
   live=base/'letsencrypt/live';archive=base/'letsencrypt/archive';
   (live/'example').mkdir(parents=True);(archive/'example').mkdir(parents=True)
   private=ec.generate_private_key(ec.SECP256R1())
   name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'example.invalid')])
   now=datetime.now(timezone.utc)
   cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
         .public_key(private.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
         .sign(private,hashes.SHA256()))
   chain=cert.public_bytes(serialization.Encoding.PEM)
   key=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())
   (archive/'example/fullchain1.pem').write_bytes(chain)
   (archive/'example/privkey1.pem').write_bytes(key)
   (live/'example/fullchain.pem').symlink_to('../../archive/example/fullchain1.pem')
   (live/'example/privkey.pem').symlink_to('../../archive/example/privkey1.pem')
   with patch.object(access,'OWNER',os.geteuid()),patch.object(access.os,'fchown'):
    result=access.stage_tls(str(live/'example/fullchain.pem'),str(live/'example/privkey.pem'),
                            tls_root=tls,live_root=live,cert_root=archive)
   self.assertEqual(set(result),{'chain.pem','key.pem'})
   self.assertTrue((tls/'current').is_symlink())
   self.assertEqual((tls/'current/key.pem').read_bytes(),key)
   self.assertEqual((tls/'current/key.pem').stat().st_mode&0o777,0o600)
   self.assertEqual(list(panel_sockets.iterdir()),[])
   published=os.readlink(tls/'current')
   replace=os.replace
   def fail_pointer(source,destination):
    if Path(destination)==tls/'current':raise RuntimeError('simulated SIGKILL before publication')
    return replace(source,destination)
   with (patch.object(access,'OWNER',os.geteuid()),patch.object(access.os,'fchown'),
         patch.object(access.os,'replace',side_effect=fail_pointer)):
    with self.assertRaisesRegex(RuntimeError,'simulated SIGKILL'):
     access.stage_tls(str(live/'example/fullchain.pem'),str(live/'example/privkey.pem'),
                      tls_root=tls,live_root=live,cert_root=archive)
   self.assertEqual(os.readlink(tls/'current'),published)
   self.assertEqual((tls/'current/key.pem').read_bytes(),key)
   bad=ec.generate_private_key(ec.SECP256R1()).private_bytes(
       serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,
       serialization.NoEncryption())
   (archive/'example/privkey1.pem').write_bytes(bad)
   with patch.object(access,'OWNER',os.geteuid()),patch.object(access.os,'fchown'):
    with self.assertRaisesRegex(ValueError,'не совпадают'):
     access.stage_tls(str(live/'example/fullchain.pem'),str(live/'example/privkey.pem'),
                      tls_root=tls,live_root=live,cert_root=archive)
   self.assertEqual((tls/'current/key.pem').read_bytes(),key)


if __name__=='__main__':unittest.main()
