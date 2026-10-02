"""Public recovery identity is separate from age secrets and archive content."""

import base64
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import system_backup as backup


class TrustIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.root = base / 'backup'
        self.root.mkdir(mode=0o700)
        self.anchors = base / 'anchors'
        self.anchors.mkdir(mode=0o700)
        self.anchor_id = 'a' * 32
        self.key = Ed25519PrivateKey.generate()
        (self.root / 'signing.key').write_bytes(self.key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        (self.root / 'settings.json').write_text(json.dumps({
            'version': 1, 'recipient': 'age1' + 'a' * 58,
            'host_id': 'local-host', 'scope': 'server', 'exclusions': [],
        }))

    def test_export_is_public_and_local_identity_is_default(self):
        exported = backup.trust_export(self.root)
        raw = json.dumps(exported)
        self.assertNotIn(base64.b64encode((self.root / 'signing.key').read_bytes()).decode(), raw)
        self.assertEqual(exported['host_id'], 'local-host')
        identity = backup.verification_identity(self.root)
        self.assertEqual(identity['public_key'], backup.public_key(self.root))
        self.assertEqual(identity['host_id'], 'local-host')

    def test_external_anchor_must_be_preprovisioned_and_exact(self):
        public = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        record = {'version': 1, 'host_id': 'old-host', 'scope': 'server',
                  'signing_public_key': base64.b64encode(public).decode(),
                  'signing_fingerprint': hashlib.sha256(public).hexdigest()}
        path = self.anchors / (self.anchor_id + '.json')
        path.write_text(json.dumps(record));path.chmod(0o600)
        with patch.object(backup, 'ANCHOR_ROOT', self.anchors), patch.object(backup.os, 'geteuid', return_value=path.stat().st_uid):
            identity = backup.verification_identity(self.root, self.anchor_id)
            self.assertEqual(identity['public_key'], public)
            self.assertEqual(identity['host_id'], 'old-host')
            self.assertEqual(identity['anchor_id'], self.anchor_id)
            self.assertEqual(backup.available_anchors(self.root),[{'id':self.anchor_id,'host_id':'old-host',
                'scope':'server','signing_fingerprint':record['signing_fingerprint']}])
            with self.assertRaises(ValueError):backup.verification_identity(self.root, 'b' * 32)
            with self.assertRaises(ValueError):backup.verification_identity(self.root, '../other')
            record['signing_fingerprint'] = '0' * 64
            path.write_text(json.dumps(record))
            with self.assertRaises(ValueError):backup.verification_identity(self.root, self.anchor_id)


@unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'),'age CLI required')
class ExternalAnchorRoundtrip(unittest.TestCase):
    from test_system_backup import SystemBackupTests as fixture
    setUp=fixture.setUp
    tearDown=fixture.tearDown
    call=fixture.call
    export=fixture.export

    def test_foreign_local_signer_needs_preprovisioned_old_anchor(self):
        exported,_=self.export();old=backup.public_key(self.root)
        (self.root/'signing.key').write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        anchors=self.path/'anchors';anchors.mkdir(mode=0o700);anchors=anchors.resolve();anchor_id='a'*32
        record={'version':1,'host_id':'fixture','scope':'server',
                'signing_public_key':base64.b64encode(old).decode(),
                'signing_fingerprint':hashlib.sha256(old).hexdigest()}
        (anchors/(anchor_id+'.json')).write_text(json.dumps(record));(anchors/(anchor_id+'.json')).chmod(0o600)
        def upload():
            value=uuid.uuid4().hex
            shutil.copyfile(self.panel/'backup-downloads'/(exported+'.age'),self.panel/'backup-uploads'/(value+'.age'))
            return value
        with patch.object(backup,'ANCHOR_ROOT',anchors):
            with self.assertRaises(ValueError):self.call('backup-inspect',id=upload(),recovery_key=self.identity.read_text())
            result=self.call('backup-inspect',id=upload(),recovery_key=self.identity.read_text(),anchor_id=anchor_id)
        self.assertEqual(result['status'],'checked')
        self.assertEqual(result['anchor_id'],anchor_id)
        self.assertEqual(result['summary']['unsupported'],0)


if __name__ == '__main__':
    unittest.main()
