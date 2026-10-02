import json
from io import BytesIO
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import build_current as kit
import verify_current


class CurrentKitTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        vendor=Path(self.temp.name)/'vendor';vendor.mkdir()
        archives={}
        for role,(name,_,prefix,members) in kit.ARCHIVES.items():
            archive=vendor/name
            with tarfile.open(archive,'w:gz') as output:
                for member in members:
                    raw=(role+'/'+member+'\n').encode();info=tarfile.TarInfo(prefix+member)
                    info.size=len(raw);output.addfile(info,BytesIO(raw))
            archives[role]=(name,kit.sha(archive),prefix,members)
        for key,value in (('VENDOR',vendor),('ARCHIVES',archives)):
            replacement=patch.object(kit,key,value);replacement.start();self.addCleanup(replacement.stop)

    def test_current_source_excludes_historical_private_and_tests(self):
        names={p.relative_to(kit.SOURCE).as_posix() for p in kit.selected_source()}
        self.assertIn('recovery_control.py',names)
        self.assertIn('router/bootstrap.sh',names)
        self.assertIn('deploy/okopy-amnezia@.service',names)
        self.assertFalse(any(n.startswith(('historical-install-materials/','privileged-runtime/','graphify-out/')) or Path(n).name.startswith('test_') for n in names))

    def test_archive_digest_mismatch_never_publishes_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);vendor=base/'vendor';vendor.mkdir()
            (vendor/kit.ARCHIVES['sing-box'][0]).write_bytes(b'wrong')
            with patch.object(kit,'VENDOR',vendor),self.assertRaisesRegex(ValueError,'digest mismatch'):
                kit.build(base/'stage')
            self.assertFalse((base/'stage').exists())

    def test_generated_manifest_contains_no_local_path_or_secret(self):
        stage=Path(self.temp.name)/'stage';manifest=kit.build(stage)
        self.assertEqual(manifest['status'],'staged')
        self.assertFalse(manifest['runtime_ready'])
        self.assertFalse(manifest['secrets_included'])
        self.assertNotIn('source_root',manifest)
        self.assertEqual(manifest['engines']['trusttunnel-client']['archive_sha256'],kit.ARCHIVES['trusttunnel-client'][1])
        self.assertEqual(manifest['provision_tool_sha256'],kit.sha(kit.ROOT/'install/provision_current.py'))
        self.assertEqual(manifest['platform'],'linux-amd64')
        self.assertNotIn('system_packages',manifest)

    def test_stage_has_current_units_and_protected_writer_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary)/'stage'
            kit.build(stage)
            root=stage/'rootfs'
            panel=(root/'etc/systemd/system/okopy-panel.service').read_text()
            candidate=(root/'etc/systemd/system/okopy-candidate.service').read_text()
            guard=(root/'usr/local/lib/systemd/system/okopy-panel.service.d/80-infrastructure-recovery-access.conf').read_text()
            rescue=(root/'etc/systemd/system/infrastructure-recovery-ui.service').read_text()
            https=(root/'usr/local/lib/systemd/system/infrastructure-recovery-https.service').read_text()
            sudoers=(root/'etc/sudoers.d/farvater-recovery-ui').read_text()
            self.assertIn('/opt/farvater/app/web.py',panel)
            self.assertIn('/var/lib/okopy-candidate/sing-box',candidate)
            boot=(root/'etc/systemd/system/okopy-candidate.service.d/10-boot-recovery.conf').read_text()
            self.assertIn('ExecStartPre=/usr/bin/python3 -E -s -B /var/lib/okopy-candidate/safe_apply.py recover-before-start',boot)
            self.assertNotIn('safe_apply.py recover-before-start',candidate)
            self.assertIn('ExecStartPre=+/usr/bin/python3 -I /opt/okopy-recovery-ui/writer_guard.py',guard)
            self.assertIn('User=okopy-recovery',rescue)
            self.assertIn('/var/www/certbot/.farvater-recovery',rescue)
            self.assertIn('/opt/okopy-panel/proxy/Caddyfile',https)
            self.assertIn('ReadOnlyPaths=/var/lib/okopy-recovery-ui/tls',https)
            refresh=(root/'etc/letsencrypt/renewal-hooks/deploy/infrastructure-recovery-tls.sh').read_text()
            self.assertIn('/opt/okopy-recovery-ui/tls_refresh.py',refresh)
            self.assertIn('infrastructure-recovery-https.service',refresh)
            self.assertIn('okopy-recovery ALL=(root)',sudoers)
            self.assertNotIn('okopy-panel ALL=(root)',sudoers)
            self.assertTrue((stage/'tools/provision_current.py').is_file())
            self.assertEqual((root/'opt/okopy-backup-tools/age').readlink(),Path('/usr/bin/age'))
            pin=kit.sha(stage/'manifest.json')
            self.assertEqual(verify_current.verify(stage,pin)['status'],'verified')
            (root/'etc/systemd/system/okopy-panel.service').write_text(panel+'\n# modified\n')
            with self.assertRaisesRegex(ValueError,'rootfs has changed'):
                verify_current.verify(stage,pin)

    def test_verifier_rejects_unmanifested_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary)/'stage';kit.build(stage);pin=kit.sha(stage/'manifest.json')
            cache=stage/'rootfs/opt/farvater/app/__pycache__';cache.mkdir()
            (cache/'candidate_bundle.cpython-312.pyc').write_bytes(b'foreign cache')
            with self.assertRaisesRegex(ValueError,'extra entries'):
                verify_current.verify(stage,pin)


if __name__=='__main__':unittest.main()
