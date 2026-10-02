"""The public Linux preflight never writes the host and refuses collisions."""

from io import BytesIO
import json
from pathlib import Path
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import build_current
import linux_install


@unittest.skipUnless(shutil.which('openssl'),'OpenSSL needed for a synthetic TLS pair')
class LinuxInstallTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.base=Path(self.temp.name).resolve();self.stage=self.base/'stage'
  vendor=self.base/'vendor';vendor.mkdir()
  archives={}
  for role,(name,_,prefix,members) in build_current.ARCHIVES.items():
   archive=vendor/name
   with tarfile.open(archive,'w:gz') as output:
    for member in members:
     raw=(role+'/'+member+'\n').encode();info=tarfile.TarInfo(prefix+member)
     info.size=len(raw);output.addfile(info,BytesIO(raw))
   archives[role]=(name,build_current.sha(archive),prefix,members)
  with patch.object(build_current,'VENDOR',vendor),patch.object(build_current,'ARCHIVES',archives):
   self.manifest=build_current.build(self.stage)
  self.pin=build_current.sha(self.stage/'manifest.json')
  self.overlay=self.base/'overlay';self.overlay.mkdir(mode=0o700)
  self.host=self.base/'host';self.host.mkdir(mode=0o700)
  for name in ('var/lib/okopy-panel/auth.json','var/lib/okopy-panel/policy.json',
               'var/lib/okopy-candidate/config.json','var/lib/okopy-backup/signing.key',
               'var/lib/okopy-backup/settings.json','var/lib/okopy-recovery-ui/auth.json',
               'var/lib/okopy-recovery-ui/barrier.json'):
   path=self.overlay/name;path.parent.mkdir(parents=True,exist_ok=True)
   path.write_text('synthetic');path.chmod(0o640 if name.startswith('var/lib/okopy-recovery-ui/') else 0o600)
  for name,content in (('etc/farvater/panel.env','OKOPY_TRUSTED_HOSTS=example.invalid\n'),
                       ('etc/farvater/recovery-ui.env','FARVATER_RECOVERY_HOSTS=example.invalid\n')):
   path=self.overlay/name;path.parent.mkdir(parents=True,exist_ok=True)
   path.write_text(content);path.chmod(0o600)
  for name in ('var/lib/okopy-panel/backup-uploads','var/lib/okopy-panel/backup-downloads',
               'var/lib/okopy-backup/jobs','var/lib/okopy-recovery/anchors',
               'var/lib/okopy-recovery-ui/tls','var/www/certbot/.farvater-recovery'):
   path=self.overlay/name;path.mkdir(parents=True,exist_ok=True)
   path.chmod(0o770 if name=='var/www/certbot/.farvater-recovery' else 0o700)
  (self.overlay/'var/lib/okopy-recovery-ui').chmod(0o750)
  for name in ('okopy-panel','okopy-candidate','okopy-backup','okopy-recovery'):
   (self.overlay/'var/lib'/name).chmod(0o700)
  settings=self.overlay/'var/lib/okopy-recovery/settings.json';settings.parent.mkdir(parents=True,exist_ok=True)
  settings.write_text(json.dumps({'tls_chain_source':'/etc/letsencrypt/live/example.invalid/fullchain.pem',
                                  'tls_key_source':'/etc/letsencrypt/live/example.invalid/privkey.pem'}));settings.chmod(0o600)
  archive=self.host/'etc/letsencrypt/archive/example.invalid';archive.mkdir(parents=True)
  live=self.host/'etc/letsencrypt/live/example.invalid';live.mkdir(parents=True)
  subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                  '-nodes','-days','1','-subj','/CN=example.invalid',
                  '-addext','subjectAltName=DNS:example.invalid',
                  '-keyout',str(archive/'privkey1.pem'),'-out',str(archive/'fullchain1.pem')],
                 check=True,capture_output=True,timeout=15)
  (live/'fullchain.pem').symlink_to('../../archive/example.invalid/fullchain1.pem')
  (live/'privkey.pem').symlink_to('../../archive/example.invalid/privkey1.pem')

 def prepare(self):
  return linux_install.plan(self.stage,self.overlay,self.pin,['127.0.0.1/32'],18443,
                            root=self.host,capabilities=False)

 def test_read_only_preflight_then_exact_copy_refuses_second_install(self):
  self.assertEqual(self.manifest['platform'],'linux-amd64')
  rootfs=self.stage/'rootfs'
  panel_unit=(rootfs/'etc/systemd/system/okopy-panel.service').read_text()
  rescue_unit=(rootfs/'etc/systemd/system/infrastructure-recovery-ui.service').read_text()
  https_unit=(rootfs/'usr/local/lib/systemd/system/infrastructure-recovery-https.service').read_text()
  self.assertNotIn('SupplementaryGroups=',panel_unit)
  self.assertNotIn('SupplementaryGroups=',rescue_unit)
  self.assertIn('SupplementaryGroups=okopy-panel okopy-recovery',https_unit)
  self.assertNotIn('Group=okopy-recovery',https_unit)
  tmpfiles=(rootfs/'etc/tmpfiles.d/farvater-recovery.conf').read_text()
  self.assertIn('.farvater-recovery 2770 root okopy-recovery',tmpfiles)
  self.assertIn('.okopy-panel 2770 root okopy-panel',tmpfiles)
  prepared=self.prepare()
  self.assertFalse((self.host/'opt/farvater/app/web.py').exists())
  linux_install.copy_tree(prepared)
  for name in ('var/www','var/www/certbot'):
   self.assertEqual(stat.S_IMODE((self.host/name).stat().st_mode),0o711)
  self.assertEqual((self.host/'opt/farvater/app/web.py').read_bytes(),
                   (self.stage/'rootfs/opt/farvater/app/web.py').read_bytes())
  self.assertIn('forward_auth',(self.host/'opt/okopy-panel/proxy/Caddyfile').read_text())
  with self.assertRaisesRegex(ValueError,'уже существует'):self.prepare()

 def test_preflight_refuses_existing_state_without_writing(self):
  prior=self.host/'var/lib/okopy-panel';prior.mkdir(parents=True)
  (prior/'keep').write_text('unrelated')
  with self.assertRaisesRegex(ValueError,'уже существует'):self.prepare()
  self.assertEqual((prior/'keep').read_text(),'unrelated')
  self.assertFalse((self.host/'opt/farvater').exists())

 def test_preflight_refuses_untraversable_existing_socket_ancestor(self):
  parent=self.host/'var/www';parent.mkdir(parents=True,mode=0o700)
  parent.chmod(0o700)
  with self.assertRaisesRegex(ValueError,'недоступен отдельному rescue'):
   self.prepare()
  self.assertFalse((self.host/'opt/farvater').exists())

 def test_preflight_rejects_certificate_for_another_host(self):
  panel=self.overlay/'etc/farvater/panel.env';rescue=self.overlay/'etc/farvater/recovery-ui.env'
  panel.write_text('OKOPY_TRUSTED_HOSTS=other.invalid\n')
  rescue.write_text('FARVATER_RECOVERY_HOSTS=other.invalid\n')
  with self.assertRaisesRegex(ValueError,'не соответствует HTTPS Host'):self.prepare()
  self.assertFalse((self.host/'opt/farvater').exists())

 def test_apply_enables_only_after_validation_and_keeps_existing_files(self):
  commands=[]
  def recorded(args):commands.append(args);return ''
  account=SimpleNamespace(pw_uid=os.geteuid(),pw_gid=os.getegid())
  group=SimpleNamespace(gr_gid=os.getegid())
  with (patch.object(linux_install,'run',side_effect=recorded),
        patch.object(linux_install.pwd,'getpwnam',return_value=account),
        patch.object(linux_install.grp,'getgrnam',return_value=group),
        patch.object(linux_install.os,'chown')):
   result=linux_install.install(self.stage,self.overlay,self.pin,['127.0.0.1/32'],18443,
                                root=self.host,capabilities=False)
  self.assertEqual(result['status'],'installed')
  self.assertEqual(result['services'],4)
  caddy=next(i for i,cmd in enumerate(commands) if cmd[:2]==['/usr/bin/caddy','validate'])
  reload=next(i for i,cmd in enumerate(commands) if cmd[:2]==['systemctl','daemon-reload'])
  enabled=[(i,cmd) for i,cmd in enumerate(commands) if cmd[:3]==['systemctl','enable','--now']]
  self.assertEqual(len(enabled),4)
  self.assertTrue(caddy<reload<enabled[0][0])
  with self.assertRaisesRegex(ValueError,'уже существует'):self.prepare()

 def test_changed_stage_and_symlinked_private_source_are_rejected(self):
  with (self.stage/'rootfs/etc/systemd/system/okopy-panel.service').open('a') as output:
   output.write('# altered\n')
  with self.assertRaisesRegex(ValueError,'changed'):self.prepare()
  # The source descriptor itself must not follow a replaced private file.
  private=self.overlay/'var/lib/okopy-panel/auth.json';private.unlink();private.symlink_to(self.host/'etc/letsencrypt/archive/example.invalid/privkey1.pem')
  with self.assertRaisesRegex(ValueError,'Ссылки в приватном overlay'):linux_install.overlay_inputs(self.overlay,os.geteuid())

 def test_copy_file_never_unlinks_existing_target_on_collision(self):
  source=self.overlay/'var/lib/okopy-panel/policy.json'
  target=self.host/'collision';target.write_text('keep me')
  with self.assertRaises(FileExistsError):linux_install.copy_file(source,target,0o600)
  self.assertEqual(target.read_text(),'keep me')
  source.unlink();source.symlink_to(target)
  other=self.host/'other'
  with self.assertRaises(OSError):linux_install.copy_file(source,other,0o600)
  self.assertFalse(other.exists())


if __name__=='__main__':unittest.main()
