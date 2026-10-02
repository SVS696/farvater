"""Private first-boot inputs stay out of the public stage and terminal output."""

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from werkzeug.security import check_password_hash
from candidate_bundle import validate_bundle
import system_backup
import provision_current as provision


@unittest.skipUnless(shutil.which('age-keygen'),'age-keygen required')
class PrivateOverlayTests(unittest.TestCase):
 def test_current_compiler_private_state_and_scope(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp).resolve();password=base/'password';password.write_text('synthetic-only-password-123');password.chmod(0o600)
   overlay=base/'overlay'
   result=provision.provision(overlay,username='testadmin',dns='192.0.2.53',host='example.invalid',
       before_url='http://127.0.0.1:18080/health',after_url='http://127.0.0.1:18080/health',
       tls_chain='/etc/letsencrypt/live/example.invalid/fullchain.pem',
       tls_key='/etc/letsencrypt/live/example.invalid/privkey.pem',password_file=password)
   self.assertEqual(result['status'],'private-overlay')
   self.assertNotIn('synthetic-only-password-123',json.dumps(result))
   panel=overlay/'var/lib/okopy-panel';candidate=overlay/'var/lib/okopy-candidate'
   auth=json.loads((panel/'auth.json').read_text())
   self.assertTrue(check_password_hash(auth['password_hash'],'synthetic-only-password-123'))
   rescue_auth=json.loads((overlay/'var/lib/okopy-recovery-ui/auth.json').read_text())
   self.assertEqual(rescue_auth['password_hash'],auth['password_hash'])
   self.assertEqual(rescue_auth['username'],auth['username'])
   self.assertNotEqual(rescue_auth['session_secret'],auth['session_secret'])
   validate_bundle({n:(candidate/n).read_bytes() for n in ('applied-policy.json','policy-manifest.json','config.json')})
   for name in ('apply.lock','routing.lock','lan.lock','vpn.lock'):
    self.assertEqual((candidate/name).stat().st_mode&0o777,0o600)
   self.assertEqual((overlay/'var/lib/okopy-recovery-ui/barrier.json').stat().st_mode&0o777,0o640)
   self.assertEqual((overlay/'var/www/certbot/.farvater-recovery').stat().st_mode&0o777,0o770)
   backup=json.loads((overlay/'var/lib/okopy-backup/settings.json').read_text())
   self.assertIn('var/lib/okopy-backup/recovery.agekey',backup['exclude'])
   self.assertIn('opt/farvater/app/web.py',backup['required'])
   self.assertNotIn('etc/systemd/system',backup['trees'])
   self.assertNotIn('var/lib/okopy-panel',backup['trees'])
   self.assertIn('var/lib/okopy-panel/policy.json',backup['globs'])
   self.assertIn('etc/systemd/system/okopy-*',backup['globs'])
   self.assertIn('etc/systemd/system/*.wants/wg-quick@*.service',backup['globs'])
   for durable in ('etc/wireguard','etc/amnezia/amneziawg','var/lib/okopy-wireguard',
                   'var/lib/okopy-openconnect','var/lib/okopy-trusttunnel','var/lib/okopy-amnezia',
                   'var/lib/okopy-monitor'):
    self.assertIn(durable,backup['trees'])
   self.assertIn('var/lib/okopy-candidate/routing-state.json',backup['exclude'])
   self.assertNotIn('var/lib/okopy-candidate/routing-preferences.json',backup['exclude'])
   host=base/'host';host.mkdir()
   for name in backup['required']:
    path=host/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('synthetic durable')
   native=host/'etc/wireguard/wg-test.conf';native.parent.mkdir(parents=True);native.write_text('synthetic key')
   monitor=host/'var/lib/okopy-monitor/checks.json';monitor.parent.mkdir(parents=True);monitor.write_text('{}')
   health=host/'var/lib/okopy-panel/health-transport.json';health.write_text('{}')
   wanted=host/'etc/systemd/system/multi-user.target.wants/wg-quick@wg-test.service'
   wanted.parent.mkdir(parents=True,exist_ok=True)
   wanted.symlink_to('/lib/systemd/system/wg-quick@.service')
   selected=system_backup.selected_paths(backup,host)
   self.assertIn('etc/wireguard/wg-test.conf',selected)
   self.assertIn('var/lib/okopy-monitor/checks.json',selected)
   self.assertNotIn('var/lib/okopy-panel/health-transport.json',selected)
   self.assertIn('etc/systemd/system/multi-user.target.wants/wg-quick@wg-test.service',selected)
   self.assertFalse(any(name.startswith('var/www/certbot/.farvater-recovery') for name in selected))

 def test_invalid_boundary_rejected_before_writing(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp).resolve();password=base/'password';password.write_text('synthetic-only-password-123');password.chmod(0o600)
   overlay=base/'overlay'
   kwargs=dict(username='testadmin',dns='192.0.2.53',host='example.invalid',
       before_url='http://127.0.0.1:18080/health',after_url='http://127.0.0.1:18080/health',
       tls_chain='/etc/letsencrypt/live/example.invalid/fullchain.pem',
       tls_key='/etc/letsencrypt/live/example.invalid/privkey.pem',password_file=password)
   with self.assertRaises(ValueError):provision.provision(Path('/'),**kwargs)
   with self.assertRaises(ValueError):provision.provision(overlay,**{**kwargs,'tls_key':'/etc/shadow'})
   self.assertFalse(overlay.exists())


if __name__=='__main__':unittest.main()
