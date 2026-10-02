import fcntl
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wireguard_control import control
from wireguard_profile import parse
from test_wireguard_profile import BASE,PRIVATE,PSK


def observed(names):
    return {n:{'service':'active','substate':'exited','boot':'enabled','interface':True} for n in names}


class WireGuardControlTests(unittest.TestCase):
    def setUp(self):
        oc_state=patch('openconnect_apply.state',return_value={});oc_state.start();self.addCleanup(oc_state.stop)
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.profiles=self.root/'profiles';self.profiles.mkdir(mode=0o700)
        self.drafts=self.root/'drafts';self.drafts.mkdir(mode=0o700)
        self.file=self.profiles/'wg0.conf';self.file.write_text(BASE);self.file.chmod(0o600)
    def tearDown(self):self.temp.cleanup()
    def call(self,action='status',**fields):
        return control({'version':1,'action':'wireguard-'+action,'profile':'wg0',**fields},profiles=self.profiles,drafts=self.drafts,observe=observed)
    def save(self,view=None,**changes):
        view=view or self.call()
        return self.call('save',file_revision=view['file_revision'],draft_revision=view['draft_revision'],values=changes.get('values',view['model']))

    def test_real_file_untouched_and_secrets_stay_server_side_after_noop_save(self):
        before=self.file.read_bytes();view=self.call();result=self.save(view)
        self.assertFalse(result['runtime_changed']);after=self.call()
        self.assertTrue(after['has_draft']);self.assertEqual(before,self.file.read_bytes())
        draft=self.drafts/'wg0.json';self.assertEqual(draft.stat().st_mode&0o777,0o600)
        self.assertEqual(parse(json.loads(draft.read_text())['profile']),parse(BASE))
        for value in (view,after,self.call(profile=None),result):
            for secret in (PRIVATE,PSK):self.assertNotIn(secret,json.dumps(value))

    def test_stale_form_cannot_replace_or_discard_newer_draft(self):
        old=self.call();self.save(old);before=(self.drafts/'wg0.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'изменился'):self.save(old)
        with self.assertRaisesRegex(ValueError,'изменился'):self.call('discard',file_revision=old['file_revision'],draft_revision='')
        self.assertEqual(before,(self.drafts/'wg0.json').read_bytes())

    def test_manual_edit_conflict_preserves_both_files_until_explicit_discard(self):
        self.save();self.file.write_text(BASE.replace('51820','51822'))
        view=self.call();self.assertTrue(view['conflict']);before=(self.drafts/'wg0.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'вне панели'):self.save(view)
        self.assertEqual(before,(self.drafts/'wg0.json').read_bytes())
        self.call('discard',file_revision=view['file_revision'],draft_revision=view['draft_revision'])
        self.assertFalse(self.call()['has_draft']);self.assertEqual(self.call()['model']['interface']['ListenPort'],51822)

    def test_write_lock_rejects_concurrent_request_without_waiting(self):
        with (self.drafts/'control.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            with self.assertRaisesRegex(ValueError,'занят'):self.call()

    def test_traversal_hooks_links_and_exposed_secret_files_are_rejected(self):
        for name in ('../passwd','wg0/../../x','-option','x'*16):
            with self.subTest(name=name),self.assertRaises(ValueError):self.call(profile=name)
        self.file.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'0600'):self.call()
        self.file.chmod(0o600);self.file.write_text(BASE.replace('[Peer]','PostUp = private-string\n[Peer]'))
        result=self.call(profile=None);self.assertFalse(result['profiles'][0]['editable']);self.assertNotIn('private-string',json.dumps(result))
        self.file.unlink();self.file.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError):self.call()

    def test_corrupt_draft_is_not_replaced_silently(self):
        draft=self.drafts/'wg0.json';draft.write_text('{bad');draft.chmod(0o600)
        view=self.call();self.assertIn('повреждён',view['error']);self.assertIsNone(view['model'])
        with self.assertRaisesRegex(ValueError,'повреждён'):self.save(view)
        self.assertEqual(draft.read_text(),'{bad')
        self.call('discard',file_revision=view['file_revision'],draft_revision=view['draft_revision'])
        self.assertFalse(draft.exists());self.assertEqual(self.file.read_text(),BASE)

    def test_unsupported_working_file_does_not_trap_existing_draft(self):
        self.save();self.file.write_text(BASE.replace('[Peer]','DNS = 1.1.1.1\n[Peer]'))
        before=self.file.read_bytes();view=self.call();self.assertTrue(view['error'])
        self.call('discard',file_revision=view['file_revision'],draft_revision=view['draft_revision'])
        self.assertFalse((self.drafts/'wg0.json').exists());self.assertEqual(self.file.read_bytes(),before)

    def test_adapter_has_no_apply_or_arbitrary_runtime_command(self):
        with patch('wireguard_control.subprocess.run') as run:
            for action in ('apply','restart','stop'):
                with self.assertRaises(ValueError):self.call(action)
            with self.assertRaises(ValueError):self.call(command='id')
            self.save()
        run.assert_not_called()
