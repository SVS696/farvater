import os,pwd,grp,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from backup_accounts import capture,compare

class BackupAccountTests(unittest.TestCase):
 def capture(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'file';p.touch();return capture(['file'],Path(d))
 def test_captures_owners_and_memberships_without_password_fields(self):
  value=self.capture();self.assertTrue(compare(value)['ready'])
  self.assertEqual(value['users'][0]['uid'],os.getuid())
  self.assertNotIn('password',str(value));self.assertNotIn('pw_passwd',str(value))
 def test_numeric_owner_collision_is_not_treated_as_compatible(self):
  value=self.capture();owner=value['users'][0]
  other=SimpleNamespace(pw_name='other-person',pw_uid=owner['uid'])
  with patch('backup_accounts.pwd.getpwuid',return_value=other):
   result=compare(value)
  self.assertFalse(result['ready']);self.assertEqual(result['issues'][0]['kind'],'conflicting_user')
 def test_missing_metadata_missing_user_and_unmapped_owner_are_visible(self):
  self.assertFalse(compare(None)['ready'])
  value=self.capture()
  with patch('backup_accounts.pwd.getpwuid',side_effect=KeyError),patch('backup_accounts.pwd.getpwnam',side_effect=KeyError):
   self.assertTrue(any(x['kind']=='missing_user' for x in compare(value)['issues']))
  value['unmapped_uids']=[99991];self.assertTrue(any(x['kind']=='unmapped_uid' for x in compare(value)['issues']))
 def test_changed_privileges_are_not_silently_accepted(self):
  value=self.capture();value['users'][0]['supplementary_gids'].append(99991)
  self.assertFalse(compare(value)['ready'])
 def test_owner_not_found_during_capture_is_recorded_without_invention(self):
  with patch('backup_accounts.pwd.getpwuid',side_effect=KeyError):value=self.capture()
  self.assertEqual(value['users'],[]);self.assertEqual(value['unmapped_uids'],[os.getuid()])
