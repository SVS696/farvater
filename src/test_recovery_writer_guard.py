"""The protected panel drop-in has no permissive unknown phase."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import stat

import recovery_writer_guard as guard


class WriterGuardTests(unittest.TestCase):
 def test_unknown_or_active_denies_panel_start(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve();root.chmod(0o750)
   lease=root/'barrier.json'
   def publish(status,job):
    lease.write_text(json.dumps({'version':1,'status':status,'job_id':job}));lease.chmod(0o640)
   with patch.object(guard,'OWNER',os.geteuid()),patch.object(guard.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=os.getegid())):
    self.assertFalse(guard.allowed(root=root))
    publish('active','a'*32);self.assertFalse(guard.allowed(root=root))
    publish('verifying_writers','a'*32);self.assertTrue(guard.allowed(root=root))
    publish('rollback_writers','a'*32);self.assertTrue(guard.allowed(root=root))
    publish('inactive',None);self.assertTrue(guard.allowed(root=root))
    self.assertTrue(guard.allowed('okopy-routing.service',root=root))
    with patch.object(guard.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=os.getegid()+1)):
     self.assertFalse(guard.allowed(root=root))
    with patch.object(os,'getegid',return_value=0):
     self.assertTrue(guard.allowed('okopy-routing.service',root=root))
    self.assertFalse(guard.allowed('other.service',root=root))
    publish('unknown',None);self.assertFalse(guard.allowed(root=root))

 def test_parent_and_leaf_group_must_match_panel_group(self):
  parent=SimpleNamespace(st_mode=stat.S_IFDIR|0o750,st_uid=0,st_gid=986)
  leaf=SimpleNamespace(st_mode=stat.S_IFREG|0o640,st_uid=0,st_gid=986,st_size=50)
  self.assertTrue(guard.secure_metadata(parent,leaf,986))
  self.assertFalse(guard.secure_metadata(SimpleNamespace(**{**vars(parent),'st_gid':0}),leaf,986))
  self.assertFalse(guard.secure_metadata(parent,SimpleNamespace(**{**vars(leaf),'st_gid':0}),986))


if __name__=='__main__':unittest.main()
