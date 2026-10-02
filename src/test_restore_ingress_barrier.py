"""A live apply cannot modify files while primary HTTP ingress is open."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import restore_files as files


class LiveIngressBarrierTests(unittest.TestCase):
 def test_live_apply_fails_before_first_write_without_matching_lease(self):
  journal=Path('/var/lib/okopy-recovery')/('a'*32)
  plan={'live_root':True,'entries':{}}
  @contextmanager
  def locked(_):yield journal,plan,Path('/'),{'status':'prepared'}
  with (patch.object(files,'locked',side_effect=locked),
        patch.object(files,'barrier_status',return_value={'status':'inactive','job_id':None}),
        patch.object(files,'save') as save,
        patch.object(files,'install') as install):
   with self.assertRaisesRegex(ValueError,'HTTPS доступ'):
    files.apply(journal)
  save.assert_not_called();install.assert_not_called()

 def test_terminal_status_of_old_job_cannot_open_new_job_ingress(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp).resolve();root.chmod(0o750)
   lease=root/'barrier.json';lease.write_text(json.dumps({'version':1,'status':'inactive','job_id':None}));lease.chmod(0o640)
   capsule=root/'capsules';first=capsule/('a'*32);other=capsule/('b'*32)
   with (patch.object(files,'BARRIER_ROOT',root),patch.object(files,'BARRIER',lease),
         patch.object(files,'BARRIER_LOCK',root/'barrier.lock'),patch.object(files,'CAPSULE_ROOT',capsule),
         patch.object(files,'BARRIER_OWNER',os.geteuid()),
         patch.object(files.os,'geteuid',return_value=0),
         patch.object(files.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=os.getegid()))):
    files.barrier_update('active',first)
    with self.assertRaisesRegex(ValueError,'Другая операция'):
     files.barrier_update('inactive',other)
    self.assertEqual(files.barrier_status()['job_id'],'a'*32)
    files.barrier_update('inactive',first)
    self.assertEqual(files.barrier_status()['status'],'inactive')


if __name__=='__main__':unittest.main()
