"""A durable guard intent without a registered timer never looks armed."""

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import restore_files as files


class GuardRegistrationCrashTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.journal=Path(self.temp.name).resolve()/('a'*32);self.journal.mkdir(mode=0o700)
  token='b'*32
  (self.journal/'guard.json').write_text(json.dumps({'token':token,'timer':'okopy-restore-undo-'+token,
      'worker':'okopy-restore-worker-'+token,'deadline':time.monotonic()+300,'seconds':300}))
  self.plan={'live_root':True}
  @contextmanager
  def locked(_):yield self.journal,self.plan,Path('/'),{'status':'prepared'}
  self.locked=locked

 def test_unregistered_timer_requires_manual_return_not_a_second_start(self):
  with (patch.object(files,'locked',side_effect=self.locked),
        patch.object(files.subprocess,'run',return_value=SimpleNamespace(returncode=3))):
   result=files.status(self.journal)
  self.assertEqual(result['status'],'recovery_required')
  self.assertEqual(result['guard_registration'],'missing')
  self.assertNotIn('seconds_left',result)

 def test_registered_timer_hides_duplicate_start_while_worker_is_queued(self):
  with (patch.object(files,'locked',side_effect=self.locked),
        patch.object(files.subprocess,'run',return_value=SimpleNamespace(returncode=0))):
   result=files.status(self.journal)
  self.assertEqual(result['status'],'start_scheduled')
  self.assertEqual(result['guard_registration'],'active')
  self.assertGreater(result['seconds_left'],0)

 def test_prepared_return_fences_late_worker_before_opening_ingress(self):
  events=[]
  def save(path,value):events.append(('save',path.name,value['status'] if 'status' in value else 'cancel'))
  with (patch.object(files,'locked',side_effect=self.locked),patch.object(files,'save',side_effect=save),
        patch.object(files,'barrier_update',side_effect=lambda status,journal:events.append(('barrier',status)))):
   self.assertEqual(files.rollback(self.journal)['status'],'rolled_back')
  self.assertEqual(events,[('save','cancel.json','cancel'),('save','state.json','rolled_back'),
                           ('barrier','inactive')])


if __name__=='__main__':unittest.main()
