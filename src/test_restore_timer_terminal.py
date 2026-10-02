"""A terminal rollback disarms its exact timer after releasing the journal lock."""

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import restore_files as files


class TerminalTimerTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.journal=Path(self.temp.name).resolve()/('a'*32);self.journal.mkdir(mode=0o700)
  token='b'*32
  self.timer='okopy-restore-undo-'+token+'.timer'
  (self.journal/'guard.json').write_text(json.dumps({'token':token,'timer':'okopy-restore-undo-'+token,
      'worker':'okopy-restore-worker-'+token,'deadline':time.monotonic()+300,'seconds':300}))
  self.held=False

 def locked(self,state):
  @contextmanager
  def enter(_):
   self.held=True
   try:yield self.journal,{'live_root':True,'entries':{}},Path('/'),{'status':state}
   finally:self.held=False
  return enter

 def test_automatic_rollback_stops_timer_outside_journal_lock(self):
  commands=[]
  def systemd(args,**kwargs):
   self.assertFalse(self.held)
   commands.append(args)
   return SimpleNamespace(stdout='loaded\n' if args[1]=='show' else '')
  with (patch.object(files,'locked',side_effect=self.locked('awaiting_confirmation')),
        patch.object(files,'verify_objects'),patch.object(files,'install'),
        patch.object(files,'save'),patch.object(files,'barrier_update'),
        patch.object(files.subprocess,'run',side_effect=systemd)):
   result=files.rollback(self.journal)
  self.assertEqual(result,{'status':'rolled_back'})
  self.assertEqual(commands[0],['systemctl','show',self.timer,'--property=LoadState','--value'])
  self.assertEqual(commands[1],['systemctl','stop',self.timer])

 def test_terminal_status_after_reboot_accepts_absent_timer(self):
  commands=[]
  def systemd(args,**kwargs):
   self.assertFalse(self.held)
   commands.append(args)
   return SimpleNamespace(stdout='not-found\n')
  with (patch.object(files,'locked',side_effect=self.locked('rolled_back')),
        patch.object(files,'barrier_status',return_value={'job_id':None}),
        patch.object(files,'barrier_update'),
        patch.object(files.subprocess,'run',side_effect=systemd)):
   result=files.status(self.journal)
  self.assertEqual(result['status'],'rolled_back')
  self.assertNotIn('timer_cleanup_pending',result)
  self.assertEqual(commands,[['systemctl','show',self.timer,'--property=LoadState','--value']])


if __name__=='__main__':unittest.main()
