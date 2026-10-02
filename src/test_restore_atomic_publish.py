"""A process death before publication cannot expose a partial journal."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import restore_files as files


class AtomicJournalPublicationTests(unittest.TestCase):
 def test_sigkill_before_rename_leaves_no_executable_journal(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp).resolve();target=base/'target';source=base/'source';journal=base/'journal'
   target.mkdir(mode=0o700);source.mkdir(mode=0o700)
   (target/'config').write_text('old');(source/'config').write_text('new')
   code='''import os,signal,sys,restore_files as r
r.os.listxattr=lambda path,follow_symlinks=False: []
r.boot_id=lambda: '00000000-0000-0000-0000-000000000001'
original=os.rename
def die_before_publish(src,dst):
 if os.path.basename(src).startswith('.preparing-'):
  os.kill(os.getpid(),signal.SIGKILL)
 return original(src,dst)
os.rename=die_before_publish
r.prepare(sys.argv[1],sys.argv[2],['config'],['config'],sys.argv[3])
'''
   env={**os.environ,'PYTHONPATH':str(Path(files.__file__).parent)}
   result=subprocess.run([sys.executable,'-B','-c',code,str(target),str(source),str(journal)],
                         capture_output=True,env=env,timeout=10)
   self.assertEqual(result.returncode,-signal.SIGKILL,result.stderr.decode())
   self.assertFalse(journal.exists())
   self.assertEqual(len(list(base.glob('.preparing-journal-*'))),1)
   with (patch.object(files.os,'listxattr',side_effect=lambda path,follow_symlinks=False:[],create=True),
         patch.object(files,'boot_id',return_value='00000000-0000-0000-0000-000000000001')):
    self.assertEqual(files.prepare(target,source,['config'],['config'],journal)['status'],'prepared')
   self.assertTrue((journal/'plan.json').is_file())
   self.assertTrue((journal/'state.json').is_file())


if __name__=='__main__':unittest.main()
