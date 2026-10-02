"""Frozen stdlib control remains usable after source replacement."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import restore_files


@unittest.skipUnless(sys.platform=='linux','Frozen filesystem test requires Linux metadata')
class FrozenControlTests(unittest.TestCase):
    def test_status_and_confirm_after_original_source_tree_disappears(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary).resolve();target=base/'target';source=base/'source';journal=base/'journal'
            target.mkdir(mode=0o700);source.mkdir(mode=0o700)
            (target/'setting').write_text('old');(source/'setting').write_text('new')
            restore_files.prepare(target,source,['setting'],['setting'],journal)
            restore_files.apply(journal)
            shutil.rmtree(source)
            frozen=journal/'rollback.py'
            first=subprocess.run([sys.executable,'-I',str(frozen),'status',str(journal)],capture_output=True,text=True,check=True)
            self.assertEqual(json.loads(first.stdout)['status'],'awaiting_confirmation')
            second=subprocess.run([sys.executable,'-I',str(frozen),'confirm',str(journal)],capture_output=True,text=True,check=True)
            self.assertEqual(json.loads(second.stdout)['status'],'confirmed')
            self.assertEqual((target/'setting').read_text(),'new')


if __name__=='__main__':unittest.main()
