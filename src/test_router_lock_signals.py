"""Exercise real shell cleanup after a terminated staging/settings operation."""
import os,signal,subprocess,tempfile,time,unittest
from pathlib import Path
from router_settings import DEFAULT,compile_settings

class RouterSignalTests(unittest.TestCase):
    def run_interruption(self,mode):
        with tempfile.TemporaryDirectory() as d:
            top=Path(d);root=top/'ram';base=top/'usb';base.mkdir()
            for name in ['state','opt/bin','opt/lib']:(root/name).mkdir(parents=True,exist_ok=True)
            ld=root/'opt/lib/ld.so.1';ld.write_text('#!/bin/sh\nshift 2\nexec "$@"\n');ld.chmod(0o700)
            entered=top/'entered';bb=root/'opt/bin/busybox'
            bb.write_text('''#!/usr/bin/env python3
import os,sys,time
if sys.argv[1]==os.environ.get('OKOPY_TEST_PAUSE'):
 open(os.environ['OKOPY_TEST_ENTERED'],'w').close()
 time.sleep(60)
os.execvp(sys.argv[1],sys.argv[1:])
''');bb.chmod(0o700)
            if mode=='status':
                for p in [root/'settings.sh',base/'settings.sh']:p.write_bytes(compile_settings(DEFAULT))
                name='settings-control.sh';pause='cmp';lock=root/'state/settings.lock';action='status'
            else:
                name='bootstrap.sh';pause='cp';lock=top/'start.lock';action='start'
                (base/'runtime-files.txt').write_text('/opt/bin/busybox\n')
            source=(Path(__file__).parent/'router'/name).read_text().replace('/tmp/okopy-router-monitor-start.lock',str(top/'start.lock')).replace('/tmp/okopy-router-monitor',str(root)).replace('/opt/okopy-router-monitor',str(base))
            if mode!='status':source=source.replace('BB=/opt/bin/busybox','BB='+str(bb))
            script=top/name;script.write_text(source)
            env={**os.environ,'OKOPY_TEST_PAUSE':pause,'OKOPY_TEST_ENTERED':str(entered)}
            proc=subprocess.Popen(['sh',str(script),action],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                deadline=time.monotonic()+3
                while not entered.exists() and time.monotonic()<deadline:time.sleep(.02)
                self.assertTrue(entered.exists(),'Operation did not reach interruption point');self.assertTrue(lock.is_dir())
                os.killpg(proc.pid,signal.SIGHUP);proc.communicate(timeout=3)
                self.assertEqual(proc.returncode,74,'HUP was not routed through the explicit trap')
                self.assertFalse(lock.exists(),'Signal left an orphan lock')
                if mode!='status':self.assertFalse(list(top.glob('ram.next.*')))
            finally:
                if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()

    def test_settings_status_releases_lock_on_hangup(self):self.run_interruption('status')
    def test_bootstrap_releases_staging_lock_on_hangup(self):self.run_interruption('start')

if __name__=='__main__':unittest.main()
