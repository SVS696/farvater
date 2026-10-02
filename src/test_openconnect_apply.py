import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from safe_apply import atomic_write,digest
from openconnect_profile import DEFAULT
from openconnect_apply import Transaction,state
from openconnect_start import prepare

class FakeBackend:
    def __init__(self,root,binding,name):
        self.root=root;self.binding=binding;self.name=name;self.running=True;self.boot='boot-1';self.events=[];self.arm_error=False;self.environment=True
    def boot_id(self):return self.boot
    def capture(self):return {'active':self.running,'boot':'enabled','unit_sha256':digest(b'known'),'script_sha256':digest(b'known')}
    def environment_matches(self,s):return self.environment
    def active(self):return self.running
    def stop(self):self.events.append('stop');self.running=False
    def start(self):self.events.append('start');self.running=True
    def validate(self,m):pass
    def probe(self,v):
        self.events.append('probe')
        if json.loads((self.root/(self.name+'.active.json')).read_text())['username']=='bad':raise ValueError('Probe failed')
        return {'http_code':200,'checked_at':1,'bound_to_vpn':True}
    def wait_ready(self,h):
        if digest((self.root/(self.name+'.active.json')).read_bytes())!=h or not self.running:raise ValueError('Not ready')
    def arm(self,i):
        self.events.append('arm')
        if self.arm_error:raise ValueError('Timer unavailable')
    def cancel(self,i):self.events.append('cancel')

class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700);self.name='work'
        self.binding={'unit':'work.service','unit_file':str(self.root/'work.service'),'password_file':str(self.root/'old.pass'),'interface':'vpn0','script':str(self.root/'route.sh'),'binary':'/usr/sbin/openconnect'}
        for key in ('unit_file','script'):Path(self.binding[key]).write_text('known')
        atomic_write(self.root/'work.installation.json',json.dumps({'unit_sha256':digest(b'known'),'script_sha256':digest(b'known')}).encode())
        self.model={**DEFAULT,'server':'https://vpn.test/?group=work','username':'old','password':'SECRET'}
        self.original=json.dumps(self.model).encode();atomic_write(self.root/'work.active.json',self.original)
        self.proposed=json.dumps({**self.model,'username':'next'}).encode();self.backend=FakeBackend(self.root,self.binding,self.name)
        self.tx=Transaction(self.root,self.binding,self.name,self.backend,network=None);self.probe={'url':'https://internal.test/','codes':[200]}
    def tearDown(self):self.tmp.cleanup()
    def apply(self):return self.tx.apply(self.original,self.proposed,self.probe)
    def test_confirm_and_stale_timer_are_noops_for_network(self):
        s=self.apply();self.assertEqual(s['status'],'pending');self.assertTrue(s['runtime_ready'])
        self.assertEqual(self.tx.confirm(s['id'])['status'],'confirmed');self.backend.events=[]
        self.assertEqual(self.tx.rollback(s['id'])['status'],'confirmed');self.assertEqual(self.tx.rollback('a'*32)['status'],'stale')
        self.assertEqual(self.backend.events,[]);self.assertEqual((self.root/'work.active.json').read_bytes(),self.proposed)
    def test_failed_probe_restores_old_model_and_runtime(self):
        self.proposed=json.dumps({**self.model,'username':'bad'}).encode()
        with self.assertRaises(ValueError):self.apply()
        self.assertEqual((self.root/'work.active.json').read_bytes(),self.original)
        self.assertTrue(self.backend.running);self.assertEqual(state(self.root)['status'],'rolled_back')
    def test_confirmation_that_finishes_after_deadline_keeps_rollback_armed(self):
        s=self.apply();self.backend.events=[]
        with patch('openconnect_apply.time.time',side_effect=[s['deadline']-20,s['deadline']+1]):
            with self.assertRaisesRegex(ValueError,'во время проверки'):self.tx.confirm(s['id'])
        self.assertEqual(state(self.root)['status'],'pending');self.assertNotIn('cancel',self.backend.events)
        self.tx.rollback(s['id']);self.assertEqual((self.root/'work.active.json').read_bytes(),self.original)
    def test_external_change_during_final_probe_cannot_be_confirmed(self):
        s=self.apply();self.backend.events=[]
        def probe(value):self.backend.environment=False;return {'http_code':200}
        with patch.object(self.backend,'probe',side_effect=probe):
            with self.assertRaisesRegex(ValueError,'во время проверки'):self.tx.confirm(s['id'])
        self.assertEqual(state(self.root)['status'],'pending');self.assertNotIn('cancel',self.backend.events)
    def test_service_stopped_outside_panel_during_initial_probe_is_not_restarted(self):
        def probe(value):self.backend.running=False;return {'http_code':200}
        with patch.object(self.backend,'probe',side_effect=probe):
            with self.assertRaisesRegex(ValueError,'во время проверки'):self.apply()
        self.assertFalse(self.backend.running);self.assertEqual(self.backend.events,[])
        self.assertFalse((self.root/'transaction.json').exists())
    def test_timer_failure_never_stops_service(self):
        self.backend.arm_error=True
        with self.assertRaises(ValueError):self.apply()
        self.assertNotIn('stop',self.backend.events);self.assertEqual((self.root/'work.active.json').read_bytes(),self.original)
        self.assertEqual(state(self.root)['status'],'schedule_failed')
    def test_only_one_unconfirmed_launch_attempt(self):
        s=self.apply();prepare(self.root,self.name,self.binding,self.backend)
        with self.assertRaises(ValueError):prepare(self.root,self.name,self.binding,self.backend)
        self.tx.confirm(s['id']);prepare(self.root,self.name,self.binding,self.backend)
    def test_reboot_recovers_before_native_launch(self):
        self.apply();self.backend.boot='boot-2';self.backend.events=[]
        runtime=prepare(self.root,self.name,self.binding,self.backend)
        self.assertEqual((self.root/'work.active.json').read_bytes(),self.original)
        self.assertEqual(state(self.root)['status'],'recovered');self.assertEqual(self.backend.events,[])
        self.assertIn(b'user=old\n',(runtime/'client.conf').read_bytes())
    def test_expired_transaction_recovers_without_another_login_attempt(self):
        s=self.apply()
        with patch('openconnect_start.time.time',return_value=s['deadline']+1):prepare(self.root,self.name,self.binding,self.backend)
        self.assertEqual((self.root/'work.active.json').read_bytes(),self.original)
    def test_unknown_external_config_is_never_overwritten(self):
        s=self.apply();foreign=json.dumps({**self.model,'username':'external'}).encode();atomic_write(self.root/'work.active.json',foreign)
        self.backend.events=[]
        with self.assertRaises(ValueError):self.tx.rollback(s['id'])
        self.assertEqual((self.root/'work.active.json').read_bytes(),foreign);self.assertNotIn('stop',self.backend.events)
        self.assertEqual(state(self.root)['status'],'recovery_required')
    def test_missing_backup_does_not_stop_current_service(self):
        s=self.apply();(self.root/'revisions'/s['id']/'previous.json').unlink();self.backend.events=[]
        with self.assertRaises(ValueError):self.tx.rollback(s['id'])
        self.assertNotIn('stop',self.backend.events)
    def test_environment_change_does_not_restart_foreign_service(self):
        s=self.apply();self.backend.environment=False;self.backend.events=[]
        with self.assertRaises(ValueError):self.tx.rollback(s['id'])
        self.assertNotIn('stop',self.backend.events);self.assertEqual(state(self.root)['status'],'recovery_required')
    def test_general_apply_excludes_openconnect_change(self):
        network=self.root/'network';network.mkdir();atomic_write(network/'transaction.json',b'{"status":"pending"}')
        self.tx.network=network
        with self.assertRaises(ValueError):self.apply()
        self.assertNotIn('stop',self.backend.events);self.assertFalse((self.root/'transaction.json').exists())

if __name__=='__main__':unittest.main()

class NativeOwnershipTests(unittest.TestCase):
    def test_active_process_must_match_config_boot_and_pid(self):
        from openconnect_runtime import LinuxBackend,CODE
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);binding={'unit':'x.service','unit_file':str(root/'unit'),'script':str(root/'script')}
            (root/'unit').write_text('ExecStart=/usr/bin/python3 -E -s -B '+str(CODE/'openconnect_start.py')+' x\n');(root/'script').write_text('script')
            content=b'{}';atomic_write(root/'x.active.json',content)
            backend=LinuxBackend(root,binding,'x')
            with patch('openconnect_control.observe',return_value={'active':'active','boot':'enabled','pid':22}),patch.object(backend,'boot_id',return_value='boot'):
                for wrong in ({'model_sha256':'bad','boot_id':'boot','pid':22},{'model_sha256':digest(content),'boot_id':'old','pid':22},{'model_sha256':digest(content),'boot_id':'boot','pid':21}):
                    atomic_write(root/'x.started.json',json.dumps(wrong).encode())
                    with self.assertRaises(ValueError):backend.capture()
                atomic_write(root/'x.started.json',json.dumps({'model_sha256':digest(content),'boot_id':'boot','pid':22}).encode())
                self.assertTrue(backend.capture()['active'])
