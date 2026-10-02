import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from safe_apply import atomic_write,digest
from trusttunnel_profile import DEFAULT
from trusttunnel_apply import Transaction,state
import test_openconnect_apply as shared

class Backend(shared.FakeBackend):
    def __init__(self,*args):super().__init__(*args);self.child=True;self.child_start_failure=False
    def capture(self):return {**super().capture(),'companions':{'entry.service':{'active':self.child,'boot':'enabled','unit_sha256':digest(b'child')}}}
    def stop(self):super().stop();self.child=False
    def start(self):
        super().start()
        if self.child_start_failure:self.child_start_failure=False;raise ValueError('Dependent service failed')
        self.child=state(self.root)['snapshot']['companions']['entry.service']['active']

class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.model={**DEFAULT,'hostname':'vpn.test','addresses':['192.0.2.1:443'],'username':'old','password':'PRIVATE'}
        self.old=json.dumps(self.model).encode();self.new=json.dumps({**self.model,'username':'next'}).encode()
        atomic_write(self.root/'vpn.active.json',self.old);self.backend=Backend(self.root,{},'vpn');self.tx=Transaction(self.root,{},'vpn',self.backend,network=None);self.probe={'url':'https://example.test/','codes':[200]}
    def tearDown(self):self.temp.cleanup()
    def apply(self):return self.tx.apply(self.old,self.new,self.probe)
    def test_confirm_and_old_timer_preserve_both_running_services(self):
        s=self.apply();self.tx.confirm(s['id']);self.backend.events=[];self.tx.rollback(s['id'])
        self.assertTrue(self.backend.running and self.backend.child);self.assertEqual(self.backend.events,[])
    def test_rollback_restores_both_services_and_private_model(self):
        s=self.apply();self.tx.rollback(s['id']);self.assertTrue(self.backend.running and self.backend.child)
        self.assertEqual((self.root/'vpn.active.json').read_bytes(),self.old)
    def test_previously_stopped_dependent_stays_stopped(self):
        self.backend.child=False;s=self.apply();self.assertFalse(self.backend.child);self.tx.rollback(s['id']);self.assertFalse(self.backend.child)
    def test_dependent_start_failure_restores_original_pair(self):
        self.backend.child_start_failure=True
        with self.assertRaises(ValueError):self.apply()
        self.assertTrue(self.backend.running and self.backend.child);self.assertEqual(state(self.root)['status'],'rolled_back')
    def test_malformed_dependent_snapshot_is_rejected_before_stop(self):
        self.apply();s=state(self.root);s['snapshot']['companions']['entry.service']['active']='yes';self.tx.save(s);self.backend.events=[]
        with self.assertRaises(ValueError):self.tx.rollback(s['id'])
        self.assertEqual(self.backend.events,[])
    def test_boot_recovery_restores_file_without_service_commands(self):
        s=self.apply();self.backend.boot='boot-2';self.backend.events=[];self.tx.rollback(s['id'],before_start=True)
        self.assertEqual((self.root/'vpn.active.json').read_bytes(),self.old);self.assertEqual(self.backend.events,[]);self.assertEqual(state(self.root)['status'],'recovered')
    def test_another_vpn_change_blocks_shared_transaction(self):
        network=self.root/'network';network.mkdir();atomic_write(network/'transaction.json',b'{"status":"confirmed"}');self.tx.network=network
        with patch('openconnect_apply.state',side_effect=lambda root=None: {} if root==self.root else {'status':'pending'}),patch('wireguard_apply.Transaction.state',return_value={'status':'confirmed'}):
            with self.assertRaises(ValueError):self.apply()
        self.assertNotIn('stop',self.backend.events)

if __name__=='__main__':unittest.main()
