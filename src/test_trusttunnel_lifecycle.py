import json,unittest
from unittest.mock import patch
from safe_apply import atomic_write,digest
from trusttunnel_control import control
from trusttunnel_runtime import LinuxBackend,CODE
from openconnect_apply import state
import test_trusttunnel_control as fixtures
import test_openconnect_apply as shared

class Backend(shared.FakeBackend):
    def __init__(self,*args):
        super().__init__(*args);self.child=True;self.enabled='enabled';self.child_enabled='enabled';self.partial_boot_failure=False
    def capture(self,stable=True):
        return {**super().capture(),'boot':self.enabled,'companions':{'inbound.service':{'active':self.child,'boot':self.child_enabled,'unit_sha256':digest(b'child')}}}
    def operation(self):return state(self.root)
    desired_companions=LinuxBackend.desired_companions
    active=LinuxBackend.active
    def stop(self):super().stop();self.child=False
    def start(self):super().start();self.child=self.desired_companions()['inbound.service']
    def set_enabled(self,enabled):
        self.events.append('enable' if enabled else 'disable');self.enabled='enabled' if enabled else 'disabled'
        if self.partial_boot_failure:raise ValueError('fixture partial failure')
        self.child_enabled=self.enabled

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ControlTests();self.fixture.setUp();f=self.fixture
        self.backend=Backend(f.root,f.binding,'vpn');self.probe={'url':'https://example.test/','codes':[200]}
        atomic_write(f.root/'vpn.active.json',json.dumps(f.model).encode())
        f.root.joinpath('tt.service').write_text('[Service]\nUser=tester\nExecStart=+/usr/bin/python3 -E -s -B '+str(CODE/'trusttunnel_start.py')+' vpn\n')
        self.receipt={'fixture':True};atomic_write(f.root/'vpn.installation.json',json.dumps(self.receipt).encode())
        self.installation=patch('trusttunnel_runtime.installation',return_value=self.receipt);self.installation.start()
    def tearDown(self):
        self.installation.stop();f=self.fixture
        f.root.joinpath('tt.service').write_bytes(f.baseline['unit_file']);self.fixture.tearDown()
    def observed(self,binding):
        b=self.backend
        return {'client':{'active':'active' if b.running else 'inactive','boot':b.enabled},'dependents':{'inbound.service':{'active':'active' if b.child else 'inactive','boot':b.child_enabled}}}
    def call(self,action,**fields):
        return control({'version':1,'action':'trusttunnel-'+action,'connection':'vpn',**fields},root=self.fixture.root,observe_state=self.observed,backend=self.backend,network=None)
    def change(self,action,**extra):
        view=self.call('status');fields={k:view[k] for k in ('file_revision','draft_revision')};fields['expected_state']=view['lifecycle_state']
        if action in ('start','enable'):fields['probe']=self.probe
        return self.call(action,**{**fields,**extra})
    def test_stop_without_probe_and_rollback_restores_pair(self):
        s=self.change('stop')['transaction'];self.assertFalse(self.backend.running or self.backend.child);self.assertNotIn('probe',self.backend.events)
        self.call('rollback',transaction=s['id']);self.assertTrue(self.backend.running and self.backend.child)
    def test_confirm_stop_then_start_whole_group_preserves_boot_flags(self):
        self.backend.child_enabled='disabled'
        s=self.change('stop')['transaction'];self.call('confirm',transaction=s['id'])
        s=self.change('start')['transaction'];self.assertTrue(self.backend.running and self.backend.child)
        self.call('confirm',transaction=s['id']);self.assertEqual(self.backend.child_enabled,'disabled')
    def test_start_rollback_restores_stopped_pair(self):
        self.backend.running=self.backend.child=False;s=self.change('start')['transaction']
        self.assertTrue(self.backend.running and self.backend.child)
        self.call('rollback',transaction=s['id']);self.assertFalse(self.backend.running or self.backend.child)
    def test_partial_group_start_rollback_keeps_previously_stopped_child_off(self):
        self.backend.child=False;s=self.change('start')['transaction'];self.assertTrue(self.backend.child)
        self.call('rollback',transaction=s['id']);self.assertTrue(self.backend.running);self.assertFalse(self.backend.child)
    def test_changed_child_state_in_browser_cannot_stop_new_group(self):
        old=self.call('status')['lifecycle_state'];self.backend.child=False
        with self.assertRaises(ValueError):self.change('stop',expected_state=old)
        self.assertEqual(self.backend.events,[])
    def test_invalid_expected_state_and_foreign_units_are_rejected(self):
        for value in ({}, {'active':1,'boot':'enabled','companions':{}},{'active':True,'boot':'enabled','companions':{'foreign.service':{'active':True,'boot':'enabled'}}}):
            with self.assertRaises(ValueError):self.change('stop',expected_state=value)
        self.assertEqual(self.backend.events,[])
    def test_autostart_disables_both_then_enables_both_without_restart(self):
        self.change('disable');self.assertEqual([self.backend.enabled,self.backend.child_enabled],['disabled','disabled'])
        self.change('enable');self.assertEqual([self.backend.enabled,self.backend.child_enabled],['enabled','enabled'])
        self.assertNotIn('stop',self.backend.events);self.assertTrue(self.backend.running and self.backend.child)
    def test_partial_boot_write_is_not_reported_as_success_and_state_remains_visible(self):
        self.backend.partial_boot_failure=True
        with self.assertRaisesRegex(ValueError,'часть настроек'):self.change('disable')
        v=self.call('status');self.assertEqual(v['lifecycle_state']['boot'],'disabled');self.assertEqual(v['lifecycle_state']['companions']['inbound.service']['boot'],'enabled')
        self.assertTrue(v['can_disable']);self.assertTrue(self.backend.running and self.backend.child)
        self.backend.partial_boot_failure=False;self.change('disable');self.assertFalse(self.call('status')['can_disable'])
    def test_enable_requires_both_services_active_and_probe(self):
        self.backend.enabled=self.backend.child_enabled='disabled';self.backend.child=False
        with self.assertRaises(ValueError):self.change('enable')
        self.assertEqual(self.backend.events,[])
    def test_pending_transaction_and_draft_block_lifecycle(self):
        view=self.call('status')
        # Use a supported endpoint setting; a pending draft cannot silently be applied by start.
        self.call('import',**{k:view[k] for k in ('file_revision','draft_revision')},format='endpoint',text='upstream_protocol="http3"')
        with self.assertRaises(ValueError):self.change('stop')
        view=self.call('status');self.call('discard',**{k:view[k] for k in ('file_revision','draft_revision')})
        self.change('stop')
        with self.assertRaises(ValueError):self.change('disable')

if __name__=='__main__':unittest.main()
