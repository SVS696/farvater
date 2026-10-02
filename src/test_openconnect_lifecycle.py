import json,unittest
from safe_apply import atomic_write
from openconnect_control import control
import test_openconnect_apply as fixtures

class LifecycleBackend(fixtures.FakeBackend):
    enabled='enabled'
    def capture(self):return {**super().capture(),'boot':self.enabled}
    def set_enabled(self,value):self.events.append('enable' if value else 'disable');self.enabled='enabled' if value else 'disabled'

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ApplyTests();self.fixture.setUp();f=self.fixture
        atomic_write(f.root/'connections.json',json.dumps({'work':f.binding}).encode())
        self.backend=LifecycleBackend(f.root,f.binding,f.name)
    def tearDown(self):self.fixture.tearDown()
    def call(self,action,**fields):
        f=self.fixture;b=self.backend
        return control({'version':1,'action':'openconnect-'+action,'connection':'work',**fields},root=f.root,
            observe_state=lambda _: {'active':'active' if b.running else 'inactive','state':'running' if b.running else 'dead','boot':b.enabled},backend=b,network=None)
    def change(self,action,expected=None):
        view=self.call('status');fields={k:view[k] for k in ('file_revision','draft_revision')}
        fields['expected_state']=expected or {'active':self.backend.running,'boot':self.backend.enabled}
        if action in ('start','enable'):fields['probe']=self.fixture.probe
        return self.call(action,**fields)
    def test_stop_does_not_require_a_working_site_and_rollback_restarts(self):
        s=self.change('stop')['transaction'];self.assertFalse(self.backend.running)
        self.assertNotIn('probe',self.backend.events)
        self.call('rollback',transaction=s['id']);self.assertTrue(self.backend.running)
        self.assertEqual((self.fixture.root/'work.active.json').read_bytes(),self.fixture.original)
    def test_confirm_stop_then_start_and_confirm_preserves_autostart(self):
        stopped=self.change('stop')['transaction'];self.call('confirm',transaction=stopped['id']);self.assertFalse(self.backend.running)
        started=self.change('start')['transaction'];self.assertTrue(self.backend.running)
        self.call('confirm',transaction=started['id']);self.assertEqual(self.backend.enabled,'enabled')
    def test_start_rollback_restores_previously_stopped_service(self):
        self.backend.running=False;s=self.change('start')['transaction']
        self.call('rollback',transaction=s['id']);self.assertFalse(self.backend.running)
    def test_stale_state_cannot_stop_newly_changed_service(self):
        self.backend.running=False
        with self.assertRaises(ValueError):self.change('stop',{'active':True,'boot':'enabled'})
        self.assertNotIn('stop',self.backend.events)
    def test_autostart_toggle_does_not_restart_vpn(self):
        self.change('disable');self.assertEqual(self.backend.enabled,'disabled');self.assertTrue(self.backend.running)
        self.change('enable');self.assertEqual(self.backend.enabled,'enabled');self.assertNotIn('stop',self.backend.events)
    def test_enable_requires_running_verified_vpn(self):
        self.backend.running=False;self.backend.enabled='disabled'
        with self.assertRaises(ValueError):self.change('enable')
        self.assertEqual(self.backend.events,[])
    def test_pending_change_blocks_autostart_and_draft_blocks_stop(self):
        view=self.call('status');self.call('import',**{k:view[k] for k in ('file_revision','draft_revision')},format='openconnect',text='mtu=1400')
        with self.assertRaises(ValueError):self.change('stop')
        self.assertTrue(self.backend.running)
        view=self.call('status');self.call('discard',**{k:view[k] for k in ('file_revision','draft_revision')})
        self.change('stop')
        with self.assertRaises(ValueError):self.change('disable')

if __name__=='__main__':unittest.main()
