import fcntl
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from safe_apply import atomic_write
from wireguard_apply import Transaction
from wireguard_profile import parse
from wireguard_runtime import probe_values
from test_wireguard_profile import BASE,PRIVATE,PSK

PROBE={'address':'10.9.0.2','port':443,'mark':0}
NEW=BASE.replace('ListenPort = 51820','ListenPort = 51822').encode()

class FakeBackend:
    def __init__(self,profiles,active=True):
        self.profiles=profiles;self.events=[];self.boot='boot1';self.live=BASE.encode() if active else None
        self.active=active;self.fail_start=0;self.fail_stop=False;self.fail_arm=False;self.fail_probe=False;self.tx=None
    def boot_id(self):return self.boot
    def capture(self,name,original):return {'active':self.live is not None,'enabled':getattr(self,'enabled','enabled' if self.active else 'disabled'),'unit_files':{},'mode':0o600}
    def environment_matches(self,name,snapshot):return not getattr(self,'drift',False) and self.capture(name,b'')['enabled']==snapshot['enabled']
    def set_enabled(self,name,enabled):self.events.append(('enable',enabled));self.enabled='enabled' if enabled else 'disabled'
    def validate(self,name,model,activation=True):self.events.append('validate');self.activation_checked=activation
    def matches(self,name,content,snapshot,*,environment=True):
        if environment and not self.environment_matches(name,snapshot):return False
        return (self.live is None) if not snapshot['active'] else self.live is not None and parse(self.live.decode())==parse(content.decode())
    def stop(self,name):
        self.events.append(('stop',(self.profiles/(name+'.conf')).read_bytes()))
        if self.fail_stop:raise ValueError('stop failed')
        self.live=None
    def start(self,name):
        self.events.append('start')
        if self.fail_start:self.fail_start-=1;raise ValueError('start failed')
        if self.tx:self.tx.recover_before_start(name)
        self.live=(self.profiles/(name+'.conf')).read_bytes()
    def probe(self,name,value,model):
        self.events.append('probe')
        if self.fail_probe:raise ValueError('probe failed')
        return {'status':'connected','interface':name,'checked_at':time.time()}
    def arm(self,identifier):
        self.events.append('arm')
        if self.fail_arm:raise ValueError('arm failed')
    def cancel(self,identifier):self.events.append(('cancel',identifier))

class WGApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();base=Path(self.tmp.name)
        self.root=base/'state';self.root.mkdir(mode=0o700)
        self.profiles=base/'profiles';self.profiles.mkdir(mode=0o700)
        self.file=self.profiles/'wg0.conf';atomic_write(self.file,BASE.encode())
        self.backend=FakeBackend(self.profiles);self.tx=Transaction(self.root,self.profiles,self.backend);self.backend.tx=self.tx
    def tearDown(self):self.tmp.cleanup()
    def apply(self,probe=PROBE):return self.tx.apply('wg0',self.file.read_bytes(),NEW,probe)
    def test_apply_is_armed_before_old_stop_and_confirm_checks_actual_new_tunnel(self):
        result=self.apply();identifier=result['id']
        self.assertEqual(result['status'],'pending');self.assertEqual(self.file.read_bytes(),NEW)
        self.assertLess(self.backend.events.index('arm'),next(i for i,x in enumerate(self.backend.events) if isinstance(x,tuple) and x[0]=='stop'))
        self.assertEqual(next(x[1] for x in self.backend.events if isinstance(x,tuple) and x[0]=='stop'),BASE.encode())
        self.assertEqual(self.tx.confirm(identifier)['status'],'confirmed')
        self.assertEqual(self.backend.events.count('probe'),2)
        for secret in (PRIVATE,PSK):self.assertNotIn(secret,json.dumps(result))
    def test_rollback_stops_new_using_new_file_then_restores_old(self):
        s=self.apply();self.backend.events=[];self.tx.rollback(s['id'])
        self.assertEqual(self.backend.events[0],('stop',NEW))
        self.assertEqual(self.file.read_text(),BASE);self.assertEqual(self.backend.live,BASE.encode())
        self.backend.events=[];self.tx.rollback(s['id'])
        self.assertFalse(any(x=='start' or isinstance(x,tuple) and x[0]=='stop' for x in self.backend.events))
    def test_arm_failure_never_touches_runtime_or_file(self):
        self.backend.fail_arm=True
        with self.assertRaisesRegex(ValueError,'arm'):self.apply()
        self.assertEqual(self.file.read_text(),BASE);self.assertNotIn('start',self.backend.events)
        self.assertEqual(self.tx.state()['status'],'schedule_failed')
    def test_start_failure_immediately_restores_old_and_old_guard_does_not_deadlock(self):
        self.backend.fail_start=1
        with (self.root/'control.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            with self.assertRaisesRegex(ValueError,'start'):self.apply()
        self.assertEqual(self.file.read_text(),BASE);self.assertEqual(self.tx.state()['status'],'rolled_back')
    def test_same_boot_apply_guard_skips_parent_writer_lock(self):
        with (self.root/'control.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            s=self.apply()
        self.assertEqual(s['status'],'pending')
    def test_corrupt_backup_refuses_before_stopping_network(self):
        s=self.apply();atomic_write(self.tx.revision(s,'previous'),b'broken');self.backend.events=[]
        with self.assertRaises(ValueError):self.tx.rollback(s['id'])
        self.assertFalse(any(x=='start' or isinstance(x,tuple) and x[0]=='stop' for x in self.backend.events));self.assertEqual(self.file.read_bytes(),NEW)
        self.assertEqual(self.tx.state()['status'],'recovery_required')
    def test_missing_live_file_restored_using_known_runtime_version(self):
        s=self.apply();self.file.unlink();self.backend.events=[]
        self.tx.rollback(s['id'])
        self.assertEqual(self.backend.events[0],('stop',NEW));self.assertEqual(self.file.read_text(),BASE)
    def test_unexpected_external_file_is_preserved_before_recovery(self):
        s=self.apply();external=BASE.replace('51820','51824').encode();atomic_write(self.file,external)
        self.tx.rollback(s['id'])
        preserved=list((self.root/'revisions'/s['id']).glob('unexpected-*.conf'))
        self.assertEqual(len(preserved),1);self.assertEqual(preserved[0].read_bytes(),external)
        self.assertEqual(self.file.read_text(),BASE)
    def test_lost_journal_ack_does_not_restart_an_already_restored_interface(self):
        s=self.apply();self.tx.rollback(s['id']);state=self.tx.state();state['status']='rollback_failed';self.tx.save(state)
        self.backend.events=[];self.tx.rollback(s['id'])
        self.assertEqual(self.tx.state()['status'],'rolled_back');self.assertNotIn('start',self.backend.events)
    def test_probe_failure_cannot_confirm_or_cancel_rollback(self):
        s=self.apply();self.backend.fail_probe=True;self.backend.events=[]
        with self.assertRaises(ValueError):self.tx.confirm(s['id'])
        self.assertEqual(self.tx.state()['status'],'pending');self.assertFalse(any(isinstance(x,tuple) for x in self.backend.events))
    def test_expired_or_changed_config_cannot_confirm(self):
        s=self.apply();state=self.tx.state();state['deadline']=time.time()-1;self.tx.save(state)
        with self.assertRaises(ValueError):self.tx.confirm(s['id'])
        state['deadline']=time.time()+100;self.tx.save(state);atomic_write(self.file,BASE.encode())
        with self.assertRaises(ValueError):self.tx.confirm(s['id'])
    def test_deadline_is_checked_again_after_probe(self):
        s=self.apply()
        with patch('wireguard_apply.time.time',side_effect=[s['deadline']-20,s['deadline']-19,s['deadline']+1]):
            with self.assertRaises(ValueError):self.tx.confirm(s['id'])
        self.assertEqual(self.tx.state()['status'],'pending')
    def test_previous_boot_recovers_file_before_start_without_recursing_service(self):
        s=self.apply();self.backend.boot='boot2';self.backend.live=None;self.backend.events=[]
        result=self.tx.recover_before_start('wg0')
        self.assertEqual(result['status'],'recovered');self.assertTrue(result['recovered_before_start'])
        self.assertEqual(self.file.read_text(),BASE);self.assertNotIn('start',self.backend.events)
    def test_boot_guard_does_not_touch_a_different_profile(self):
        self.apply();self.backend.boot='boot2'
        self.assertEqual(self.tx.recover_before_start('other'),{'status':'unchanged'});self.assertEqual(self.file.read_bytes(),NEW)
    def test_stale_timer_cannot_undo_new_transaction(self):
        old=self.apply();self.tx.rollback(old['id']);new=self.apply()
        self.tx.rollback(old['id']);self.assertEqual(self.tx.state()['id'],new['id']);self.assertEqual(self.file.read_bytes(),NEW)
    def test_inactive_profile_stays_inactive_and_does_not_probe(self):
        self.backend.active=False;self.backend.live=None
        s=self.apply(probe=None);self.tx.confirm(s['id'])
        self.assertNotIn('start',self.backend.events);self.assertNotIn('probe',self.backend.events)
        self.assertFalse(self.backend.activation_checked)
        self.assertFalse(any(isinstance(x,tuple) and x[0]=='stop' for x in self.backend.events))
    def test_same_probe_must_be_allowed_after_change(self):
        changed=NEW.replace(b'10.9.0.2/32',b'10.9.0.3/32')
        with self.assertRaisesRegex(ValueError,'исключён'):self.tx.apply('wg0',BASE.encode(),changed,PROBE)
        self.assertNotIn('arm',self.backend.events);self.assertEqual(self.file.read_text(),BASE)
    def test_probe_fields_are_ip_only_and_strictly_bounded(self):
        for value in [{**PROBE,'address':'example.com'},{**PROBE,'address':'127.0.0.1'},{**PROBE,'port':True},{**PROBE,'mark':-1},{**PROBE,'command':'id'}]:
            with self.subTest(value=value),self.assertRaises(ValueError):probe_values(value)

    def test_unit_drift_does_not_flap_restored_tunnel(self):
        s=self.apply();self.backend.drift=True
        with self.assertRaisesRegex(ValueError,'systemd'):self.tx.rollback(s['id'])
        self.assertEqual(self.file.read_text(),BASE);self.assertEqual(self.tx.state()['status'],'recovery_required')
        self.backend.events=[];self.tx.rollback(s['id'])
        self.assertNotIn('start',self.backend.events)
        with self.assertRaises(ValueError):self.tx.rollback(s['id'],manual=True)
        self.assertNotIn('start',self.backend.events)
        self.backend.drift=False;self.tx.rollback(s['id'],manual=True)
        self.assertEqual(self.tx.state()['status'],'rolled_back');self.assertNotIn('start',self.backend.events)

    def test_failed_stops_are_bounded_to_three_automatic_attempts(self):
        s=self.apply();self.backend.fail_stop=True
        for _ in range(3):
            with self.assertRaises(ValueError):self.tx.rollback(s['id'])
        self.backend.events=[];self.tx.rollback(s['id'])
        self.assertEqual(self.tx.state()['status'],'recovery_required')
        self.assertFalse(any(isinstance(x,tuple) and x[0]=='stop' for x in self.backend.events))
        self.backend.fail_stop=False;self.tx.rollback(s['id'],manual=True)
        self.assertEqual(self.tx.state()['status'],'rolled_back')

    def test_boot_accepts_live_original_when_backup_is_missing(self):
        s=self.apply();atomic_write(self.file,BASE.encode());self.tx.revision(s,'previous').unlink()
        self.backend.boot='boot2';self.backend.live=None
        self.assertEqual(self.tx.recover_before_start('wg0')['status'],'recovered')
        self.assertEqual(self.file.read_text(),BASE)

    def test_boot_preserves_emergency_edit_before_replacement(self):
        s=self.apply();emergency=BASE.replace('51820','51825').encode();atomic_write(self.file,emergency)
        self.backend.boot='boot2';self.backend.live=None;self.tx.recover_before_start('wg0')
        copies=list((self.root/'revisions'/s['id']).glob('unexpected-*.conf'))
        self.assertEqual(copies[0].read_bytes(),emergency);self.assertEqual(self.file.read_text(),BASE)

    def test_stale_file_rollback_after_reboot_never_restarts_transiently_active_profile(self):
        self.backend.enabled='disabled';s=self.apply()
        self.backend.boot='boot2';self.backend.live=None;self.backend.events=[]
        self.assertEqual(self.tx.rollback(s['id'],manual=True)['status'],'recovered')
        self.assertEqual(self.file.read_text(),BASE);self.assertIsNone(self.backend.live)
        self.assertFalse(any(x=='start' or isinstance(x,tuple) and x[0]=='stop' for x in self.backend.events))
