"""Behavior of runtime trials, durable boot policy, and their separate failures."""
import fcntl
import json
import unittest
from unittest.mock import patch
import test_wireguard_apply as apply_tests
from test_wireguard_apply import PROBE
import test_wireguard_web as web_tests
from test_wireguard_profile import BASE


class RuntimeLifecycleTests(unittest.TestCase):
    setUp=apply_tests.WGApplyTests.setUp
    tearDown=apply_tests.WGApplyTests.tearDown
    def runtime(self,active):
        snapshot=self.backend.capture('wg0',self.file.read_bytes())
        return self.tx.apply('wg0',self.file.read_bytes(),self.file.read_bytes(),PROBE if active else None,
                             runtime_active=active,expected_state={k:snapshot[k] for k in ('active','enabled')})
    def test_stop_arms_before_disconnect_and_rolls_back_without_changing_file_or_boot(self):
        state=self.runtime(False)
        self.assertIsNone(self.backend.live);self.assertEqual(self.file.read_text(),BASE)
        self.assertLess(self.backend.events.index('arm'),next(i for i,x in enumerate(self.backend.events) if isinstance(x,tuple) and x[0]=='stop'))
        self.tx.rollback(state['id'])
        self.assertEqual(self.backend.live,BASE.encode());self.assertEqual(self.backend.capture('wg0',b'')['enabled'],'enabled')
    def test_failed_runtime_start_restores_inactive_without_changing_autostart(self):
        self.backend.live=None;self.backend.enabled='disabled';self.backend.fail_start=1
        with self.assertRaisesRegex(ValueError,'start'):self.runtime(True)
        self.assertIsNone(self.backend.live);self.assertEqual(self.file.read_text(),BASE)
        self.assertEqual(self.tx.state()['status'],'rolled_back');self.assertEqual(self.backend.enabled,'disabled')
        self.assertNotIn('probe',self.backend.events)
    def test_confirm_start_and_stop_verify_target_runtime(self):
        stop=self.runtime(False);self.tx.confirm(stop['id']);self.assertIsNone(self.backend.live)
        start=self.runtime(True);self.tx.confirm(start['id']);self.assertEqual(self.backend.live,BASE.encode())
        self.assertEqual(self.backend.events.count('probe'),0)
    def test_arm_failure_keeps_active_tunnel_running(self):
        self.backend.fail_arm=True
        with self.assertRaises(ValueError):self.runtime(False)
        self.assertEqual(self.backend.live,BASE.encode())
    def test_stale_observed_state_never_arms_or_mutates(self):
        with self.assertRaisesRegex(ValueError,'изменилось'):
            self.tx.apply('wg0',self.file.read_bytes(),self.file.read_bytes(),None,runtime_active=False,
                          expected_state={'active':False,'enabled':'enabled'})
        self.assertNotIn('arm',self.backend.events)
    def test_reboot_follows_boot_policy_for_all_four_prior_combinations(self):
        for prior_active in (False,True):
            for enabled in ('enabled','disabled'):
                with self.subTest(prior_active=prior_active,enabled=enabled):
                    path=self.root/'transaction.json'
                    if path.exists():path.unlink()
                    self.backend.boot='boot1';self.backend.enabled=enabled
                    self.backend.live=BASE.encode() if prior_active else None
                    state=self.runtime(not prior_active)
                    self.backend.boot='boot2';self.backend.live=BASE.encode() if enabled=='enabled' else None
                    self.backend.events=[]
                    self.assertEqual(self.tx.recover_before_start('wg0'),{'status':'unchanged'})
                    self.assertTrue(self.tx.public()['boot_changed'])
                    result=self.tx.rollback(state['id'],manual=True)
                    self.assertEqual(result['status'],'rolled_back')
                    self.assertFalse(any(x=='start' or isinstance(x,tuple) and x[0]=='stop' for x in self.backend.events))
    def test_reboot_failed_start_is_not_claimed_as_recovered(self):
        state=self.runtime(False);self.backend.boot='boot2';self.backend.live=None;self.backend.events=[]
        with self.assertRaisesRegex(ValueError,'После перезагрузки'):self.tx.rollback(state['id'])
        self.assertEqual(self.tx.state()['status'],'recovery_required');self.assertNotIn('start',self.backend.events)
    def test_external_file_edit_is_preserved_without_running_it(self):
        state=self.runtime(False);external=BASE.replace('51820','51824');self.file.write_text(external)
        self.backend.events=[]
        with self.assertRaisesRegex(ValueError,'изменён вне'):self.tx.rollback(state['id'])
        self.assertEqual(self.file.read_text(),external);self.assertNotIn('start',self.backend.events)
    def test_unit_drift_prevents_using_changed_service_during_runtime_recovery(self):
        state=self.runtime(False);self.backend.drift=True;self.backend.events=[]
        with self.assertRaisesRegex(ValueError,'systemd'):self.tx.rollback(state['id'])
        self.assertNotIn('start',self.backend.events);self.assertIsNone(self.backend.live)
    def test_runtime_boot_guard_never_takes_parent_lock(self):
        state=self.runtime(False);self.backend.boot='boot2'
        with (self.root/'control.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            self.assertEqual(self.tx.recover_before_start('wg0'),{'status':'unchanged'})

    def test_failed_boot_can_be_closed_honestly_then_guarded_start_retried(self):
        state=self.runtime(False);self.backend.boot='boot2';self.backend.live=None
        with self.assertRaises(ValueError):self.tx.rollback(state['id'],manual=True)
        closed=self.tx.abandon_runtime(state['id']);self.assertEqual(closed['status'],'closed_unrestored')
        self.assertIsNone(self.backend.live)
        retry=self.runtime(True);self.assertEqual(retry['status'],'pending')

    def test_abandon_refuses_healthy_same_boot_trial_and_never_reopens_old_timer(self):
        state=self.runtime(False)
        with self.assertRaises(ValueError):self.tx.abandon_runtime(state['id'])
        self.backend.boot='boot2';self.tx.abandon_runtime(state['id']);self.backend.events=[]
        self.tx.rollback(state['id']);self.assertNotIn('start',self.backend.events)

    def test_external_start_is_not_confirmed_as_stop_or_flapped_by_rollback(self):
        state=self.runtime(False);self.backend.live=BASE.encode();self.backend.events=[]
        with self.assertRaises(ValueError):self.tx.confirm(state['id'])
        self.assertEqual(self.tx.state()['status'],'pending')
        self.tx.rollback(state['id'])
        self.assertFalse(any(x=='start' or isinstance(x,tuple) and x[0]=='stop' for x in self.backend.events))

    def test_process_died_before_ready_can_rollback_but_not_confirm(self):
        state=self.runtime(False);s=self.tx.state();s['runtime_ready']=False;self.tx.save(s)
        with self.assertRaises(ValueError):self.tx.confirm(state['id'])
        self.tx.rollback(state['id']);self.assertEqual(self.backend.live,BASE.encode())

    def test_corrupt_journal_stops_own_timer_without_start_or_stop(self):
        from unittest.mock import Mock
        import wireguard_apply
        fake=Mock();fake.root=self.root;fake.state.side_effect=ValueError('corrupt')
        identifier='a'*32
        with patch.object(wireguard_apply,'ROOT',self.root),patch.object(wireguard_apply,'Transaction',return_value=fake),patch('wireguard_apply.os.geteuid',return_value=0),patch('wireguard_apply.sys.argv',['runner','rollback',identifier]):
            with self.assertRaisesRegex(ValueError,'corrupt'):wireguard_apply.main()
        fake.backend.cancel.assert_called_once_with(identifier);fake.rollback.assert_not_called()


class LifecycleWebTests(unittest.TestCase):
    setUp=web_tests.WireGuardWebTests.setUp
    tearDown=web_tests.WireGuardWebTests.tearDown
    call=web_tests.WireGuardWebTests.call
    fields=web_tests.WireGuardWebTests.fields
    def lifecycle_fields(self):
        fields=self.fields();s=self.backend.capture('wg0',b'')
        fields.update(expected_active='true' if s['active'] else 'false',expected_enabled=s['enabled'])
        return fields
    def test_web_stop_and_manual_restore_preserve_autostart(self):
        response=self.client.post('/wireguard/wg0/stop',data=self.lifecycle_fields(),follow_redirects=True)
        self.assertEqual(response.status_code,200);self.assertIn('Подтвердить выключение',response.text)
        state=json.loads((self.drafts/'transaction.json').read_text())
        response=self.client.post('/wireguard/wg0/rollback',data={'csrf':'test-csrf','transaction':state['id']})
        self.assertEqual(response.status_code,302);self.assertEqual(self.backend.live,BASE.encode())
    def test_autostart_disable_keeps_running_and_enable_requires_probe(self):
        response=self.client.post('/wireguard/wg0/disable',data=self.lifecycle_fields())
        self.assertEqual(response.status_code,302);self.assertEqual(self.backend.enabled,'disabled')
        self.assertEqual(self.backend.live,BASE.encode())
        fields=self.lifecycle_fields();fields.update(probe_address='10.9.0.2',probe_port='443',probe_mark='0')
        self.backend.fail_probe=True
        self.assertEqual(self.client.post('/wireguard/wg0/enable',data=fields).status_code,409)
        self.assertEqual(self.backend.enabled,'disabled')
        self.backend.fail_probe=False
        self.assertEqual(self.client.post('/wireguard/wg0/enable',data=fields).status_code,302)
        self.assertEqual(self.backend.enabled,'enabled');self.assertNotIn('start',self.backend.events)
        self.assertFalse(any(isinstance(x,tuple) and x[0]=='stop' for x in self.backend.events))
    def test_autostart_enable_inactive_is_rejected_without_start(self):
        self.backend.live=None;self.backend.enabled='disabled'
        fields=self.lifecycle_fields();fields.update(probe_address='10.9.0.2',probe_port='443',probe_mark='0')
        self.assertEqual(self.client.post('/wireguard/wg0/enable',data=fields).status_code,409)
        self.assertEqual(self.backend.events,[])
    def test_runtime_start_rejects_pending_network_before_mutation(self):
        self.backend.live=None;self.backend.enabled='disabled'
        (self.network/'transaction.json').write_text(json.dumps({'status':'pending'}))
        fields=self.lifecycle_fields();fields.update(probe_address='10.9.0.2',probe_port='443',probe_mark='0')
        self.assertEqual(self.client.post('/wireguard/wg0/start',data=fields).status_code,409)
        self.assertEqual(self.backend.events,[])
    def test_lifecycle_posts_keep_csrf_origin_and_stale_state_guards(self):
        fields=self.lifecycle_fields()
        for action in ('start','stop','enable','disable'):
            self.assertEqual(self.client.post('/wireguard/wg0/'+action,data=fields,headers={'Origin':'https://other.example'}).status_code,403)
        fields['expected_active']='false'
        self.assertEqual(self.client.post('/wireguard/wg0/stop',data=fields).status_code,409)
        self.assertEqual(self.backend.events,[])
    def test_status_after_reboot_is_readonly_and_explicit(self):
        self.client.post('/wireguard/wg0/stop',data=self.lifecycle_fields())
        path=self.drafts/'transaction.json';original=path.read_bytes();self.backend.boot='boot2'
        page=self.client.get('/wireguard/wg0')
        self.assertIn('Сервер перезагрузился',page.text);self.assertEqual(path.read_bytes(),original)

    def test_web_can_close_failed_boot_without_false_recovery_claim_then_restart(self):
        self.client.post('/wireguard/wg0/stop',data=self.lifecycle_fields())
        s=json.loads((self.drafts/'transaction.json').read_text());self.backend.boot='boot2'
        fields={'csrf':'test-csrf','transaction':s['id']}
        response=self.client.post('/wireguard/wg0/abandon',data=fields,follow_redirects=True)
        self.assertEqual(response.status_code,200);self.assertIn('закрыта без восстановления',response.text)
        fields=self.lifecycle_fields();fields.update(probe_address='10.9.0.2',probe_port='40043',probe_mark='0')
        response=self.client.post('/wireguard/wg0/start',data=fields)
        self.assertEqual(response.status_code,302)

    def test_enable_uncertain_postcheck_preserves_changed_setting_without_retry(self):
        self.backend.enabled='disabled'
        original=self.backend.set_enabled
        def change(name,enabled):original(name,enabled);self.backend.drift=True
        self.backend.set_enabled=change
        fields=self.lifecycle_fields();fields.update(probe_address='10.9.0.2',probe_port='443',probe_mark='0')
        response=self.client.post('/wireguard/wg0/enable',data=fields)
        self.assertEqual(response.status_code,409);self.assertEqual(self.backend.enabled,'enabled')
        self.assertEqual([x for x in self.backend.events if isinstance(x,tuple) and x[0]=='enable'],[('enable',True)])
