import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import subprocess

from safe_apply import Backend, Coordinator


class FakeBackend:
    def __init__(self):
        self.events = []
        self.fail_schedule = False
        self.fail_restart = False
        self.current_boot = 'boot-A'

    def boot_id(self):
        return self.current_boot

    def validate(self, path):
        json.loads(path.read_text())
        self.events.append('validated')

    def arm(self, transaction, seconds):
        if self.fail_schedule:
            raise RuntimeError('cannot schedule rollback')
        self.events.append('armed')
        return 'test-timer'

    def verify_runtime(self):
        pass

    def restart(self):
        self.events.append('restart')
        if self.fail_restart:
            self.fail_restart = False
            raise RuntimeError('start failed')

    def cancel(self, timer):
        self.events.append('cancel')


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.old = b'{"version":"old"}'
        (self.root/'config.json').write_bytes(self.old)
        self.backend = FakeBackend()
        self.coordinator = Coordinator(self.root, self.backend)

    def tearDown(self):
        self.directory.cleanup()

    def test_invalid_json_never_stops_or_replaces(self):
        with self.assertRaises(ValueError):
            self.coordinator.apply(b'{broken', 30)
        self.assertEqual((self.root/'config.json').read_bytes(), self.old)
        self.assertEqual(self.backend.events, [])

    def test_missing_timer_never_changes_active_config(self):
        self.backend.fail_schedule = True
        with self.assertRaises(RuntimeError):
            self.coordinator.apply(b'{}', 30)
        self.assertEqual((self.root/'config.json').read_bytes(), self.old)
        self.assertNotIn('restart', self.backend.events)

    def test_failed_restart_restores_previous_config(self):
        self.backend.fail_restart = True
        with self.assertRaises(RuntimeError):
            self.coordinator.apply(b'{}', 30)
        self.assertEqual((self.root/'config.json').read_bytes(), self.old)
        self.assertEqual(self.coordinator.state()['status'], 'rolled_back')
        self.assertEqual(self.backend.events, ['validated','armed','restart','restart'])

    def test_timer_restores_without_web_process(self):
        state = self.coordinator.apply(b'{}', 30)
        another_process = Coordinator(self.root, self.backend)
        another_process.rollback(state['id'])
        self.assertEqual((self.root/'config.json').read_bytes(), self.old)
        self.assertEqual(another_process.state()['status'], 'rolled_back')

    def test_confirmed_change_ignores_queued_callback(self):
        state = self.coordinator.apply(b'{}', 30)
        self.coordinator.confirm(state['id'])
        self.coordinator.rollback(state['id'])
        self.assertEqual((self.root/'config.json').read_bytes(), b'{}')
        self.assertEqual(self.coordinator.state()['status'], 'confirmed')

    def test_runtime_failure_cannot_confirm_or_cancel_rollback(self):
        state = self.coordinator.apply(b'{}', 30)
        with patch.object(self.backend, 'verify_runtime', side_effect=ValueError('VPN handoff missing')):
            with self.assertRaisesRegex(ValueError, 'handoff'):
                self.coordinator.confirm(state['id'])
        self.assertEqual(self.coordinator.state()['status'], 'pending')
        self.assertNotIn('cancel', self.backend.events)
        self.coordinator.rollback(state['id'])
        self.assertEqual((self.root/'config.json').read_bytes(), self.old)

    def test_drift_blocks_confirmation(self):
        state = self.coordinator.apply(b'{}', 30)
        (self.root/'config.json').write_bytes(b'{"other":true}')
        with self.assertRaises(ValueError):
            self.coordinator.confirm(state['id'])

    def test_parallel_apply_is_rejected(self):
        self.coordinator.apply(b'{}', 30)
        with self.assertRaises(ValueError):
            self.coordinator.apply(b'{"second":true}', 30)

    def test_expired_confirmation_cannot_cancel_rollback(self):
        state = self.coordinator.apply(b'{}', 30)
        state['deadline'] = time.time()-1
        self.coordinator.save(state)
        with self.assertRaises(ValueError):
            self.coordinator.confirm(state['id'])
        self.assertNotIn('cancel', self.backend.events)

    def test_verification_crossing_deadline_cannot_confirm_or_cancel_rollback(self):
        state = self.coordinator.apply(b'{}', 30)
        state['deadline'] = 101
        self.coordinator.save(state)
        with patch('safe_apply.time.time', side_effect=[100, 102]), \
             patch.object(self.backend, 'verify_runtime') as verify:
            with self.assertRaisesRegex(ValueError, 'Deadline'):
                self.coordinator.confirm(state['id'])
        verify.assert_called_once()
        self.assertEqual(self.coordinator.state()['status'], 'pending')
        self.assertNotIn('cancel', self.backend.events)

    def test_failed_timer_cleanup_does_not_undo_confirmation(self):
        state = self.coordinator.apply(b'{}', 30)
        def fail_cancel(timer):
            raise RuntimeError('timer cleanup failed')
        self.backend.cancel = fail_cancel
        result = self.coordinator.confirm(state['id'])
        self.assertEqual(result['status'], 'confirmed')
        self.assertIn('warning', result)
        self.assertEqual(self.coordinator.rollback(state['id'])['status'], 'ignored')

    def test_corrupt_backup_is_not_restored(self):
        state = self.coordinator.apply(b'{}', 30)
        (self.root/'revisions'/(state['id']+'.json')).write_bytes(b'corrupt')
        with self.assertRaises(ValueError):
            self.coordinator.rollback(state['id'])
        self.assertEqual((self.root/'config.json').read_bytes(), b'{}')
        self.assertEqual(self.coordinator.state()['status'], 'rollback_failed')

    def test_startup_guard_allows_same_boot_pending_apply_without_restart(self):
        self.coordinator.apply(b'{}', 30)
        events=list(self.backend.events)
        self.assertEqual(self.coordinator.recover_before_start()['status'],'ignored')
        self.assertEqual((self.root/'config.json').read_bytes(),b'{}')
        self.assertEqual(self.backend.events,events)

    def test_new_boot_restores_before_start_even_before_deadline(self):
        self.coordinator.apply(b'{}', 600)
        self.backend.current_boot='boot-B';events=list(self.backend.events)
        result=self.coordinator.recover_before_start()
        self.assertEqual(result['status'],'rolled_back')
        self.assertEqual((self.root/'config.json').read_bytes(),self.old)
        self.assertEqual(self.backend.events,events)

    def test_confirmed_config_survives_new_boot(self):
        state=self.coordinator.apply(b'{}',30);self.coordinator.confirm(state['id'])
        self.backend.current_boot='boot-B'
        self.assertEqual(self.coordinator.recover_before_start()['status'],'ignored')
        self.assertEqual((self.root/'config.json').read_bytes(),b'{}')

    def test_previous_boot_confirmation_is_refused_before_deadline(self):
        state=self.coordinator.apply(b'{}',600);self.backend.current_boot='boot-B'
        with self.assertRaises(ValueError):self.coordinator.confirm(state['id'])
        self.assertEqual(self.coordinator.state()['status'],'pending')

    def test_missing_boot_hook_refuses_to_arm_timer(self):
        with patch('safe_apply.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout='ExecStartPre=\n')) as run:
            with self.assertRaises(ValueError):Backend(self.root).arm('test',60)
        self.assertEqual(run.call_count,1)

    def test_boot_hook_requires_exact_command_and_compatible_service(self):
        good='ExecStartPre={ argv[]=/usr/bin/python3 -E -s -B '+str(self.root/'safe_apply.py')+' recover-before-start ; ignore_errors=no ; }\nUser=\nDynamicUser=no\nProtectSystem=strict\nReadWritePaths='+str(self.root)+'\nProcSubset=all\nRootDirectory=\nRootImage=\n'
        good+='NeedDaemonReload=no\nTransient=no\nFragmentPath=/etc/systemd/system/okopy-candidate.service\nDropInPaths=/etc/systemd/system/okopy-candidate.service.d/10-boot-recovery.conf\n'
        with patch('safe_apply.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=good)):
            Backend(self.root).check_boot_guard()
        multiple=good+'ExecStartPre={ argv[]=/usr/bin/python3 -E -s -B '+str(self.root/'adguard_runtime.py')+' wait-ready ; ignore_errors=no ; }\n'
        with patch('safe_apply.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=multiple)):
            Backend(self.root).check_boot_guard()
        for text in (good.replace('User=\n','User=nobody\n'),good.replace('ignore_errors=no','ignore_errors=yes'),good.replace('ProcSubset=all','ProcSubset=pid'),good.replace('ReadWritePaths='+str(self.root),'ReadWritePaths='),good.replace('Transient=no','Transient=yes'),good.replace('DropInPaths=/etc/','DropInPaths=/run/'),good.replace('NeedDaemonReload=no','NeedDaemonReload=yes')):
            with patch('safe_apply.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=text)):
                with self.assertRaises(ValueError):Backend(self.root).check_boot_guard()

    def test_boot_recovery_refuses_corrupted_backup(self):
        state=self.coordinator.apply(b'{}',30)
        (self.root/'revisions'/(state['id']+'.json')).write_bytes(b'corrupt')
        self.backend.current_boot='boot-B';events=list(self.backend.events)
        with self.assertRaises(ValueError):self.coordinator.recover_before_start()
        self.assertEqual(self.backend.events,events)
        self.assertEqual(self.coordinator.state()['status'],'rollback_failed')

    def test_failed_rollback_cannot_start_unconfirmed_file_even_in_same_boot(self):
        state=self.coordinator.apply(b'{}',30)
        backup=self.root/'revisions'/(state['id']+'.json');backup.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.coordinator.rollback(state['id'])
        with self.assertRaises(ValueError):self.coordinator.recover_before_start()
        backup.write_bytes(self.old)
        self.assertEqual(self.coordinator.recover_before_start()['status'],'rolled_back')
        self.assertEqual((self.root/'config.json').read_bytes(),self.old)

    def test_manual_rollback_after_boot_does_not_reenter_guard_lock(self):
        state=self.coordinator.apply(b'{}',30);self.backend.current_boot='boot-B'
        guard_results=[]
        self.backend.restart=lambda:guard_results.append(self.coordinator.recover_before_start()['status'])
        self.coordinator.rollback(state['id'])
        self.assertEqual(guard_results,['ignored'])

    def test_public_or_file_serving_api_is_rejected(self):
        config = {'inbounds':[{'type':'direct','listen':'127.0.0.1','listen_port':5301},
                              {'type':'mixed','listen':'127.0.0.1','listen_port':2081}],
                  'experimental':{'clash_api':{'external_controller':'127.0.0.1:9091','secret':'test'},
                                  'cache_file':{'path':str(self.root/'cache.db')}},'log':{}}
        unsafe = [
            ('api_extra',lambda c:c['experimental']['clash_api'].update(external_ui='/etc')),
            ('api_public',lambda c:c['experimental']['clash_api'].update(external_controller='0.0.0.0:9091')),
            ('v2ray_listener',lambda c:c['experimental'].update(v2ray_api={'listen':'0.0.0.0:10085'})),
            ('cache_path',lambda c:c['experimental']['cache_file'].update(path='/etc/bad.db')),
            ('log_path',lambda c:c['log'].update(output='/etc/bad.log')),
            ('services',lambda c:c.update(services=[{'type':'api','listen':'0.0.0.0'}]))]
        for label, mutate in unsafe:
            with self.subTest(label=label):
                candidate=json.loads(json.dumps(config));mutate(candidate)
                path=self.root/'unsafe.json';path.write_text(json.dumps(candidate))
                with self.assertRaises(ValueError):
                    Backend(self.root).validate(path)


class AdapterConfirmationTests(unittest.TestCase):
    def test_disabled_adapters_are_not_called(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {'build_options': {'lan_adapter': False, 'adguard_adapter': False, 'vpn_adapter': False}}
            with patch('candidate_bundle.read_bundle', return_value={}), \
                 patch('candidate_bundle.validate_bundle', return_value=manifest), \
                 patch('incoming_runtime.verify') as incoming, \
                 patch('lan_runtime.verify_runtime') as lan, \
                 patch('adguard_runtime.verify_runtime') as adguard:
                Backend(root).verify_runtime()
            incoming.assert_called_once_with(root)
            lan.assert_not_called()
            adguard.assert_not_called()

    def test_enabled_adapters_are_rechecked_without_reacquiring_apply_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'lan.lock').touch()
            manifest = {'build_options': {'lan_adapter': True, 'adguard_adapter': True, 'vpn_adapter': False}}
            with patch('candidate_bundle.read_bundle', return_value={}), \
                 patch('candidate_bundle.validate_bundle', return_value=manifest), \
                 patch('incoming_runtime.verify') as incoming, \
                 patch('lan_runtime.verify_runtime', create=True) as lan, \
                 patch('adguard_runtime.verify_runtime') as adguard:
                with (root/'apply.lock').open('a') as lock:
                    import fcntl
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    Backend(root).verify_runtime()
            incoming.assert_called_once_with(root)
            lan.assert_called_once_with(root)
            adguard.assert_called_once_with(root)

    def test_adapter_drift_keeps_confirm_pending_and_rollback_armed(self):
        for adapter in ('lan', 'adguard'):
            with self.subTest(adapter=adapter), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/'config.json').write_bytes(b'{"old":true}')
                (root/'lan.lock').touch()
                backend = Backend(root)
                backend.boot_id = lambda: 'boot-A'
                backend.validate = lambda path: None
                backend.arm = lambda transaction, seconds: 'test-timer'
                backend.restart = lambda: None
                cancelled = []
                backend.cancel = cancelled.append
                coordinator = Coordinator(root, backend)
                state = coordinator.apply(b'{}', 30)
                manifest = {'build_options': {'lan_adapter': True, 'adguard_adapter': True, 'vpn_adapter': False}}
                with patch('candidate_bundle.read_bundle', return_value={}), \
                     patch('candidate_bundle.validate_bundle', return_value=manifest), \
                     patch('incoming_runtime.verify'), \
                     patch('lan_runtime.verify_runtime', create=True,
                           side_effect=ValueError('LAN drift') if adapter == 'lan' else None), \
                     patch('adguard_runtime.verify_runtime',
                           side_effect=ValueError('AdGuard drift') if adapter == 'adguard' else None):
                    with self.assertRaisesRegex(ValueError, 'drift'):
                        coordinator.confirm(state['id'])
                self.assertEqual(coordinator.state()['status'], 'pending')
                self.assertEqual(cancelled, [])


if __name__ == '__main__':
    unittest.main()
