import json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from candidate_remote import CandidateRemote,RemoteError

class CandidateRemoteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();p=Path(self.temp.name)/'server.json';p.write_text(json.dumps({'version':1,'targets':[{'host':h,'port':2222,'username':'operator','identity_file':''} for h in ['lan.example.test','backup.example.test']],'sudo_password':'test-private-password'}));p.chmod(0o600);self.remote=CandidateRemote(p)
    def tearDown(self):self.temp.cleanup()
    def test_uncertain_mutation_is_never_retried_on_other_host(self):
        with patch('candidate_remote.subprocess.run',side_effect=[subprocess.CompletedProcess([],0,b'',b''),subprocess.TimeoutExpired('ssh',50)]) as run:
            with self.assertRaises(RemoteError):self.remote.call('apply',policy={})
        self.assertEqual(run.call_count,2);self.assertEqual(run.call_args_list[0].args[0][-1],'true')
        self.assertNotIn('test-private-password',' '.join(run.call_args.args[0]))
    def test_readonly_status_may_use_verified_external_fallback(self):
        results=[subprocess.CompletedProcess([],1,b'',b''),subprocess.CompletedProcess([],0,b'{"ok":true,"result":{"integrity":true}}',b'')]
        with patch('candidate_remote.subprocess.run',side_effect=results) as run:
            self.assertTrue(self.remote.call('status')['integrity'])
        self.assertIn('operator@backup.example.test',run.call_args.args[0]);self.assertIn('StrictHostKeyChecking=yes',run.call_args.args[0])
    def test_transport_stderr_is_never_exposed(self):
        with patch('candidate_remote.subprocess.run',return_value=subprocess.CompletedProcess([],1,b'',b'test-private-password')):
            with self.assertRaises(RemoteError) as caught:self.remote.call('status')
        self.assertNotIn('test-private-password',str(caught.exception))
    def test_sudo_authentication_failure_is_distinguished_without_retrying_write(self):
        responses=[subprocess.CompletedProcess([],0,b'',b''),subprocess.CompletedProcess([],1,b'',b'sudo: 3 incorrect password attempts\n')]
        with patch('candidate_remote.subprocess.run',side_effect=responses) as run:
            with self.assertRaisesRegex(RemoteError,'Команда управления не запущена'):self.remote.call('apply',policy={})
        self.assertEqual(run.call_count,2)
    def test_external_write_path_is_selected_before_a_single_mutation(self):
        responses=[subprocess.CompletedProcess([],255,b'',b''),subprocess.CompletedProcess([],0,b'',b''),subprocess.CompletedProcess([],0,b'{"ok":true,"result":{}}',b'')]
        with patch('candidate_remote.subprocess.run',side_effect=responses) as run:self.remote.call('apply',policy={})
        self.assertEqual(run.call_count,3);self.assertIn('operator@backup.example.test',run.call_args.args[0]);self.assertIn(b'\nOKOPY-CONTROL-V1\n',run.call_args.kwargs['input'])

    def test_wg_operations_allow_bounded_recovery_time_without_retry(self):
        for action in ('wireguard-apply','wireguard-confirm','wireguard-rollback','wireguard-start','wireguard-stop','wireguard-enable','wireguard-disable'):
            with self.subTest(action=action):
                with patch('candidate_remote.subprocess.run',side_effect=[subprocess.CompletedProcess([],0,b'',b''),subprocess.TimeoutExpired('ssh',90)]) as run:
                    with self.assertRaises(RemoteError):self.remote.call(action,profile='wg0')
                self.assertEqual(run.call_count,2)
                self.assertEqual(run.call_args.kwargs['timeout'],90)

    def test_uncertain_boot_setting_has_no_false_rollback_promise(self):
        with patch('candidate_remote.subprocess.run',side_effect=[subprocess.CompletedProcess([],0,b'',b''),subprocess.TimeoutExpired('ssh',90)]) as run:
            with self.assertRaisesRegex(RemoteError,'таймера отката у автозапуска нет'):self.remote.call('wireguard-disable',profile='wg0')
        self.assertEqual(run.call_count,2)
