import json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from candidate_remote import CandidateLocal,RemoteError
from health_pull import pull_once
from web import create_app

class ServerPanelTests(unittest.TestCase):
    def test_local_control_uses_fixed_root_helper_without_password_or_shell(self):
        with patch('candidate_remote.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'{"ok":true,"result":{"integrity":true}}',b'')) as run:
            self.assertTrue(CandidateLocal().call('status')['integrity'])
        self.assertEqual(run.call_count,1)
        self.assertEqual(run.call_args.args[0],CandidateLocal.COMMAND)
        self.assertEqual(run.call_args.kwargs['cwd'],'/')
        self.assertTrue(run.call_args.kwargs['input'].startswith(b'OKOPY-CONTROL-V1\n'))
        self.assertNotIn('shell',run.call_args.kwargs)

    def test_local_uncertain_write_never_retries_or_exposes_process_output(self):
        with patch('candidate_remote.subprocess.run',side_effect=subprocess.TimeoutExpired('private-value',50)) as run:
            with self.assertRaises(RemoteError) as caught:CandidateLocal().call('apply',policy={})
        self.assertEqual(run.call_count,1);self.assertNotIn('private-value',str(caught.exception))

    def test_local_uncertain_boot_setting_is_not_misrepresented_as_timed(self):
        with patch('candidate_remote.subprocess.run',side_effect=subprocess.TimeoutExpired('private-value',90)) as run:
            with self.assertRaisesRegex(RemoteError,'таймера отката у автозапуска нет'):CandidateLocal().call('wireguard-enable',profile='wg0')
        self.assertEqual(run.call_count,1);self.assertEqual(run.call_args.kwargs['timeout'],90)

    def test_local_health_preserves_measurement_time_and_stale_snapshot_on_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);snapshot={'version':1,'generated_at':1000,'interval_seconds':30,'checks':[],'events':[]}
            with patch('health_pull.subprocess.run',return_value=subprocess.CompletedProcess([],0,json.dumps(snapshot).encode(),b'')) as run:
                self.assertTrue(pull_once(root,'local'))
            self.assertEqual(run.call_args.args[0],['/usr/bin/sudo','-n','/usr/bin/head','-c','524289','/var/lib/okopy-monitor/health.json'])
            self.assertEqual(json.loads((root/'health.json').read_text())['generated_at'],1000)
            before=(root/'health.json').read_bytes()
            with patch('health_pull.subprocess.run',return_value=subprocess.CompletedProcess([],1,b'',b'private-data')):
                self.assertFalse(pull_once(root,'local'))
            self.assertEqual((root/'health.json').read_bytes(),before)
            self.assertFalse(json.loads((root/'health-transport.json').read_text())['ok'])

    def test_https_session_host_and_origin_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'auth.json').write_text(json.dumps({'username':'owner','password_hash':generate_password_hash('test-password'),'session_secret':'test-secret'}))
            (root/'policy.json').write_text('{}')
            app=create_app(root,trusted_hosts=['panel.example.test'],secure_cookie=True);app.testing=True;c=app.test_client()
            response=c.get('/login',base_url='https://panel.example.test')
            self.assertEqual(response.status_code,200)
            for flag in ['Secure','HttpOnly','SameSite=Strict']:self.assertIn(flag,response.headers['Set-Cookie'])
            self.assertEqual(c.get('/login',base_url='https://attacker.test').status_code,400)
            import re
            token=re.search('name="csrf" value="([^"]+)"',response.text).group(1)
            data={'csrf':token,'username':'owner','password':'test-password'}
            self.assertEqual(c.post('/login',base_url='https://panel.example.test',data=data,headers={'Origin':'http://panel.example.test'}).status_code,403)
            self.assertEqual(c.post('/login',base_url='https://panel.example.test',data=data,headers={'Origin':'https://panel.example.test'}).status_code,302)
