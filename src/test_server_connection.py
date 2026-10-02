import copy,json,os,tempfile,unittest,subprocess
from pathlib import Path
from unittest.mock import patch
from server_connection import read,validate,ssh
from candidate_remote import CandidateRemote,RemoteError

class ServerConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'server.json'
        self.config={'version':1,'targets':[{'host':'vpn.example.test','port':2201,'username':'network','identity_file':'/keys/network key'}],'sudo_password':''}
    def tearDown(self):self.temp.cleanup()
    def write(self):self.path.write_text(json.dumps(self.config));self.path.chmod(0o600)
    def test_explicit_config_modes_and_ssh_arguments(self):
        self.write();self.assertEqual(read(self.path),self.config)
        command=ssh(self.config['targets'][0]);self.assertIn('/keys/network key',command);self.assertEqual(command[-2:],['--','network@vpn.example.test']);self.assertIn('2201',command)
        self.assertNotIn('sudo_password',command)
        with patch('candidate_remote.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'{"ok":true,"result":{}}',b'')) as run:
            CandidateRemote(self.path).call('status')
        self.assertIn('sudo -n',run.call_args.args[0][-1]);self.assertTrue(run.call_args.kwargs['input'].startswith(b'OKOPY-CONTROL-V1\n'))
    def test_missing_bad_permissions_and_symlink_do_not_connect(self):
        for mode in ['missing','world','symlink']:
            with self.subTest(mode=mode):
                self.path.unlink(missing_ok=True)
                if mode=='world':self.write();self.path.chmod(0o644)
                if mode=='symlink':self.path.symlink_to(self.path.parent/'absent')
                with patch('candidate_remote.subprocess.run') as run,self.assertRaises(RemoteError):CandidateRemote(self.path).call('status')
                run.assert_not_called()
    def test_injected_targets_and_malformed_credentials_rejected(self):
        for key,value in [('host','-oProxyCommand=bad'),('host','server;reboot'),('port',True),('username','user@other'),('identity_file','relative')]:
            config=copy.deepcopy(self.config);config['targets'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate(config)
        for password in ['a\nb','a\x00b',True]:
            with self.assertRaises(ValueError):validate({**self.config,'sudo_password':password})
        with self.assertRaises(ValueError):validate({**self.config,'targets':[]})

import test_web as fixtures
from web import create_app
class ServerAccessWebTests(unittest.TestCase):
    setUp=fixtures.WebTests.setUp
    tearDown=fixtures.WebTests.tearDown
    login=fixtures.WebTests.login
    def test_local_mode_needs_no_ssh_config(self):
        from candidate_remote import CandidateLocal
        self.app=create_app(self.path,CandidateLocal());self.app.testing=True;self.client=self.app.test_client()
        token=self.login();self.assertIn('выполняются локально',self.client.get('/server/access').text)
        self.assertEqual(self.client.post('/server/access',data={'csrf':token}).status_code,400)
    def test_remote_settings_form_roundtrip_and_revision_protection(self):
        path=self.path/'server.json';self.app=create_app(self.path,CandidateRemote(path));self.app.testing=True;self.client=self.app.test_client()
        token=self.login();self.assertIn('Основной',self.client.get('/server/access').text.replace('Адрес доступа','Основной'))
        data={'csrf':token,'revision':'empty','target_host':['first.example.test','backup.example.test'],'target_port':['22','2222'],'target_username':['operator','operator'],'target_identity_file':['',''],'sudo_password':'test-private'}
        with patch('candidate_remote.subprocess.run') as run:
            self.assertEqual(self.client.post('/server/access',data=data).status_code,302)
            run.assert_not_called()
        self.assertNotIn('test-private',self.client.get('/server/access').text)
        before=path.read_bytes();self.assertEqual(self.client.post('/server/access',data=data).status_code,400);self.assertEqual(before,path.read_bytes())
        from server_connection import snapshot
        data.update(revision=snapshot(path)[1],sudo_password='');self.assertEqual(self.client.post('/server/access',data=data).status_code,302);self.assertEqual(read(path)['sudo_password'],'test-private')
        data.update(revision=snapshot(path)[1],clear_password='on');self.assertEqual(self.client.post('/server/access',data=data).status_code,302);self.assertEqual(read(path)['sudo_password'],'')
