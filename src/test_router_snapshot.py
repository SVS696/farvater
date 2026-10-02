import copy,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import MagicMock,patch
import paramiko
import router_health
from router_settings import DEFAULT
from health_settings import fingerprint
from health_model import present_snapshot,merge_presented
import test_web as fixtures

VALUE={'status':'up','observed_at':1000,'uptime_seconds':200,'dns_udp':'up','dns_tcp':'up','https':'up','http_code':200}

class RouterSnapshotTests(unittest.TestCase):
    def test_inconsistent_or_malformed_data_is_not_accepted(self):
        for change in [{'status':'up','dns_tcp':'down'},{'http_code':0},{'observed_at':True},{'uptime_seconds':-1},{'extra':'x'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):router_health.snapshot({**VALUE,**change})

    def test_staleness_survives_repeated_reads_and_server_failure(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'router.json';p.write_text(json.dumps(router_health.snapshot(VALUE)))
            fresh=present_snapshot(p,now=1020,max_age=30);self.assertEqual(fresh['status'],'up')
            old=present_snapshot(p,now=1031,max_age=30);self.assertEqual(old['status'],'stale')
            missing=present_snapshot(Path(d)/'server.json',now=1020)
            self.assertEqual(merge_presented(missing,fresh)['status'],'unknown')
            self.assertEqual(merge_presented(fresh,old)['status'],'stale')

    def test_authenticated_read_preserves_router_measurement_time(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);creds=root/'creds';creds.write_text('ROUTER_HOST="router.example.test"\nROUTER_PORT=2222\nROUTER_USERNAME="owner"\nROUTER_PASSWORD="test-secret"\n')
            client=MagicMock();stream=MagicMock();channel=stream.channel
            client.exec_command.return_value=(None,stream,None)
            channel.recv_ready.side_effect=[True,False];channel.recv.return_value=json.dumps({'settings':{'check':DEFAULT,'revision':fingerprint(DEFAULT),'persistent_matches':True},'snapshot':{'version':1,'revision':fingerprint(DEFAULT),'measurement':VALUE}}).encode()
            channel.exit_status_ready.return_value=True;channel.recv_exit_status.return_value=0
            with patch('router_health.paramiko.SSHClient',return_value=client):self.assertTrue(router_health.pull_once(root,creds))
            self.assertEqual(json.loads((root/'router-health.json').read_text())['generated_at'],1000)
            client.load_system_host_keys.assert_called_once();client.set_missing_host_key_policy.assert_not_called()
            self.assertEqual(client.connect.call_args.args,('router.example.test',));client.close.assert_called_once()
            saved=(root/'router-health.json').read_bytes()
            client.connect.side_effect=paramiko.SSHException('test-secret')
            with patch('router_health.paramiko.SSHClient',return_value=client):self.assertFalse(router_health.pull_once(root,creds))
            self.assertEqual(saved,(root/'router-health.json').read_bytes())
            text=(root/'router-health-transport.json').read_text();self.assertNotIn('test-secret',text);self.assertFalse(json.loads(text)['ok'])

class RouterWebTests(unittest.TestCase):
    setUp=fixtures.WebTests.setUp
    tearDown=fixtures.WebTests.tearDown
    login=fixtures.WebTests.login

    def test_router_snapshot_does_not_create_removed_ui_routes(self):
        self.login()
        self.assertEqual(self.client.get('/routers').status_code,404)
        self.assertNotIn('routers',self.app.extensions)
        self.assertIn('Нет данных',self.client.get('/health').text)

if __name__=='__main__':unittest.main()
