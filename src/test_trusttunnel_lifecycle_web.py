import json,unittest
from web import create_app
from candidate_remote import RemoteError
import test_web as base
from test_trusttunnel_lifecycle import LifecycleTests

class LifecycleWebTests(unittest.TestCase):
    login=base.WebTests.login
    def setUp(self):
        base.WebTests.setUp(self);self.fixture=LifecycleTests();self.fixture.setUp();f=self.fixture;self.calls=[];calls=self.calls
        class Candidate:
            def call(self,action,**fields):
                calls.append(action)
                try:return f.call(action.removeprefix('trusttunnel-'),**fields)
                except ValueError as e:raise RemoteError(str(e)) from None
        self.policy['exits']['vpn']={'name':'VPN','scope':'public','protocol':'TrustTunnel','native':{'type':'socks','server':'127.0.0.1','server_port':1080}}
        (self.path/'policy.json').write_text(json.dumps(self.policy));self.app=create_app(self.path,candidate=Candidate());self.app.testing=True;self.client=self.app.test_client()
    def tearDown(self):self.fixture.tearDown();base.WebTests.tearDown(self)
    def values(self,csrf):
        v=self.fixture.call('status');return {'csrf':csrf,**{k:v[k] for k in ('file_revision','draft_revision')},'expected_state':json.dumps(v['lifecycle_state'])}
    def test_stop_rollback_and_group_autostart_are_wired_to_guarded_control(self):
        csrf=self.login();html=self.client.get('/tunnels/vpn/edit').text
        self.assertIn('Остановить связку',html);self.assertIn('inbound.service',html)
        r=self.client.post('/trusttunnel/vpn/stop',data=self.values(csrf));self.assertEqual(r.status_code,302)
        v=self.fixture.call('status');self.assertFalse(self.fixture.backend.child)
        r=self.client.post('/trusttunnel/vpn/rollback',data={'csrf':csrf,'transaction':v['transaction']['id']});self.assertEqual(r.status_code,302)
        self.assertTrue(self.fixture.backend.child)
        self.assertEqual(self.client.post('/trusttunnel/vpn/disable',data=self.values(csrf)).status_code,302)
        self.assertEqual(self.fixture.backend.child_enabled,'disabled')
        self.assertEqual(self.client.post('/trusttunnel/vpn/enable',data={**self.values(csrf),'probe_url':'https://example.test/','probe_codes':'200'}).status_code,302)
        self.assertEqual(self.fixture.backend.child_enabled,'enabled')
    def test_csrf_stale_state_and_missing_probe_rejected_without_restart(self):
        csrf=self.login();values=self.values(csrf)
        self.assertEqual(self.client.post('/trusttunnel/vpn/stop',data={**values,'csrf':'bad'}).status_code,403)
        self.assertEqual(self.client.post('/trusttunnel/vpn/start',data=values).status_code,400)
        self.fixture.backend.child=False
        self.assertEqual(self.client.post('/trusttunnel/vpn/stop',data=values).status_code,409)
        self.assertEqual(self.fixture.backend.events,[])
    def test_confirmed_stop_then_web_start_and_confirm_starts_both_components(self):
        csrf=self.login()
        self.assertEqual(self.client.post('/trusttunnel/vpn/stop',data=self.values(csrf)).status_code,302)
        tx=self.fixture.call('status')['transaction']
        result=self.client.post('/trusttunnel/vpn/confirm',data={'csrf':csrf,'transaction':tx['id']},follow_redirects=True)
        self.assertEqual(result.status_code,200);self.assertIn('Остановка TrustTunnel подтверждена',result.text)
        self.assertNotIn('подтверждено после проверки трафика',result.text)
        self.assertIn('Запустить связку',self.client.get('/tunnels/vpn/edit').text)
        r=self.client.post('/trusttunnel/vpn/start',data={**self.values(csrf),'probe_url':'https://example.test/','probe_codes':'200'})
        self.assertEqual(r.status_code,302);tx=self.fixture.call('status')['transaction']
        self.assertEqual(self.client.post('/trusttunnel/vpn/confirm',data={'csrf':csrf,'transaction':tx['id']}).status_code,302)
        self.assertTrue(self.fixture.backend.running and self.fixture.backend.child)

if __name__=='__main__':unittest.main()
