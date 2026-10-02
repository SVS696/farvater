import io,json,unittest
from web import create_app
import test_web as base
import test_trusttunnel_control as fixture
from trusttunnel_control import control
from candidate_remote import RemoteError

class WebTests(unittest.TestCase):
    login=base.WebTests.login
    def setUp(self):
        base.WebTests.setUp(self);self.fixture=fixture.ControlTests();self.fixture.setUp();f=self.fixture;self.calls=[];calls=self.calls
        class Backend:
            def call(self,action,**fields):
                calls.append(action)
                try:return control({'version':1,'action':action,**fields},root=f.root,observe_state=lambda b:{'client':{'active':'active','boot':'enabled'},'dependents':{'inbound.service':{'active':'active','boot':'enabled'}}})
                except ValueError as e:raise RemoteError(str(e)) from None
        self.policy['exits']['vpn']={'name':'VPN','scope':'public','protocol':'TrustTunnel','native':{'type':'socks','server':'127.0.0.1','server_port':1080}}
        (self.path/'policy.json').write_text(json.dumps(self.policy))
        self.app=create_app(self.path,candidate=Backend());self.app.testing=True;self.client=self.app.test_client()
    def tearDown(self):self.fixture.tearDown();base.WebTests.tearDown(self)
    def test_editor_is_authenticated_and_hides_secret(self):
        self.assertEqual(self.client.get('/tunnels/vpn/edit').status_code,302)
        self.login();r=self.client.get('/tunnels/vpn/edit');self.assertEqual(r.status_code,200)
        self.assertIn('name="hostname" value="vpn.test"',r.text);self.assertNotIn('PRIVATE-password',r.text)
        self.assertIn('name="connection_file"',r.text);self.assertNotIn('name="bind_interface"',r.text);self.assertEqual(r.headers['Cache-Control'],'no-store')
    def test_import_check_and_discard_stay_draft_only(self):
        csrf=self.login();v=self.fixture.call('status')
        r=self.client.post('/trusttunnel/vpn/import',data={'csrf':csrf,**self.fixture.revisions(v),'format':'endpoint','connection_file':(io.BytesIO(b'upstream_protocol="http3"'),'endpoint.toml')})
        self.assertEqual(r.status_code,302);v=self.fixture.call('status');self.assertTrue(v['has_draft'])
        r=self.client.post('/trusttunnel/vpn/check',data={'csrf':csrf,**self.fixture.revisions(v)});self.assertEqual(r.status_code,302)
        r=self.client.post('/trusttunnel/vpn/discard',data={'csrf':csrf,**self.fixture.revisions(v)});self.assertEqual(r.status_code,302)
        self.assertFalse(self.fixture.call('status')['has_draft']);self.assertEqual(self.calls,['trusttunnel-import','trusttunnel-check','trusttunnel-discard'])
    def test_csrf_and_unsafe_upload_rejected(self):
        csrf=self.login();v=self.fixture.call('status')
        self.assertEqual(self.client.post('/trusttunnel/vpn/discard',data=self.fixture.revisions(v)).status_code,403)
        r=self.client.post('/trusttunnel/vpn/import',data={'csrf':csrf,**self.fixture.revisions(v),'format':'endpoint','connection_file':(io.BytesIO(b'script="/tmp/run"'),'bad.toml')})
        self.assertEqual(r.status_code,409);self.assertFalse(self.fixture.call('status')['has_draft'])

if __name__=='__main__':unittest.main()
