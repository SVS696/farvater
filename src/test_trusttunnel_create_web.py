import io,json,re,unittest
from unittest.mock import patch
from web import create_app
from candidate_remote import RemoteError
import test_web as base
import test_trusttunnel_create as fixture
from trusttunnel_profile import render

class WebTests(unittest.TestCase):
    login=base.WebTests.login;revision=base.WebTests.revision
    def setUp(self):
        base.WebTests.setUp(self);self.f=fixture.CreateTests();self.f.setUp();self.calls=[];owner=self
        class Backend:
            def call(self,action,**fields):
                owner.calls.append(action)
                try:return owner.f.call(action.removeprefix('trusttunnel-'),**fields)
                except ValueError as e:raise RemoteError(str(e)) from None
        self.app=create_app(self.path,candidate=Backend());self.app.testing=True;self.client=self.app.test_client()
    def tearDown(self):self.f.tearDown();base.WebTests.tearDown(self)
    def data(self,csrf):
        return {'csrf':csrf,'revision':self.revision(),'connection':'tt-0123456789ab','format':'endpoint','name':'Test VPN','scope':'public','connection_file':(io.BytesIO(b'hostname="vpn.test"\naddresses=["192.0.2.1:443"]\nusername="test"\npassword="PRIVATE-create-password"'),'endpoint.toml')}
    def test_creation_is_authenticated_validated_and_attached_only_to_draft(self):
        self.assertEqual(self.client.get('/trusttunnel-new').status_code,302);csrf=self.login()
        page=self.client.get('/trusttunnel-new');self.assertEqual(page.status_code,200);self.assertNotIn('name="bind_interface"',page.text)
        data=self.data(csrf);r=self.client.post('/trusttunnel-create',data=data);self.assertEqual(r.status_code,302)
        self.assertIn('/tunnels/tt-0123456789ab/edit',r.location)
        policy=json.loads((self.path/'policy.json').read_text());self.assertEqual(policy['default_exit'],'direct');self.assertEqual(policy['profiles'],[])
        self.assertEqual(policy['exits']['tt-0123456789ab']['protocol'],'TrustTunnel');self.assertNotIn('PRIVATE-create-password',json.dumps(policy))
        self.assertEqual(self.f.calls,[['systemctl','daemon-reload']])
    def test_native_link_can_be_pasted_in_creation_form(self):
        from trusttunnel_profile import DEFAULT
        from trusttunnel_link import export
        csrf=self.login()
        model={**DEFAULT,'hostname':'vpn.test','addresses':['192.0.2.1:443'],'username':'test','password':'PRIVATE-link'}
        result=self.client.post('/trusttunnel-create',data={'csrf':csrf,'revision':self.revision(),'connection':'tt-0123456789ab','format':'deeplink','name':'Link VPN','scope':'public','connection_text':export(model,'deeplink')})
        self.assertEqual(result.status_code,302)
        saved=json.loads((self.f.root/'tt-0123456789ab.active.json').read_text());self.assertEqual(saved['password'],'PRIVATE-link')

    def test_stale_form_and_csrf_block_before_server_creation(self):
        csrf=self.login();d=self.data(csrf);d['revision']='stale';self.assertEqual(self.client.post('/trusttunnel-create',data=d).status_code,409)
        d=self.data(csrf);d['csrf']='wrong';self.assertEqual(self.client.post('/trusttunnel-create',data=d).status_code,403);self.assertEqual(self.calls,[])
    def test_panel_write_failure_is_recoverable_without_duplicate_client(self):
        csrf=self.login()
        with patch('web.atomic_write',side_effect=OSError('disk full')):
            r=self.client.post('/trusttunnel-create',data=self.data(csrf))
        self.assertEqual(r.status_code,302);page=self.client.get('/trusttunnel-new')
        self.assertIn('Добавить в список панели',page.text);self.assertNotIn('PRIVATE-create-password',page.text)
        r=self.client.post('/trusttunnel-complete/tt-0123456789ab',data={'csrf':csrf,'revision':self.revision()});self.assertEqual(r.status_code,302)
        self.assertEqual(len(json.loads((self.f.root/'connections.json').read_text())),2)
        self.assertEqual(self.f.calls,[['systemctl','daemon-reload']])

if __name__=='__main__':unittest.main()
