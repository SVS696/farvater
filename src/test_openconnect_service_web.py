import io,json,unittest
from web import create_app
from test_web import WebTests
from test_openconnect_control import ControlTests
from openconnect_control import control
from openconnect_profile import DEFAULT,FLAGS,NUMBERS,SECRETS
from candidate_remote import RemoteError

class OpenConnectWebTests(unittest.TestCase):
    login=WebTests.login
    def setUp(self):
        WebTests.setUp(self);self.fixture=ControlTests();self.fixture.setUp();self.calls=[]
        fixture=self.fixture;calls=self.calls
        class Backend:
            def call(self,action,**fields):
                calls.append(action)
                try:return control({'version':1,'action':action,**fields},root=fixture.root,observe_state=lambda b:{'active':'active','state':'running','boot':'enabled'})
                except ValueError as e:raise RemoteError(str(e)) from None
        self.policy['exits']['work']={'name':'Work VPN','scope':'work','protocol':'OpenConnect','native':{'type':'direct','tag':'work','bind_interface':'test0'}}
        (self.path/'policy.json').write_text(json.dumps(self.policy))
        self.app=create_app(self.path,candidate=Backend());self.app.testing=True;self.client=self.app.test_client()
    def tearDown(self):self.fixture.tearDown();WebTests.tearDown(self)
    def test_authenticated_editor_has_real_fields_without_saved_secret(self):
        self.assertEqual(self.client.get('/tunnels/work/edit').status_code,302)
        self.login();r=self.client.get('/tunnels/work/edit');self.assertEqual(r.status_code,200)
        self.assertIn('https://vpn.test/?group=work',r.text);self.assertIn('name="username" value="worker"',r.text)
        self.assertNotIn('PRIVATE-password',r.text);self.assertNotIn('name="bind_interface"',r.text)
        self.assertIn('name="connection_file"',r.text);self.assertEqual(r.headers['Cache-Control'],'no-store')
    def test_save_typed_draft_keeps_runtime_and_secrets(self):
        csrf=self.login();view=self.fixture.call('status');values={k:'' if v is None else v for k,v in DEFAULT.items() if k not in FLAGS}
        values.update({k:v for k,v in view['model'].items() if k not in ('saved_secrets',*FLAGS)})
        values.update({k:'' for k in SECRETS});values.update({k+'_action':'keep' for k in SECRETS})
        for key in NUMBERS:values[key]='' if values[key] is None else str(values[key])
        values.update(csrf=csrf,username='updated',**self.fixture.revisions(view))
        r=self.client.post('/openconnect/work/save',data=values);self.assertEqual(r.status_code,302)
        after=self.fixture.call('status');self.assertEqual(after['model']['username'],'updated');self.assertTrue(after['model']['saved_secrets']['password'])
        self.assertEqual(self.calls,['openconnect-save'])
    def test_import_file_and_reject_unsafe_import_without_draft_change(self):
        csrf=self.login();view=self.fixture.call('status')
        r=self.client.post('/openconnect/work/import',data={'csrf':csrf,**self.fixture.revisions(view),'format':'openconnect','connection_file':(io.BytesIO(b'user=imported\nno-dtls'),'work.conf')})
        self.assertEqual(r.status_code,302)
        view=self.fixture.call('status');before=(self.fixture.root/'work.draft.json').read_bytes()
        r=self.client.post('/openconnect/work/import',data={'csrf':csrf,**self.fixture.revisions(view),'format':'openconnect','connection_file':(io.BytesIO(b'script=/tmp/unsafe'),'unsafe.conf')})
        self.assertEqual(r.status_code,409);self.assertEqual(before,(self.fixture.root/'work.draft.json').read_bytes())
    def test_csrf_and_unknown_connections_rejected(self):
        csrf=self.login()
        self.assertEqual(self.client.post('/openconnect/work/discard',data={}).status_code,403)
        self.assertEqual(self.client.post('/openconnect/other/discard',data={'csrf':csrf}).status_code,404)
        self.assertEqual(self.calls,[])

    def test_lifecycle_http_validates_state_and_does_not_require_probe_for_stop(self):
        from unittest.mock import patch
        csrf=self.login();view=self.fixture.call('status')
        fields={'csrf':csrf,**self.fixture.revisions(view),'expected_active':'true','expected_boot':'enabled'}
        with patch(__name__+'.control',return_value={'transaction':{'status':'pending'}}) as call:
            result=self.client.post('/openconnect/work/stop',data=fields)
            self.assertEqual(result.status_code,302)
            request=call.call_args.args[0]
            self.assertEqual(request['expected_state'],{'active':True,'boot':'enabled'});self.assertNotIn('probe',request)
        with patch(__name__+'.control') as call:
            result=self.client.post('/openconnect/work/start',data={**fields,'expected_active':'false','probe_url':'http://bad.test/','probe_codes':'200'})
            self.assertEqual(result.status_code,400);call.assert_not_called()
        with patch(__name__+'.control',return_value={'enabled':'disabled'}) as call:
            self.assertEqual(self.client.post('/openconnect/work/disable',data=fields).status_code,302)
            self.assertEqual(call.call_args.args[0]['action'],'openconnect-disable')

if __name__=='__main__':unittest.main()
