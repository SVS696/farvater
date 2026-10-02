import io
import json
import unittest
from unittest.mock import patch
from web import create_app
from candidate_remote import RemoteError
import test_web as base
from test_trusttunnel_clients import ClientsTests

class WebTests(unittest.TestCase):
    login=base.WebTests.login
    def setUp(self):
        base.WebTests.setUp(self);self.fixture=ClientsTests();self.fixture.setUp();owner=self
        class Backend:
            def call(self,action,**fields):
                try:return owner.fixture.call(action.removeprefix('tt-clients-'),**fields)
                except ValueError as e:raise RemoteError(str(e)) from None
        self.app=create_app(self.path,candidate=Backend());self.app.testing=True;self.client=self.app.test_client()
    def tearDown(self):self.fixture.tearDown();base.WebTests.tearDown(self)
    def data(self,csrf):return {'csrf':csrf,'revision':self.fixture.view()['revision'],'id':'','username':'phone','password':'','max_http2_conns':'','max_http3_conns':'','confirm':'on'}
    def test_authenticated_create_export_qr_and_delete(self):
        self.assertEqual(self.client.get('/devices/trusttunnel').status_code,302);csrf=self.login()
        page=self.client.get('/devices/trusttunnel');self.assertEqual(page.status_code,200);self.assertNotIn('PRIVATE-password',page.text)
        bad=self.data(csrf);bad['csrf']='bad';self.assertEqual(self.client.post('/devices/trusttunnel/main/save',data=bad).status_code,403)
        bad=self.data(csrf);bad.pop('confirm');self.assertEqual(self.client.post('/devices/trusttunnel/main/save',data=bad).status_code,400)
        result=self.client.post('/devices/trusttunnel/main/save',data=self.data(csrf));self.assertEqual(result.status_code,302)
        view=self.fixture.view();new=view['clients'][1];fields={'csrf':csrf,'revision':view['revision'],'id':new['id'],'mode':'local','format':'toml'}
        r=self.client.post('/devices/trusttunnel/main/export',data=fields);self.assertEqual(r.status_code,200);self.assertIn('attachment',r.headers['Content-Disposition']);self.assertIn('no-store',r.headers['Cache-Control'])
        fields['format']='qr'
        with patch('subprocess.run') as run:
            run.return_value.returncode=0;run.return_value.stdout='<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>'
            r=self.client.post('/devices/trusttunnel/main/export',data=fields);self.assertEqual(r.mimetype,'image/svg+xml');self.assertEqual(run.call_args.kwargs['input'],'tt://?native-secret')
        fields['confirm']='on';r=self.client.post('/devices/trusttunnel/main/delete',data=fields);self.assertEqual(r.status_code,302);self.assertEqual(len(self.fixture.view()['clients']),1)
    def test_import_size_format_and_round_trip(self):
        csrf=self.login();fields={'csrf':csrf,'revision':self.fixture.view()['revision'],'confirm':'on','credentials_file':(io.BytesIO(b'[[client]]\nusername="imported"\npassword="secret"\n'),'credentials.toml')}
        self.assertEqual(self.client.post('/devices/trusttunnel/main/import',data=fields).status_code,302)
        r=self.client.post('/devices/trusttunnel/main/export',data={'csrf':csrf,'revision':self.fixture.view()['revision'],'format':'credentials'})
        self.assertEqual(r.status_code,200);self.assertIn('imported',r.text)
        self.assertNotIn('password="secret"',self.client.get('/devices/trusttunnel').text)
    def test_no_servers_has_honest_empty_state(self):
        self.login();(self.fixture.root/'endpoints.json').unlink()
        r=self.client.get('/devices/trusttunnel');self.assertEqual(r.status_code,200);self.assertIn('ещё не зарегистрирован',r.text)

if __name__=='__main__':unittest.main()
