import io
import json
import unittest
import test_web as base

class IncomingWebTests(unittest.TestCase):
    setUp=base.WebTests.setUp
    tearDown=base.WebTests.tearDown
    login=base.WebTests.login
    revision=base.WebTests.revision
    def fields(self,csrf,kind='socks'):
        return {'csrf':csrf,'revision':self.revision(),'id':'','type':kind,'name':'Laptop access','enabled':'on',
                'listen':'127.0.0.1','listen_port':'18642','local_host':'127.0.0.1','external_host':'vpn.example.org',
                'client_original':[''],'client_name':['phone'],'client_secret':[''],'client_flow':['']}
    def saved(self):return json.loads((self.path/'policy.json').read_text())['incoming_connections'][0]
    def test_auth_csrf_and_create_without_empty_fake_row(self):
        self.assertEqual(self.client.get('/devices/incoming').status_code,302);csrf=self.login()
        r=self.client.get('/devices/incoming/new?protocol=socks');self.assertEqual(r.status_code,200)
        self.assertIn('Добавить клиента',r.text)
        f=self.fields(csrf);f['csrf']='bad';self.assertEqual(self.client.post('/devices/incoming/save',data=f).status_code,403)
        self.assertEqual(self.client.post('/devices/incoming/save',data=self.fields(csrf)).status_code,302)
        e=self.saved();secret=e['native']['users'][0]['password'];self.assertGreater(len(secret),20)
        page=self.client.get('/devices/incoming/'+e['id']+'/edit');self.assertEqual(page.status_code,200);self.assertNotIn(secret,page.text)
    def test_save_rename_preserves_secret_and_exports_both_addresses(self):
        csrf=self.login();self.client.post('/devices/incoming/save',data=self.fields(csrf));e=self.saved();old=e['native']['users'][0]['password']
        f=self.fields(csrf);f.update(id=e['id'],client_original=['phone'],client_name=['renamed'])
        self.assertEqual(self.client.post('/devices/incoming/save',data=f).status_code,302)
        self.assertEqual(self.saved()['native']['users'][0]['password'],old)
        for mode,host in [('local','127.0.0.1'),('external','vpn.example.org')]:
            r=self.client.post('/devices/incoming/'+e['id']+'/export',data={'csrf':csrf,'revision':self.revision(),'format':'json','client':'renamed','mode':mode})
            self.assertEqual(r.status_code,200);self.assertEqual(r.json['outbounds'][0]['server'],host);self.assertIn('no-store',r.headers['Cache-Control'])
        self.assertEqual(self.client.post('/devices/incoming/save',data=f).status_code,409)
    def test_server_roundtrip_and_delete_require_confirmation(self):
        csrf=self.login();self.client.post('/devices/incoming/save',data=self.fields(csrf));e=self.saved();path='/devices/incoming/'+e['id']
        f={'csrf':csrf,'revision':self.revision(),'format':'server'}
        r=self.client.post(path+'/export',data=f);self.assertEqual(r.status_code,200)
        payload=r.data
        self.assertEqual(self.client.post(path+'/import',data={'csrf':csrf,'revision':self.revision(),'connection_file':(io.BytesIO(payload),'in.json')}).status_code,302)
        f={'csrf':csrf,'revision':self.revision()};self.assertEqual(self.client.post(path+'/delete',data=f).status_code,400)
        f['confirm']='on';self.assertEqual(self.client.post(path+'/delete',data=f).status_code,302)
        self.assertEqual(json.loads((self.path/'policy.json').read_text())['incoming_connections'],[])
    def test_all_protocol_forms_and_passwords_validate(self):
        csrf=self.login()
        for kind in ['socks','http','vless','shadowsocks']:
            self.assertEqual(self.client.get('/devices/incoming/new?protocol='+kind).status_code,200)
        f=self.fields(csrf,'shadowsocks');f['method']='2022-blake3-aes-128-gcm'
        self.assertEqual(self.client.post('/devices/incoming/save',data=f).status_code,302)
        self.assertEqual(len(self.saved()['native']['users']),1)

if __name__=='__main__':unittest.main()
