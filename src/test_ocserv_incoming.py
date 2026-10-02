import copy
import base64
import io
import json
import socket
import subprocess
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from ocserv_incoming import validate,render_config,client_model,device_prefix
from incoming_kernel import ocserv_scope,nft_script,validate as validate_scopes
from openconnect_export import export_bundle,import_bundle
from ocserv_exchange import export_server,import_server,read_archive


def entry(cert,key):
    return {'id':'ocserv-proof','name':'AnyConnect','enabled':True,'local_host':'192.0.2.1',
            'external_host':'vpn.example.org','disabled_clients':[], 'native':{
        'type':'openconnect-server','listen':'192.0.2.1','listen_port':19443,'dtls':True,
        'pools':['10.213.0.0/24','fd12:213::/112'],'client_dns':['10.213.0.1','fd12:213::1'],
        'client_routes':['0.0.0.0/0','::/0'],'split_dns':[],'certificate':cert,'private_key':key,
        'users':[{'username':'phone','password':'proof-password'}], 'mtu':1400,'max_clients':16,
        'max_same_clients':1,'keepalive':30,'dpd':30,'mobile_dpd':120,'compression':False}}


class OcservIncomingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(p/'key'),'-out',str(p/'cert'),'-days','1','-subj','/CN=test-server'],check=True,capture_output=True)
            cls.cert=(p/'cert').read_text();cls.key=(p/'key').read_text()
    def entry(self):return entry(self.cert,self.key)
    def port_preflight(self,port,dtls=False):
        from incoming_ocserv_runtime import preflight
        e=self.entry();e['native'].update(listen='127.0.0.1',listen_port=port,dtls=dtls)
        with patch('incoming_ocserv_runtime.Path.is_file',return_value=True), \
             patch('incoming_ocserv_runtime.receipt',return_value=(None,None)), \
             patch('incoming_ocserv_runtime.interfaces',return_value=[]), \
             patch('incoming_ocserv_runtime.command',return_value=SimpleNamespace(stdout='[]')):
            return preflight(e,validate_native=False)
    def test_port_preflight_allows_restart_after_closed_tcp_session(self):
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            server.bind(('127.0.0.1',0));server.listen(1);port=server.getsockname()[1]
            with socket.create_connection(('127.0.0.1',port),timeout=2) as client:
                connection,_=server.accept();connection.close()
                self.assertEqual(client.recv(1),b'')
        self.port_preflight(port)
    def test_port_preflight_still_rejects_live_tcp_and_udp_listeners(self):
        for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
            with self.subTest(kind=kind),socket.socket(socket.AF_INET,kind) as server:
                server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                server.bind(('127.0.0.1',0))
                if kind==socket.SOCK_STREAM:server.listen(1)
                with self.assertRaisesRegex(ValueError,'порт OpenConnect'):
                    self.port_preflight(server.getsockname()[1],dtls=True)
    def test_client_native_archive_roundtrip_and_secret_separation(self):
        e=self.entry()
        for mode in ('local','external'):
            client=client_model(e,'phone',mode)
            self.assertEqual(client,import_bundle(export_bundle(client)))
            self.assertIn(e[mode+'_host'],client['server']);self.assertEqual(client['password'],'proof-password')
            self.assertEqual(client['private_key'],'');self.assertEqual(client['certificate'],'')
            self.assertTrue(client['servercert'].startswith('pin-sha256:'))
    def test_disabled_server_or_client_cannot_export(self):
        e=self.entry();e['disabled_clients']=['phone']
        with self.assertRaises(ValueError):client_model(e,'phone','local')
        e=self.entry();e['enabled']=False
        with self.assertRaises(ValueError):client_model(e,'phone','local')
    def test_only_declared_pools_on_owned_prefix_enter_common_policy(self):
        e=self.entry();scope=ocserv_scope(e);opened=nft_script([scope],True)
        self.assertIn('iifname "'+device_prefix(e['id'])+'*"',opened)
        self.assertIn('10.213.0.0/24',opened);self.assertIn('fd12:213::/112',opened)
        self.assertNotIn('tproxy',nft_script([scope],False))
        with self.assertRaises(ValueError):validate_scopes([{**scope,'interface':'fc*'}])
        with self.assertRaises(ValueError):validate_scopes([scope,{**scope,'interface':device_prefix('other')+'*'}])
    def test_invalid_fields_or_material_rejected(self):
        for changes in ({'listen':'evil\nroute=default'},{'users':[{'username':'x:y','password':'p'}]},
                        {'users':[{'username':'x','password':'a\nb'}]}, {'pools':['0.0.0.0/0']},
                        {'pools':['10.213.0.1/24']},{'pools':['10.213.0.0/24','10.214.0.0/24']},
                        {'client_routes':[]},{'max_same_clients':17},{'script':'/tmp/evil'},
                        {'private_key':self.cert},{'listen_port':True},{'mtu':1280}):
            n=copy.deepcopy(self.entry()['native']);n.update(changes)
            with self.subTest(changes=list(changes)),self.assertRaises(ValueError):validate(n)
    def test_render_no_password_or_arbitrary_hooks(self):
        e=self.entry();n=e['native'];value=render_config(n,'/run/farvater-ocserv/test',device_prefix(e['id']))
        self.assertIn('udp-port = 19443',value);self.assertNotIn('proof-password',value)
        self.assertNotIn('PRIVATE KEY',value);self.assertNotIn('script',value)
        n['dtls']=False;self.assertIn('udp-port = 0',render_config(n,'/run/test',device_prefix(e['id'])))
        for path in ('relative','/tmp/x\nroute=default','/tmp/x"'):
            with self.assertRaises(ValueError):render_config(n,path,device_prefix(e['id']))
    def test_server_standard_archive_and_native_only_import(self):
        e=self.entry();e['native']['users'].append({'username':'disabled','password':'not-shared'});e['disabled_clients']=['disabled']
        raw=export_server(e);self.assertEqual(import_server(raw,e),e)
        files=read_archive(raw);self.assertNotIn('disabled:',files['ocpasswd']);self.assertNotIn('proof-password',files['ocpasswd'])
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            for name,value in files.items():
                if name!='farvater.json':z.writestr(name,value)
        native=import_server(stream.getvalue(),e)
        self.assertEqual(native['native']['users'][0]['password'],'');self.assertEqual(len(native['native']['users']),1)
        with self.assertRaisesRegex(ValueError,'хеш'):client_model(native,'phone','local')
        self.assertEqual(import_server(export_server(native),native),native)
    def test_import_rejects_hooks_and_mismatched_metadata(self):
        e=self.entry();files=read_archive(export_server(e))
        for filename,text in [('ocserv.conf','connect-script = /tmp/script\n'),('ocpasswd','extra:*:$6$invalid$bad\n')]:
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as z:
                for name,value in files.items():z.writestr(name,value+(text if name==filename else ''))
            with self.assertRaises(ValueError):import_server(stream.getvalue(),e)
    def test_shared_bundle_has_only_kernel_listener_for_ocserv(self):
        from test_incoming_connections import IncomingTests
        from candidate_bundle import build_bundle
        from incoming_connections import validate as entries_validate
        e=self.entry();entries_validate([e]);p=IncomingTests().base();p['incoming_connections']=[e]
        files=build_bundle(p,api_secret='x'*32);config=json.loads(files['config.json'])
        self.assertTrue(any(i.get('tag')=='incoming-kernel-4' for i in config['inbounds']))
        self.assertNotIn('openconnect-server',[i['type'] for i in config['inbounds']])
        self.assertIn('10.213.0.0/24',json.dumps(config['route']['rules']))


import test_incoming_web as web_tests
class OcservWebTests(unittest.TestCase):
    setUp=web_tests.IncomingWebTests.setUp
    tearDown=web_tests.IncomingWebTests.tearDown
    login=web_tests.IncomingWebTests.login
    revision=web_tests.IncomingWebTests.revision
    saved=web_tests.IncomingWebTests.saved
    @classmethod
    def setUpClass(cls):OcservIncomingTests.setUpClass()
    def fields(self,csrf):
        n=entry(OcservIncomingTests.cert,OcservIncomingTests.key)['native']
        f={'csrf':csrf,'revision':self.revision(),'id':'','type':'openconnect-server','name':'Test server','enabled':'on',
           'local_host':'192.0.2.1','external_host':'vpn.example.org','client_original':[''],'client_name':['phone'],'client_secret':['proof-password']}
        for key,value in n.items():
            if key=='users':continue
            f[key]='\n'.join(value) if isinstance(value,list) else 'on' if value is True else '' if value is False else str(value)
        return f
    def test_create_rename_mask_export_import_disable_and_delete(self):
        csrf=self.login();page=self.client.get('/devices/incoming/new?protocol=openconnect-server');self.assertEqual(page.status_code,200)
        self.assertIn('Добавить клиента',page.text)
        f=self.fields(csrf);r=self.client.post('/devices/incoming/save',data=f);self.assertEqual(r.status_code,302,r.text)
        e=self.saved();path='/devices/incoming/'+e['id'];page=self.client.get(path+'/edit')
        self.assertNotIn('proof-password',page.text);self.assertNotIn(OcservIncomingTests.key,page.text)
        for mode in ('local','external'):
            r=self.client.post(path+'/export',data={'csrf':csrf,'revision':self.revision(),'format':'zip','client':'phone','mode':mode});self.assertEqual(r.status_code,200,r.data[:200])
            model=import_bundle(base64.b64encode(r.data).decode());self.assertIn(e[mode+'_host'],model['server'])
        f=self.fields(csrf);f.update(id=e['id'],client_original=['phone'],client_name=['renamed'],client_secret=[''],certificate='',private_key='')
        self.assertEqual(self.client.post('/devices/incoming/save',data=f).status_code,302)
        self.assertEqual(self.saved()['native']['users'][0]['password'],'proof-password')
        r=self.client.post(path+'/export',data={'csrf':csrf,'revision':self.revision(),'format':'server'});self.assertEqual(r.status_code,200,r.data[:200])
        r=self.client.post(path+'/import',data={'csrf':csrf,'revision':self.revision(),'connection_file':(io.BytesIO(r.data),'server.zip')});self.assertEqual(r.status_code,302,r.text)
        f=self.fields(csrf);f.update(id=e['id'],client_original=['renamed'],client_name=['renamed'],client_secret=[''],disabled_client=['renamed'])
        self.assertEqual(self.client.post('/devices/incoming/save',data=f).status_code,302)
        self.assertEqual(self.client.post(path+'/export',data={'csrf':csrf,'revision':self.revision(),'format':'zip','client':'renamed','mode':'local'}).status_code,400)
        self.assertEqual(self.client.post(path+'/delete',data={'csrf':csrf,'revision':self.revision(),'confirm':'on'}).status_code,302)


if __name__=='__main__':unittest.main()
