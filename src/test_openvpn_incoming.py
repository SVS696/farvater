import copy
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from werkzeug.datastructures import MultiDict
from incoming_connections import validate,client_config,compile_endpoints,import_native
from incoming_form import parse
from openvpn_format import render,parse as parse_ovpn
from candidate_bundle import build_bundle
from safe_apply import Backend
import test_incoming_connections as connection_tests
import test_incoming_web as web_tests

class OpenVPNIncomingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(p/'key'),'-out',str(p/'cert'),'-days','1','-subj','/CN=test-server','-addext','extendedKeyUsage=serverAuth'],check=True,capture_output=True)
            cls.cert=(p/'cert').read_text();cls.key=(p/'key').read_text()
    def entry(self):
        return {'id':'ovpn','name':'OpenVPN','enabled':True,'local_host':'127.0.0.1','external_host':'vpn.example.org','native':{
            'type':'openvpn-server','listen':'127.0.0.1','listen_port':19432,'system':False,'mode':'tls','network':'udp',
            'address':['10.222.0.1/24'],'users':[{'username':'phone','password':'test-secret'}],
            'tls':{'certificate':self.cert.splitlines(),'key':self.key.splitlines(),'verify_client_certificate':'none'},
            'push':{'dns':['10.222.0.1'],'redirect_gateway':True}}}
    def test_native_and_standard_client_export(self):
        e=self.entry();validate([e])
        for mode in ('local','external'):
            n=client_config(e,'phone',mode);out=render({'native':n});again=parse_ovpn(out)['native']
            self.assertEqual(again['servers'][0]['server'],e[mode+'_host'])
            self.assertEqual(again['username'],'phone');self.assertNotIn('PRIVATE KEY',out)
            self.assertEqual(again['tls']['peer_fingerprint'],n['tls']['peer_fingerprint'])
        raw=json.dumps({'endpoints':[e['native']]}).encode();again=import_native(raw,e)
        self.assertEqual(compile_endpoints([again])[0]['type'],'openvpn-server')
    def test_draft_forms_preserve_credentials_and_supported_settings(self):
        e=self.entry();f=MultiDict({'type':'openvpn-server','name':'Renamed','enabled':'on','listen':'127.0.0.1','listen_port':'19432',
          'local_host':'127.0.0.1','external_host':'vpn.example.org','network':'udp','address':'10.222.0.1/24',
          'client_original':'phone','client_name':'laptop','client_secret':'','client_flow':'',
          'certificate':'','private_key':'','mtu':'1400','max_clients':'12','ping_interval':'10','redirect_gateway':'on','dns':'10.222.0.1'})
        r=parse(f,e);self.assertEqual(r['native']['users'],[{'username':'laptop','password':'test-secret'}])
        self.assertEqual(r['native']['tls']['key'],e['native']['tls']['key']);self.assertEqual(r['native']['ping_interval'],'10s')
    def test_control_key_standard_export_and_server_import(self):
        from openvpn_incoming import control_key
        for mode,direction,expected in [('tls_crypt',None,None),('tls_auth','server','client'),('tls_auth','client','server'),('tls_auth',None,None)]:
            e=self.entry();wrap={'type':mode,'key':control_key()}
            if direction:wrap['direction']=direction
            e['native']['tls']['control_wrap']=wrap;validate([e])
            c=client_config(e,'phone','external');self.assertEqual(c['tls']['control_wrap'].get('direction'),expected)
            exported=render({'native':c});again=parse_ovpn(exported)['native']
            self.assertEqual(again['tls']['control_wrap'],c['tls']['control_wrap'])
            self.assertNotIn(self.key.strip(),exported)
            imported=import_native(json.dumps({'endpoints':[e['native']]}).encode(),e)
            self.assertEqual(imported['native']['tls']['control_wrap'],wrap)
    def test_control_wrap_form_generates_preserves_replaces_and_disables(self):
        from openvpn_incoming import control_key
        e=self.entry();f=MultiDict({'type':'openvpn-server','name':'VPN','listen':'127.0.0.1','listen_port':'19432','local_host':'127.0.0.1','external_host':'vpn.example.org','network':'udp','address':'10.222.0.1/24','client_original':'phone','client_name':'phone','client_secret':'','client_flow':'','control_wrap':'tls_crypt','control_key':''})
        first=parse(f,e);key=first['native']['tls']['control_wrap']['key']
        self.assertEqual(parse(f,first)['native']['tls']['control_wrap']['key'],key)
        legacy=f.copy();legacy.pop('control_wrap');self.assertEqual(parse(legacy,first)['native']['tls']['control_wrap']['key'],key)
        replacement=control_key();f['control_key']='\n'.join(replacement)
        self.assertEqual(parse(f,first)['native']['tls']['control_wrap']['key'],replacement)
        f['control_key']='';f['control_wrap']='tls_auth';f['control_direction']='server'
        changed=parse(f,first);self.assertEqual(changed['native']['tls']['control_wrap'],{'type':'tls_auth','key':key,'direction':'server'})
        f['control_wrap']='';self.assertNotIn('control_wrap',parse(f,first)['native']['tls'])
    def test_control_wrap_rejects_unsafe_and_incomplete_keys(self):
        from openvpn_incoming import control_key
        for wrap in [{'type':'tls_crypt','key_path':'/etc/shadow'}, {'type':'tls_crypt','key':['broken']}, {'type':'tls_crypt','key':control_key(),'direction':'server'}, {'type':'tls_auth','key':control_key(),'direction':'bad'}, {'type':'tls_crypt_v2','key':control_key()}]:
            e=self.entry();e['native']['tls']['control_wrap']=wrap
            with self.subTest(wrap=wrap['type']),self.assertRaises(ValueError):validate([e])
    def test_endpoints_bound_to_bundle(self):
        p=connection_tests.IncomingTests().base();p['incoming_connections']=[self.entry()];files=build_bundle(p,api_secret='x'*32)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);c=json.loads(files['config.json']);c['experimental']['cache_file']['path']=str(root/'cache.db')
            path=root/'config.json';path.write_text(json.dumps(c));backend=Backend(root)
            with self.assertRaisesRegex(ValueError,'validated complete bundle'):backend.validate(path)
            with patch('incoming_runtime.check_service') as service,patch('incoming_runtime.preflight') as preflight:
                backend.validate_bundle(files)
                service.assert_called_once_with(root);preflight.assert_called_once_with(p)
            with patch('safe_apply.subprocess.run') as run:run.return_value.returncode=0;backend.validate(path)
            c['endpoints'][0]['listen']='0.0.0.0';path.write_text(json.dumps(c))
            with self.assertRaisesRegex(ValueError,'validated complete bundle'):backend.validate(path)
    def test_reject_unsafe_or_invalid_server(self):
        for change in [{'system':True},{'address':['10.2.0.0/24']},{'network':'bad'},{'users':[]}, {'listen':123}, {'address':['10.2.0.1/24','10.3.0.1/24']}]:
            e=self.entry();e['native'].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):validate([e])
        e=self.entry();e['native']['tls']['key_path']='/etc/shadow'
        with self.assertRaises(ValueError):validate([e])
        e=self.entry();e['native']['tls']['key']=self.cert.splitlines()
        with self.assertRaises(ValueError):validate([e])

class OpenVPNIncomingWebTests(unittest.TestCase):
    setUp=web_tests.IncomingWebTests.setUp
    tearDown=web_tests.IncomingWebTests.tearDown
    login=web_tests.IncomingWebTests.login
    revision=web_tests.IncomingWebTests.revision
    fields=web_tests.IncomingWebTests.fields
    saved=web_tests.IncomingWebTests.saved
    def test_create_and_export_ovpn_and_native(self):
        OpenVPNIncomingTests.setUpClass();csrf=self.login();f=self.fields(csrf,'openvpn-server')
        f.update(network='udp',address='10.222.0.1/24',certificate=OpenVPNIncomingTests.cert,private_key=OpenVPNIncomingTests.key)
        self.assertEqual(self.client.get('/devices/incoming/new?protocol=openvpn-server').status_code,200)
        f['control_wrap']='tls_crypt';f['control_key']=''
        response=self.client.post('/devices/incoming/save',data=f);self.assertEqual(response.status_code,302,response.text)
        e=self.saved();path='/devices/incoming/'+e['id']
        page=self.client.get(path+'/edit');self.assertEqual(page.status_code,200)
        self.assertNotIn(e['native']['tls']['control_wrap']['key'][1],page.text)
        r=self.client.post(path+'/export',data={'csrf':csrf,'revision':self.revision(),'client':'phone','mode':'external','format':'ovpn'})
        self.assertEqual(r.status_code,200,r.text);self.assertIn('<auth-user-pass>',r.text);self.assertNotIn('PRIVATE KEY',r.text)
        self.assertIn('<tls-crypt>',r.text)
        r=self.client.post(path+'/export',data={'csrf':csrf,'revision':self.revision(),'client':'phone','mode':'local','format':'json'})
        self.assertEqual(r.status_code,200);self.assertEqual(r.json['endpoints'][0]['type'],'openvpn-client')

if __name__=='__main__':unittest.main()
