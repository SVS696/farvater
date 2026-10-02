import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from incoming_connections import validate, compile_inbounds, attach, client_config, client_link, import_native
from protocol_modules import choices, engines
from candidate_bundle import build_bundle, validate_bundle
from policy_exchange import encode, decode
from safe_apply import Backend
import test_candidate_config as fixtures


def entry(kind='socks', port=18080):
    n={'type':kind,'listen':'127.0.0.1','listen_port':port}
    if kind in ('socks','http'):n['users']=[{'username':'phone','password':'only-client-secret'}]
    if kind=='vless':n['users']=[{'name':'phone','uuid':'b2cbf950-daf7-481a-b276-fd6c85b8c353'}]
    if kind=='shadowsocks':n.update(method='aes-128-gcm',password='only-client-secret')
    return {'id':kind,'name':'Example','enabled':True,'local_host':'127.0.0.1','external_host':'vpn.example.org','native':n}

class IncomingTests(unittest.TestCase):
    def base(self):
        p=fixtures.CandidateConfigTests().base()
        for group in ('exits','dns'):
            for key,value in p[group].items():value.setdefault('name',key)
        return p
    def test_optional_engine_dependencies(self):
        self.assertEqual(engines([], 'incoming'), [])
        self.assertEqual(engines(['socks','vless','openvpn'], 'incoming'), ['sing-box'])
        self.assertEqual(engines(['openconnect'], 'outgoing'), ['sing-box'])
        self.assertEqual(engines(['openconnect'], 'incoming'), ['ocserv'])
        self.assertEqual(choices('incoming'), choices('outgoing'))
        with self.assertRaises(ValueError):engines(['direct'], 'incoming')
    def test_native_clients_and_links(self):
        for kind in ['socks','http','vless','shadowsocks']:
            with self.subTest(kind=kind):
                e=entry(kind);before=copy.deepcopy(e)
                for mode in ('local','external'):
                    user='' if kind=='shadowsocks' else 'phone'
                    out=client_config(e,user,mode)
                    self.assertEqual(out['type'],kind);self.assertEqual(out['server'],e[mode+'_host'])
                    self.assertNotIn('users',out);self.assertIn('://',client_link(e,user,mode))
                self.assertEqual(e,before)
    def test_policy_roundtrip_and_bundle(self):
        e=entry('vless');imported=import_native(json.dumps({'inbounds':[e['native']]}).encode(),e)
        p=self.base();p['incoming_connections']=[imported]
        self.assertEqual(decode(encode(p).encode()),p)
        files=build_bundle(p,api_secret='x'*32);validate_bundle(files)
        c=json.loads(files['config.json']);self.assertEqual(c['inbounds'][-1]['tag'],'incoming-vless')
        self.assertEqual(c['route']['rules'][0],{'inbound':['incoming-vless'],'port':53,'action':'hijack-dns'})
        self.assertEqual(c['route']['rules'][-1]['action'],'reject')
    def test_disabled_and_authentication(self):
        e=entry();e['enabled']=False;self.assertEqual(compile_inbounds([e]),[])
        with self.assertRaises(ValueError):client_config(e,'phone','local')
        for kind in ('socks','http','vless'):
            e=entry(kind);e['native']['users']=[]
            with self.subTest(kind=kind),self.assertRaises(ValueError):validate([e])
        e=entry();e['native']['users']*=2
        with self.assertRaises(ValueError):validate([e])
        e=entry('vless');e['native']['users'][0]['uuid']='invalid'
        with self.assertRaises(ValueError):validate([e])
        e=entry();e['native']['listen_port']=True
        with self.assertRaises(ValueError):validate([e])
    def test_disabled_clients_cannot_export_or_open_anonymous_listener(self):
        e=entry();e['disabled_clients']=['phone']
        self.assertEqual(compile_inbounds([e]),[])
        with self.assertRaisesRegex(ValueError,'отключён'):client_config(e,'phone','local')
        e['native']['users'].append({'username':'laptop','password':'another-secret'})
        self.assertEqual(compile_inbounds([e])[0]['users'],[{'username':'laptop','password':'another-secret'}])
        e['disabled_clients']=['missing']
        with self.assertRaises(ValueError):validate([e])

    def test_socks_runtime_socket_mark_does_not_leak_to_portable_config(self):
        from incoming_kernel import SOCKS_UDP_MARK
        e=entry();compiled=compile_inbounds([e])[0]
        self.assertEqual(compiled['routing_mark'],SOCKS_UDP_MARK)
        self.assertNotIn('routing_mark',e['native'])
        self.assertNotIn('routing_mark',client_config(e,'phone','external'))
        self.assertNotIn('routing_mark',compile_inbounds([entry('http')])[0])
        e['native']['routing_mark']=SOCKS_UDP_MARK
        with self.assertRaises(ValueError):validate([e])

    def test_server_key_never_in_client_export(self):
        e=entry('http');e['native']['tls']={'enabled':True,'server_name':'vpn.example.org',
            'certificate':['-----BEGIN CERTIFICATE-----','public-cert','-----END CERTIFICATE-----'],
            'key':['-----BEGIN PRIVATE KEY-----','server-secret','-----END PRIVATE KEY-----']}
        out=client_config(e,'phone','external')
        self.assertNotIn('server-secret',json.dumps(out));self.assertIn('public-cert',json.dumps(out))
        with self.assertRaises(ValueError):client_link(e,'phone','external')
        e['native']['tls']['key_path']='/etc/shadow'
        with self.assertRaises(ValueError):validate([e])
    def test_ss_multiclient_key_composition(self):
        e=entry('shadowsocks');a=base64.b64encode(b'a'*16).decode();b=base64.b64encode(b'b'*16).decode()
        e['native'].update(method='2022-blake3-aes-128-gcm',password=a,users=[{'name':'phone','password':b}])
        self.assertEqual(client_config(e,'phone','local')['password'],a+':'+b)
        self.assertTrue(client_link(e,'phone','local').startswith('ss://'))
        e['native']['method']='aes-128-gcm'
        with self.assertRaises(ValueError):validate([e])
    def test_port_collisions_and_unsafe_import(self):
        for port in (5301,2081,9091):
            p=self.base();p['incoming_connections']=[entry(port=port)]
            with self.subTest(port=port),self.assertRaises(ValueError):build_bundle(p,api_secret='x'*32)
        with self.assertRaises(ValueError):attach({'inbounds':[],'route':{'rules':[]}},[entry('socks'),entry('http')])
        e=entry();e['native']['detour']='escape'
        with self.assertRaises(ValueError):validate([e])
        with self.assertRaises(ValueError):import_native(b'{"inbounds":[],"inbounds":[]}',entry())
    def test_backend_binding(self):
        p=self.base();p['incoming_connections']=[entry()];files=build_bundle(p,api_secret='x'*32)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'config.json';c=json.loads(files['config.json']);c['experimental']['cache_file']['path']=str(root/'cache.db');path.write_text(json.dumps(c))
            backend=Backend(root)
            with self.assertRaisesRegex(ValueError,'validated complete bundle'):backend.validate(path)
            with patch("incoming_runtime.check_service") as service, patch("incoming_runtime.preflight") as preflight:
                backend.validate_bundle(files)
                service.assert_called_once_with(root);preflight.assert_called_once_with(p)
            with patch('safe_apply.subprocess.run') as run:
                run.return_value.returncode=0;backend.validate(path)
            c['inbounds'][-1]['users'][0]['password']='tampered';path.write_text(json.dumps(c))
            with self.assertRaisesRegex(ValueError,'validated complete bundle'):backend.validate(path)

if __name__=='__main__':unittest.main()
