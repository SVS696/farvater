import copy
import unittest
from amnezia_incoming import private_key,public_key,validate,allocate,server_model,client_config,import_server
from amnezia_profile import parse,render


def entry():
    secret=private_key()
    return {'id':'awg-test','name':'AWG','enabled':True,'local_host':'192.0.2.1','external_host':'vpn.example.org',
      'native':{'type':'amneziawg','listen_port':51821,'interface':{'PrivateKey':private_key(),'Address':['10.212.0.1/24','fd12:212::1/64'],
      'Jc':3,'Jmin':40,'Jmax':70,'S1':16,'S2':32,'S3':16,'S4':16,'H1':'100-200','H2':'300-400','H3':'500-600','H4':'700-800'},
      'users':[{'name':'phone','public_key':public_key(secret),'private_key':secret,'preshared_key':private_key(),
                'allowed_ips':['10.212.0.2/32','fd12:212::2/128'],'addresses':['10.212.0.2/32','fd12:212::2/128']}],
      'client_dns':['10.212.0.1'],'client_routes':['0.0.0.0/0','::/0'],'keepalive':25}}


class IncomingAmneziaTests(unittest.TestCase):
    def test_native_server_and_client_roundtrip(self):
        e=entry();n=validate(e['native']);server=render(server_model(n));client=render(client_config(e,'phone','external'))
        self.assertEqual(parse(server),parse(render(parse(server))))
        self.assertNotIn(n['users'][0]['private_key'],server)
        self.assertNotIn(n['interface']['PrivateKey'],client)
        c=parse(client);self.assertEqual(c['peers'][0]['Endpoint'],'vpn.example.org:51821')
        self.assertEqual(c['interface']['DNS'],n['client_dns']);self.assertEqual(c['interface']['H1'],n['interface']['H1'])
        self.assertEqual(parse(render(client_config(e,'phone','local')))['peers'][0]['Endpoint'],'192.0.2.1:51821')
        e['external_host']='2001:db8::1'
        self.assertEqual(client_config(e,'phone','external')['peers'][0]['Endpoint'],'[2001:db8::1]:51821')
    def test_allocate_both_families_and_routed_network(self):
        n=entry()['native'];self.assertEqual(allocate(n),['10.212.0.3/32','fd12:212::3/128'])
        n['users'][0]['allowed_ips'].append('10.212.0.0/25');self.assertEqual(allocate(n)[0],'10.212.0.128/32')
        n['interface']['Address']=['10.212.0.1/31'];n['users']=[];self.assertEqual(allocate(n),['10.212.0.0/32'])
        n['interface']['Address']=['::2/120'];self.assertEqual(allocate(n),['::1/128'])
        n['interface']['Address']=['10.212.0.1/32']
        with self.assertRaisesRegex(ValueError,'закончились'):allocate(n)
    def test_import_retains_matching_private_material(self):
        n=entry()['native'];model=server_model(n);model['interface']['Jc']=5
        restored=import_server(render(model),n)
        self.assertEqual(restored['users'][0]['private_key'],n['users'][0]['private_key']);self.assertEqual(restored['interface']['Jc'],5)
        self.assertEqual(restored['client_dns'],n['client_dns'])
        model['peers'][0]['PublicKey']=public_key(private_key());new=import_server(render(model),n)['users'][0]
        self.assertNotIn('private_key',new);self.assertEqual(new['addresses'],[])
    def test_import_does_not_confuse_new_and_retained_names(self):
        n=entry()['native'];n['users'][0]['name']='Пир 1';model=server_model(n)
        model['peers'].insert(0,{'PublicKey':public_key(private_key()),'AllowedIPs':['10.212.0.3/32']})
        r=import_server(render(model),n);self.assertEqual([u['name'] for u in r['users']],['Пир 2','Пир 1'])
    def test_disabled_and_imported_clients_cannot_export(self):
        e=entry();e['disabled_clients']=['phone'];self.assertEqual(server_model(e['native'],e['disabled_clients'])['peers'],[])
        with self.assertRaises(ValueError):client_config(e,'phone','local')
        e['disabled_clients']=[];e['native']['users'][0].pop('private_key')
        with self.assertRaisesRegex(ValueError,'ключа'):client_config(e,'phone','local')
    def test_reject_overlap_server_spoof_and_mismatched_key(self):
        n=entry()['native'];cases=[]
        v=copy.deepcopy(n);v['users'][0]['private_key']=private_key();cases.append(v)
        for address in ('0.0.0.0/0','10.212.0.1/32','10.212.0.0/24'):
            v=copy.deepcopy(n);v['users'][0]['allowed_ips']=[address];cases.append(v)
        v=copy.deepcopy(n);u=copy.deepcopy(v['users'][0]);u['name']='second';u['private_key']=private_key();u['public_key']=public_key(u['private_key']);v['users'].append(u);cases.append(v)
        v=copy.deepcopy(n);v['interface']['PostUp']='echo bad';cases.append(v)
        for v in cases:
            with self.assertRaises(ValueError):validate(v)
    def test_import_client_recovers_private_key_and_preserves_other_clients(self):
        from amnezia_incoming import import_client
        e=entry();raw=render(client_config(e,'phone','external'))
        n=copy.deepcopy(e['native']);n['users'][0].pop('private_key')
        result=import_client(raw,n,'renamed')
        self.assertEqual(result['users'][0]['name'],'renamed')
        self.assertEqual(result['users'][0]['private_key'],e['native']['users'][0]['private_key'])
        other=entry()
        with self.assertRaises(ValueError):import_client(raw,other['native'],'wrong server')

    def test_server_import_rejects_client_profile_and_hooks(self):
        e=entry()
        with self.assertRaises(ValueError):import_server(render(client_config(e,'phone','external')),e['native'])
        with self.assertRaises(ValueError):import_server(render(server_model(e['native']))+'PostUp = echo bad\n',e['native'])

if __name__=='__main__':unittest.main()

class IncomingAmneziaWebTests(unittest.TestCase):
    import test_incoming_web as web_tests
    setUp=web_tests.IncomingWebTests.setUp
    tearDown=web_tests.IncomingWebTests.tearDown
    login=web_tests.IncomingWebTests.login
    revision=web_tests.IncomingWebTests.revision
    saved=web_tests.IncomingWebTests.saved
    def fields(self,csrf):
        return {'csrf':csrf,'revision':self.revision(),'type':'amneziawg','name':'AWG server','enabled':'on',
          'listen_port':'51821','local_host':'192.0.2.1','external_host':'vpn.example.org',
          'address':'10.212.0.1/24\nfd12:212::1/64','client_dns':'10.212.0.1', 'client_routes':'0.0.0.0/0\n::/0','keepalive':'25',
          **{'client_'+k:['phone' if k=='name' else ''] for k in ('original','name','secret','public','psk','address','networks')}}
    def test_create_allocate_rename_disable_export_and_native_import(self):
        import io
        csrf=self.login();f=self.fields(csrf)
        r=self.client.get('/devices/incoming/new?protocol=amneziawg');self.assertEqual(r.status_code,200)
        self.assertIn('Добавить клиента',r.text)
        r=self.client.post('/devices/incoming/save',data=f);self.assertEqual(r.status_code,302,r.text)
        e=self.saved();u=e['native']['users'][0];self.assertEqual(u['addresses'],['10.212.0.2/32','fd12:212::2/128'])
        page=self.client.get('/devices/incoming/'+e['id']+'/edit');self.assertEqual(page.status_code,200)
        self.assertNotIn(u['private_key'],page.text);self.assertNotIn(e['native']['interface']['PrivateKey'],page.text)
        listing=self.client.get('/devices/incoming');self.assertEqual(listing.status_code,200);self.assertIn('AmneziaWG',listing.text)
        for mode,address in [('local','192.0.2.1:51821'),('external','vpn.example.org:51821')]:
            r=self.client.post('/devices/incoming/'+e['id']+'/export',data={'csrf':csrf,'revision':self.revision(),'client':'phone','mode':mode,'format':'conf'})
            self.assertEqual(r.status_code,200,r.text);self.assertEqual(parse(r.text)['peers'][0]['Endpoint'],address)
        imported=self.client.post('/devices/incoming/'+e['id']+'/import-client',data={'csrf':csrf,'revision':self.revision(),'client_file':(io.BytesIO(r.data),'client.conf')})
        self.assertEqual(imported.status_code,302,imported.text)
        f=self.fields(csrf);f.update(id=e['id'],client_original=['phone'],client_name=['renamed'],client_address=['\n'.join(u['addresses'])],client_networks=['\n'.join(u['allowed_ips'])])
        r=self.client.post('/devices/incoming/save',data=f);self.assertEqual(r.status_code,302,r.text)
        self.assertEqual(self.saved()['native']['users'][0]['private_key'],u['private_key'])
        path='/devices/incoming/'+e['id'];r=self.client.post(path+'/export',data={'csrf':csrf,'revision':self.revision(),'format':'server'})
        self.assertEqual(r.status_code,200);self.assertNotIn(u['private_key'],r.text)
        r=self.client.post(path+'/import',data={'csrf':csrf,'revision':self.revision(),'connection_file':(io.BytesIO(r.data),'server.conf')})
        self.assertEqual(r.status_code,302,r.text);self.assertEqual(self.saved()['native']['users'][0]['private_key'],u['private_key'])
        f.update(revision=self.revision(),client_original=['renamed'],disabled_client=['renamed'])
        r=self.client.post('/devices/incoming/save',data=f);self.assertEqual(r.status_code,302,r.text)
        r=self.client.post(path+'/export',data={'csrf':csrf,'revision':self.revision(),'client':'renamed','mode':'local','format':'conf'})
        self.assertEqual(r.status_code,400)
    def test_kernel_listeners_are_bound_to_complete_bundle(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        from candidate_bundle import build_bundle
        from safe_apply import Backend
        from test_incoming_connections import IncomingTests
        p=IncomingTests().base();p['incoming_connections']=[entry()]
        files=build_bundle(p,api_secret='x'*32)
        c=json.loads(files['config.json']);self.assertEqual(len([v for v in c['inbounds'] if v['type']=='tproxy']),2)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);c['experimental']['cache_file']['path']=str(root/'cache.db');path=root/'config.json';path.write_text(json.dumps(c));b=Backend(root)
            with self.assertRaisesRegex(ValueError,'validated complete bundle'):b.validate(path)
            with patch('incoming_runtime.check_service'),patch('incoming_runtime.preflight'):b.validate_bundle(files)
            with patch('safe_apply.subprocess.run') as run:run.return_value.returncode=0;b.validate(path)
            c['inbounds'][-1]['listen']='::';path.write_text(json.dumps(c))
            with self.assertRaisesRegex(ValueError,'validated complete bundle'):b.validate(path)

class IncomingAmneziaPortTests(unittest.TestCase):
    def test_protocol_port_cannot_collide_with_common_core(self):
        from candidate_bundle import build_bundle
        from test_incoming_connections import IncomingTests
        p=IncomingTests().base();e=entry();e['native']['listen_port']=2081;p['incoming_connections']=[e]
        with self.assertRaisesRegex(ValueError,'Порт AmneziaWG'):build_bundle(p,api_secret='x'*32)
