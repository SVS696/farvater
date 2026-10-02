import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from werkzeug.security import generate_password_hash
from wg_clients import control
from web import create_app
from candidate_remote import RemoteError

SERVER_PRIVATE=base64.b64encode(b's'*32).decode()
SERVER_PUBLIC=base64.b64encode(b'S'*32).decode()
PRIVATE=base64.b64encode(b'c'*32).decode()
PUBLIC=base64.b64encode(b'C'*32).decode()
ROUTER_PUBLIC=base64.b64encode(b'R'*32).decode()
BASE=f'''[Interface]
PrivateKey = {SERVER_PRIVATE}
Address = 10.77.0.1/24
ListenPort = 51820
[Peer]
# roaming Phone
PublicKey = {PUBLIC}
AllowedIPs = 10.77.0.8/32
[Peer]
# Router
PublicKey = {ROUTER_PUBLIC}
AllowedIPs = 10.77.0.2/32, 192.168.77.0/24
'''
CLIENT=f'''[Interface]
PrivateKey = {PRIVATE}
Address = 10.77.0.8/32
DNS = 10.77.0.1
[Peer]
PublicKey = {SERVER_PUBLIC}
Endpoint = old.example:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
'''

class IncomingClients(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.profiles=self.root/'profiles';self.profiles.mkdir()
        self.directory=self.root/'clients';self.directory.mkdir(mode=0o700)
        self.save(self.profiles/'wg0.conf',BASE);self.save(self.directory/'10.77.0.8.conf',CLIENT)
        self.config={'interface':'wg0','directory':str(self.directory),'external_endpoint':'new.example:51820','local_endpoint':'192.168.77.10:51820'}
        self.save(self.root/'clients.json',json.dumps(self.config));self.commands=[]
        self.save(self.root/'auth.json',json.dumps({'username':'owner','password_hash':generate_password_hash('test'),'session_secret':'test'}))
        self.remote=Mock();self.remote.call.side_effect=self.remote_call
        self.client=create_app(self.root,self.remote).test_client()
        with self.client.session_transaction() as session:session.update(authenticated=True,csrf='test')
    def tearDown(self):self.temp.cleanup()
    def save(self,path,data):path.write_text(data);path.chmod(0o600)
    def command(self,args,data=None):
        self.commands.append(args)
        if args==['/usr/bin/wg','pubkey']:return {SERVER_PRIVATE:SERVER_PUBLIC,PRIVATE:PUBLIC}[data.strip()]+'\n'
        if args==['/usr/bin/wg','show','wg0','latest-handshakes']:return PUBLIC+'\t12345\n'+ROUTER_PUBLIC+'\t0\n'
        raise AssertionError(args)
    def call(self,action='clients-status',**fields):
        return control({'version':1,'action':action,**fields},root=self.root,profiles=self.profiles,command=self.command)
    def remote_call(self,action,**fields):
        try:return self.call(action,**fields)
        except ValueError as exc:raise RemoteError(str(exc)) from None
    def export_fields(self):
        state=self.call();return {'id':state['clients'][0]['id'],'mode':'external','file_revision':state['file_revision']}
    def test_inventory_hides_all_keys_and_separates_router(self):
        state=self.call();raw=json.dumps(state)
        for key in (PRIVATE,PUBLIC,SERVER_PRIVATE,SERVER_PUBLIC,ROUTER_PUBLIC):self.assertNotIn(key,raw)
        self.assertEqual(state['clients'][0]['name'],'Phone');self.assertTrue(state['clients'][0]['downloadable'])
        self.assertFalse(state['clients'][1]['downloadable']);self.assertEqual(state['clients'][0]['handshake'],12345)
    def test_export_preserves_keys_and_only_changes_endpoint(self):
        fields=self.export_fields();before=(self.profiles/'wg0.conf').read_bytes()
        for mode,addr in [('local',self.config['local_endpoint']),('external',self.config['external_endpoint'])]:
            out=self.call('clients-export',**{**fields,'mode':mode});self.assertEqual(out['config'],CLIENT.replace('old.example:51820',addr))
        self.assertEqual((self.profiles/'wg0.conf').read_bytes(),before);self.assertEqual((self.directory/'10.77.0.8.conf').read_text(),CLIENT)
        self.assertTrue(all(c[:2] in (['/usr/bin/wg','show'],['/usr/bin/wg','pubkey']) for c in self.commands))
    def test_mismatched_addresses_server_key_and_hooks_refuse_export(self):
        for changed in (CLIENT.replace('10.77.0.8/32','10.77.0.9/32'),CLIENT.replace(SERVER_PUBLIC,ROUTER_PUBLIC),CLIENT.replace('DNS =','PostUp = bad\nDNS =')):
            self.save(self.directory/'10.77.0.8.conf',changed);self.assertFalse(self.call()['clients'][0]['downloadable'])
            with self.assertRaises(ValueError):self.call('clients-export',**self.export_fields())
    def test_stale_inventory_invalid_mode_and_router_cannot_export(self):
        fields=self.export_fields()
        for change in ({'file_revision':'0'*64},{'mode':'../../etc/passwd'},{'id':self.call()['clients'][1]['id']}):
            with self.assertRaises(ValueError):self.call('clients-export',**{**fields,**change})
    def test_symlink_public_file_and_duplicate_key_not_exported(self):
        p=self.directory/'10.77.0.8.conf';p.chmod(0o644);self.assertFalse(self.call()['clients'][0]['downloadable']);p.chmod(0o600)
        copy_path=self.directory/'copy.conf';self.save(copy_path,CLIENT);self.assertFalse(self.call()['clients'][0]['downloadable']);copy_path.unlink()
        p.unlink();p.symlink_to(self.profiles/'wg0.conf');self.assertFalse(self.call()['clients'][0]['downloadable'])
    def test_settings_validate_endpoints_staleness_and_do_not_touch_runtime(self):
        state=self.call();fields={k:state[k] for k in ('settings_revision','local_endpoint','external_endpoint')}
        for bad in ('example:0','example:65536','example\nPostUp=cmd','example', 'https://example:443'):
            with self.assertRaises(ValueError):self.call('clients-settings',**{**fields,'external_endpoint':bad})
        self.commands.clear();result=self.call('clients-settings',**{**fields,'external_endpoint':'[2001:db8::2]:51820'})
        self.assertFalse(result['runtime_changed']);self.assertEqual(self.commands,[])
        with self.assertRaises(ValueError):self.call('clients-settings',**fields)
    def test_web_auth_csrf_no_secret_in_listing_download_no_store(self):
        html=self.client.get('/devices').text;self.assertIn('Phone',html);self.assertNotIn(PRIVATE,html);self.assertNotIn(SERVER_PRIVATE,html)
        fields=self.export_fields();url='/devices/'+fields.pop('id')+'/export'
        self.assertEqual(self.client.post(url,data=fields).status_code,403)
        self.assertEqual(self.client.post(url,data={**fields,'csrf':'test'},headers={'Origin':'https://bad.example'}).status_code,403)
        result=self.client.post(url,data={**fields,'csrf':'test'});self.assertEqual(result.status_code,200);self.assertIn(PRIVATE,result.text)
        self.assertEqual(result.headers['Cache-Control'],'no-store');self.assertIn('attachment',result.headers['Content-Disposition'])
        with self.client.session_transaction() as session:session.pop('authenticated')
        self.assertEqual(self.client.get('/devices').status_code,302)
    def test_both_paths_are_available_without_inlining_client_secrets(self):
        html=self.client.get('/devices').text
        for marker in ('Локальный адрес','Внешний адрес','value="local"','value="external"','data-qr-output'):
            self.assertIn(marker,html)
        self.assertEqual(html.count('data-client-export='),2)
        for secret in (PRIVATE,PUBLIC,SERVER_PRIVATE,SERVER_PUBLIC):self.assertNotIn(secret,html)

    def test_qr_is_generated_locally_without_exposing_config_in_url(self):
        fields=self.export_fields();url='/devices/'+fields.pop('id')+'/export'
        with patch('subprocess.run',return_value=Mock(returncode=0,stdout='<?xml version="1.0"?><svg/>')) as qr:
            response=self.client.post(url,data={**fields,'csrf':'test','format':'qr'})
        self.assertEqual(response.status_code,200);self.assertEqual(response.mimetype,'image/svg+xml')
        self.assertIn(PRIVATE,qr.call_args.kwargs['input']);self.assertNotIn(PRIVATE,url)
    def test_unavailable_backend_no_stale_download_controls(self):
        self.remote.call.side_effect=RemoteError('Нет связи');page=self.client.get('/devices')
        self.assertIn('Нет связи',page.text);self.assertNotIn('name="mode"',page.text)

    def test_router_can_import_and_export_without_changing_network(self):
        router_private=base64.b64encode(b'r'*32).decode()
        command=self.command
        def with_router(args,data=None):
            if args==['/usr/bin/wg','pubkey'] and data.strip()==router_private:return ROUTER_PUBLIC+'\n'
            return command(args,data)
        self.command=with_router
        state=self.call();row=state['clients'][1]
        fields={'id':row['id'],'file_revision':state['file_revision']}
        before=(self.profiles/'wg0.conf').read_bytes()
        router=CLIENT.replace(PRIVATE,router_private).replace('10.77.0.8/32','10.77.0.2/32')
        for invalid in (CLIENT,router.replace('10.77.0.2/32','10.77.0.99/32'),router.replace('DNS =','PostUp = bad\nDNS =')):
            with self.assertRaises(ValueError):self.call('clients-import',**fields,config=invalid)
        self.call('clients-import',**fields,config=router)
        self.assertTrue(self.call()['clients'][1]['downloadable'])
        for mode in ('local','external'):
            result=self.call('clients-export',**fields,mode=mode)
            self.assertIn(router_private,result['config'])
            self.assertIn(self.config[mode+'_endpoint'],result['config'])
        self.assertEqual((self.profiles/'wg0.conf').read_bytes(),before)
        self.assertEqual((self.directory/('imported-'+row['id']+'.conf')).stat().st_mode & 0o777,0o600)

    def test_rename_router_persists_and_checks_stale_name_without_network_write(self):
        state=self.call();row=state['clients'][1];before=(self.profiles/'wg0.conf').read_bytes()
        fields={'id':row['id'],'file_revision':state['file_revision'],'name':'Дачный роутер','previous_name':row['name']}
        self.call('clients-rename',**fields)
        self.assertEqual(self.call()['clients'][1]['name'],'Дачный роутер')
        with self.assertRaises(ValueError):self.call('clients-rename',**fields)
        self.assertEqual((self.profiles/'wg0.conf').read_bytes(),before)
        for bad in ('', 'a\nb', 'a'*81):
            with self.assertRaises(ValueError):self.call('clients-rename',**{**fields,'name':bad,'previous_name':'Дачный роутер'})

    def test_rename_and_import_routes_require_csrf(self):
        import io
        state=self.call();row=state['clients'][0]
        data={'file_revision':state['file_revision'],'name':'Renamed','previous_name':row['name']}
        url='/devices/'+row['id']
        self.assertEqual(self.client.post(url+'/rename',data=data).status_code,403)
        self.assertEqual(self.client.post(url+'/rename',data={**data,'csrf':'test'}).status_code,302)
        self.assertEqual(self.client.post(url+'/import',data={'file_revision':state['file_revision'],'connection_file':(io.BytesIO(CLIENT.encode()),'client.conf')}).status_code,403)
        self.assertEqual(self.client.post(url+'/import',data={'csrf':'test','file_revision':state['file_revision'],'connection_file':(io.BytesIO(CLIENT.encode()),'client.conf')}).status_code,302)

if __name__=='__main__':unittest.main()
