import json
import tempfile
import unittest
from pathlib import Path

from safe_apply import atomic_write, digest
import trusttunnel_clients as tc


class Native:
    def __init__(self): self.restarts=0;self.failure=False;self.armed=[];self.canceled=[]
    def state(self,b):return {'active':True,'pid':123}
    def restart(self,b):
        self.restarts+=1
        if self.failure:self.failure=False;raise ValueError('listener failed')
    def export(self,b,username,mode,kind):
        row=next(c for c in tc.parse(Path(b['credentials']).read_text()) if c['username']==username)
        return 'tt://?native-secret' if kind=='deeplink' else tc.render([row]).decode()
    def fingerprint(self,root,b):
        material=json.dumps(b,sort_keys=True).encode()
        for p in b['dependent_files']:material+=b'\0'+Path(p).read_bytes()
        return tc.encode({'unit_sha256':digest(b'unit'),'script_sha256':digest(material),'companions':{}})
    def arm(self,token):self.armed.append(token)
    def cancel(self,token):self.canceled.append(token)


class ClientsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700);self.native=Native()
        self.binding={'name':'My server','unit':'tt-endpoint.service','unit_file':str(self.root/'unit'),
                      'directory':str(self.root),'binary':str(self.root/'endpoint'),'config':str(self.root/'vpn.toml'),
                      'hosts':str(self.root/'hosts.toml'),'credentials':str(self.root/'credentials.toml'),
                      'local_address':'192.0.2.1:8444','external_address':'vpn.example.org:8444','dns_upstreams':[]}
        atomic_write(self.root/'vpn.toml',b'credentials_file="credentials.toml"\nlisten_address="[::]:8444"\n')
        atomic_write(self.root/'unit',b'unit');atomic_write(self.root/'hosts.toml',b'host="vpn.example.org"')
        atomic_write(self.root/'credentials.toml',tc.render([{'username':'old','password':'PRIVATE-password','max_http2_conns':3}]))
        atomic_write(self.root/'endpoints.json',tc.encode({'main':self.binding}))
        self.outgoing={'unit':'out.service','unit_file':str(self.root/'out.service'),'config':str(self.root/'out.toml'),
                       'binary':str(self.root/'out'),'user':'tunnel','uid':1,'socks_address':'127.0.0.1:1080','dependents':['tt-endpoint.service'],
                       'dependent_files':[str(self.root/'vpn.toml'),str(self.root/'credentials.toml')]}
        atomic_write(self.root/'connections.json',tc.encode({'test':self.outgoing}))
        atomic_write(self.root/'test.installation.json',self.native.fingerprint(self.root,self.outgoing))
    def tearDown(self):self.tmp.cleanup()
    def call(self,action,**fields):return tc.control({'version':1,'action':'tt-clients-'+action,**fields},root=self.root,native=self.native,network=None)
    def view(self):return self.call('status')['servers'][0]
    def values(self,name='new',password=''):return dict(username=name,password=password,max_http2_conns='',max_http3_conns='')
    def save(self,**fields):return self.call('save',endpoint='main',revision=self.view()['revision'],id='',values=self.values(),**fields)
    def test_add_export_and_revoke_keep_existing_account_and_fingerprint(self):
        before=tc.parse((self.root/'credentials.toml').read_text())[0];view=self.view();self.assertNotIn('PRIVATE-password',json.dumps(view))
        self.save();clients=tc.parse((self.root/'credentials.toml').read_text());self.assertEqual(clients[0],before);self.assertGreater(len(clients[1]['password']),32)
        self.assertEqual((self.root/'test.installation.json').read_bytes(),self.native.fingerprint(self.root,self.outgoing))
        view=self.view();new=view['clients'][1];r=self.call('export',endpoint='main',revision=view['revision'],id=new['id'],mode='external',format='toml');self.assertIn(clients[1]['password'],r['content'])
        self.call('delete',endpoint='main',revision=view['revision'],id=new['id']);self.assertEqual(tc.parse((self.root/'credentials.toml').read_text()),[before]);self.assertEqual(self.native.restarts,2)
    def test_failed_restart_restores_files_and_receipt(self):
        before={p:p.read_bytes() for p in (self.root/'credentials.toml',self.root/'test.installation.json')};self.native.failure=True
        with self.assertRaises(ValueError):self.save()
        for p,raw in before.items():self.assertEqual(p.read_bytes(),raw)
        self.assertEqual(tc.operation(self.root)['status'],'rolled_back');self.assertEqual(self.native.restarts,2)
    def test_stale_form_duplicate_invalid_and_last_delete_never_restart(self):
        rev=self.view()['revision'];old=self.view()['clients'][0]['id']
        for values in [self.values('old'),self.values('bad:name'),{**self.values(),'max_http2_conns':'65536'}]:
            with self.assertRaises(ValueError):self.call('save',endpoint='main',revision=rev,id='',values=values)
        with self.assertRaises(ValueError):self.call('save',endpoint='main',revision='stale',id='',values=self.values())
        with self.assertRaises(ValueError):self.call('delete',endpoint='main',revision=rev,id=old)
        self.assertEqual(self.native.restarts,0)
    def test_empty_password_preserved_and_import_round_trip(self):
        view=self.view();old=view['clients'][0]['id'];self.call('save',endpoint='main',revision=view['revision'],id=old,values=self.values('renamed'))
        self.assertEqual(tc.parse((self.root/'credentials.toml').read_text())[0]['password'],'PRIVATE-password')
        raw='[[client]]\nusername="imported"\npassword="another-secret"\nmax_http3_conns=20\n'
        self.call('import',endpoint='main',revision=self.view()['revision'],text=raw)
        out=self.call('export',endpoint='main',revision=self.view()['revision'],id='',mode='',format='credentials')
        self.assertEqual(tc.parse(out['content']),tc.parse(raw))
    def test_settings_change_export_revision_without_restarting(self):
        rev=self.view()['revision'];self.call('settings',endpoint='main',revision=rev,values={'local_address':'10.0.0.1:8444','external_address':'new.example.org:443','dns_upstreams':['https://dns.example.org/dns-query']})
        self.assertNotEqual(rev,self.view()['revision']);self.assertEqual(self.native.restarts,0)
    def test_interrupted_mutation_rollback_and_external_conflict(self):
        before=(self.root/'credentials.toml').read_bytes();original=self.native.export
        def crash(*args):raise KeyboardInterrupt()
        self.native.export=crash
        with self.assertRaises(KeyboardInterrupt):self.save()
        self.assertEqual(tc.operation(self.root)['status'],'pending')
        with self.assertRaises(ValueError):tc.ensure_idle(self.root)
        self.native.export=original;job=tc.operation(self.root)
        tc.restore(self.root,job['id'],self.native);self.assertEqual(before,(self.root/'credentials.toml').read_bytes())
        self.native.export=crash
        with self.assertRaises(KeyboardInterrupt):self.save()
        job=tc.operation(self.root);atomic_write(self.root/'credentials.toml',tc.render([{'username':'external','password':'outside'}]))
        with self.assertRaises(ValueError):tc.restore(self.root,job['id'],self.native)
        self.assertEqual(tc.operation(self.root)['status'],'recovery_required');self.assertIn('external',(self.root/'credentials.toml').read_text())
    def test_native_cli_hint_is_not_part_of_exported_uri(self):
        from trusttunnel_link import export
        from trusttunnel_profile import DEFAULT
        uri=export({**DEFAULT,'hostname':'vpn.test','addresses':['vpn.test:443'],'username':'a','password':'b'},'deeplink').strip()
        native=tc.Native();native.run=lambda *args,**kwargs:(uri+'\n\nTo connect: see the application help.\n').encode()
        self.assertEqual(native.export(self.binding,'a','local','deeplink'),uri+'\n')

    def test_future_fields_symlink_and_secret_control_chars_rejected(self):
        for raw in ['[[client]]\nusername="a"\npassword="b"\nfuture=true','client=[]','[[client]]\nusername="a"\npassword="b\\n"']:
            with self.assertRaises(ValueError):tc.parse(raw)
        (self.root/'credentials.toml').rename(self.root/'private');(self.root/'credentials.toml').symlink_to(self.root/'private')
        with self.assertRaises((ValueError,OSError)):self.view()


if __name__=='__main__':unittest.main()
