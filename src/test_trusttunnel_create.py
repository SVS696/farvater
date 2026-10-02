import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from safe_apply import atomic_write
from trusttunnel_create import control,encode,imported,publish
from trusttunnel_profile import DEFAULT,render

class CreateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.units=self.root/'units';self.units.mkdir();self.calls=[]
        self.source={'unit':'existing.service','unit_file':str(self.units/'existing.service'),'config':str(self.root/'old.toml'),'binary':'/usr/bin/false','user':'tester','uid':max(1,os.geteuid()),'socks_address':'127.0.0.1:1080','dependents':[]}
        atomic_write(self.root/'connections.json',encode({'existing':self.source}))
        atomic_write(self.root/'creation-settings.json',encode({'template':'existing','port_range':[25180,25243]}))
        self.model={**DEFAULT,'hostname':'vpn.test','addresses':['192.0.2.1:443'],'username':'tester','password':'PRIVATE-create-password'}
        self.values={**self.model,'password_action':'replace','client_random_action':'keep'}
    def tearDown(self):self.tmp.cleanup()
    def command(self,args):self.calls.append(args);return 0,b''
    def call(self,action,**fields):
        return control({'version':1,'action':'trusttunnel-'+action,**fields},root=self.root,units=self.units,run=self.command,inspect=lambda b:{'client':{'active':'inactive','boot':'disabled'},'dependents':{}},fingerprint=lambda r,b:{'unit_sha256':'fixture','script_sha256':'fixture','companions':{}},inactive=lambda *a:None)
    def create(self,name='tt-abcdef123456',**override):
        args={'connection':name,'name':'My VPN','scope':'public','values':self.values,'text':'','format':'form'};args.update(override)
        return self.call('create',**args)
    def test_disabled_creation_and_catalog_hide_secrets(self):
        r=self.create();self.assertFalse(r['runtime_changed']);self.assertEqual(self.calls,[['systemctl','daemon-reload']])
        b=json.loads((self.root/'connections.json').read_text());self.assertEqual(b['existing'],self.source)
        self.assertEqual(b[r['id']]['dependents'],[]);self.assertNotEqual(b[r['id']]['socks_address'],self.source['socks_address'])
        self.assertEqual(json.loads((self.root/(r['id']+'.active.json')).read_text()),self.model)
        self.assertEqual((self.root/(r['id']+'.active.json')).stat().st_mode&0o777,0o600)
        self.assertNotIn('PRIVATE-create-password',json.dumps(self.call('catalog')))
        self.assertNotIn('PRIVATE-create-password',(self.root/'creations'/(r['id']+'.json')).read_text())
    def test_invalid_or_duplicate_does_not_replace(self):
        with self.assertRaises(ValueError):self.create(values={**self.values,'password':''})
        self.assertFalse((self.root/'creations').exists())
        self.create();before=(self.root/'connections.json').read_bytes()
        with self.assertRaises(ValueError):self.create()
        with self.assertRaises(ValueError):self.create(name='../escape')
        self.assertEqual(before,(self.root/'connections.json').read_bytes())
    def interrupted(self,suffix):
        def write(path,*args):
            if path.name.endswith(suffix):raise OSError('interrupted')
            return publish(path,*args)
        with patch('trusttunnel_create.publish',side_effect=write):
            with self.assertRaises(OSError):self.create()
    def test_interruption_is_resumable_without_reentering_password(self):
        self.interrupted('.installation.json')
        self.assertEqual(self.call('catalog')['connections'][0]['status'],'prepared')
        result=self.call('complete',connection='tt-abcdef123456');self.assertTrue(result['created'])
        self.assertEqual(self.call('catalog')['connections'][0]['status'],'complete')
        path=self.root/'tt-abcdef123456.active.json';changed={**self.model,'loglevel':'warn'};atomic_write(path,encode(changed))
        self.call('complete',connection='tt-abcdef123456');self.assertEqual(json.loads(path.read_text()),changed)
    def test_recovery_will_not_overwrite_external_file(self):
        self.interrupted('.active.json');path=self.root/'tt-abcdef123456.active.json';atomic_write(path,b'foreign')
        with self.assertRaises(ValueError):self.call('complete',connection='tt-abcdef123456')
        self.assertEqual(path.read_bytes(),b'foreign')
    def test_port_allocation_respects_registered_clients(self):
        a=self.create();b=self.create('tt-abcdef123457');self.assertNotEqual(a['outbound']['native']['server_port'],b['outbound']['native']['server_port']);self.assertEqual(len(self.calls),2)
    def test_native_import_preserves_model_reallocates_port(self):
        text=render(self.model,self.source);r=self.create(format='client',values=None,text=text)
        self.assertEqual(json.loads((self.root/(r['id']+'.active.json')).read_text()),self.model)
        self.assertNotEqual(r['outbound']['native']['server_port'],1080)
        for raw in [text.replace('127.0.0.1','0.0.0.0'),text.replace('exclusions = []','exclusions = ["example.com"]'),text+'\nunsupported=true']:
            with self.assertRaises(ValueError):imported(raw,'client',self.source)
    def test_pending_transaction_blocks_creation(self):
        with patch('trusttunnel_apply.state',return_value={'status':'pending'}):
            with self.assertRaises(ValueError):self.create()
        self.assertEqual(self.calls,[])

if __name__=='__main__':unittest.main()
