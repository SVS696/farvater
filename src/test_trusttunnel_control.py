import json,os,tempfile,unittest
from pathlib import Path
from safe_apply import atomic_write
from trusttunnel_control import control
from trusttunnel_profile import DEFAULT,render

class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.binding={'unit':'tt.service','unit_file':str(self.root/'tt.service'),'config':str(self.root/'client.toml'),'binary':'/usr/bin/false','user':'tester','uid':max(1,os.geteuid()),'socks_address':'127.0.0.1:1080','dependents':['inbound.service']}
        self.model={**DEFAULT,'hostname':'vpn.test','addresses':['192.0.2.1:443'],'username':'user','password':'PRIVATE-password'}
        atomic_write(self.root/'connections.json',json.dumps({'vpn':self.binding}).encode())
        Path(self.binding['unit_file']).write_text('[Service]\nUser=tester\nExecStart=/usr/bin/false --config '+self.binding['config']+'\n')
        atomic_write(Path(self.binding['config']),render(self.model,self.binding).encode())
        self.baseline={k:Path(self.binding[k]).read_bytes() for k in ('config','unit_file')}
    def tearDown(self):
        self.assertEqual(self.baseline,{k:Path(self.binding[k]).read_bytes() for k in self.baseline});self.tmp.cleanup()
    def call(self,action,**fields):
        return control({'version':1,'action':'trusttunnel-'+action,'connection':'vpn',**fields},root=self.root,observe_state=lambda b:{'client':{'active':'active','boot':'enabled'},'dependents':{'inbound.service':{'active':'active','boot':'enabled'}}})
    def revisions(self,v):return {k:v[k] for k in ('file_revision','draft_revision')}
    def test_draft_import_check_discard_is_private_and_does_not_mutate_runtime(self):
        v=self.call('status');self.assertNotIn('PRIVATE-password',json.dumps(v));self.assertFalse(v['has_draft'])
        v=self.call('import',**self.revisions(v),format='endpoint',text='upstream_protocol="http3"');self.assertTrue(v['has_draft']);self.assertEqual(v['model']['upstream_protocol'],'http3')
        self.assertEqual((self.root/'vpn.draft.json').stat().st_mode&0o777,0o600)
        v=self.call('check',**self.revisions(v));self.assertFalse(v['check']['authentication_tested'])
        v=self.call('discard',**self.revisions(v));self.assertEqual(v['model']['upstream_protocol'],'http2');self.assertFalse(v['has_draft'])
    def test_stale_browser_and_invalid_import_cannot_overwrite_draft(self):
        v=self.call('status');self.call('import',**self.revisions(v),format='endpoint',text='upstream_protocol="http3"');before=(self.root/'vpn.draft.json').read_bytes()
        with self.assertRaises(ValueError):self.call('discard',**self.revisions(v))
        v=self.call('status')
        with self.assertRaises(ValueError):self.call('import',**self.revisions(v),format='endpoint',text='script="/tmp/run"')
        self.assertEqual(before,(self.root/'vpn.draft.json').read_bytes())
    def test_external_config_change_is_a_conflict_until_draft_discarded(self):
        v=self.call('status');self.call('import',**self.revisions(v),format='endpoint',text='upstream_protocol="http3"')
        p=Path(self.binding['config']);old=p.read_bytes()
        try:
            p.write_bytes(old+b'\n');v=self.call('status');self.assertTrue(v['conflict'])
            with self.assertRaises(ValueError):self.call('check',**self.revisions(v))
            self.assertFalse(self.call('discard',**self.revisions(v))['has_draft'])
        finally:p.write_bytes(old)
    def test_public_config_and_unknown_binding_are_rejected(self):
        p=Path(self.binding['config']);p.chmod(0o644)
        try:self.assertIn('error',self.call('status'))
        finally:p.chmod(0o600)
        with self.assertRaises(ValueError):control({'version':1,'action':'trusttunnel-status','connection':'missing'},root=self.root)

if __name__=='__main__':unittest.main()
