import copy,json,os,tempfile,unittest
from pathlib import Path
from openconnect_control import control
from openconnect_profile import SECRETS

class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.unit=self.root/'vpn.service';self.password=self.root/'pass';self.script=self.root/'routes.sh'
        self.binding={'unit':'test-vpn.service','unit_file':str(self.unit),'password_file':str(self.password),'interface':'test0','script':str(self.script),'binary':'/usr/sbin/openconnect'}
        self.unit.write_text('[Service]\nStandardInput=file:'+str(self.password)+'\nExecStart=/usr/sbin/openconnect --protocol=anyconnect --user=worker --passwd-on-stdin --non-inter --interface=test0 --script='+str(self.script)+' https://vpn.test/?group=work\n')
        self.password.write_text('PRIVATE-password\n');self.password.chmod(0o600);self.script.write_text('#!/bin/sh\nexit 0\n')
        p=self.root/'connections.json';p.write_text(json.dumps({'work':self.binding}));p.chmod(0o600)
        self.baseline=[p.read_bytes() for p in (self.unit,self.password,self.script)]
    def tearDown(self):
        self.assertEqual(self.baseline,[p.read_bytes() for p in (self.unit,self.password,self.script)])
        self.tmp.cleanup()
    def call(self,action,**fields):
        return control({'version':1,'action':'openconnect-'+action,'connection':'work',**fields},root=self.root,observe_state=lambda b:{'active':'active','state':'running','boot':'enabled'})
    def revisions(self,view):return {k:view[k] for k in ('file_revision','draft_revision')}
    def test_secret_redaction_status_and_draft(self):
        view=self.call('status');self.assertNotIn('PRIVATE-password',json.dumps(view));self.assertFalse(view['has_draft'])
        result=self.call('import',**self.revisions(view),format='openconnect',text='server=https://other.test/?group=two\nmtu=1320')
        self.assertTrue(result['has_draft']);self.assertNotIn('PRIVATE-password',json.dumps(result))
        self.assertEqual((self.root/'work.draft.json').stat().st_mode&0o777,0o600)
        checked=self.call('check',**self.revisions(result));self.assertTrue(checked['check']['parameters']);self.assertFalse(checked['check']['authentication_tested'])
    def test_stale_revision_cannot_overwrite_draft(self):
        initial=self.call('status');self.call('import',**self.revisions(initial),format='openconnect',text='user=one')
        with self.assertRaises(ValueError):self.call('import',**self.revisions(initial),format='openconnect',text='user=two')
    def test_invalid_import_writes_nothing(self):
        view=self.call('status')
        with self.assertRaises(ValueError):self.call('import',**self.revisions(view),format='openconnect',text='script=/tmp/run')
        self.assertFalse((self.root/'work.draft.json').exists())
    def test_unknown_or_injected_id_is_rejected(self):
        for name in ('../x','other'):
            with self.assertRaises(ValueError):control({'version':1,'action':'openconnect-status','connection':name},root=self.root)
    def test_discard_and_external_edit_conflict(self):
        view=self.call('status');view=self.call('import',**self.revisions(view),format='openconnect',text='user=one')
        old=self.script.read_bytes()
        try:
            self.script.write_text('#!/bin/sh\nexit 1\n');changed=self.call('status');self.assertTrue(changed['conflict'])
            with self.assertRaises(ValueError):self.call('check',**self.revisions(changed))
            discarded=self.call('discard',**self.revisions(changed));self.assertFalse(discarded['has_draft'])
        finally:self.script.write_bytes(old)
    def test_symbolic_link_password_is_rejected(self):
        old=self.password.read_bytes();replacement=self.root/'other';replacement.write_bytes(old);replacement.chmod(0o600)
        self.password.unlink();self.password.symlink_to(replacement)
        try:
            view=self.call('status');self.assertIsNone(view['model']);self.assertIn('error',view)
        finally:self.password.unlink();self.password.write_bytes(old);self.password.chmod(0o600)

if __name__=='__main__':unittest.main()
