import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import amnezia_control as control
import amnezia_profile as codec
from test_amnezia_profile import PROFILE,KEY


def observe(names):
    return {n:dict(service='inactive',substate='dead',boot='disabled',interface=False) for n in names}


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.profiles=self.root/'profiles';self.profiles.mkdir(mode=0o700)
        self.drafts=self.root/'drafts';self.drafts.mkdir(mode=0o700)
        for name,value in [('amnezia_control.occupied_tables',{30000,30001}),('wireguard_create.public_key',KEY)]:
            p=patch(name,return_value=value);p.start();self.addCleanup(p.stop)
        self.native=PROFILE.replace('AdvancedSecurity = on\n','')

    def call(self,action,profile=None,**kwargs):
        return control.control(dict(version=1,action='amnezia-'+action,profile=profile,**kwargs),
                               profiles=self.profiles,drafts=self.drafts,observe=observe)

    def create(self):
        # create()'s default derive function was bound at definition time.
        with patch('wireguard_create.command',return_value=(0,(KEY+'\n').encode())):
            return self.call('create',values={'text':self.native})

    def test_native_import_creates_inactive_profile_with_allocated_routes(self):
        result=self.create();name=result['name']
        self.assertTrue(name.startswith('awg'));self.assertFalse(result['runtime_changed'])
        model=codec.parse((self.profiles/(name+'.conf')).read_text())
        self.assertEqual(model['interface']['Table'],'30002')
        original=codec.parse(self.native);original['interface']['Table']='30002'
        self.assertEqual(model,original)
        self.assertEqual((self.profiles/(name+'.conf')).stat().st_mode&0o777,0o600)

    def test_public_view_masked_save_preserves_keys_and_stale_save_rejected(self):
        name=self.create()['name'];view=self.call('status',name)
        self.assertNotIn('PrivateKey',view['model']['interface']);self.assertNotIn('HeaderProtectionKey',view['model']['interface'])
        versions={k:view[k] for k in ('file_revision','draft_revision')}
        self.call('save',name,values=view['model'],**versions)
        with self.assertRaisesRegex(ValueError,'изменился'):self.call('save',name,values=view['model'],**versions)
        draft=json.loads((self.drafts/(name+'.json')).read_text())
        self.assertEqual(codec.parse(draft['profile']),codec.parse((self.profiles/(name+'.conf')).read_text()))

    def test_replace_import_preserves_allocated_table_and_exports_all_fields(self):
        name=self.create()['name'];view=self.call('status',name)
        native=self.native.replace('[Interface]','[Interface]\nTable = 1234')
        self.call('import',name,text=native,**{k:view[k] for k in ('file_revision','draft_revision')})
        view=self.call('status',name)
        exported=self.call('export',name,source='draft',**{k:view[k] for k in ('file_revision','draft_revision')})
        self.assertNotIn('Table',codec.parse(exported['content'])['interface'])
        self.assertEqual(view['model']['interface']['Table'],'30002')
        self.assertIn('HeaderProtectionKey = '+KEY,exported['content'])
        self.assertEqual(codec.parse(exported['content'])['interface']['DNS'],['10.77.0.1'])

    def test_hooks_and_explicit_name_rejected_without_files(self):
        for profile,text in [('manual',self.native),(None,self.native.replace('[Interface]','[Interface]\nPostUp = command'))]:
            with self.subTest(profile=profile),self.assertRaises(ValueError):self.call('create',profile,values={'text':text})
        self.assertFalse(list(self.profiles.iterdir()))


if __name__=='__main__':unittest.main()
