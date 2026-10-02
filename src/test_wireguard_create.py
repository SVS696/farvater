import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wireguard_create import create
from wireguard_control import control
from wireguard_profile import parse
from test_wireguard_profile import PRIVATE, PUBLIC, PSK


def inactive(names):
    return {n:{'service':'inactive','substate':'dead','boot':'disabled','interface':False} for n in names}


class CreationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.profiles=self.root/'profiles';self.profiles.mkdir(mode=0o700)
        self.drafts=self.root/'drafts';self.drafts.mkdir(mode=0o700)
        self.values={'interface':{'Address':['10.50.0.2/32'],'Table':'off'},'peers':[]}
    def tearDown(self):self.temp.cleanup()
    def create(self,**kwargs):
        return create('wg-new',self.values,self.profiles,self.drafts,kwargs.pop('observe',inactive),generate=lambda:PRIVATE,derive=lambda private:PUBLIC,**kwargs)
    def test_generated_key_stays_private_and_profile_stays_inactive(self):
        with patch('wireguard_runtime.command') as command:
            result=self.create()
        command.assert_not_called()
        path=self.profiles/'wg-new.conf';self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertEqual(parse(path.read_text())['interface']['PrivateKey'],PRIVATE)
        self.assertFalse(result['runtime_changed']);self.assertFalse(result['enabled'])
        self.assertEqual(result['public_key'],PUBLIC);self.assertNotIn(PRIVATE,json.dumps(result))
        self.assertEqual(list(self.profiles.glob('.okopy-create-*')),[])
    def test_supplied_key_and_peer_psk_preserved_without_generation_or_echo(self):
        self.values['interface']['PrivateKey']=PRIVATE
        self.values['peers']=[{'PublicKey':PUBLIC,'AllowedIPs':['10.50.0.1/32'],'PresharedKey':PSK}]
        from unittest.mock import Mock
        generate=Mock(side_effect=AssertionError('Existing key must be reused'))
        result=create('wg-new',self.values,self.profiles,self.drafts,inactive,generate=generate,derive=lambda private:PUBLIC)
        generate.assert_not_called()
        self.assertEqual(parse((self.profiles/'wg-new.conf').read_text())['peers'][0]['PresharedKey'],PSK)
        for secret in (PRIVATE,PSK):self.assertNotIn(secret,json.dumps(result))
    def test_existing_file_symlink_or_orphan_draft_never_overwritten(self):
        path=self.profiles/'wg-new.conf';path.write_text('existing')
        with self.assertRaises(ValueError):self.create()
        self.assertEqual(path.read_text(),'existing');path.unlink()
        path.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError):self.create()
        self.assertTrue(path.is_symlink());path.unlink()
        (self.drafts/'wg-new.json').write_text('orphan')
        with self.assertRaises(ValueError):self.create()
        self.assertFalse(path.exists())
    def test_active_enabled_or_unknown_runtime_blocks_before_key_generation(self):
        for change in [{'service':'active'},{'boot':'enabled'},{'interface':True},{'interface':None},{'boot':'unknown'}]:
            with self.subTest(change=change):
                observation=inactive(['wg-new']);observation['wg-new'].update(change)
                with self.assertRaises(ValueError):self.create(observe=lambda names:observation)
                self.assertFalse((self.profiles/'wg-new.conf').exists())
    def test_concurrent_external_file_wins_atomic_publication(self):
        link=os.link
        def race(source,destination,**kwargs):
            destination.write_text('external');return link(source,destination,**kwargs)
        with patch('wireguard_create.os.link',side_effect=race),self.assertRaisesRegex(ValueError,'во время'):
            self.create()
        self.assertEqual((self.profiles/'wg-new.conf').read_text(),'external')
        self.assertEqual(list(self.profiles.glob('.okopy-create-*')),[])
    def test_traversal_and_commands_in_model_never_create_file(self):
        with self.assertRaises(ValueError):create('../bad',self.values,self.profiles,self.drafts,inactive)
        self.values['interface']['PostUp']='touch /tmp/forbidden'
        with self.assertRaises(ValueError):self.create()
        self.assertEqual(list(self.profiles.iterdir()),[])
    def test_dispatch_checks_exact_fields_and_pending_transaction(self):
        request={'version':1,'action':'wireguard-create','profile':'wg-new','values':self.values}
        with patch('wireguard_create.create',return_value={'created':True}) as generate:
            self.assertTrue(control(request,profiles=self.profiles,drafts=self.drafts,observe=inactive)['created'])
            generate.assert_called_once()
        transaction=self.drafts/'transaction.json'
        transaction.write_text(json.dumps({'id':'a'*32,'profile':'wg0','status':'pending'}));transaction.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'завершите'):control(request,profiles=self.profiles,drafts=self.drafts,observe=inactive)
        transaction.unlink()
        with self.assertRaises(ValueError):control({**request,'command':'id'},profiles=self.profiles,drafts=self.drafts,observe=inactive)


if __name__=='__main__':unittest.main()
