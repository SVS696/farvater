import copy
import unittest
from openconnect_profile import DEFAULT,validate,public,update,import_config,from_legacy_unit,values_from_form

class ProfileTests(unittest.TestCase):
    def model(self):
        return {**copy.deepcopy(DEFAULT),'server':'https://vpn.example.test/login?group=work','username':'worker','password':'SENSITIVE-ONE'}
    def test_query_is_preserved_and_secrets_are_not_returned(self):
        m=self.model();self.assertEqual(validate(m,ready=True),m)
        view=public(m);self.assertNotIn('password',view);self.assertNotIn('SENSITIVE-ONE',str(view));self.assertTrue(view['saved_secrets']['password'])
    def test_invalid_url_and_command_injection_are_rejected(self):
        for url in ('http://vpn.test','https://user:pass@vpn.test','https://vpn.test/#x','https://vpn.test/\n--script=/tmp/run','https://vpn.test:0/','https://vpn.test /x'):
            with self.subTest(url=url),self.assertRaises(ValueError):validate({**self.model(),'server':url})
    def test_secret_actions_are_explicit(self):
        original=self.model();values={**original,**{key+'_action':'keep' for key in ('password','cookie','private_key','key_password')}}
        for key in ('password','cookie','private_key','key_password'):values[key]=''
        self.assertEqual(update(original,values)['password'],'SENSITIVE-ONE')
        values['password']='SECOND'
        with self.assertRaises(ValueError):update(original,values)
        values['password_action']='replace';self.assertEqual(update(original,values)['password'],'SECOND')
        values.update(password='',password_action='clear');draft=update(original,values)
        self.assertEqual(draft['password'],'')
        with self.assertRaises(ValueError):validate(draft,ready=True)
    def test_import_does_not_execute_or_ignore_unknown_options(self):
        for content in ('script=/tmp/evil','config=/etc/shadow','user=first\nuser=second','--user=worker','cafile=/etc/pki/ca','no-dtls=false','mtu=-1','cookie=x\nunknown=x'):
            with self.subTest(content=content),self.assertRaises(ValueError):import_config(content,self.model(),'openconnect')
    def test_native_config_merges_values_and_keeps_unspecified_password(self):
        out=import_config('# Example\nserver=https://new.test/?x=1\nuser = updated\nmtu=1300\nno-dtls\nauthgroup=Work Users',self.model(),'openconnect')
        self.assertEqual(out['server'],'https://new.test/?x=1');self.assertEqual(out['username'],'updated');self.assertEqual(out['password'],'SENSITIVE-ONE')
        self.assertEqual(out['mtu'],1300);self.assertTrue(out['no_dtls']);self.assertEqual(out['authgroup'],'Work Users')
    def test_xml_address_and_group(self):
        doc='<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/"><ServerList><HostEntry><HostName>Work</HostName><HostAddress>vpn.test</HostAddress><UserGroup>work</UserGroup></HostEntry></ServerList></AnyConnectProfile>'
        out=import_config(doc,self.model(),'anyconnect');self.assertEqual(out['server'],'https://vpn.test');self.assertEqual(out['usergroup'],'work')
    def test_xml_unknown_security_options_and_entities_rejected(self):
        for text in ('<!DOCTYPE x><AnyConnectProfile/>','<AnyConnectProfile><ClientInitialization><AutomaticCertSelection>true</AutomaticCertSelection></ClientInitialization></AnyConnectProfile>','<AnyConnectProfile><ServerList/></AnyConnectProfile>'):
            with self.subTest(text=text),self.assertRaises(ValueError):import_config(text,self.model(),'anyconnect')
    def test_bounds_and_types(self):
        for key,value in [('mtu',True),('mtu',575),('reconnect_timeout',0),('no_dtls','yes'),('protocol','invented'),('os','other'),('no_system_trust',True),('private_key','not a key')]:
            with self.subTest(key=key),self.assertRaises(ValueError):validate({**self.model(),key:value})
    def test_legacy_adoption_is_strict(self):
        binding={'binary':'/usr/sbin/openconnect','interface':'vpn0','script':'/etc/openconnect/network.sh','password_file':'/etc/openconnect/pass'}
        unit='[Service]\nStandardInput=file:/etc/openconnect/pass\nExecStart=/usr/sbin/openconnect --protocol=anyconnect --user=worker --passwd-on-stdin --interface=vpn0 --script=/etc/openconnect/network.sh --non-inter --reconnect-timeout=86400 --no-dtls https://vpn.test/?group=work\n'
        out=from_legacy_unit(unit,'SENSITIVE-ONE\n',binding);self.assertEqual(out['password'],'SENSITIVE-ONE');self.assertEqual(out['reconnect_timeout'],86400)
        for changed in (unit.replace('vpn0','vpn1'),unit+'Environment=TEST=x\n',unit.replace('--no-dtls','--dump-http-traffic')):
            with self.assertRaises(ValueError):from_legacy_unit(changed,'secret',binding)
    def test_partial_web_form_cannot_erase_settings(self):
        with self.assertRaises(ValueError):values_from_form({'server':'https://vpn.test'})

if __name__=='__main__':unittest.main()
