import json,unittest
from trusttunnel_profile import DEFAULT,SECRETS,FLAGS,validate,render,parse_client,import_config,update,public,values_from_form

class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.binding={'socks_address':'127.0.0.1:1080'}
        self.model={**DEFAULT,'hostname':'vpn.example.test','addresses':['192.0.2.10:443','[2001:db8::1]:443'],'username':'user','password':'PRIVATE-password','client_random':'aabb','dns_upstreams':['tls://1.1.1.1']}
    def test_native_toml_roundtrip_preserves_secrets_and_multiple_endpoints(self):
        self.assertEqual(parse_client(render(self.model,self.binding),self.binding),self.model)
        visible=public(self.model);self.assertNotIn('PRIVATE-password',json.dumps(visible));self.assertNotIn('aabb',json.dumps(visible));self.assertTrue(visible['saved_secrets']['password'])
    def test_native_strings_are_quoted_not_interpolated_as_toml(self):
        model={**self.model,'username':'user"=value','password':'secret"\\value'}
        self.assertEqual(parse_client(render(model,self.binding),self.binding),model)
    def test_unsafe_or_invalid_fields_are_rejected(self):
        bad=[{'hostname':'*.example.test'},{'addresses':['https://example.test/']},{'addresses':['user:pass@vpn.test:443']},{'addresses':['vpn.test:70000']},{'has_ipv6':1},{'upstream_protocol':'direct'},{'password':'bad\ncommand'},{'client_random':'abc'},{'certificate':'not PEM'},{'dns_upstreams':['tls://user:pass@dns.test']},{'dns_upstreams':['file:///etc/passwd']}]
        for change in bad:
            with self.subTest(fields=list(change)),self.assertRaises(ValueError):validate({**self.model,**change},ready=True)
    def test_unknown_native_keys_and_local_route_changes_are_rejected(self):
        raw=render(self.model,self.binding)
        for text in [raw+'\nscript="/tmp/run"\n',raw.replace('vpn_mode = "general"','vpn_mode = "selective"'),raw.replace('exclusions = []','exclusions = ["work.test"]'),raw.replace('127.0.0.1:1080','0.0.0.0:1080'),raw.replace('[listener.socks]','[listener.tun]')]:
            with self.assertRaises(ValueError):parse_client(text,self.binding)
    def test_endpoint_import_preserves_unmentioned_settings_and_rejects_unknown(self):
        result=import_config('hostname="next.test"\naddresses=["192.0.2.20:443"]',self.model,'endpoint',self.binding)
        self.assertEqual(result['hostname'],'next.test');self.assertEqual(result['password'],self.model['password']);self.assertEqual(result['dns_upstreams'],self.model['dns_upstreams'])
        with self.assertRaises(ValueError):import_config('password_file="/etc/passwd"',self.model,'endpoint',self.binding)
    def test_secret_replacement_is_explicit_and_blank_password_cannot_connect(self):
        values={**self.model,**{k:'' for k in SECRETS},**{k+'_action':'keep' for k in SECRETS}}
        self.assertEqual(update(self.model,values),self.model)
        with self.assertRaises(ValueError):update(self.model,{**values,'password':'new'})
        cleared=update(self.model,{**values,'password_action':'clear'});self.assertEqual(cleared['password'],'')
        with self.assertRaises(ValueError):validate(cleared,ready=True)
        new=update(self.model,{**values,'password_action':'replace','password':'new'});self.assertEqual(new['password'],'new')
    def test_form_types_and_dns_conflict(self):
        form={k:v for k,v in self.model.items() if k not in FLAGS};form.update(addresses='192.0.2.10:443\n[2001:db8::1]:443',dns_upstreams='tls://1.1.1.1',has_ipv6='on',post_quantum_group_enabled='on')
        form.update({**{k:'' for k in SECRETS},**{k+'_action':'keep' for k in SECRETS}})
        self.assertEqual(update(self.model,values_from_form(form)),self.model)
        with self.assertRaises(ValueError):parse_client('dns_upstreams=["9.9.9.9"]\n'+render(self.model,self.binding),self.binding)

if __name__=='__main__':unittest.main()
