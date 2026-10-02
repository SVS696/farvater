import base64
import copy
import json
import unittest

from wireguard_profile import parse,public_view,render,update

PRIVATE=base64.b64encode(bytes(range(1,33))).decode()
PUBLIC=base64.b64encode(bytes(range(33,65))).decode()
PSK=base64.b64encode(bytes(range(65,97))).decode()
BASE=f'''# Existing profile
[Interface]
PrivateKey = {PRIVATE}
Address = 10.9.0.1/24
Address = fd90::1/64
ListenPort = 51820

[Peer]
PublicKey = {PUBLIC}
PresharedKey = {PSK}
AllowedIPs = 10.9.0.2/32, fd90::2/128
Endpoint = [2001:db8::1]:51821
PersistentKeepalive = 25
'''


class WireGuardProfileTests(unittest.TestCase):
    def test_duplicate_address_lines_and_secrets_survive_roundtrip(self):
        original=parse(BASE)
        self.assertEqual(original['interface']['Address'],['10.9.0.1/24','fd90::1/64'])
        self.assertEqual(parse(render(original)),original)
        self.assertEqual(original['interface']['PrivateKey'],PRIVATE)
        self.assertEqual(original['peers'][0]['PresharedKey'],PSK)

    def test_public_view_does_not_disclose_or_modify_secrets(self):
        model=parse(BASE);before=copy.deepcopy(model);view=public_view(model)
        encoded=json.dumps(view)
        self.assertNotIn(PRIVATE,encoded);self.assertNotIn(PSK,encoded)
        self.assertIn(PUBLIC,encoded)
        self.assertTrue(view['interface']['private_key_present'])
        self.assertTrue(view['peers'][0]['preshared_key_present'])
        self.assertEqual(before,model)

    def test_all_eight_hub_peers_are_preserved(self):
        model=parse(BASE);model['peers']=[]
        for number in range(8):
            model['peers'].append({'PublicKey':base64.b64encode(bytes([100+number])*32).decode(),
                'AllowedIPs':['10.9.0.'+str(number+2)+'/32']})
        self.assertEqual(parse(render(model)),model)

    def test_hooks_dns_and_saveconfig_are_not_silently_removed(self):
        for field in ('DNS = 1.1.1.1','PostUp = touch /tmp/should-not-execute','PreDown = id',
                      'SaveConfig = true','Unknown = secret-value'):
            raw=BASE.replace('[Peer]',field+'\n[Peer]',1)
            with self.subTest(field=field),self.assertRaises(ValueError) as result:parse(raw)
            self.assertNotIn('secret-value',str(result.exception))

    def test_scalar_duplicates_and_section_reordering_are_rejected(self):
        for raw in (BASE.replace('[Peer]','[Interface]\n[Peer]'),
                    BASE.replace('ListenPort = 51820','ListenPort = 51820\nListenPort = 51821'),
                    '[Peer]\nPublicKey = '+PUBLIC,
                    BASE+'\n[Peer]\nPublicKey = '+PUBLIC+'\nAllowedIPs = 10.9.0.3/32'):
            with self.subTest(raw=raw[:20]),self.assertRaises(ValueError):parse(raw)

    def test_invalid_keys_never_appear_in_error_text(self):
        invalid='bad-private-key-never-echo-this'
        with self.assertRaises(ValueError) as result:parse(BASE.replace(PRIVATE,invalid))
        self.assertNotIn(invalid,str(result.exception))
        zero=base64.b64encode(bytes(32)).decode()
        with self.assertRaises(ValueError):parse(BASE.replace(PUBLIC,zero))

    def test_endpoint_and_mtu_validation(self):
        normalized=parse(BASE.replace('[2001:db8::1]:51821','VPN.Example.COM:51821'))
        self.assertEqual(normalized['peers'][0]['Endpoint'],'vpn.example.com:51821')
        for value in ('2001:db8::1:51821','[fe80::1%eth0]:51821','example.com:0','user:pass@host:51821'):
            with self.subTest(value=value),self.assertRaises(ValueError):parse(BASE.replace('[2001:db8::1]:51821',value))
        with self.assertRaises(ValueError):parse(BASE.replace('ListenPort = 51820','MTU = 1000'))

    def test_render_rejects_injection_instead_of_adding_native_directives(self):
        for value in ('vpn.example.com:51821\nPostUp = id','vpn.example.com:51821#comment'):
            model=parse(BASE);model['peers'][0]['Endpoint']=value
            with self.subTest(value=value),self.assertRaises(ValueError):render(model)

    def test_current_de6_style_is_supported(self):
        model=parse(BASE);model['interface']={'PrivateKey':PRIVATE,'Address':['2a06:fcc0:a:6969::2/64'],'MTU':1420,'Table':'246'}
        model['peers'][0]['AllowedIPs']=['::/0']
        self.assertEqual(parse(render(model)),model)

    def test_public_form_preserves_keys_when_editing_endpoint(self):
        model=parse(BASE);before=copy.deepcopy(model);form=public_view(model)
        form['interface']['PrivateKey']='';form['peers'][0]['PresharedKey']=''
        form['peers'][0]['Endpoint']='vpn.example.com:444'
        result=update(model,form)
        self.assertEqual(result['interface']['PrivateKey'],PRIVATE)
        self.assertEqual(result['peers'][0]['PresharedKey'],PSK)
        self.assertEqual(result['peers'][0]['Endpoint'],'vpn.example.com:444')
        self.assertEqual(model,before)

    def test_peer_identity_controls_psk_preservation_and_explicit_clear(self):
        model=parse(BASE);form=public_view(model)
        form['peers'][0]['clear_preshared_key']=True
        self.assertNotIn('PresharedKey',update(model,form)['peers'][0])
        form=public_view(model);form['peers'][0]['PublicKey']=base64.b64encode(bytes([120])*32).decode()
        self.assertNotIn('PresharedKey',update(model,form)['peers'][0])
        form=public_view(model);form['peers'][0].update(clear_preshared_key=True,PresharedKey=PSK)
        with self.assertRaises(ValueError):update(model,form)

    def test_removing_a_peer_and_replacing_private_key_are_explicit_draft_changes(self):
        model=parse(BASE);form=public_view(model);form['peers']=[]
        replacement=base64.b64encode(bytes([121])*32).decode();form['interface']['PrivateKey']=replacement
        result=update(model,form)
        self.assertEqual(result['peers'],[]);self.assertEqual(result['interface']['PrivateKey'],replacement)
        self.assertEqual(len(model['peers']),1)

    def test_unknown_form_fields_are_rejected(self):
        model=parse(BASE);form=public_view(model);form['interface']['PostUp']='arbitrary command'
        with self.assertRaises(ValueError):update(model,form)
        for field,target in [('PrivateKey','interface'),('PresharedKey','peer'),('PublicKey','peer')]:
            form=public_view(model)
            (form['interface'] if target=='interface' else form['peers'][0])[field]=0
            with self.subTest(field=field),self.assertRaises(ValueError):update(model,form)


if __name__=='__main__':unittest.main()
