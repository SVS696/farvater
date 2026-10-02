import copy
import unittest
from tunnel_form import parse_outbound


class TunnelFormTests(unittest.TestCase):
    def setUp(self):
        self.policy={'exits':{'other':{'scope':'public'}}}
        self.form={'name':'Proxy','scope':'public','type':'socks','server':'127.0.0.1','server_port':'1080','version':'5'}

    def test_empty_password_preserves_secret_and_unedited_fields(self):
        previous={'protocol':'TrustTunnel','native':{'type':'socks','password':'stored-secret','tcp_fast_open':True}}
        before=copy.deepcopy(previous)
        result=parse_outbound(self.form,previous,'proxy',self.policy)
        self.assertEqual(result['native']['password'],'stored-secret')
        self.assertTrue(result['native']['tcp_fast_open'])
        self.assertEqual(result['protocol'],'TrustTunnel');self.assertEqual(previous,before)

    def test_type_change_clears_old_secrets_and_advanced_fields(self):
        previous={'protocol':'VLESS','native':{'type':'vless','uuid':'old-secret','tls':{'reality':{'public_key':'key'}}}}
        result=parse_outbound(self.form,previous,'proxy',self.policy)
        self.assertNotIn('uuid',result['native']);self.assertNotIn('tls',result['native'])
        self.assertEqual(result['protocol'],'socks')

    def test_password_clear_and_replace_are_explicit(self):
        previous={'native':{'type':'socks','password':'old'}}
        result=parse_outbound({**self.form,'clear_password':'on'},previous,'proxy',self.policy)
        self.assertNotIn('password',result['native'])
        result=parse_outbound({**self.form,'password':'new'},previous,'proxy',self.policy)
        self.assertEqual(result['native']['password'],'new')

    def test_vless_preserves_uuid_reality_and_transport(self):
        native={'type':'vless','uuid':'ab61cbe2-a43a-4c2f-9357-a4e5881aa001','tls':{'enabled':True,'reality':{'enabled':True,'public_key':'key'}},'transport':{'type':'ws','path':'/vpn'}}
        result=parse_outbound({**self.form,'type':'vless','tls_enabled':'on'},{'native':native},'proxy',self.policy)
        self.assertEqual(result['native']['uuid'],native['uuid'])
        self.assertEqual(result['native']['tls'],native['tls'])
        self.assertEqual(result['native']['transport'],native['transport'])

    def test_invalid_port_server_uuid_and_protected_direct_rejected(self):
        for patch in [{'server_port':'0'},{'server':'https://bad'},{'type':'vless','uuid':'bad'}, {'type':'direct','scope':'work'}]:
            with self.subTest(patch=patch),self.assertRaises(ValueError):
                parse_outbound({**self.form,**patch},{},'proxy',self.policy)

    def test_selector_requires_known_unique_members_and_member_default(self):
        base={**self.form,'type':'selector','outbounds':'other','default':'other'}
        self.assertEqual(parse_outbound(base,{},'proxy',self.policy)['native']['outbounds'],['other'])
        for patch in [{'outbounds':'other\nother'},{'outbounds':'proxy'},{'default':'missing'}]:
            with self.subTest(patch=patch),self.assertRaises(ValueError):
                parse_outbound({**base,**patch},{},'proxy',self.policy)


if __name__=='__main__':unittest.main()
