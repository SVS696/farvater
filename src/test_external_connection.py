import json
import unittest
from test_web import WebTests
from tunnel_form import external_connection


class ExistingVpnWebTests(unittest.TestCase):
    setUp=WebTests.setUp
    tearDown=WebTests.tearDown
    login=WebTests.login
    revision=WebTests.revision

    def install_connection(self,protocol='OpenConnect',kind='direct'):
        self.policy['exits']['work']={'name':'Work VPN','scope':'work','protocol':protocol,
            'native':{'type':kind,'tag':'work','bind_interface':'vpn0'}}
        (self.path/'policy.json').write_text(json.dumps(self.policy))

    def test_existing_vpn_does_not_offer_unrelated_native_settings(self):
        self.login()
        for protocol,kind in [('OpenConnect','direct'),('WireGuard','direct'),('TrustTunnel','socks')]:
            with self.subTest(protocol=protocol):
                self.install_connection(protocol,kind)
                page=self.client.get('/tunnels/work/edit')
                self.assertEqual(page.status_code,200)
                self.assertIn('<strong>'+protocol+'</strong>',page.text)
                if protocol=='WireGuard':
                    self.assertIn('href="/devices"',page.text)
                    self.assertNotIn('Редактор параметров недоступен',page.text)
                else:
                    self.assertIn('Редактор параметров недоступен',page.text)
                self.assertNotIn('name="bind_interface"',page.text)
                self.assertNotIn('action="/tunnels/save"',page.text)

    def test_old_page_cannot_replace_existing_vpn_with_native_outbound(self):
        self.install_connection();csrf=self.login()
        before=(self.path/'policy.json').read_bytes()
        response=self.client.post('/tunnels/save',data={'csrf':csrf,'revision':self.revision(),
            'id':'work','name':'Changed','scope':'public','type':'direct'})
        self.assertEqual(response.status_code,409)
        self.assertEqual((self.path/'policy.json').read_bytes(),before)

    def test_native_openconnect_and_ordinary_direct_remain_editable(self):
        self.assertFalse(external_connection({'protocol':'OpenConnect','native':{'type':'openconnect'}}))
        self.assertFalse(external_connection({'protocol':'direct','native':{'type':'direct'}}))
        self.login()
        page=self.client.get('/tunnels/direct/edit')
        self.assertEqual(page.status_code,200)
        self.assertIn('action="/tunnels/save"',page.text)


if __name__=='__main__':unittest.main()
