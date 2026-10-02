import unittest,base64,copy
from amnezia_profile import parse,render,public_view,update
from test_wg_clients import CLIENT
KEY=base64.b64encode(bytes(range(32))).decode()
PROFILE=CLIENT.replace('[Interface]','[Interface]\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 16\nS2 = 32\nS3 = 16\nS4 = 16\nH1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800\nI1 = <r 32>\nHeaderProtectionKey = '+KEY+'\nContentPaddingAddition = 0-8\nRekeyAfterTime = 90-120')
PROFILE=PROFILE.replace('[Peer]','[Peer]\nAdvancedSecurity = on').replace('PersistentKeepalive = 25','PersistentKeepalive = 20-30')
PROFILE=PROFILE.replace('RekeyAfterTime = 90-120','RekeyAfterTime = 90-120\nRandomTrailers = on\nDisableCookies = off\nRekeyTimeout = 4-6\nRejectAfterTime = 180\nKeepaliveTimeout = 10\nMaxHandshakeAttempts = 18-20')
class Profiles(unittest.TestCase):
    def test_native_roundtrip_all_awg_fields_and_dns(self):
        model=parse(PROFILE);self.assertEqual(parse(render(model)),model)
        self.assertEqual(model['interface']['DNS'],['10.77.0.1'])
        with self.assertRaises(ValueError):render(model,runtime=True)
        model['peers'][0].pop('AdvancedSecurity')
        self.assertNotIn('DNS =',render(model,runtime=True))
        self.assertEqual(parse(render(model,runtime=True))['interface']['H1'],'100-200')
    def test_public_form_hides_both_private_keys(self):
        model=parse(PROFILE);view=public_view(model)
        self.assertNotIn('PrivateKey',view['interface']);self.assertNotIn('HeaderProtectionKey',view['interface'])
        self.assertTrue(view['interface']['header_protection_key_present'])
        self.assertEqual(update(model,view),model)
        view['interface']['clear_header_protection_key']=True
        self.assertNotIn('HeaderProtectionKey',update(model,view)['interface'])
    def test_bad_ranges_dns_and_unknown_hooks_refused(self):
        for old,new in [('Jmin = 40','Jmin = 80'),('H1 = 100-200','H1 = 200-100'),('S1 = 16','S1 = 65536'),('DNS = 10.77.0.1','DNS = $(command)'),('I1 = <r 32>','PostUp = command')]:
            with self.subTest(new=new),self.assertRaises(ValueError):parse(PROFILE.replace(old,new))
    def test_wireguard_does_not_accept_awg_as_plain_wg(self):
        from wireguard_profile import parse as wg_parse
        with self.assertRaises(ValueError):wg_parse(PROFILE)
