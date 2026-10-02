import base64,json,unittest
from trusttunnel_profile import DEFAULT, ENDPOINT, import_config, validate
from trusttunnel_link import export, decode
from trusttunnel_deeplink_encode import encode_config,tlv

class LinkTests(unittest.TestCase):
    def setUp(self):
        self.model={**DEFAULT,'hostname':'vpn.example.org','addresses':['192.0.2.1:443','[2001:db8::1]:8444'],'username':'a"b','password':'secret\\"quoted','client_random':'aabb/ffff','custom_sni':'alt.example.org','has_ipv6':False,'anti_dpi':True,'upstream_protocol':'http3','dns_upstreams':['tls://1.1.1.1','https://dns.example.org/dns-query']}
    def test_both_native_formats_round_trip_endpoint_fields(self):
        for kind in ('endpoint','deeplink'):
            raw=export(self.model,kind);result=import_config(raw,DEFAULT,kind,{})
            self.assertEqual({k:result[k] for k in ENDPOINT},{k:self.model[k] for k in ENDPOINT})
    def test_native_name_is_validated_and_prefix_alias_is_imported(self):
        raw=export(self.model,'endpoint')+'name="Display metadata"\n';self.assertEqual(import_config(raw,DEFAULT,'endpoint',{})['client_random'],'aabb/ffff')
        with self.assertRaises(ValueError):import_config(raw+'client_random="bad"',DEFAULT,'endpoint',{})
        with self.assertRaises(ValueError):import_config(raw.replace('name="Display metadata"','name=123'),DEFAULT,'endpoint',{})
    def test_complete_link_clears_old_optional_parameters(self):
        new={**DEFAULT,'hostname':'vpn.test','addresses':['vpn.test:443'],'username':'new','password':'new'}
        result=import_config(export(new,'deeplink'),self.model,'deeplink',{})
        self.assertEqual(result,new)
    def test_unknown_duplicate_truncated_and_invalid_flags_do_not_silently_import(self):
        base=encode_config({'hostname':'vpn.test','addresses':['vpn.test:443'],'username':'a','password':'b'})
        for payload in [base+tlv(99,b'unknown'),base+tlv(1,b'other.test'),base+tlv(4,b''),base+tlv(4,b'\x02'),base+tlv(9,b'\x03'),base[:-1],tlv(0,b'\x02')+base[3:]]:
            uri='tt://?'+base64.urlsafe_b64encode(payload).decode()
            with self.subTest(payload=payload.hex()),self.assertRaises(ValueError):decode(uri)
        with self.assertRaises(ValueError):decode('tt://?%%%')
        with self.assertRaises(ValueError):decode('tt://?'+('a'*131072))

if __name__=='__main__':unittest.main()
