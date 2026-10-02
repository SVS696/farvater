import io,json,copy,unittest,base64
from urllib.parse import quote
from vless_uri import parse,render
import test_web

UUID='b0dd64e4-0fbd-4038-9139-d1f32a68a0dc'
BASE='vless://'+UUID+'@vpn.example.org:443'
KEY=base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
CASES=[BASE+'#'+quote('Мой VPN'),BASE+'?security=tls&sni=edge.example.org&alpn=h2%2Chttp%2F1.1',
 BASE+'?security=reality&fp=chrome&pbk='+KEY+'&sid=abcd&flow=xtls-rprx-vision',
 BASE+'?type=ws&security=tls&host=edge.example.org&path=%2Fproxy%3Fmode%3D1',
 BASE+'?type=grpc&security=tls&serviceName=my-service&mode=gun',
 BASE+'?type=httpupgrade&security=tls&path=%2Fupgrade&host=edge.example.org',
 BASE+'?type=http&security=tls&host=a.example.org%2Cb.example.org&path=%2Fh2',
 'vless://'+UUID+'@[2001:db8::1]:8443?type=tcp&security=none#IPv6']

class Links(unittest.TestCase):
    def test_common_links_round_trip_and_use_typed_native_fields(self):
        for uri in CASES:
            with self.subTest(uri=uri):
                outbound=parse(uri);self.assertEqual(parse(render(outbound)),outbound)
        reality=parse(CASES[2])['native']
        self.assertEqual(reality['tls']['reality']['public_key'],KEY)
        self.assertEqual(reality['flow'],'xtls-rprx-vision')
        self.assertEqual(parse(CASES[1])['native']['tls']['utls']['fingerprint'],'chrome')
    def test_bad_or_unsupported_link_never_silently_drops_parameters(self):
        for suffix in ['?type=xhttp','?type=grpc&mode=multi','?security=reality&pbk='+KEY,
                       '?security=tls&fp=chrome&fp=firefox','?encryption=other','?path=%ZZ',
                       '?type=ws&path=','?security=none&sni=test.example','?type=grpc&authority=host',
                       '?type=ws&path=%2Fx%0D%0AHeader%3Abad']:
            with self.subTest(suffix=suffix),self.assertRaises(ValueError):parse(BASE+suffix)
    def test_export_rejects_unrepresentable_native_parameters(self):
        for change in [{'bind_interface':'eth0'},{'network':'tcp'},{'packet_encoding':'xudp'}]:
            out=parse(CASES[0]);out['native'].update(change)
            with self.assertRaises(ValueError):render(out)
        out=parse(CASES[1]);out['native']['tls'].pop('utls')
        with self.assertRaises(ValueError):render(out)
        out=parse(CASES[3]);out['native']['transport']['headers']['Custom']='value'
        with self.assertRaises(ValueError):render(out)

class WebVless(unittest.TestCase):
    setUp=test_web.WebTests.setUp
    tearDown=test_web.WebTests.tearDown
    login=test_web.WebTests.login
    revision=test_web.WebTests.revision
    def test_import_export_and_edit_keep_secret_private_until_download(self):
        csrf=self.login();before=copy.deepcopy(self.policy)
        response=self.client.post('/vless-import',data={'csrf':csrf,'revision':self.revision(),'uri':CASES[2],'scope':'public'})
        self.assertEqual(response.status_code,302)
        policy=json.loads((self.path/'policy.json').read_text());identifier=next(k for k in policy['exits'] if k!='direct')
        self.assertEqual(policy['profiles'],before['profiles'])
        html=self.client.get(response.location).text;self.assertNotIn(UUID,html)
        self.assertIn('Экспортировать vless://',html)
        result=self.client.post('/tunnels/'+identifier+'/export-vless',data={'csrf':csrf,'revision':self.revision()})
        self.assertEqual(result.status_code,200);self.assertEqual(result.headers['Cache-Control'],'no-store')
        native=policy['exits'][identifier]['native'];native.pop('tag')
        self.assertEqual(parse(result.text)['native'],native)
    def test_file_import_and_bad_requests_do_not_touch_policy(self):
        csrf=self.login();before=(self.path/'policy.json').read_bytes()
        self.assertEqual(self.client.post('/vless-import',data={'uri':CASES[0]}).status_code,403)
        response=self.client.post('/vless-import',data={'csrf':csrf,'revision':self.revision(),'uri':BASE+'?type=xhttp','scope':'public'})
        self.assertEqual(response.status_code,400);self.assertEqual((self.path/'policy.json').read_bytes(),before)
        response=self.client.post('/vless-import',data={'csrf':csrf,'revision':self.revision(),'scope':'public','connection_file':(io.BytesIO(CASES[3].encode()),'vpn.txt')})
        self.assertEqual(response.status_code,302)
        identifier=response.location.split('/')[2]
        self.assertEqual(self.client.post('/tunnels/'+identifier+'/export-vless',data={'csrf':csrf,'revision':'stale'}).status_code,409)
