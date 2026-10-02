import base64
import io
import json
import unittest
import zipfile

import test_openconnect_service_web as oc
import test_trusttunnel_web as tt
import test_wireguard_web as wg
from openconnect_export import export_bundle,import_bundle
from openconnect_profile import DEFAULT
from trusttunnel_profile import parse_client
from wireguard_profile import parse


class OpenConnectExportTests(unittest.TestCase):
    setUp=oc.OpenConnectWebTests.setUp
    tearDown=oc.OpenConnectWebTests.tearDown
    login=oc.OpenConnectWebTests.login
    def test_native_archive_roundtrip_and_no_runtime_changes(self):
        csrf=self.login();view=self.fixture.call('status')
        data={'csrf':csrf,**self.fixture.revisions(view),'source':'active'}
        self.assertEqual(self.client.get('/openconnect/work/export').status_code,405)
        self.assertEqual(self.client.post('/openconnect/work/export',data={**data,'csrf':'wrong'}).status_code,403)
        response=self.client.post('/openconnect/work/export',data=data)
        self.assertEqual(response.status_code,200);self.assertEqual(response.mimetype,'application/zip')
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertIn('attachment;',response.headers['Content-Disposition'])
        with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
            conf=archive.read('client.conf').decode()
            self.assertIn('passwd-on-stdin',conf);self.assertNotIn('script=',conf);self.assertNotIn('interface=',conf)
            self.assertIn(b'PRIVATE-password',archive.read('stdin.txt'))
        imported=import_bundle(base64.b64encode(response.data).decode())
        self.assertEqual(imported['username'],'worker')
        response=self.client.post('/openconnect/work/import',data={'csrf':csrf,**self.fixture.revisions(view),'format':'native-bundle','connection_file':(io.BytesIO(response.data),'work.zip')})
        self.assertEqual(response.status_code,302)
        saved=json.loads((self.fixture.root/'work.draft.json').read_text())
        self.assertEqual(saved['model'],imported)
        self.assertNotIn('PRIVATE-password',self.client.get('/tunnels/work/edit').text)

    def test_archive_rejects_unsafe_entries_and_changed_native_files(self):
        model={**DEFAULT,'server':'https://vpn.test/','username':'user','password':'secret'}
        encoded=export_bundle(model)
        self.assertEqual(import_bundle(encoded),model)
        for filename,data in [('../outside',b'x'),('client.conf',b'script=/bin/false')]:
            source=zipfile.ZipFile(io.BytesIO(base64.b64decode(encoded)));out=io.BytesIO()
            with zipfile.ZipFile(out,'w') as target:
                for entry in source.infolist():
                    target.writestr(entry, data if entry.filename==filename else source.read(entry))
                if filename not in source.namelist():target.writestr(filename,data)
            with self.assertRaises(ValueError):import_bundle(base64.b64encode(out.getvalue()).decode())


class TrustTunnelExportTests(unittest.TestCase):
    setUp=tt.WebTests.setUp
    tearDown=tt.WebTests.tearDown
    login=tt.WebTests.login
    def test_active_and_draft_native_roundtrip_are_distinct(self):
        csrf=self.login();view=self.fixture.call('status')
        view=self.fixture.call('import',**self.fixture.revisions(view),text='upstream_protocol="http3"',format='endpoint')
        for source,transport in [('active','http2'),('draft','http3')]:
            response=self.client.post('/trusttunnel/vpn/export',data={'csrf':csrf,**self.fixture.revisions(view),'source':source})
            self.assertEqual(response.status_code,200);self.assertEqual(response.headers['Cache-Control'],'no-store')
            model=parse_client(response.text,self.fixture.binding)
            self.assertEqual(model['upstream_protocol'],transport);self.assertEqual(model['password'],'PRIVATE-password')
        response=self.client.post('/trusttunnel/vpn/import',data={'csrf':csrf,**self.fixture.revisions(view),'format':'client','connection_file':(io.BytesIO(response.data),'client.toml')})
        self.assertEqual(response.status_code,302)
        self.assertEqual(json.loads((self.fixture.root/'vpn.draft.json').read_text())['model'],model)
        self.assertEqual(self.client.post('/trusttunnel/vpn/export',data={'csrf':'wrong',**self.fixture.revisions(view),'source':'active'}).status_code,403)


class WireGuardExportTests(unittest.TestCase):
    setUp=wg.WireGuardWebTests.setUp
    tearDown=wg.WireGuardWebTests.tearDown
    call=wg.WireGuardWebTests.call
    fields=wg.WireGuardWebTests.fields
    def test_other_vpn_pending_prevents_apply_before_service_mutation(self):
        self.assertEqual(self.client.post('/wireguard/wg0/save',data=self.fields()).status_code,302)
        self.vpn_state.side_effect=lambda root=None: {'status':'pending'} if root is not None else {}
        response=self.client.post('/wireguard/wg0/apply',data=self.fields())
        self.assertEqual(response.status_code,409);self.assertEqual(self.backend.events,[])

    def test_native_export_import_preserves_all_keys_without_touching_live_profile(self):
        original=(self.profiles/'wg0.conf').read_bytes();fields=self.fields()
        response=self.client.post('/wireguard/wg0/export',data={**fields,'source':'active'})
        self.assertEqual(response.status_code,200);self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertEqual(parse(response.text),parse(original.decode()))
        response=self.client.post('/wireguard/wg0/import',data={**fields,'connection_file':(io.BytesIO(response.data),'wg.conf')})
        self.assertEqual(response.status_code,302)
        self.assertEqual(parse(json.loads((self.drafts/'wg0.json').read_text())['profile']),parse(original.decode()))
        self.assertEqual((self.profiles/'wg0.conf').read_bytes(),original)
        fields=self.fields();before=(self.drafts/'wg0.json').read_bytes()
        bad=original.replace(b'[Interface]',b'[Interface]\nPostUp=touch /tmp/no')
        response=self.client.post('/wireguard/wg0/import',data={**fields,'connection_file':(io.BytesIO(bad),'bad.conf')})
        self.assertEqual(response.status_code,409);self.assertEqual((self.drafts/'wg0.json').read_bytes(),before)


if __name__=='__main__':unittest.main()
