import io,json,unittest
from test_candidate_web import CandidateWebTests
from test_amnezia_profile import PROFILE,KEY
from amnezia_profile import parse,public_view

class AmneziaWebTests(unittest.TestCase):
    setUp=CandidateWebTests.setUp
    tearDown=CandidateWebTests.tearDown
    fields=CandidateWebTests.fields

    def view(self):
        return dict(name='awgfixture',model=public_view(parse(PROFILE)),transaction={},error=None,
                    file_revision='a'*64,draft_revision='',has_draft=False,conflict=False,
                    observed_at=1000,runtime=dict(service='inactive',substate='dead',boot='disabled',interface=False))

    def test_protocol_form_and_masked_editor_have_awg_fields_and_own_actions(self):
        response=self.client.get('/connections/new?protocol=amnezia')
        self.assertEqual(response.status_code,200);self.assertIn('name="connection_file"',response.text)
        self.assertNotIn('name="interface_Table"',response.text);self.assertNotIn('name="profile"',response.text)
        self.remote.call.return_value=self.view();response=self.client.get('/amnezia/awgfixture')
        self.assertEqual(response.status_code,200)
        self.assertIn('action="/amnezia/awgfixture/save"',response.text)
        self.assertNotIn('action="/wireguard/',response.text)
        self.assertNotIn(KEY,response.text);self.assertIn('name="interface_H1" value="100-200"',response.text)
        self.assertNotIn('name="interface_Table"',response.text)
        self.assertIn('type="text" name="peer_0_PersistentKeepalive"',response.text)

    def test_import_registers_exit_and_dns_in_draft_without_changing_default(self):
        before=json.loads((self.root/'policy.json').read_text())
        self.remote.call.return_value=dict(name='awgfixture',created=True,runtime_changed=False,dns=['10.77.0.1'])
        fields={**self.fields(),'name':'My AWG','scope':'public','connection_file':(io.BytesIO(PROFILE.encode()),'client.conf')}
        response=self.client.post('/amnezia/create',data=fields,content_type='multipart/form-data')
        self.assertEqual(response.status_code,302);self.assertTrue(response.location.endswith('/amnezia/awgfixture'))
        self.remote.call.assert_called_once_with('amnezia-create',profile=None,values={'text':PROFILE})
        saved=json.loads((self.root/'policy.json').read_text());self.assertEqual(saved['default_exit'],before['default_exit'])
        self.assertEqual(saved['profiles'],before['profiles'])
        self.assertEqual(saved['exits']['amnezia-awgfixture']['native']['bind_interface'],'awgfixture')
        self.assertEqual(saved['dns']['amnezia-awgfixture-dns-1']['native']['detour'],'amnezia-awgfixture')
        response=self.client.get('/tunnels/amnezia-awgfixture/edit');self.assertEqual(response.status_code,302)
        self.assertTrue(response.location.endswith('/amnezia/awgfixture'))

    def test_stale_creation_does_not_create_orphan_profile(self):
        fields={**self.fields(),'revision':'0'*64,'name':'My AWG','scope':'public','connection_file':(io.BytesIO(PROFILE.encode()),'client.conf')}
        self.assertEqual(self.client.post('/amnezia/create',data=fields,content_type='multipart/form-data').status_code,409)
        self.remote.call.assert_not_called()
