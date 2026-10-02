import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock
from werkzeug.security import generate_password_hash
from web import create_app
from candidate_remote import RemoteError
import test_candidate_config as fixtures

class CandidateWebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'auth.json').write_text(json.dumps({'username':'owner','password_hash':generate_password_hash('test-password'),'session_secret':'test-cookie-secret'}))
        (self.root/'policy.json').write_text(json.dumps(fixtures.CandidateConfigTests().base()))
        self.remote=Mock();self.state={'integrity':True,'config_sha256':'a'*64,'policy_sha256':'b'*64,'observed_at':1000,'default_filtering':False,'transaction':{'id':'c'*32,'status':'confirmed','runtime_ready':True,'deadline':2000}}
        self.remote.call.return_value=self.state;self.client=create_app(self.root,self.remote).test_client()
        with self.client.session_transaction() as s:s['authenticated']=True;s['csrf']='csrf-token'
    def tearDown(self):self.temp.cleanup()
    def fields(self):return {'csrf':'csrf-token','candidate_revision':'a'*64,'revision':hashlib.sha256((self.root/'policy.json').read_bytes()).hexdigest(),'transaction':'c'*32}
    def test_apply_sends_exact_current_draft_and_bound_server_revision(self):
        self.remote.call.return_value={**self.state,'transaction':{**self.state['transaction'],'status':'pending'}}
        self.assertEqual(self.client.post('/candidate/apply',data=self.fields()).status_code,302)
        self.remote.call.assert_called_once_with('apply',expected_config_sha256='a'*64,policy=json.loads((self.root/'policy.json').read_text()))
    def test_stale_draft_csrf_and_cross_origin_do_not_reach_server(self):
        cases=[({**self.fields(),'revision':'0'*64},{},409),({**self.fields(),'csrf':'bad'},{},403),(self.fields(),{'Origin':'https://foreign.example'},403)]
        for fields,headers,code in cases:
            with self.subTest(code=code):self.assertEqual(self.client.post('/candidate/apply',data=fields,headers=headers).status_code,code)
        self.remote.call.assert_not_called()
    def test_pending_form_offers_confirmation_and_rollback_not_new_apply(self):
        self.state['transaction']['status']='pending';html=self.client.get('/changes').text
        self.assertIn('Проверить и подтвердить',html);self.assertIn('Вернуть прежний пакет',html);self.assertNotIn('action="/candidate/apply"',html)
    def test_unready_or_damaged_package_still_offers_rollback(self):
        self.state['transaction'].update(status='pending',runtime_ready=False);self.state['integrity']=False
        html=self.client.get('/changes').text;self.assertIn('Вернуть прежний пакет',html);self.assertNotIn('action="/candidate/confirm"',html)
    def test_transport_error_never_offers_actions_from_old_state(self):
        self.remote.call.side_effect=RemoteError('Нет связи');html=self.client.get('/changes').text
        self.assertIn('Нет достоверного состояния',html);self.assertNotIn('action="/candidate/apply"',html);self.assertNotIn('action="/candidate/confirm"',html)
    def test_unknown_write_result_is_shown_and_not_retried(self):
        self.remote.call.side_effect=RemoteError('Ответ операции не получен')
        result=self.client.post('/candidate/apply',data=self.fields());self.assertEqual(result.status_code,302);self.remote.call.assert_called_once()
    def test_confirmation_binds_transaction_and_config(self):
        self.client.post('/candidate/confirm',data=self.fields())
        self.remote.call.assert_called_once_with('confirm',transaction='c'*32,expected_config_sha256='a'*64)
    def test_active_routing_form_binds_server_and_preference_revisions(self):
        fields={'csrf':'csrf-token','config_sha256':'a'*64,'transaction_id':'b'*32,'preferences_revision':'settings','mode':'known','enabled':'on','queue':['default'],'pin':['pair-choice']}
        self.assertEqual(self.client.post('/failover/control',data=fields).status_code,302)
        self.remote.call.assert_called_once_with('routing-set',expected_config_sha256='a'*64,expected_transaction_id='b'*32,expected_preferences_revision='settings',expected_mode='known',enabled=True,pins={'default':'pair-choice'})
    def test_routing_control_rejects_forgery_and_duplicate_queues(self):
        fields={'csrf':'bad','queue':['default'],'pin':['auto']}
        self.assertEqual(self.client.post('/failover/control',data=fields).status_code,403)
        fields.update(csrf='csrf-token',queue=['default','default'],pin=['auto','auto'])
        self.assertEqual(self.client.post('/failover/control',data=fields).status_code,400)
        self.remote.call.assert_not_called()
    def test_probe_targets_are_saved_generically_and_protected_names_are_rejected(self):
        fields={**self.fields(),'queue':'default','enabled':'on','dns_name':'api.ipify.org','urls':'https://example.com/','codes':'200, 204'}
        self.assertEqual(self.client.post('/failover/probes',data=fields).status_code,302)
        policy=json.loads((self.root/'policy.json').read_text());self.assertEqual(policy['health_probes']['default']['codes'],[200,204])
        policy['profiles'].append({'id':'secret','name':'Secret','kind':'work','domains':['*.secret.test'],'exit':'work','dns':'private'})
        (self.root/'policy.json').write_text(json.dumps(policy));before=(self.root/'policy.json').read_bytes()
        fields.update(revision=self.fields()['revision'],dns_name='api.secret.test')
        self.assertEqual(self.client.post('/failover/probes',data=fields).status_code,400)
        self.assertEqual(before,(self.root/'policy.json').read_bytes());self.remote.call.assert_not_called()
    def test_removed_probe_queue_can_be_deleted_through_form(self):
        policy=json.loads((self.root/'policy.json').read_text());policy['health_probes']={'rule:removed':{'dns_name':'example.com','urls':['https://example.com/'],'codes':[200]}}
        (self.root/'policy.json').write_text(json.dumps(policy))
        self.assertIn('Удалённая очередь',self.client.get('/rules').text)
        fields={**self.fields(),'queue':'rule:removed'}
        self.assertEqual(self.client.post('/failover/probes',data=fields).status_code,302)
        self.assertEqual(json.loads((self.root/'policy.json').read_text())['health_probes'],{})
