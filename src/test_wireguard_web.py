import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch

from werkzeug.security import generate_password_hash
from web import create_app
from candidate_remote import RemoteError
from wireguard_control import control
from wireguard_form import parse_form
from test_wireguard_control import observed
from test_wireguard_profile import BASE,PRIVATE,PSK,PUBLIC
from wireguard_profile import parse
from test_wireguard_apply import FakeBackend


class WireGuardWebTests(unittest.TestCase):
    def setUp(self):
        # The fixture must not inspect real root-owned VPN journals on a host.
        vpn_state=patch('openconnect_apply.state',return_value={})
        self.vpn_state=vpn_state.start();self.addCleanup(vpn_state.stop)
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'auth.json').write_text(json.dumps({'username':'owner','password_hash':generate_password_hash('test-password'),'session_secret':'test-cookie-secret'}))
        self.profiles=self.root/'profiles';self.profiles.mkdir(mode=0o700)
        self.drafts=self.root/'drafts';self.drafts.mkdir(mode=0o700)
        path=self.profiles/'wg0.conf';path.write_text(BASE);path.chmod(0o600)
        self.network=self.root/'network';self.network.mkdir()
        state=self.network/'transaction.json';state.write_text(json.dumps({'status':'confirmed'}));state.chmod(0o600)
        self.backend=FakeBackend(self.profiles)
        self.remote=Mock();self.remote.call.side_effect=self.call
        self.client=create_app(self.root,self.remote).test_client()
        with self.client.session_transaction() as session:session.update(authenticated=True,csrf='test-csrf')
    def tearDown(self):self.temp.cleanup()
    def call(self,action,**fields):
        try:return control({'version':1,'action':action,**fields},profiles=self.profiles,drafts=self.drafts,observe=observed,backend=self.backend,network_lock=self.network/'apply.lock',peer_roots=(self.root/'other-vpn',))
        except ValueError as error:raise RemoteError(str(error)) from None
    def fields(self):
        view=self.call('wireguard-status',profile='wg0')
        return {'csrf':'test-csrf','file_revision':view['file_revision'],'draft_revision':view['draft_revision'],
                'peer_count':'1','interface_Address':'10.9.0.1/24\nfd90::1/64','interface_ListenPort':'51820',
                'peer_0_PublicKey':PUBLIC,'peer_0_AllowedIPs':'10.9.0.2/32\nfd90::2/128',
                'peer_0_Endpoint':'[2001:db8::1]:51821','peer_0_PersistentKeepalive':'25'}
    def test_other_pending_vpn_blocks_apply_before_network_mutation(self):
        fields=self.fields();self.client.post('/wireguard/wg0/save',data=fields)
        other=self.root/'other-vpn';other.mkdir(mode=0o700)
        state=other/'transaction.json';state.write_text(json.dumps({'id':'b'*32,'profile':'awg-other','status':'pending'}));state.chmod(0o600)
        response=self.client.post('/wireguard/wg0/apply',data={**self.fields(),'probe_address':'10.9.0.2','probe_port':'443','probe_mark':'0'})
        self.assertEqual(response.status_code,409);self.assertIn('другого WG/AWG',response.text)
        self.assertEqual(self.backend.events,[])

    def test_html_does_not_echo_secrets_and_form_saves_all_profile_parameters(self):
        html=self.client.get('/wireguard/wg0').text
        for secret in (PRIVATE,PSK):self.assertNotIn(secret,html)
        self.assertIn('peer_0_PublicKey',html);self.assertIn('Добавить пира',html)
        response=self.client.post('/wireguard/wg0/save',data=self.fields(),follow_redirects=True)
        self.assertEqual(response.status_code,200);self.assertIn('Черновик WireGuard сохранён',response.text)
        stored=json.loads((self.drafts/'wg0.json').read_text())
        self.assertEqual(parse(stored['profile']),parse(BASE))
        self.assertEqual((self.profiles/'wg0.conf').read_text(),BASE)
    def test_existing_auth_origin_and_csrf_guard_every_write(self):
        fields=self.fields()
        for values,headers in [({**fields,'csrf':'bad'},{}),(fields,{'Origin':'https://other.example'})]:
            self.assertEqual(self.client.post('/wireguard/wg0/save',data=values,headers=headers).status_code,403)
        self.remote.call.assert_not_called()
        with self.client.session_transaction() as session:session.pop('authenticated')
        self.assertEqual(self.client.get('/wireguard').status_code,302)
    def test_unavailable_server_does_not_render_editable_stale_model(self):
        self.remote.call.side_effect=RemoteError('Нет связи')
        response=self.client.get('/wireguard/wg0');self.assertIn('Нет связи',response.text)
        self.assertNotIn('name="interface_PrivateKey"',response.text)
    def test_remove_and_blank_new_peer_do_not_drop_others(self):
        fields=self.fields();fields['peer_0_remove']='on'
        self.assertEqual(parse_form(fields)['peers'],[])
        fields=self.fields();fields['peer_1_PublicKey']=PSK;fields['peer_1_AllowedIPs']='10.9.0.3/32'
        self.assertEqual(len(parse_form(fields)['peers']),2)
    def test_stale_post_is_shown_once_without_retry_or_secret_echo(self):
        fields=self.fields();self.client.post('/wireguard/wg0/save',data=fields)
        self.remote.call.reset_mock();fields['interface_PrivateKey']=PRIVATE
        response=self.client.post('/wireguard/wg0/save',data=fields)
        self.assertEqual(response.status_code,409);self.assertNotIn(PRIVATE,response.text);self.remote.call.assert_called_once()

    def test_corrupt_draft_offers_discard_but_not_save_in_browser(self):
        draft=self.drafts/'wg0.json';draft.write_text('{broken');draft.chmod(0o600)
        html=self.client.get('/wireguard/wg0').text
        self.assertIn('/wireguard/wg0/discard',html);self.assertNotIn('/wireguard/wg0/save',html)
        fields=self.fields();response=self.client.post('/wireguard/wg0/discard',data=fields,follow_redirects=True)
        self.assertEqual(response.status_code,200);self.assertFalse(draft.exists())

    def test_preflight_shows_blockers_without_saving_or_leaking_keys(self):
        result={'blockers':[{'code':'vpn-network','message':'Сеть занята другим VPN'}],
                'warnings':[],'native_valid':True,'checked_at':1000,'traffic_verified':False,'note':'Трафик не проверен'}
        with patch('wireguard_preflight.check',return_value=result):
            response=self.client.post('/wireguard/wg0/check',data=self.fields())
        self.assertEqual(response.status_code,200)
        self.assertIn('Включение блокируют конфликты',response.text)
        self.assertIn('Сеть занята другим VPN',response.text)
        self.assertEqual((self.profiles/'wg0.conf').read_text(),BASE)
        self.assertFalse((self.drafts/'wg0.json').exists())
        for secret in (PRIVATE,PSK):self.assertNotIn(secret,response.text)

    def test_preflight_rejects_stale_revision_and_cross_site_request(self):
        fields=self.fields()
        with patch('wireguard_preflight.check') as check:
            self.assertEqual(self.client.post('/wireguard/wg0/check',data=fields,headers={'Origin':'https://other.example'}).status_code,403)
            fields['file_revision']='0'*64
            self.assertEqual(self.client.post('/wireguard/wg0/check',data=fields).status_code,409)
        check.assert_not_called()

    def apply_draft(self):
        fields=self.fields();fields['interface_MTU']='1400'
        self.client.post('/wireguard/wg0/save',data=fields)
        fields=self.fields();fields.update(probe_address='10.9.0.2',probe_port='443',probe_mark='0')
        response=self.client.post('/wireguard/wg0/apply',data=fields,follow_redirects=True)
        self.assertEqual(response.status_code,200)
        return json.loads((self.drafts/'transaction.json').read_text())

    def test_apply_confirm_and_draft_cleanup_through_web(self):
        state=self.apply_draft()
        page=self.client.get('/wireguard/wg0').text
        self.assertIn('Проверить трафик и подтвердить',page)
        self.assertNotIn('Исходный файл изменился',page)
        response=self.client.post('/wireguard/wg0/confirm',data={'csrf':'test-csrf','transaction':state['id']},follow_redirects=True)
        self.assertEqual(response.status_code,200);self.assertIn('подтверждено',response.text)
        self.assertFalse((self.drafts/'wg0.json').exists())
        self.assertEqual(parse((self.profiles/'wg0.conf').read_text())['interface']['MTU'],1400)
        for secret in (PRIVATE,PSK):self.assertNotIn(secret,response.text)

    def test_missing_live_file_keeps_web_rollback_available(self):
        state=self.apply_draft();(self.profiles/'wg0.conf').unlink()
        html=self.client.get('/wireguard/wg0').text
        self.assertIn('Вернуть прежнее состояние WG',html)
        response=self.client.post('/wireguard/wg0/rollback',data={'csrf':'test-csrf','transaction':state['id']},follow_redirects=True)
        self.assertEqual(response.status_code,200);self.assertEqual((self.profiles/'wg0.conf').read_text(),BASE)
        self.assertTrue((self.drafts/'wg0.json').exists())

    def test_pending_draft_is_locked_and_confirm_requires_current_transaction(self):
        state=self.apply_draft();fields=self.fields()
        for action in ('save','discard','apply'):
            self.assertEqual(self.client.post('/wireguard/wg0/'+action,data=fields).status_code,409)
        self.assertEqual(self.client.post('/wireguard/wg0/confirm',data={'csrf':'test-csrf','transaction':'0'*32}).status_code,409)
        self.assertEqual(json.loads((self.drafts/'transaction.json').read_text())['id'],state['id'])

    def test_unconfirmed_network_policy_blocks_wg_before_runtime_change(self):
        self.client.post('/wireguard/wg0/save',data=self.fields())
        (self.network/'transaction.json').write_text(json.dumps({'status':'pending'}))
        fields=self.fields();fields.update(probe_address='10.9.0.2',probe_port='443',probe_mark='0')
        response=self.client.post('/wireguard/wg0/apply',data=fields)
        self.assertEqual(response.status_code,409);self.assertEqual(self.backend.events,[])
        self.assertEqual((self.profiles/'wg0.conf').read_text(),BASE)

    def test_invalid_or_missing_candidate_journal_has_specific_error_before_mutation(self):
        self.client.post('/wireguard/wg0/save',data=self.fields())
        fields=self.fields();fields.update(probe_address='10.9.0.2',probe_port='443',probe_mark='0')
        path=self.network/'transaction.json'
        for content in ('[]','null','{broken',None):
            with self.subTest(content=content):
                if content is None:path.unlink()
                else:path.write_text(content)
                response=self.client.post('/wireguard/wg0/apply',data=fields)
                self.assertEqual(response.status_code,409)
                self.assertIn('Журнал сетевой политики',response.text)
                self.assertEqual(self.backend.events,[])
                self.assertEqual((self.profiles/'wg0.conf').read_text(),BASE)

    def test_create_form_saves_inactive_profile_and_shows_only_public_key(self):
        from test_wireguard_create import inactive
        def call(action,**fields):
            try:return control({'version':1,'action':action,**fields},profiles=self.profiles,drafts=self.drafts,observe=inactive)
            except ValueError as error:raise RemoteError(str(error)) from None
        self.remote.call.side_effect=call
        fields={'csrf':'test-csrf','profile':'wg-new','peer_count':'0','interface_Address':'10.50.0.2/32'}
        def native(args,**kwargs):return 0,(PRIVATE if args[-1]=='genkey' else PUBLIC).encode()+b'\n'
        with patch('wireguard_create.command',side_effect=native):
            response=self.client.post('/wireguard/create',data=fields,follow_redirects=True)
        self.assertEqual(response.status_code,200)
        self.assertIn('создан выключенным',response.text);self.assertIn(PUBLIC,response.text);self.assertNotIn(PRIVATE,response.text)
        self.assertTrue((self.profiles/'wg-new.conf').is_file())
        self.assertEqual((self.profiles/'wg0.conf').read_text(),BASE)
        self.assertEqual(self.client.get('/wireguard-new').status_code,200)
        self.assertIn('Создать профиль WireGuard',self.client.get('/wireguard').text)

    def test_creation_is_csrf_origin_protected_and_errors_never_echo_key(self):
        fields={'csrf':'test-csrf','profile':'wg-new','peer_count':'0','interface_Address':'10.50.0.2/32','interface_PrivateKey':PRIVATE}
        for values,headers in [({**fields,'csrf':'bad'},{}),(fields,{'Origin':'https://other.example'})]:
            self.assertEqual(self.client.post('/wireguard/create',data=values,headers=headers).status_code,403)
        self.remote.call.assert_not_called()
        self.remote.call.side_effect=RemoteError('Имя профиля уже занято')
        response=self.client.post('/wireguard/create',data=fields)
        self.assertEqual(response.status_code,409);self.assertNotIn(PRIVATE,response.text);self.remote.call.assert_called_once()
