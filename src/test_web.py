import json
from pathlib import Path
import tempfile
import unittest
from werkzeug.security import generate_password_hash
from web import create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)
        self.policy={'default_exit':'direct','default_dns':'isp','exits':{'direct':{'name':'Провайдер','scope':'public'}},'dns':{'isp':{'name':'ISP','scope':'public'}},'profiles':[],'failover':{'priority':['direct'],'failures':3,'recovery_seconds':30}}
        (self.path/'policy.json').write_text(json.dumps(self.policy))
        (self.path/'auth.json').write_text(json.dumps({'username':'owner','password_hash':generate_password_hash('test-password'),'session_secret':'test-session-secret'}))
        self.app=create_app(self.path);self.app.testing=True;self.client=self.app.test_client()

    def tearDown(self):self.temp.cleanup()

    def login(self):
        self.client.get('/login')
        with self.client.session_transaction() as s:token=s['csrf']
        response=self.client.post('/login',data={'csrf':token,'username':'owner','password':'test-password'})
        self.assertEqual(response.status_code,302)
        with self.client.session_transaction() as s:return s['csrf']

    def revision(self):
        import hashlib
        return hashlib.sha256((self.path/'policy.json').read_bytes()).hexdigest()

    def test_connection_picker_uses_typed_forms_without_mutating_policy(self):
        self.assertEqual(self.client.get('/connections/new').status_code,302)
        self.login();before=(self.path/'policy.json').read_bytes()
        for protocol,marker in [('wireguard','WireGuard'),('openvpn','OpenVPN'),('trusttunnel','TrustTunnel'),
                                ('openconnect','openconnect'),('vless','vless'),('shadowsocks','shadowsocks'),
                                ('shadowsocks-import','Shadowsocks'),('socks','socks'),('http','http'),('direct','direct'),('selector','selector')]:
            response=self.client.get('/connections/new',query_string={'protocol':protocol})
            self.assertEqual(response.status_code,200,protocol)
            self.assertIn(marker,response.text)
        self.assertEqual(self.client.get('/connections/new?protocol=unknown').status_code,400)
        self.assertEqual(before,(self.path/'policy.json').read_bytes())

    def test_auth_and_csrf_are_required_before_mutation(self):
        self.assertEqual(self.client.get('/rules').status_code,302)
        self.login()
        before=(self.path/'policy.json').read_bytes()
        self.assertEqual(self.client.post('/rules/save',data={'name':'attack'}).status_code,403)
        self.assertEqual(before,(self.path/'policy.json').read_bytes())

    def test_cross_origin_write_and_rebinding_are_rejected(self):
        csrf=self.login()
        self.assertEqual(self.client.post('/failover/save',data={'csrf':csrf},headers={'Origin':'https://attacker.example'}).status_code,403)
        self.assertEqual(self.client.post('/failover/save',data={'csrf':csrf},headers={'Origin':'null'}).status_code,403)
        self.assertEqual(self.client.get('/overview',headers={'Host':'attacker.example'}).status_code,400)

    def test_same_origin_form_submission_succeeds(self):
        self.assertEqual(self.client.get('/login').headers['Referrer-Policy'],'same-origin')
        csrf=self.login()
        data={'csrf':csrf,'revision':self.revision(),'exit':'direct','dns':'isp','failures':'4','recovery':'30'}
        self.assertEqual(self.client.post('/failover/save',data=data,headers={'Origin':'http://localhost'}).status_code,302)
        self.assertEqual(json.loads((self.path/'policy.json').read_text())['failover']['failures'],4)

    def test_rule_edit_is_draft_only_and_html_escaped(self):
        csrf=self.login()
        data={'csrf':csrf,'revision':self.revision(),'name':'<script>alert(1)</script>','kind':'public','enabled':'on','domains':'*.example.com','exit':'direct','dns':'isp'}
        r=self.client.post('/rules/save',data=data);self.assertEqual(r.status_code,302)
        html=self.client.get('/rules').text
        self.assertIn('&lt;script&gt;',html);self.assertNotIn('<script>alert(1)</script>',html)
        self.assertEqual(len(json.loads((self.path/'policy.json').read_text())['profiles']),1)

    def test_monitoring_requires_login_and_missing_data_is_not_green(self):
        self.assertEqual(self.client.get('/health').status_code,302)
        self.login();response=self.client.get('/health')
        self.assertEqual(response.status_code,200);self.assertIn('Нет данных',response.text)
        self.assertIn('Нет данных',response.text);self.assertNotIn('Giga',response.text)
        self.assertIn('http-equiv="refresh"',response.text)

    def test_adguard_settings_round_trip_and_conflict_protection(self):
        csrf=self.login();revision=self.revision()
        data={'csrf':csrf,'revision':revision,'default_enabled':'on','rules':'||blocked.test^\n@@||allowed.test^',
              'blocklists_name':['Main',''],'blocklists_url':['https://example.org/filter.txt',''],
              'blocklists_enabled':['true','false']}
        response=self.client.post('/filtering/save',data=data);self.assertEqual(response.status_code,302)
        saved=json.loads((self.path/'policy.json').read_text())['filtering']
        self.assertTrue(saved['default_enabled']);self.assertEqual(len(saved['blocklists']),1)
        self.assertIn('https://example.org/filter.txt',self.client.get('/filtering').text)
        before=(self.path/'policy.json').read_bytes()
        self.assertEqual(self.client.post('/filtering/save',data=data).status_code,409)
        data.update(revision=self.revision(),rules='||x.test^$client=10.0.0.1')
        self.assertEqual(self.client.post('/filtering/save',data=data).status_code,400)
        self.assertEqual((self.path/'policy.json').read_bytes(),before)

    def test_monitoring_escapes_source_text_and_expires_old_success(self):
        self.login()
        (self.path/'health.json').write_text(json.dumps({'version':1,'generated_at':1000,'checks':[
            {'id':'probe','name':'<script>unsafe</script>','scope':'Сервер','status':'up','observed_at':1000,
             'duration_ms':1,'detail':'old','action':'Проверьте сборщик'}]}))
        html=self.client.get('/health').text
        self.assertIn('Нет свежих данных',html);self.assertNotIn('<script>unsafe</script>',html)
        self.assertIn('&lt;script&gt;',html)

    def test_stale_page_cannot_overwrite_newer_draft(self):
        csrf=self.login();revision=self.revision()
        data={'csrf':csrf,'revision':revision,'name':'Первое','kind':'public','domains':'example.com','exit':'direct','dns':'isp'}
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        data['name']='Второе';self.assertEqual(self.client.post('/rules/save',data=data).status_code,409)
        self.assertEqual(len(json.loads((self.path/'policy.json').read_text())['profiles']),1)

    def test_general_rule_options_survive_form_save_and_rename(self):
        self.policy['failover']['dns_by_exit']={'direct':'isp'}
        (self.path/'policy.json').write_text(json.dumps(self.policy))
        csrf=self.login()
        data={'csrf':csrf,'revision':self.revision(),'name':'Произвольное исключение',
              'kind':'public','enabled':'on','source_networks':'192.168.2.82\n192.168.2.82/32',
              'domains':'*.example.com','exclude_domains':'excluded.example.com',
              'route_network':'tcp','route_ports':'80,443',
              'exit':'direct','dns':'isp','adguard':'off','ip_family':'ipv4_only','udp_blocked_ports':'443, 8443',
              'dns_response_mode':'nodata','dns_query_types':['HTTPS','SVCB']}
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        saved=json.loads((self.path/'policy.json').read_text())['profiles'][0]
        self.assertEqual(saved['source_networks'],['192.168.2.82/32'])
        self.assertEqual(saved['udp_blocked_ports'],[443,8443])
        self.assertEqual(saved['route_network'],'tcp');self.assertEqual(saved['route_ports'],[80,443])
        self.assertEqual(saved['dns_response'],{'mode':'nodata','query_types':['HTTPS','SVCB']})
        self.assertEqual(saved['adguard'],'off');self.assertEqual(saved['ip_family'],'ipv4_only')
        html=self.client.get('/rules/'+saved['id']+'/edit').text
        for selected in ['off','ipv4_only','nodata']:
            self.assertIn('value="'+selected+'" selected',html)
        for checked in ['HTTPS','SVCB']:
            self.assertIn('value="'+checked+'" checked',html)
        self.assertIn('192.168.2.82/32',html)
        self.assertIn('name="udp_blocked_ports" value="443, 8443"',html)
        self.assertIn('name="route_ports" value="80, 443"',html)
        self.assertIn('value="tcp" selected',html)
        self.assertIn('укажите протокол',self.client.get('/rules?domain=a.example.com&source=192.168.2.82').text)
        self.assertIn('правило №1',self.client.get('/rules?domain=a.example.com&source=192.168.2.82&network=tcp&port=443').text)
        self.assertIn('правило по умолчанию',self.client.get('/rules?domain=a.example.com&source=192.168.2.82&network=udp&port=3478').text)
        data.update(id=saved['id'],revision=self.revision(),name='Другое название')
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        renamed=json.loads((self.path/'policy.json').read_text())['profiles'][0]
        self.assertEqual({k:v for k,v in saved.items() if k!='name'},
                         {k:v for k,v in renamed.items() if k!='name'})

    def test_bad_general_options_do_not_change_draft(self):
        csrf=self.login();before=(self.path/'policy.json').read_bytes()
        for invalid in [{'source_networks':'0.0.0.0/0'},{'ip_family':'typo'},
                        {'adguard':'typo'},{'dns_response_mode':'nodata'},{'udp_blocked_ports':'65536'},
                        {'route_ports':'0'},{'route_network':'icmp'},{'kind':'work','route_network':'tcp'},
                        {'dns_response_mode':'nodata','dns_query_types':['AAAA','invented']}]:
            with self.subTest(invalid=invalid):
                data={'csrf':csrf,'revision':self.revision(),'name':'Исключение',
                      'kind':'public','enabled':'on','domains':'example.com',
                      'exit':'direct','dns':'isp',**invalid}
                self.assertEqual(self.client.post('/rules/save',data=data).status_code,400)
                self.assertEqual((self.path/'policy.json').read_bytes(),before)

    def test_rule_backup_pairs_round_trip_and_reject_incomplete_row(self):
        self.policy['exits']['vpn']={'name':'VPN','scope':'public'}
        self.policy['dns']['vpn-dns']={'name':'VPN DNS','scope':'public'}
        (self.path/'policy.json').write_text(json.dumps(self.policy))
        csrf=self.login()
        data={'csrf':csrf,'revision':self.revision(),'name':'Общее правило','kind':'public',
              'enabled':'on','domains':'example.com','exit':'vpn','dns':'vpn-dns',
              'fallback_exit':['direct',''],'fallback_dns':['isp','']}
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        profile=json.loads((self.path/'policy.json').read_text())['profiles'][0]
        self.assertEqual(profile['fallback_pairs'],[{'exit':'direct','dns':'isp'}])
        html=self.client.get('/rules/'+profile['id']+'/edit').text
        self.assertIn('Резерв этого правила',html)
        before=(self.path/'policy.json').read_bytes()
        data.update(id=profile['id'],revision=self.revision(),fallback_dns=['',''])
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,400)
        self.assertEqual((self.path/'policy.json').read_bytes(),before)

    def test_legacy_exit_list_is_not_silently_deleted_by_rule_edit(self):
        self.policy['profiles']=[{'id':'old','name':'Прежнее','kind':'public','enabled':True,
            'domains':['example.com'],'exit':'direct','dns':'isp','fallback':['direct']}]
        (self.path/'policy.json').write_text(json.dumps(self.policy))
        csrf=self.login();before=(self.path/'policy.json').read_bytes()
        data={'csrf':csrf,'revision':self.revision(),'id':'old','name':'Новое имя','kind':'public',
              'enabled':'on','domains':'example.com','exit':'direct','dns':'isp'}
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,400)
        self.assertEqual((self.path/'policy.json').read_bytes(),before)
        data['replace_legacy_fallback']='on'
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        self.assertEqual(json.loads((self.path/'policy.json').read_text())['profiles'][0]['fallback'],[])

    def test_all_pages_render_without_credentials(self):
        self.login()
        for name in ['overview','rules','tunnels','dns','failover','changes','help']:
            with self.subTest(name=name):
                r=self.client.get('/'+name,follow_redirects=True);self.assertEqual(r.status_code,200)
                self.assertNotIn('test-password',r.text);self.assertNotIn('test-session-secret',r.text)

    def test_dns_form_saves_draft_and_rejects_bad_port_without_write(self):
        csrf=self.login()
        for path in ['/dns/new','/dns/isp/edit']:
            self.assertEqual(self.client.get(path).status_code,200)
        data={'csrf':csrf,'revision':self.revision(),'id':'isp','name':'Provider','scope':'public','type':'udp','server':'77.37.251.33','server_port':'53'}
        self.assertEqual(self.client.post('/dns/save',data=data).status_code,302)
        before=(self.path/'policy.json').read_bytes()
        data.update(revision=self.revision(),server_port='0')
        self.assertEqual(self.client.post('/dns/save',data=data).status_code,400)
        self.assertEqual((self.path/'policy.json').read_bytes(),before)

    def test_tunnel_secrets_are_preserved_but_never_rendered(self):
        self.policy['exits']['proxy']={'name':'Proxy','scope':'public','native':{'type':'socks','server':'127.0.0.1','server_port':1080,'password':'hidden-proxy-secret','tcp_fast_open':True}}
        (self.path/'policy.json').write_text(json.dumps(self.policy))
        csrf=self.login()
        for path in ['/tunnels/new','/tunnels/proxy/edit']:
            response=self.client.get(path)
            self.assertEqual(response.status_code,200)
            self.assertNotIn('hidden-proxy-secret',response.text)
        data={'csrf':csrf,'revision':self.revision(),'id':'proxy','name':'Proxy','scope':'public','type':'socks','server':'127.0.0.1','server_port':'1080','version':'5'}
        self.assertEqual(self.client.post('/tunnels/save',data=data).status_code,302)
        native=json.loads((self.path/'policy.json').read_text())['exits']['proxy']['native']
        self.assertEqual(native['password'],'hidden-proxy-secret');self.assertTrue(native['tcp_fast_open'])
        before=(self.path/'policy.json').read_bytes();data.update(revision=self.revision(),server_port='0')
        self.assertEqual(self.client.post('/tunnels/save',data=data).status_code,400)
        self.assertEqual(before,(self.path/'policy.json').read_bytes())


if __name__=='__main__':unittest.main()
