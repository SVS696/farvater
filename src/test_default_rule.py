import copy,json
import unittest
from werkzeug.datastructures import MultiDict
import test_web
from default_rule import view,save
from policy_modes import compile_policy_modes

class DefaultRuleTests(unittest.TestCase):
    def setUp(self):
        self.web=test_web.WebTests();self.web.setUp();self.addCleanup(self.web.tearDown)
        self.policy={'default_exit':'vpn','default_dns':'vpn-dns',
                     'exits':{k:{'name':k,'scope':'public'} for k in ('vpn','backup','direct')},
                     'dns':{k:{'name':k,'scope':'public'} for k in ('vpn-dns','backup-dns','isp')},
                     'profiles':[{'id':'specific','name':'Specific','kind':'public','domains':['example.com'],'exit':'direct','dns':'isp'}],
                     'failover':{'priority':['vpn','backup','direct'],'dns_by_exit':{'vpn':'vpn-dns','backup':'backup-dns','direct':'isp'},'failures':4,'recovery_seconds':60}}
        (self.web.path/'policy.json').write_text(json.dumps(self.policy))
        self.csrf=self.web.login();self.client=self.web.client
    def form(self):
        rule=view(self.policy)
        return MultiDict([('csrf',self.csrf),('id','__default__'),('revision',self.web.revision()),('exit',rule['exit']),('dns',rule['dns'])]+[(k,p[field]) for p in rule['fallback_pairs'] for k,field in [('fallback_exit','exit'),('fallback_dns','dns')]])
    def test_default_is_last_in_list_and_edits_shared_fields(self):
        page=self.client.get('/rules').text
        self.assertLess(page.index('Specific'),page.index('id="default-route"'))
        self.assertIn('/rules/default',page)
        page=self.client.get('/rules/default').text
        for marker in ('name="exit"','name="dns"','data-reserve-add','data-reserve-remove','data-reserve-up'):
            self.assertIn(marker,page)
        self.assertNotIn('name="domains"',page)
        self.assertNotIn('name="enabled"',page)
        self.assertNotIn('action="/failover/save"',self.client.get('/rules').text)
    def test_noop_save_preserves_compiled_modes_and_specific_rules(self):
        before=compile_policy_modes(self.policy,default_filtering=False)
        response=self.client.post('/rules/save',data=self.form());self.assertEqual(response.status_code,302)
        after=json.loads((self.web.path/'policy.json').read_text())
        self.assertEqual(after,self.policy)
        self.assertEqual(compile_policy_modes(after,default_filtering=False),before)
    def test_reorder_delete_and_zero_backups_preserve_primary_and_global_timing(self):
        data=self.form();data.setlist('fallback_exit',['direct','backup']);data.setlist('fallback_dns',['isp','backup-dns'])
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        saved=json.loads((self.web.path/'policy.json').read_text());self.assertEqual(saved['failover']['priority'],['vpn','direct','backup'])
        data['revision']=self.web.revision();data.setlist('fallback_exit',[]);data.setlist('fallback_dns',[])
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        saved=json.loads((self.web.path/'policy.json').read_text())
        self.assertEqual(saved['failover']['priority'],['vpn']);self.assertEqual(saved['failover']['failures'],4)
        self.assertEqual(saved['failover']['recovery_seconds'],60);self.assertEqual(saved['profiles'],self.policy['profiles'])
    def test_incomplete_pair_stale_form_and_deleting_final_rule_are_rejected(self):
        before=(self.web.path/'policy.json').read_bytes()
        data=self.form();data.setlist('fallback_dns',['','isp'])
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,400)
        data=self.form();data['revision']='outdated'
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,409)
        for action in ('delete','move'):
            self.assertEqual(self.client.post('/rules/__default__/'+action,data={'csrf':self.csrf,'revision':self.web.revision(),'direction':'up'}).status_code,400)
        self.assertEqual((self.web.path/'policy.json').read_bytes(),before)
    def test_ordinary_rule_keeps_three_ordered_backups(self):
        data=MultiDict([('csrf',self.csrf),('revision',self.web.revision()),('id','specific'),('name','Specific'),('kind','public'),('domains','example.com'),('enabled','on'),('exit','direct'),('dns','isp')]+[(k,p[field]) for p in [{'exit':'vpn','dns':'vpn-dns'},{'exit':'backup','dns':'backup-dns'},{'exit':'direct','dns':'backup-dns'}] for k,field in [('fallback_exit','exit'),('fallback_dns','dns')]])
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        saved=json.loads((self.web.path/'policy.json').read_text())['profiles'][0]
        self.assertEqual([p['exit'] for p in saved['fallback_pairs']],['vpn','backup','direct'])

    def test_drag_order_requires_exact_list_and_current_revision(self):
        extra={**self.policy['profiles'][0],'id':'second','name':'Second','domains':['second.example']}
        self.policy['profiles'].append(extra)
        (self.web.path/'policy.json').write_text(json.dumps(self.policy))
        data=MultiDict([('csrf',self.csrf),('revision',self.web.revision()),('order','second'),('order','specific')])
        self.assertEqual(self.client.post('/rules/reorder',data=data).status_code,302)
        saved=json.loads((self.web.path/'policy.json').read_text())
        self.assertEqual([p['id'] for p in saved['profiles']],['second','specific'])
        self.assertEqual(saved['failover'],self.policy['failover'])
        self.assertEqual(self.client.post('/rules/reorder',data=data).status_code,409)
        for ids in (['specific'],['specific','specific'],['specific','second','__default__']):
            data['revision']=self.web.revision();data.setlist('order',ids)
            self.assertEqual(self.client.post('/rules/reorder',data=data).status_code,400)

    def test_legacy_failover_redirects_without_duplicate_editor(self):
        response=self.client.get('/failover')
        self.assertEqual(response.status_code,302);self.assertTrue(response.location.endswith('/rules#rule-automation'))
        page=self.client.get('/rules').text
        self.assertNotIn('>Резервирование</a>',page)
        self.assertEqual(page.count('action="/failover/timing"'),1)
        self.assertEqual(page.count('action="/failover/save"'),0)
        self.assertIn('/health/switches',page)
        self.assertIn('Журнал переключений этого правила',self.client.get('/rules/default').text)
