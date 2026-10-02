import copy,json,unittest
from domain_document import parse,validate,text_for
from policy import singbox_match,validate_policy,domain_matches
import test_web as fixtures

class DomainDocumentTests(unittest.TestCase):
    def test_comments_do_not_change_network_semantics(self):
        doc=parse('# Основное\nExample.COM\n*.example.com\n\n# Поддомены\nbeta.example.com\n# Пустая группа')
        self.assertEqual(doc['domains'],['example.com','*.example.com','beta.example.com'])
        self.assertEqual([g['title'] for g in doc['groups']],['Основное','Поддомены','Пустая группа'])
        self.assertEqual(singbox_match(doc['domains'],[]),singbox_match(['example.com','*.example.com','beta.example.com'],[]))
        self.assertFalse(domain_matches('*.example.com','example.com'))
        self.assertTrue(domain_matches('*.example.com','beta.example.com'))
        self.assertEqual(parse(doc['text']),doc)

    def test_international_domains_and_invalid_lines(self):
        self.assertEqual(parse('# РФ\n*.РФ\nпример.рф')['domains'],['*.xn--p1ai','xn--e1afmkfd.xn--p1ai'])
        for text in ['#','https://example.com','a.com # comment','*example.com','a.com\n<script>','x'*100001]:
            with self.subTest(text=text[:30]),self.assertRaises(ValueError):parse(text)

    def test_metadata_cannot_silently_diverge_from_matches(self):
        with self.assertRaises(ValueError):validate({'domains':['a.com'],'domain_document':'# group\nb.com'})
        validate({'domains':['a.com']})
        self.assertEqual(text_for({'domains':['a.com']}),'a.com')

class DomainDocumentWebTests(unittest.TestCase):
    setUp=fixtures.WebTests.setUp
    tearDown=fixtures.WebTests.tearDown
    login=fixtures.WebTests.login
    revision=fixtures.WebTests.revision

    def test_save_reload_comments_and_collapsed_summary(self):
        self.policy['failover']['dns_by_exit']={'direct':'isp'}
        (self.path/'policy.json').write_text(json.dumps(self.policy))
        csrf=self.login();text='# <b>Видео</b>\nexample.com\n*.example.com\n# Отдельно\nbeta.example.com'
        data={'csrf':csrf,'revision':self.revision(),'name':'Sites','kind':'public','enabled':'on','domains':text,'exit':'direct','dns':'isp'}
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,302)
        policy=json.loads((self.path/'policy.json').read_text());p=policy['profiles'][0]
        self.assertEqual(p['domains'],['example.com','*.example.com','beta.example.com']);self.assertEqual(p['domain_document'],text)
        self.assertNotIn('error',[i['severity'] for i in validate_policy(policy)])
        html=self.client.get('/rules').text
        self.assertIn('<details class="rule-conditions">',html);self.assertIn('&lt;b&gt;Видео&lt;/b&gt;',html);self.assertNotIn('<b>Видео</b>',html)
        self.assertIn('# &lt;b&gt;Видео&lt;/b&gt;',self.client.get('/rules/'+p['id']+'/edit').text)
        before=(self.path/'policy.json').read_bytes();data.update(revision=self.revision(),domains='https://broken')
        self.assertEqual(self.client.post('/rules/save',data=data).status_code,400)
        self.assertEqual(before,(self.path/'policy.json').read_bytes())
