import json,time,unittest
import test_web as fixture
class OverviewTests(unittest.TestCase):
 setUp=fixture.WebTests.setUp
 tearDown=fixture.WebTests.tearDown
 login=fixture.WebTests.login
 def test_overview_stale_is_never_green_and_names_are_escaped(self):
  self.login();self.policy['exits']['direct']['name']='<script>bad</script>'
  (self.path/'policy.json').write_text(json.dumps(self.policy))
  (self.path/'health.json').write_text(json.dumps({'version':1,'generated_at':1,'checks':[{'id':'p','name':'Test','scope':'Server','status':'up','observed_at':1,'duration_ms':1,'detail':'old','action':'Check'}]}))
  response=self.client.get('/overview');self.assertEqual(response.status_code,200)
  self.assertIn('Нет свежих данных',response.text);self.assertNotIn('Все проверки пройдены',response.text)
  self.assertNotIn('<script>bad</script>',response.text);self.assertIn('&lt;script&gt;bad',response.text)
  self.assertIn('Сохранённый черновик',response.text)
