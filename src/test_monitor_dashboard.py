import json,time,unittest
from pathlib import Path
from health_settings import new_check,read_settings
from monitor_control import control
from monitor_view import read_view,save_view,arrange
from health_model import present_snapshot
import test_monitor_settings as fixture
from test_monitor_settings import CHECK,values

class DashboardTests(unittest.TestCase):
 setUp=fixture.MonitorWebTests.setUp
 tearDown=fixture.MonitorWebTests.tearDown
 login=fixture.MonitorWebTests.login
 def add(self,kind='dns'):
  v=values(new_check(kind,''));v['name']='Added probe'
  if kind=='dns':v['domain']='example.com'
  if kind=='tcp':v['host']='192.0.2.2'
  return control({'version':1,'action':'monitor-add','kind':kind,'revision':read_settings(self.monitor)[1],'values':v},self.monitor)['selected']['id']
 def test_layout_cas_persistence_hidden_failure_stays_in_summary(self):
  token=self.login();identifier=self.add();order=[identifier,CHECK['id']]
  self.assertEqual(self.client.post('/health/dashboard',data={}).status_code,403)
  r=self.client.post('/health/dashboard',data={'csrf':token,'view_revision':'empty','order':order,'visible':[identifier]})
  self.assertEqual(r.status_code,302)
  view,revision=read_view(self.path);self.assertEqual(view,{'order':order,'hidden':[CHECK['id']]})
  self.assertEqual(self.client.post('/health/dashboard',data={'csrf':token,'view_revision':'empty','order':order}).status_code,409)
  now=time.time();rows=[]
  for key,state in [(CHECK['id'],'down'),(identifier,'up')]:rows.append({'id':key,'name':key,'scope':'Tests','status':state,'detail':'test','action':'Check','observed_at':now,'duration_ms':1})
  (self.path/'health.json').write_text(json.dumps({'version':1,'generated_at':now,'checks':rows}))
  page=self.client.get('/health').text
  self.assertIn('Требуют внимания: 1',page);self.assertIn('Скрыто карточек: 1',page)
  self.assertNotIn('identifier=server:dns:test',page)
  self.assertEqual([r['id'] for r in arrange(rows,view,True)],[identifier])
  with self.assertRaises(ValueError):save_view(self.path,revision,[identifier],[identifier],set(order))
 def test_retype_custom_probe_preserves_id_and_invalidates_old_result(self):
  token=self.login();identifier=self.add();now=time.time()
  row={'id':identifier,'name':'Added probe','scope':'Tests','status':'up','detail':'old','action':'Check','observed_at':now,'duration_ms':1}
  (self.monitor/'health.json').write_text(json.dumps({'version':1,'generated_at':now,'checks':[row]}))
  fields={**values(new_check('tcp',identifier)),'host':'192.0.2.4','kind':'tcp','csrf':token,'revision':read_settings(self.monitor)[1]}
  self.assertEqual(self.client.post('/health/settings/'+identifier,data=fields).status_code,302)
  current=read_settings(self.monitor)[0]['checks'][-1]
  self.assertEqual(current['id'],identifier);self.assertEqual(current['kind'],'tcp');self.assertNotIn('domain',current)
  self.assertEqual(json.loads((self.monitor/'health.json').read_text())['checks'][0]['status'],'unknown')
  fields['revision']=read_settings(self.monitor)[1]
  self.assertEqual(self.client.post('/health/settings/'+CHECK['id'],data=fields).status_code,400)
 def test_unrelated_router_endpoints_unavailable(self):
  self.login()
  for path in ['/routers','/routers/new','/routers/giga/ipv6','/lan/fallback']:
   self.assertEqual(self.client.get(path).status_code,404,path)
 def test_management_has_explicit_actions_type_inside_editor(self):
  self.login();identifier=self.add()
  page=self.client.get('/health/settings').text
  for phrase in ['Добавить датчик','Изменить или удалить','На дашборде','data-drag-handle']:self.assertIn(phrase,page)
  self.assertNotIn('?kind=',page)
  page=self.client.get('/health/settings/'+identifier).text
  self.assertIn('data-monitor-kind',page);self.assertIn('data-monitor-fields="tcp"',page)

if __name__=='__main__':unittest.main()
