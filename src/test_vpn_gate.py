import json,tempfile,unittest,types,fcntl
from pathlib import Path
from unittest.mock import patch
from health_settings import edit_check,form_fields
import vpn_gate

def config():
 return {'id':'gate-test','kind':'vpn_gate','name':'Gate','scope':'Network','action':'Check settings','client':'10.77.0.9','host':'10.77.0.1','port':19090,'dns_server':'127.0.0.2','dns_port':5354,'proxy':'127.0.0.2:1089','url':'https://canary.example.net:8443/path','codes':['204'],'dns_timeout_seconds':2,'timeout_seconds':4,'rise':3,'fall':2,'max_age_seconds':30,'interval_seconds':5}
def values(c):return {f['key']:str(f['value']) for f in form_fields(c)}
class GateTests(unittest.TestCase):
 def multi_address_probe(self, outcomes, *, elapsed=0, revision_changed=False):
  """Exercise DNS/curl selection without opening a socket."""
  calls=[];clock=[100.0]
  response=';; status: NOERROR\ncanary.example.net. 0 IN A 8.8.8.8\ncanary.example.net. 0 IN A 8.8.4.4\n'
  def run(args,**kwargs):
   calls.append((args,kwargs))
   if args[0]=='dig':return types.SimpleNamespace(returncode=0,stdout=response)
   address=args[args.index('--resolve')+1].rsplit(':',1)[1]
   clock[0]+=elapsed
   return types.SimpleNamespace(returncode=outcomes[address][0],stdout=outcomes[address][1])
  revisions=[(b'initial',),(b'changed',) if revision_changed else (b'initial',)]
  with patch.object(vpn_gate,'runtime_revision',side_effect=revisions) as revision, \
       patch.object(vpn_gate.subprocess,'run',side_effect=run), \
       patch.object(vpn_gate.time,'monotonic',side_effect=lambda:clock[0]):
   result=vpn_gate.probe(config())
  return result,[entry for entry in calls if entry[0][0]=='curl'],revision.call_count

 def test_first_a_failure_second_a_success_uses_same_proxy_and_tls_name(self):
  result,curls,revisions=self.multi_address_probe({'8.8.8.8':(28,'000'),'8.8.4.4':(0,'204')})
  self.assertTrue(result);self.assertEqual(len(curls),2);self.assertEqual(revisions,2)
  self.assertEqual([c[0][c[0].index('--resolve')+1] for c in curls],
                   ['canary.example.net:8443:8.8.8.8','canary.example.net:8443:8.8.4.4'])
  self.assertTrue(all(c[0][c[0].index('--socks5')+1]==config()['proxy'] for c in curls))

 def test_distinct_addresses_are_tried_once_and_all_failures_close_gate(self):
  response=';; status: NOERROR\ncanary.example.net. 0 IN A 8.8.8.8\ncanary.example.net. 0 IN A 8.8.8.8\ncanary.example.net. 0 IN A 8.8.4.4\n'
  calls=[]
  def run(args,**kwargs):
   if args[0]=='dig':return types.SimpleNamespace(returncode=0,stdout=response)
   calls.append(args);return types.SimpleNamespace(returncode=28,stdout='000')
  with patch.object(vpn_gate,'runtime_revision',return_value=(b'fixed',)), \
       patch.object(vpn_gate.subprocess,'run',side_effect=run):
   self.assertFalse(vpn_gate.probe(config()))
  self.assertEqual([c[c.index('--resolve')+1].rsplit(':',1)[1] for c in calls],['8.8.8.8','8.8.4.4'])

 def test_first_address_consuming_https_budget_prevents_second_attempt(self):
  result,curls,_=self.multi_address_probe({'8.8.8.8':(28,'000'),'8.8.4.4':(0,'204')},elapsed=config()['timeout_seconds'])
  self.assertFalse(result);self.assertEqual(len(curls),1)
  self.assertLessEqual(float(curls[0][0][curls[0][0].index('--max-time')+1]),config()['timeout_seconds'])

 def test_second_attempt_gets_only_the_remaining_https_budget(self):
  result,curls,_=self.multi_address_probe({'8.8.8.8':(28,'000'),'8.8.4.4':(0,'204')},elapsed=1)
  self.assertTrue(result);self.assertEqual(len(curls),2)
  first=float(curls[0][0][curls[0][0].index('--max-time')+1])
  second=float(curls[1][0][curls[1][0].index('--max-time')+1])
  self.assertLess(second,first)
  self.assertLessEqual(curls[1][1]['timeout'],second)

 def test_revision_change_rejects_success_after_fallback_address(self):
  result,curls,revisions=self.multi_address_probe({'8.8.8.8':(28,'000'),'8.8.4.4':(0,'204')},revision_changed=True)
  self.assertFalse(result);self.assertEqual(len(curls),2);self.assertEqual(revisions,2)

 def test_typed_settings_and_freshness_budget(self):
  c=config();self.assertEqual(edit_check(c,values(c)),c)
  for key,value in [('proxy',''),('url','http://test.example'),('client','0.0.0.0'),('host','8.8.8.8'),('max_age_seconds','5')]:
   with self.subTest(key=key),self.assertRaises(ValueError):edit_check(c,{**values(c),key:value})
 def test_dns_answer_is_used_for_tls_with_configured_inputs(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'apply.lock').touch();(root/'vpn.lock').touch();(root/'config.json').write_text('{}');(root/'transaction.json').write_text('{"id":"initial"}');(root/'applied-policy.json').write_text(json.dumps({'vpn_ingress':{'clients':['10.77.0.9/32']}}))
   calls=[]
   def run(args,**kw):
    calls.append(args);return types.SimpleNamespace(returncode=0,stdout=';; status: NOERROR\ncanary.example.net. 0 IN A 198.18.1.2\n' if args[0]=='dig' else '204')
   with patch.object(vpn_gate,'ROOT',root),patch('vpn_runtime.verify_runtime',return_value={'enabled':True}),patch.object(vpn_gate.subprocess,'run',side_effect=run):self.assertTrue(vpn_gate.probe(config()))
   self.assertIn('@127.0.0.2',calls[0]);self.assertIn('5354',calls[0]);self.assertIn('+tcp',calls[1]);self.assertIn('canary.example.net:8443:198.18.1.2',calls[2]);self.assertIn('127.0.0.2:1089',calls[2]);self.assertEqual(calls[2][-1],config()['url'])
 def test_unselected_client_cannot_open_gate(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'apply.lock').touch();(root/'vpn.lock').touch();(root/'config.json').write_text('{}');(root/'transaction.json').write_text('{"id":"initial"}');(root/'applied-policy.json').write_text(json.dumps({'vpn_ingress':{'clients':[]}}))
   with patch.object(vpn_gate,'ROOT',root),patch('vpn_runtime.verify_runtime',return_value={'enabled':True}),patch.object(vpn_gate.subprocess,'run') as command:self.assertFalse(vpn_gate.probe(config()));command.assert_not_called()
 def test_settings_revision_changes_with_canary(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);c=config();(root/'checks.json').write_text(json.dumps({'checks':[c]}));_,a=vpn_gate.settings(c['id'],root)
   c['url']='https://other.example/';(root/'checks.json').write_text(json.dumps({'checks':[c]}));_,b=vpn_gate.settings(c['id'],root);self.assertNotEqual(a,b)
 def test_slow_network_probe_does_not_hold_writer_locks(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   for name in ['apply.lock','vpn.lock']:(root/name).touch()
   (root/'config.json').write_text('{}');(root/'transaction.json').write_text('{"id":"initial"}')
   (root/'applied-policy.json').write_text(json.dumps({'vpn_ingress':{'clients':['10.77.0.9/32']}}))
   def network(args,**kw):
    for name in ['apply.lock','vpn.lock']:
     with (root/name).open('r') as writer:fcntl.flock(writer,fcntl.LOCK_EX|fcntl.LOCK_NB)
    return types.SimpleNamespace(returncode=0,stdout=';; status: NOERROR\ncanary.example.net. 0 IN A 198.18.1.2\n' if args[0]=='dig' else '204')
   with patch.object(vpn_gate,'ROOT',root),patch('vpn_runtime.verify_runtime',return_value={'enabled':True}),patch.object(vpn_gate.subprocess,'run',side_effect=network):self.assertTrue(vpn_gate.probe(config()))
 def test_changed_transaction_cannot_report_old_probe_healthy(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   for name in ['apply.lock','vpn.lock']:(root/name).touch()
   (root/'config.json').write_text('{}');(root/'transaction.json').write_text('{"id":"initial"}')
   (root/'applied-policy.json').write_text(json.dumps({'vpn_ingress':{'clients':['10.77.0.9/32']}}))
   def network(args,**kw):
    if args[0]=='curl':(root/'transaction.json').write_text('{"id":"replaced-and-rolled-back"}')
    return types.SimpleNamespace(returncode=0,stdout=';; status: NOERROR\ncanary.example.net. 0 IN A 198.18.1.2\n' if args[0]=='dig' else '204')
   with patch.object(vpn_gate,'ROOT',root),patch('vpn_runtime.verify_runtime',return_value={'enabled':True}),patch.object(vpn_gate.subprocess,'run',side_effect=network):self.assertFalse(vpn_gate.probe(config()))
if __name__=='__main__':unittest.main()
