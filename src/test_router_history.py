import copy,json,os,signal,subprocess,tempfile,time,unittest
from pathlib import Path
from router_health import decode_packet
from router_settings import DEFAULT,compile_settings
from health_settings import fingerprint

VALUE={'status':'up','observed_at':1000,'uptime_seconds':100,'dns_udp':'up','dns_tcp':'up','https':'up','http_code':200}

def packet(history):
 return {'settings':{'check':DEFAULT,'revision':fingerprint(DEFAULT),'persistent_matches':True},'snapshot':{'version':2,'revision':fingerprint(DEFAULT),'measurement':VALUE,'history':history}}
def record(**changes):return {'revision':fingerprint(DEFAULT),'measurement':{**VALUE,**changes}}

class RouterHistoryTests(unittest.TestCase):
 def test_transient_failure_is_preserved_after_recovery_between_polls(self):
  history=[record(),record(status='down',observed_at=1006,dns_udp='down'),record(observed_at=1012)]
  value=decode_packet(packet(history))
  self.assertEqual({x['status'] for x in value['checks']},{'up'})
  self.assertEqual([(e['at'],e['status']) for e in value['events'] if e['id']==DEFAULT['id']+':dns_udp'],[(1000,'up'),(1006,'down'),(1012,'up')])

 def test_history_validation_and_configuration_change(self):
  for bad in [None,[record()]*11,[{'revision':'invalid','measurement':VALUE}],[record(status='down')]]:
   with self.subTest(bad=bad),self.assertRaises(ValueError):decode_packet(packet(bad))
  older=record();older['revision']='a'*64
  value=decode_packet(packet([older,record(observed_at=1006)]))
  self.assertEqual(len(value['events']),6);self.assertTrue(all('Изменились параметры' in e['detail'] for e in value['events'][-3:]))

 def test_monitor_records_transitions_in_ram_with_bounded_history(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)
   for name in ['state','opt/bin','opt/lib']:(root/name).mkdir(parents=True,exist_ok=True)
   ld=root/'opt/lib/ld.so.1';ld.write_text('#!/bin/sh\nshift 2\nexec "$@"\n');ld.chmod(0o700)
   bb=root/'opt/bin/busybox';bb.write_text('#!/bin/sh\nif [ "$1" = sleep ]; then exec sleep .01; fi\nexec "$@"\n');bb.chmod(0o700)
   (root/'settings.sh').write_bytes(compile_settings(DEFAULT))
   # One repeated success, then transitions. Pause before publishing cycle 13.
   mock=root/'mock-health.py';mock.write_text('''import json,pathlib,sys,time
root=pathlib.Path(sys.argv[1]);p=root/'counter'
n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
if n>=13:time.sleep(30)
state='up' if n<=2 or n%2==0 else 'down'
print(json.dumps({'status':state,'observed_at':1000+n,'uptime_seconds':n,'dns_udp':state,'dns_tcp':state,'https':state,'http_code':200 if state=='up' else 0},separators=(',',':')))
''')
   import sys
   (root/'health.sh').write_text('#!/bin/sh\nexec '+sys.executable+' '+str(mock)+' "$1"\n')
   monitor=(Path(__file__).parent/'router/monitor.sh').read_text().replace('/tmp/okopy-router-monitor',str(root))
   (root/'monitor.sh').write_text(monitor)
   proc=subprocess.Popen(['sh',str(root/'monitor.sh')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
   try:
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
     try:
      if int((root/'counter').read_text())>=13:break
     except (OSError,ValueError):pass
     time.sleep(.03)
    else:self.fail('Monitor did not finish bounded scenario')
    wire=json.loads((root/'state/health.json').read_text());self.assertEqual(wire['version'],2)
    self.assertEqual([r['measurement']['uptime_seconds'] for r in wire['history']],list(range(3,13)))
    self.assertEqual(len((root/'state/history.jsonl').read_text().splitlines()),10)
    value=decode_packet({**packet([]),'snapshot':wire});self.assertEqual(len(value['events']),30)
   finally:
    if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM)
    try:proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()

if __name__=='__main__':unittest.main()
