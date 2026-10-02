"""Exercise the real shell control flow, with executable stand-ins for network I/O."""
import json,os,subprocess,tempfile,time,unittest
from pathlib import Path

class RouterHealthTests(unittest.TestCase):
    def probe(self,mode):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for name in ('opt/lib','opt/bin','tmp'):(root/name).mkdir(parents=True,exist_ok=True)
            programs={
                'opt/lib/ld.so.1':'#!/bin/sh\nshift 2\nexec "$@"\n',
                'opt/bin/busybox':'#!/bin/sh\nexec "$@"\n',
                'opt/bin/dig':'''#!/usr/bin/env python3
import os,sys,time
mode=os.environ['PROBE_MODE'];udp='+notcp' in sys.argv
if mode=='hang' and udp:time.sleep(30)
status='REFUSED' if mode=='refused' else 'NOERROR'
print(';; ->>HEADER<<- opcode: QUERY, status: '+status+', id: 2')
print(';; flags: qr rd ra'+(' tc' if mode=='truncated' and udp else '')+'; QUERY: 1, ANSWER: 1')
if status=='NOERROR':print('example.com. 30 IN A 203.0.113.1')
''',
                'opt/bin/curl':'''#!/usr/bin/env python3
import os,sys
print('200' if os.environ['PROBE_MODE']!='https-failure' else '000',end='')
sys.exit(7 if os.environ['PROBE_MODE']=='https-failure' else 0)
'''}
            for name,content in programs.items():
                p=root/name;p.write_text(content);p.chmod(0o700)
            # macOS lacks procfs. Only the monotonic-clock file is substituted.
            clock=root/'uptime';clock.write_text('123.42 99.00\n')
            text=(Path(__file__).parent/'router/health.sh').read_text().replace('/proc/uptime',str(clock))
            script=root/'probe.sh';script.write_text(text)
            started=time.monotonic()
            r=subprocess.run(['sh',str(script),str(root),'192.168.2.43','15454','15458','example.com','https://api.ipify.org'],
                             env={**os.environ,'PROBE_MODE':mode},capture_output=True,text=True,timeout=8)
            elapsed=time.monotonic()-started
            value=json.loads(r.stdout);self.assertEqual(value['uptime_seconds'],123)
            self.assertFalse(list((root/'tmp').iterdir()))
            return r.returncode,value,elapsed

    def test_independent_dns_and_https_success(self):
        rc,v,elapsed=self.probe('up');self.assertLess(elapsed,2);self.assertEqual(rc,0);self.assertEqual(v['status'],'up')
        self.assertEqual([v[x] for x in ['dns_udp','dns_tcp','https']],['up']*3)

    def test_refused_is_not_success_despite_zero_exit(self):
        rc,v,_=self.probe('refused');self.assertNotEqual(rc,0)
        self.assertEqual([v[x] for x in ['dns_udp','dns_tcp','https']],['down','down','up'])

    def test_udp_truncation_is_not_hidden_by_tcp_success(self):
        rc,v,_=self.probe('truncated');self.assertNotEqual(rc,0)
        self.assertEqual([v[x] for x in ['dns_udp','dns_tcp','https']],['down','up','up'])

    def test_process_initialization_hang_has_external_deadline(self):
        rc,v,elapsed=self.probe('hang');self.assertNotEqual(rc,0)
        self.assertEqual([v[x] for x in ['dns_udp','dns_tcp','https']],['down','up','up'])
        self.assertLess(elapsed,6)

    def test_https_failure_keeps_dns_results(self):
        rc,v,_=self.probe('https-failure');self.assertNotEqual(rc,0)
        self.assertEqual([v[x] for x in ['dns_udp','dns_tcp','https']],['up','up','down'])
        self.assertEqual(v['http_code'],0)

if __name__=='__main__':unittest.main()
