import base64,copy,hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from router_settings import DEFAULT,compile_settings,status_view,validate
from router_health import decode_packet,RouterRemote
from health_settings import fingerprint,form_fields
from candidate_remote import RemoteError
import test_web as fixtures
from web import create_app

class RouterSettingsTests(unittest.TestCase):
    def test_compiled_values_are_data_and_not_shell_commands(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);check=copy.deepcopy(DEFAULT)
            check['name']="Name ' $(touch "+str(root/'unexpected')+") `false`"
            path=root/'settings.sh';path.write_bytes(compile_settings(check))
            r=subprocess.run(['sh','-c','. "$1"; printf "%s" "$SETTINGS_JSON"','sh',str(path)],capture_output=True,text=True,check=True)
            self.assertEqual(json.loads(r.stdout),check);self.assertFalse((root/'unexpected').exists())

    def test_endpoint_constraints(self):
        for changes in [{'server':'8.8.8.8'},{'server':'::1'},{'url':'http://example.com'},{'url':'https://example.com:444'},{'url':'https://1.1.1.1'},{'url':'https://example.com/?token=x'},{'domain':'*.example.com'}]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):compile_settings({**DEFAULT,**changes})

    def test_old_measurement_cannot_restore_success_after_edit(self):
        old=fingerprint(DEFAULT);check={**DEFAULT,'domain':'api.ipify.org'}
        measurement={'status':'up','observed_at':1000,'uptime_seconds':100,'dns_udp':'up','dns_tcp':'up','https':'up','http_code':200}
        packet={'settings':{'check':check,'revision':fingerprint(check),'persistent_matches':True},'snapshot':{'version':1,'revision':old,'measurement':measurement}}
        result=decode_packet(packet);self.assertEqual({c['status'] for c in result['checks']},{'unknown'})
        self.assertEqual(result['generated_at'],1000)
        packet['snapshot']['revision']=fingerprint(check);packet['settings']['persistent_matches']=False
        self.assertEqual({c['status'] for c in decode_packet(packet)['checks']},{'degraded'})

    def test_remote_save_is_not_retried_and_invalidates_local_success(self):
        current={'check':DEFAULT,'revision':fingerprint(DEFAULT),'persistent_matches':True}
        values={f['key']:str(f['value']) for f in form_fields(DEFAULT)};values['dns_port']='15459'
        with tempfile.TemporaryDirectory() as d,patch('router_health.connect') as connect,patch('router_health.exchange',side_effect=[current,OSError('connection lost')]) as exchange:
            remote=RouterRemote(Path(d))
            with self.assertRaisesRegex(RemoteError,'не подтверждён'):remote.save(fingerprint(DEFAULT),values)
            self.assertEqual(exchange.call_count,2)
            self.assertEqual({c['status'] for c in json.loads((Path(d)/'router-health.json').read_text())['checks']},{'unknown'})
        with tempfile.TemporaryDirectory() as d,patch('router_health.connect'),patch('router_health.exchange',return_value=current) as exchange:
            with self.assertRaisesRegex(RemoteError,'уже изменились'):RouterRemote(Path(d)).save('0'*64,values)
            self.assertEqual(exchange.call_count,1)
        for failure in ['busy','payload','persist']:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as d,patch('router_health.connect'),patch('router_health.exchange',side_effect=[current,{'error':failure}]) as exchange:
                with self.assertRaisesRegex(RemoteError,'не сохранены'):RouterRemote(Path(d)).save(fingerprint(DEFAULT),values)
                self.assertEqual(exchange.call_count,2)

    def test_router_control_compare_and_swap_and_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            top=Path(d);root=top/'ram';base=top/'usb';base.mkdir()
            for name in ['state','opt/bin','opt/lib']:(root/name).mkdir(parents=True,exist_ok=True)
            ld=root/'opt/lib/ld.so.1';ld.write_text('#!/bin/sh\nshift 2\nexec "$@"\n');ld.chmod(0o700)
            bb=root/'opt/bin/busybox';bb.write_text('''#!/usr/bin/env python3
import hashlib,os,sys
if sys.argv[1]=='fsync':
 fd=os.open(sys.argv[2],os.O_RDONLY);os.fsync(fd);os.close(fd)
elif sys.argv[1]=='sha256sum':
 print(hashlib.sha256(open(sys.argv[2],'rb').read()).hexdigest()+'  '+sys.argv[2])
else:os.execvp(sys.argv[1],sys.argv[1:])
''');bb.chmod(0o700)
            for p in [root/'settings.sh',base/'settings.sh']:p.write_bytes(compile_settings(DEFAULT))
            text=(Path(__file__).parent/'router/settings-control.sh').read_text().replace('/tmp/okopy-router-monitor',str(root)).replace('/opt/okopy-router-monitor',str(base))
            control=top/'control.sh';control.write_text(text)
            def call(args,content=b''):
                # Entware ash supports read -t; Debian /bin/sh (dash) does not.
                r=subprocess.run(['bash',str(control),*args],input=base64.b64encode(content)+b'\n',capture_output=True,timeout=6)
                self.assertEqual(r.returncode,0,r.stderr.decode());return json.loads(r.stdout)
            new={**DEFAULT,'dns_port':15459};blob=compile_settings(new)
            value=call(['apply',fingerprint(DEFAULT),hashlib.sha256(blob).hexdigest()],blob);self.assertTrue(value['saved'])
            self.assertEqual((root/'settings.sh').read_bytes(),blob);self.assertEqual((base/'settings.sh').read_bytes(),blob)
            self.assertEqual(call(['status'])['revision'],fingerprint(new))
            self.assertEqual(call(['apply',fingerprint(DEFAULT),hashlib.sha256(blob).hexdigest()],blob),{'error':'conflict'})
            lock=root/'state/settings.lock';lock.mkdir()
            self.assertEqual(call(['apply',fingerprint(new),hashlib.sha256(blob).hexdigest()],blob),{'error':'busy'})
            self.assertEqual(call(['status']),{'error':'busy'})
            lock.rmdir()
            self.assertEqual(call(['apply',fingerprint(new),'0'*64],blob),{'error':'payload'})
            self.assertFalse(lock.exists())
            (base/'settings.previous.sh').unlink();(base/'settings.previous.sh').mkdir()
            # A blocked USB preparation must not change the live or persistent settings.
            (base/'settings.previous.sh'/'settings.sh').mkdir()
            altered=compile_settings({**new,'domain':'api.ipify.org'})
            self.assertEqual(call(['apply',fingerprint(new),hashlib.sha256(altered).hexdigest()],altered),{'error':'persist'})
            self.assertEqual((root/'settings.sh').read_bytes(),blob);self.assertEqual((base/'settings.sh').read_bytes(),blob)
            self.assertFalse(lock.exists())
            call(['status'])
            (base/'settings.sh').write_bytes(compile_settings(DEFAULT))
            self.assertFalse(call(['status'])['persistent_matches'])
            self.assertFalse(call(['read'])['settings']['persistent_matches'])
            (base/'settings.sh').write_bytes(blob);call(['status'])
            state=call(['read']);self.assertEqual(state['snapshot']['measurement']['status'],'unknown')
            self.assertTrue(status_view(state['settings'])['persistent_matches'])
            # USB read would block on this FIFO. The regular read path must use RAM only.
            (base/'settings.sh').unlink();os.mkfifo(base/'settings.sh')
            start=__import__('time').monotonic();state=call(['read'])
            self.assertLess(__import__('time').monotonic()-start,2)
            self.assertTrue(status_view(state['settings'])['persistent_matches'])
            (root/'state/persisted-settings.sh').unlink()
            self.assertFalse(call(['read'])['settings']['persistent_matches'])

class RouterSettingsWebTests(unittest.TestCase):
    setUp=fixtures.WebTests.setUp
    tearDown=fixtures.WebTests.tearDown
    login=fixtures.WebTests.login

    def test_historical_router_settings_are_not_in_current_panel(self):
        from unittest.mock import Mock
        remote=Mock();remote.status.return_value=status_view({'check':DEFAULT,'revision':fingerprint(DEFAULT),'persistent_matches':True})
        self.app=create_app(self.path,router_monitor=remote);self.app.testing=True;self.client=self.app.test_client()
        self.assertEqual(self.client.get('/health/settings/router:default').status_code,302)
        csrf=self.login()
        self.assertEqual(self.client.get('/health/settings/router:default').status_code,404)
        self.assertEqual(self.client.post('/health/settings/router:default',data={'csrf':csrf,'revision':fingerprint(DEFAULT)}).status_code,404)
        remote.save.assert_not_called()

if __name__=='__main__':unittest.main()
