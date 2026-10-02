import base64,hashlib,json,os,platform,shutil,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from router_ipv6_settings import compile_settings,revision,parse_form,import_settings,export_settings
from router_ipv6_remote import RouterIPv6Remote,status_view
from candidate_remote import RemoteError
import test_web as fixtures

SETTINGS=dict(policy='ViaWG',server_connection='Wireguard1',provider_connection='GigabitEthernet1',prefixes=['2000::/3','fc00::/7','200::/7'],health_address='10.9.0.1',health_port=18082,probe_seconds=1,interval_seconds=2,failures=3,recovery_seconds=15)
def view(settings=SETTINGS,tx=None):
    return dict(settings=settings,revision=revision(settings),persistent_matches=True,controller='running',path='home',transaction=tx)

class SettingsTests(unittest.TestCase):
    def test_router_shell_keeps_the_full_argument_vector_and_rejects_commands(self):
        from router_health import control_command
        with tempfile.TemporaryDirectory() as d:
            script=Path(d)/'echo.sh';script.write_text('printf "%s\\n" "$#" "$@"\n')
            control='exec /usr/bin/env sh '+str(script)
            action='apply '+'a'*64+' '+'b'*64+' '+'c'*64+' '+'d'*32
            p=subprocess.run(['sh','-c',control_command(control,action)],capture_output=True,text=True,check=True)
            self.assertEqual(p.stdout.splitlines(),['5',*action.split()])
            for bad in ['status; reboot','apply $(id)','apply `id`','status\nreboot']:
                with self.assertRaises(ValueError):control_command(control,bad)
    def test_import_export_and_form_preserve_all_fields(self):
        self.assertEqual(import_settings(export_settings(SETTINGS)),SETTINGS)
        form={k:'\n'.join(v) if isinstance(v,list) else str(v) for k,v in SETTINGS.items()}
        self.assertEqual(parse_form(form),SETTINGS)
        for raw in ['{}','{"version":true,"settings":{}}','not-json',export_settings(SETTINGS).replace('Wireguard1','a;reboot')]:
            with self.subTest(raw=raw),self.assertRaises(ValueError):import_settings(raw)
        for bad in ['1.5','-1','yes','999999']:
            with self.assertRaises(ValueError):parse_form(form|{'failures':bad})
    def test_reply_must_match_configuration_and_transaction(self):
        self.assertEqual(status_view(view()),view())
        for bad in [view()|{'revision':'0'*64},view()|{'persistent_matches':1},view()|{'transaction':{'id':'1'*32,'status':'pending','remaining_seconds':121}}]:
            with self.assertRaises(ValueError):status_view(bad)
    def test_remote_rejects_stale_form_and_never_retries_uncertain_apply(self):
        with patch('router_ipv6_remote.connect'),patch('router_ipv6_remote.exchange',return_value=view()) as exchange:
            with self.assertRaisesRegex(RemoteError,'уже изменились'):RouterIPv6Remote('unused').apply('0'*64,SETTINGS|{'failures':4})
            self.assertEqual(exchange.call_count,1)
        with patch('router_ipv6_remote.connect'),patch('router_ipv6_remote.exchange',side_effect=[view(),OSError('disconnected')]) as exchange:
            with self.assertRaisesRegex(RemoteError,'не подтверждён'):RouterIPv6Remote('unused').apply(revision(SETTINGS),SETTINGS|{'failures':4})
            self.assertEqual(exchange.call_count,2)

class WebTests(unittest.TestCase):
    setUp=fixtures.WebTests.setUp
    tearDown=fixtures.WebTests.tearDown
    login=fixtures.WebTests.login
    def test_historical_ipv6_routes_do_not_accept_actions(self):
        remote=Mock();remote.status.return_value=view();remote.choices.return_value={'policies':[{'id':'ViaWG','label':'ViaWG'}],'interfaces':[{'id':'Wireguard1','label':'Сервер'},{'id':'GigabitEthernet1','label':'Провайдер'}]}
        self.app.extensions['router_ipv6']=remote
        self.assertEqual(self.client.get('/routers/giga/ipv6').status_code,302)
        csrf=self.login()
        self.assertEqual(self.client.get('/routers/giga/ipv6').status_code,404)
        self.assertEqual(self.client.post('/routers/giga/ipv6/apply',data={'revision':revision(SETTINGS)}).status_code,403)
        self.assertEqual(self.client.post('/routers/giga/ipv6/apply',data={'csrf':csrf,'revision':revision(SETTINGS)}).status_code,404)
        self.assertEqual(self.client.post('/routers/giga/ipv6/confirm',data={'csrf':csrf,'transaction':'a'*32}).status_code,404)
        remote.apply.assert_not_called();remote.finish.assert_not_called()

@unittest.skipUnless(platform.system()=='Linux' and shutil.which('busybox'),'Native Linux process/timeout semantics')
class RouterTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='okopy-ipv6-control-test-',dir='/tmp')
        self.top=Path(self.temp.name);self.root=self.top/'ram';self.base=self.top/'usb';self.edit=self.top/'edit'
        for p in [self.base,self.root/'state',self.root/'opt/bin',self.root/'opt/lib',self.root/'opt/libexec']:p.mkdir(parents=True,exist_ok=True)
        ld=self.root/'opt/lib/ld.so.1';ld.write_text('#!/bin/sh\nshift 2\nexec "$@"\n');ld.chmod(0o700)
        # Ubuntu BusyBox lacks Entware's -O log option. Keep its real daemon,
        # /proc and process semantics; remove only that logging option here.
        bb=self.root/'opt/bin/busybox'
        bb.write_text('#!/usr/bin/python3\nimport os,sys\nargs=sys.argv[1:]\nif args[0]=="start-stop-daemon" and "-O" in args:\n i=args.index("-O");del args[i:i+2]\nif args[0]=="fsync":\n fd=os.open(args[1],os.O_RDONLY);os.fsync(fd);os.close(fd);raise SystemExit(0)\nos.execv('+repr(shutil.which('busybox'))+',['+repr(shutil.which('busybox'))+']+args)\n')
        bb.chmod(0o700)
        (self.root/'opt/libexec/timeout-coreutils').symlink_to(shutil.which('timeout'))
        for p in [self.root/'ipv6-settings.sh',self.base/'ipv6-settings.sh']:p.write_bytes(compile_settings(SETTINGS))
        self.control=self.root/'ipv6-control.sh'
        self.control.write_text((Path(__file__).parent/'router/ipv6-control.sh').read_text().replace('/tmp/okopy-router-ipv6-edit',str(self.edit)).replace('/tmp/okopy-router-ipv6',str(self.root)).replace('/opt/okopy-router-ipv6',str(self.base)))
        (self.root/'ipv6-routes.sh').write_text('''#!/bin/sh
. "$1/ipv6-settings.sh"
[ "$POLICY" != Missing ] || exit 1
mode=provider
[ ! -r "$1/state/path" ] || mode=$(cat "$1/state/path")
[ "$3" = check ] && [ "$4" = "$mode" ]
''')
        (self.root/'ipv6-service.sh').write_text('''#!/bin/sh
root=$1
while [ ! -f "$root/state/service.stop" ]; do
 . "$root/ipv6-settings.sh"
 read -r uptime rest < /proc/uptime
 echo "${uptime%%.*}" > "$root/state/tick.next"; mv "$root/state/tick.next" "$root/state/worker.tick"
 echo "$REVISION home" > "$root/state/decision.next"; mv "$root/state/decision.next" "$root/state/decision"
 echo watching > "$root/state/supervisor.next"; mv "$root/state/supervisor.next" "$root/state/supervisor.status"
 echo home > "$root/state/path"
 sleep .1
done
echo provider > "$root/state/path"
''')
        self.proc=subprocess.Popen(['sh',str(self.root/'ipv6-service.sh'),str(self.root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (self.root/'state/service.pid').write_text(str(self.proc.pid));time.sleep(.2)
    def tearDown(self):
        (self.root/'state/service.stop').touch()
        for pidfile in [self.root/'state/service.pid',*self.edit.glob('guard-*.pid')]:
            try:os.kill(int(pidfile.read_text()),15)
            except (OSError,ValueError):pass
        self.proc.wait(timeout=3);time.sleep(.2);self.temp.cleanup()
    def call(self,args,blob=b''):
        p=subprocess.run([shutil.which('busybox'),'sh',str(self.control),*args],input=base64.b64encode(blob)+b'\n',capture_output=True,timeout=35)
        self.assertEqual(p.returncode,0,p.stderr.decode());return json.loads(p.stdout)
    def apply(self,settings,tx='a'*32,expected=None):
        blob=compile_settings(settings)
        return self.call(['apply',expected or revision(SETTINGS),hashlib.sha256(blob).hexdigest(),revision(settings),tx],blob)
    def test_ram_trial_confirm_and_idempotent_stale_guard(self):
        changed=SETTINGS|{'recovery_seconds':16}
        self.assertTrue(self.apply(changed)['applied'])
        end=time.monotonic()+5
        while time.monotonic()<end:
            if self.call(['status'])['controller']=='running':break
            time.sleep(.1)
        self.assertEqual(self.call(['status'])['controller'],'running')
        self.assertEqual((self.base/'ipv6-settings.sh').read_bytes(),compile_settings(SETTINGS))
        status=self.call(['status']);self.assertFalse(status['persistent_matches']);self.assertEqual(status['transaction']['status'],'pending')
        self.assertEqual(self.apply(changed,tx='b'*32),{'error':'pending'})
        self.assertEqual(self.call(['confirm','a'*32]),{'done':True})
        self.assertEqual((self.base/'ipv6-settings.sh').read_bytes(),compile_settings(changed))
        self.assertEqual(self.call(['rollback','a'*32]),{'error':'transaction'})
        self.assertEqual(self.call(['status'])['transaction']['status'],'confirmed')
    def test_guard_retries_busy_lock_then_restores_without_panel(self):
        changed=SETTINGS|{'failures':4};self.assertTrue(self.apply(changed)['applied'])
        lock=self.edit/'lock';lock.mkdir();(lock/'pid').write_text(str(os.getpid()))
        (self.edit/'deadline').write_text('0');time.sleep(1.3)
        self.assertEqual((self.edit/'status').read_text().strip(),'pending')
        (lock/'pid').unlink();lock.rmdir()
        end=time.monotonic()+8
        while time.monotonic()<end and (self.edit/'status').read_text().strip()=='pending':time.sleep(.2)
        self.assertEqual(self.call(['status'])['transaction']['status'],'rolled_back')
        self.assertEqual((self.root/'ipv6-settings.sh').read_bytes(),compile_settings(SETTINGS))
        self.assertEqual(self.call(['confirm','a'*32]),{'error':'transaction'})
    def test_conflict_and_missing_native_base_do_not_stop_controller(self):
        self.assertEqual(self.apply(SETTINGS|{'policy':'Missing'}),{'error':'baseline'})
        self.assertIsNone(self.proc.poll())
        self.assertEqual(self.apply(SETTINGS|{'failures':4},expected='0'*64),{'error':'conflict'})
        self.assertEqual(self.call(['status'])['settings'],SETTINGS)
    def test_confirmation_does_not_overwrite_external_usb_edit(self):
        changed=SETTINGS|{'failures':4};self.assertTrue(self.apply(changed)['applied'])
        external=compile_settings(SETTINGS|{'failures':5})
        (self.base/'ipv6-settings.sh').write_bytes(external)
        self.assertEqual(self.call(['confirm','a'*32]),{'error':'conflict'})
        self.assertEqual((self.base/'ipv6-settings.sh').read_bytes(),external)
        self.assertEqual(self.call(['rollback','a'*32]),{'done':True})
        self.assertEqual((self.base/'ipv6-settings.sh').read_bytes(),external)
        self.assertEqual((self.root/'ipv6-settings.sh').read_bytes(),compile_settings(SETTINGS))
