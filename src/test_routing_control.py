import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from candidate_bundle import build_bundle
from safe_apply import digest
from candidate_control import handle,ControlError
from routing_control import tick
from routing_decision import choices
import test_candidate_config as fixtures

class FakeClient:
    def __init__(self,modes):self.modes=modes;self.mode=modes[0]['name'];self.writes=[]
    def _request(self,method):return {'mode':self.mode}
    def choose(self,selection,expected_mode):
        if expected_mode!=self.mode:raise ValueError('Changed')
        before=self.mode;self.writes.append(selection);self.mode=next(m['name'] for m in self.modes if m['selection']==selection)
        return {'changed':before!=self.mode,**next(m for m in self.modes if m['name']==self.mode)}

class RoutingControlTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.policy=fixtures.CandidateConfigTests().base();self.policy['profiles']=[]
        files=build_bundle(self.policy,api_secret='x'*32)
        for n,d in files.items():(self.root/n).write_bytes(d)
        self.manifest=json.loads(files['policy-manifest.json']);self.hash=digest(files['config.json'])
        self.state={'id':'a'*32,'status':'confirmed','next_files':{n:digest(d) for n,d in files.items()}}
        self.save_transaction();self.fake=FakeClient(self.manifest['modes'])
        self.mock=patch('routing_control.client_for',return_value=self.fake);self.mock.start()
        self.boot=patch('routing_control.boot_id',return_value='test-boot');self.boot.start()
    def tearDown(self):self.boot.stop();self.mock.stop();self.temp.cleanup()
    def save_transaction(self):(self.root/'transaction.json').write_text(json.dumps(self.state))
    def request(self,**extra):return {'version':1,'action':'routing-set','expected_config_sha256':self.hash,'expected_transaction_id':self.state['id'],'expected_preferences_revision':'absent','expected_mode':self.fake.mode,'enabled':False,'pins':{},**extra}
    def test_owner_pin_persists_and_changes_mode_with_readback(self):
        pin=choices(self.manifest)['default'][1]['id'];result=handle(self.request(pins={'default':pin}),root=self.root)
        self.assertEqual(result['selection']['default'],1)
        prefs=json.loads((self.root/'routing-preferences.json').read_text());self.assertEqual(prefs['pins']['default'],pin)
        self.assertNotIn('x'*32,json.dumps(result))
    def test_stale_ui_or_pending_apply_cannot_write_preferences(self):
        for patch_ in [{'expected_transaction_id':'old'},{'expected_config_sha256':'wrong'},{'expected_preferences_revision':'old'},{'expected_mode':'other'}]:
            with self.assertRaises(ControlError):handle(self.request(**patch_),root=self.root)
        self.state['status']='pending';self.save_transaction()
        with self.assertRaises(ControlError):handle(self.request(),root=self.root)
        self.assertFalse((self.root/'routing-preferences.json').exists());self.assertFalse(self.fake.writes)
    def test_no_coverage_blocks_enable_without_mutation(self):
        with self.assertRaises(ControlError):handle(self.request(enabled=True),root=self.root)
        self.assertFalse((self.root/'routing-preferences.json').exists())
    def test_disabled_default_has_no_switch_and_no_monitor_dependency(self):
        with patch('pathlib.Path.read_text',autospec=True) as read:
            # Only boot-id uses read_text in this path.
            read.return_value='test-boot'
            result=tick(self.root,self.root/'missing-health.json',now=100)
        self.assertFalse(self.fake.writes);self.assertIn('выключена',result['reasons']['default'])
    def test_foreign_paths_and_actions_are_rejected(self):
        with self.assertRaises(ControlError):handle({'version':1,'action':'routing-status','path':'/etc/shadow'},root=self.root)

class RoutingNativeClientTests(RoutingControlTests):
    def setUp(self):
        super().setUp();self.mock.stop()
        import threading
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                body=json.dumps({'mode':outer.fake.mode,'mode-list':[m['name'] for m in outer.manifest['modes']]}).encode()
                self.send_response(200);self.end_headers();self.wfile.write(body)
            def do_PATCH(self):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));outer.fake.mode=body['mode'];outer.fake.writes.append(body)
                self.send_response(204);self.end_headers()
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        from mode_client import ModeClient
        def actual(root,config,manifest,state):
            return ModeClient(manifest['modes'],api_secret='x'*32,lock_path=root/'mode.lock',api_port=self.server.server_port,bound_config_sha256=manifest['config_sha256'],bound_transaction=state['id'],require_settled=True)
        self.mock=patch('routing_control.client_for',side_effect=actual);self.mock.start()
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();super().tearDown()
    def health(self,t,statuses=('down','up')):
        pairs=choices(self.manifest)['default'];rows=[]
        for p,status in zip(pairs,statuses):
            rows.append({'id':p['id'],'name':'Test','scope':'test','status':status,'detail':'Test','action':'Inspect','observed_at':t,'duration_ms':1,'config_sha256':self.hash,'transaction_id':self.state['id']})
        path=self.root/'health.json';path.write_text(json.dumps({'version':1,'generated_at':t,'checks':rows}));return path
    def enable_fixture(self):
        (self.root/'routing-preferences.json').write_text(json.dumps({'revision':'test','enabled':True,'pins':{}}))
    def test_tick_switches_with_real_mode_client_and_records_event(self):
        self.enable_fixture()
        for t in (100,105,110):tick(self.root,self.health(t),now=t)
        self.assertEqual(self.fake.mode,self.manifest['modes'][1]['name'])
        events=json.loads((self.root/'routing-events.json').read_text());self.assertEqual(len(events),1)
        self.assertEqual(events[0]['to'],self.fake.mode)
    def test_tick_reconciles_pin_after_runtime_divergence(self):
        pin=choices(self.manifest)['default'][1]['id'];handle(self.request(pins={'default':pin}),root=self.root)
        self.fake.mode=self.manifest['modes'][0]['name']
        tick(self.root,self.health(100,('up','down')),now=100)
        self.assertEqual(self.fake.mode,self.manifest['modes'][1]['name'])
    def test_event_write_failure_preserves_decision_and_replays_once(self):
        self.enable_fixture()
        for t in (100,105):tick(self.root,self.health(t),now=t)
        with patch('routing_control.append_event',side_effect=OSError('Disk temporarily busy')):
            with self.assertRaises(OSError):tick(self.root,self.health(110),now=110)
        saved=json.loads((self.root/'routing-state.json').read_text());self.assertIn('decision',saved);self.assertIn('transition',saved)
        tick(self.root,self.health(110),now=111)
        events=json.loads((self.root/'routing-events.json').read_text());self.assertEqual(len(events),1)
        self.assertNotIn('transition',json.loads((self.root/'routing-state.json').read_text()))
    def test_lock_busy_does_not_clobber_state(self):
        import fcntl
        path=self.root/'routing-state.json';path.write_text('{"preserved": true}')
        with (self.root/'routing.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            with self.assertRaises(ValueError):tick(self.root,self.health(100),now=100)
        self.assertEqual(json.loads(path.read_text()),{'preserved':True})
