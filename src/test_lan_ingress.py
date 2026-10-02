import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from candidate_bundle import build_bundle, validate_bundle, encode
from lan_ingress import settings, validate_config
import lan_runtime
from safe_apply import Backend, digest
import test_candidate_config as config_tests
import test_web as web_tests

LAN = {'enabled':True,'listen':'192.168.2.43','interface':'enp0s25',
       'gateway':'192.168.2.1','return_via_gateway':False,'transparent_targets':[],'gateway_probe_domains':[],'clients':['192.168.2.82/32']}


class LanTests(unittest.TestCase):
    def policy(self):
        p=config_tests.CandidateConfigTests().base();p['lan_ingress']=copy.deepcopy(LAN)
        p['profiles'][0]['source_networks']=['192.168.2.82/32']
        return p

    def bundle(self):
        return build_bundle(self.policy(),api_secret='x'*32,options={'default_filtering':False,'lan_adapter':True})

    def test_private_listener_requires_installed_adapter_and_source_guard(self):
        with self.assertRaisesRegex(ValueError,'адаптера'):build_bundle(self.policy(),api_secret='x'*32)
        files=self.bundle();validate_bundle(files);c=json.loads(files['config.json'])
        validate_config(c,LAN)
        self.assertEqual(c['route']['rules'][0]['rules'][1],{'source_ip_cidr':LAN['clients'],'invert':True})
        self.assertIn('source_ip_cidr',json.dumps(c['dns']['rules']))
        self.assertEqual([i['listen'] for i in c['inbounds'][-2:]],['192.168.2.43']*2)
        c['route']['rules'].pop(0)
        with self.assertRaises(ValueError):validate_config(c,LAN)
        files['config.json']=encode(c)
        with self.assertRaises(ValueError):validate_bundle(files)

    def test_disabled_policy_reproduces_legacy_bundle(self):
        p=config_tests.CandidateConfigTests().base()
        legacy=build_bundle(p,api_secret='x'*32)
        p['lan_ingress']={'enabled':False}
        new=build_bundle(p,api_secret='x'*32,options={'default_filtering':False,'lan_adapter':True})
        c=json.loads(new['config.json']);old=json.loads(legacy['config.json'])
        # Policy identity changes only the persistent DNS cache namespace.
        c['experimental']['cache_file']=old['experimental']['cache_file']
        self.assertEqual(c,old)

    def test_rejects_wide_public_gateway_and_extra_native_fields(self):
        for change in [{'listen':'0.0.0.0'}, {'gateway':'8.8.8.8'}, {'clients':['192.168.2.0/24']},
                       {'clients':['192.168.2.1/32']}, {'clients':['192.168.2.43/32']},
                       {'clients':['2001:db8::1/128']}, {'enabled':'yes'}, {'interface':'x;touch /tmp/a'},
                       {'users':[]}, {'clients':[]}]:
            with self.subTest(change=change),self.assertRaises(ValueError):settings({'lan_ingress':{**LAN,**change}})

    def test_native_only_apply_cannot_bypass_bundle_guard(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'candidate.json';p.write_bytes(self.bundle()['config.json'])
            with self.assertRaisesRegex(ValueError,'complete bundle'):Backend(root).validate(p)

    def test_prepare_owns_before_mutation_and_cleans_partial_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);events=[]
            def run(args,check=True):
                events.append(args)
                self.assertTrue((root/'lan-installed.json').exists())
                if '-A' in args:raise RuntimeError('injected firewall failure')
                return subprocess.CompletedProcess(args,0,'','')
            with patch('lan_runtime.current',return_value=LAN),patch('lan_runtime.preflight'),patch('lan_runtime.vacant',return_value=True),patch('lan_runtime.run',side_effect=run),patch('lan_runtime.cleanup') as clean:
                with self.assertRaises(RuntimeError):lan_runtime.prepare(root)
                self.assertEqual(clean.call_count,2)
                self.assertNotIn('ip',[args[0] for args in events])

    def test_collision_and_disabled_state_do_not_install_rules(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch('lan_runtime.current',return_value=LAN),patch('lan_runtime.preflight'),patch('lan_runtime.vacant',return_value=False),patch('lan_runtime.cleanup'),patch('lan_runtime.run') as run:
                with self.assertRaises(ValueError):lan_runtime.prepare(root)
                run.assert_not_called();self.assertFalse((root/'lan-installed.json').exists())
            with patch('lan_runtime.current',return_value={'enabled':False}),patch('lan_runtime.cleanup') as cleanup,patch('lan_runtime.run') as run,patch('lan_transparent.clear'):
                lan_runtime.prepare(root);cleanup.assert_called_once();run.assert_not_called()

    def test_disabled_runtime_verifier_requires_closed_and_clean_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('apply.lock','lan.lock'):(root/name).touch()
            disabled={'enabled':False}
            with patch('lan_runtime.current',return_value=disabled), \
                 patch('lan_runtime.transparent.verify') as guard, \
                 patch('lan_runtime.vacant',return_value=True):
                self.assertEqual(lan_runtime.health(root)['status'],'up')
                guard.assert_called_once_with(root,disabled,False,lan_runtime.run)
            with patch('lan_runtime.current',return_value=disabled), \
                 patch('lan_runtime.transparent.verify'), \
                 patch('lan_runtime.vacant',return_value=False):
                with self.assertRaisesRegex(ValueError,'LAN выключен'):
                    lan_runtime.verify_runtime(root)
                result=lan_runtime.health(root)
                self.assertEqual(result['status'],'down')
                self.assertEqual(result['detail'],'LAN выключен, но сетевые правила не очищены')

    def test_return_paths_are_distinct_and_disabled_ingress_keeps_device_rules(self):
        direct=lan_runtime.specs(LAN)[2]
        router=lan_runtime.specs({**LAN,'return_via_gateway':True})[2]
        self.assertNotIn('via',direct[0]);self.assertIn('via',router[0])
        p=self.policy();p['lan_ingress']['enabled']=False
        files=build_bundle(p,api_secret='x'*32,options={'default_filtering':False,'lan_adapter':True})
        self.assertFalse(any(i['tag'].startswith('okopy-lan-') for i in json.loads(files['config.json'])['inbounds']))

    def test_preserves_production_tproxy_first_rule(self):
        response=subprocess.CompletedProcess([],0,'-P INPUT DROP\n-A INPUT -m mark --mark 0x1/0x1 -j ACCEPT\n-A INPUT -j ufw-before-input\n','')
        with patch('lan_runtime.run',return_value=response):self.assertEqual(lan_runtime.hook_position(),2)
        response.stdout='-P INPUT DROP\n-A INPUT -j ufw-before-input\n'
        with patch('lan_runtime.run',return_value=response):self.assertEqual(lan_runtime.hook_position(),1)

    def test_gateway_must_belong_to_live_interface(self):
        value=[{'addr_info':[{'local':LAN['listen'],'prefixlen':24}]}]
        response=subprocess.CompletedProcess([],0,json.dumps(value),'')
        with patch('lan_runtime.run',return_value=response):
            lan_runtime.preflight(LAN)
            for update in [{'listen':'192.168.2.44'},{'gateway':'192.168.3.1'}]:
                with self.assertRaises(ValueError):lan_runtime.preflight({**LAN,**update})

    def test_boot_restore_reads_previous_exact_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);files=self.bundle()
            for name,data in files.items():(root/name).write_bytes(data)
            boot=Path('/proc/sys/kernel/random/boot_id')
            hashes={n:digest(b) for n,b in files.items()}
            state={'status':'pending','next_files':{n:'bad' for n in files},'previous_files':hashes,'restore_boot_id':'boot-test'}
            (root/'transaction.json').write_text(json.dumps(state))
            original=Path.read_text
            def read(path,*args,**kwargs):return 'boot-test' if path==boot else original(path,*args,**kwargs)
            with patch.object(Path,'read_text',read):
                self.assertEqual(lan_runtime.current(root),LAN)
                (root/'config.json').write_text('{}')
                with self.assertRaises((ValueError,KeyError)):lan_runtime.current(root)


class LanWebTests(unittest.TestCase):
    setUp=web_tests.WebTests.setUp
    tearDown=web_tests.WebTests.tearDown
    login=web_tests.WebTests.login
    revision=web_tests.WebTests.revision

    def test_lan_form_is_draft_only_and_rejects_unsafe_values(self):
        csrf=self.login();before=self.revision()
        self.assertIn('исходным IP',self.client.get('/lan').text)
        data={'csrf':csrf,'revision':before,**LAN,'enabled':'on','clients':'192.168.2.82/32'}
        self.assertEqual(self.client.post('/lan/save',data=data).status_code,302)
        self.assertEqual(json.loads((self.path/'policy.json').read_text())['lan_ingress'],LAN)
        self.assertEqual(self.client.post('/lan/save',data=data).status_code,409)
        data.update(revision=self.revision(),listen='0.0.0.0')
        self.assertEqual(self.client.post('/lan/save',data=data).status_code,400)
