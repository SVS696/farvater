import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import adguard_runtime
from candidate_bundle import build_bundle
from safe_apply import Backend
import test_candidate_config as fixtures


class AdGuardRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.policy=fixtures.CandidateConfigTests().base()
        self.policy['filtering']={'default_enabled':True,'blocklists':[],'allowlists':[],'rules':['||blocked.test^']}
        self.files=build_bundle(self.policy,api_secret='x'*32,options={'default_filtering':False,'adguard_adapter':True})
        for name,data in self.files.items():(self.root/name).write_bytes(data)
        base={'http':{},'dns':{},'filtering':{},'dhcp':{},'tls':{},'querylog':{}}
        (self.root/'adguard-base.json').write_text(json.dumps(base))
        self.state={'id':'a'*32,'status':'pending','runtime_ready':True,'next_files':{n:hashlib.sha256(b).hexdigest() for n,b in self.files.items()}}
        (self.root/'transaction.json').write_text(json.dumps(self.state))
        self.boot=patch('adguard_runtime.boot_id',return_value='boot-A');self.boot.start()
    def tearDown(self):self.boot.stop();self.temp.cleanup()

    def test_runtime_is_derived_from_exact_current_bundle(self):
        adguard_runtime.prepare(self.root)
        config=json.loads((self.root/'adguard/AdGuardHome.yaml').read_text())
        self.assertEqual(config['user_rules'],['||blocked.test^'])
        stamp=json.loads((self.root/'adguard-source.json').read_text())
        self.assertEqual(stamp['transaction_id'],self.state['id'])
        self.assertEqual(stamp['config_sha256'],hashlib.sha256(self.files['config.json']).hexdigest())

    def test_partial_bundle_never_generates_runtime(self):
        (self.root/'applied-policy.json').write_text('{}')
        with self.assertRaises(ValueError):adguard_runtime.prepare(self.root)
        self.assertFalse((self.root/'adguard/AdGuardHome.yaml').exists())

    def test_unready_mapping_cannot_start_while_old_candidate_is_running(self):
        self.state['runtime_ready']=False;(self.root/'transaction.json').write_text(json.dumps(self.state))
        for running in ('active','activating','deactivating'):
            with patch('adguard_runtime.subprocess.run',return_value=subprocess.CompletedProcess([],0,running,'')),self.assertRaises(ValueError):
                adguard_runtime.prepare(self.root)
        with patch('adguard_runtime.subprocess.run',return_value=subprocess.CompletedProcess([],0,'inactive','')):
            adguard_runtime.prepare(self.root)

    def test_pending_rollback_loads_previous_bundle_only_after_drain(self):
        self.state.update(restore_boot_id='boot-A',previous_files=self.state['next_files'],
                          next_files={n:'0'*64 for n in self.files})
        (self.root/'transaction.json').write_text(json.dumps(self.state))
        with patch('adguard_runtime.subprocess.run',return_value=subprocess.CompletedProcess([],0,'active','')),self.assertRaises(ValueError):
            adguard_runtime.prepare(self.root)
        with patch('adguard_runtime.subprocess.run',return_value=subprocess.CompletedProcess([],0,'inactive','')):
            adguard_runtime.prepare(self.root)
        self.state['restore_boot_id']='other-boot';(self.root/'transaction.json').write_text(json.dumps(self.state))
        with self.assertRaises(ValueError):adguard_runtime.prepare(self.root)

    def test_rollback_to_previous_policy_regenerates_previous_filter_rules(self):
        adguard_runtime.prepare(self.root)
        p=copy.deepcopy(self.policy);p['filtering']['rules']=['||previous.test^']
        old=build_bundle(p,api_secret='x'*32,options={'default_filtering':False,'adguard_adapter':True})
        for name,data in old.items():(self.root/name).write_bytes(data)
        self.state.update(status='rolled_back',previous_files={n:hashlib.sha256(b).hexdigest() for n,b in old.items()})
        (self.root/'transaction.json').write_text(json.dumps(self.state))
        adguard_runtime.prepare(self.root)
        self.assertEqual(json.loads((self.root/'adguard/AdGuardHome.yaml').read_text())['user_rules'],['||previous.test^'])

    def test_both_engines_stop_before_either_starts(self):
        response=subprocess.CompletedProcess([],0,b'',b'')
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self):return b'{}'
        with patch('safe_apply.subprocess.run',return_value=response) as run,patch('adguard_runtime.wait_ready'),patch('safe_apply.urllib.request.urlopen',return_value=Reply()):
            Backend(self.root).restart()
        commands=[call.args[0] for call in run.call_args_list]
        self.assertEqual(commands,[['systemctl','stop','okopy-candidate.service','okopy-adguard-candidate.service'],
            ['systemctl','start','okopy-adguard-candidate.service'],['systemctl','start','okopy-candidate.service']])

    def test_service_check_keeps_both_repeated_execstartpre_properties(self):
        text=''.join('ExecStartPre={ argv[]=/usr/bin/python3 -E -s -B '+str(self.root/name)+' '+action+' ; ignore_errors=no ; }\n'
            for name,action in [('safe_apply.py','recover-before-start'),('adguard_runtime.py','prepare')])
        text+='ExecStart={ argv[]='+adguard_runtime.BINARY+' --config '+str(self.root/'adguard/AdGuardHome.yaml')+' --work-dir '+str(self.root/'adguard')+' --no-check-update ; ignore_errors=no ; }\n'
        text+='NeedDaemonReload=no\nTransient=no\nFragmentPath=/etc/systemd/system/okopy-adguard-candidate.service\nUser=root\nDynamicUser=no\nProtectSystem=strict\nReadWritePaths='+str(self.root)+'\n'
        with patch('adguard_runtime.subprocess.run',return_value=subprocess.CompletedProcess([],0,text,'')):
            adguard_runtime.check_service(self.root)

        text=text.replace('recover-before-start','wrong-hook')
        with patch('adguard_runtime.subprocess.run',return_value=subprocess.CompletedProcess([],0,text,'')),self.assertRaises(ValueError):
            adguard_runtime.check_service(self.root)

    def native_api(self):
        desired=adguard_runtime.configuration(self.root,self.files)
        return {'status':{'protection_enabled':True},'filtering/status':{
            'enabled':True,'filters':desired['filters'],'whitelist_filters':[],
            'user_rules':desired['user_rules']},'dns_info':desired['dns'],
            'clients':{'clients':desired['clients']['persistent']}}

    def test_loaded_mapping_and_cache_are_verified(self):
        values=self.native_api()
        with patch('adguard_runtime.api',side_effect=lambda root,path:values[path]):
            self.assertGreater(adguard_runtime.verify_runtime(self.root)['resolvers'],0)
            values['dns_info']['cache_enabled']=True
            with self.assertRaises(ValueError):adguard_runtime.verify_runtime(self.root)
            values['dns_info']['cache_enabled']=False
            values['clients']['clients'][0]['upstreams']=['8.8.8.8']
            with self.assertRaises(ValueError):adguard_runtime.verify_runtime(self.root)

    def test_health_never_reports_previous_runtime_as_current(self):
        (self.root/'apply.lock').touch()
        adguard_runtime.prepare(self.root)
        values=self.native_api()
        with patch('adguard_runtime.api',side_effect=lambda root,path:values[path]):
            self.assertEqual(adguard_runtime.health(self.root)['status'],'up')
            path=self.root/'adguard-source.json';source=json.loads(path.read_text())
            source['config_sha256']='0'*64;path.write_text(json.dumps(source))
            self.assertEqual(adguard_runtime.health(self.root)['status'],'unknown')

    def test_health_reports_mutation_and_api_unavailability(self):
        (self.root/'apply.lock').touch();adguard_runtime.prepare(self.root)
        with patch('adguard_runtime.api',side_effect=adguard_runtime.urllib.error.URLError('private diagnostic')):
            result=adguard_runtime.health(self.root)
            self.assertEqual(result['status'],'down');self.assertNotIn('private',result['detail'])
        with patch('adguard_runtime.fcntl.flock',side_effect=BlockingIOError):
            self.assertEqual(adguard_runtime.health(self.root)['status'],'unknown')


if __name__=='__main__':unittest.main()
