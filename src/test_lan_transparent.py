import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import lan_ingress
import lan_runtime
import lan_transparent as nft
from candidate_bundle import build_bundle,validate_bundle
import test_lan_ingress as fixtures


def value(enabled=True):
    return {**copy.deepcopy(fixtures.LAN),'enabled':enabled,'transparent_targets':['104.26.12.205/32']}


class TransparentTests(unittest.TestCase):
    def test_same_engine_preserves_source_and_has_separate_capture_reply_marks(self):
        p=fixtures.LanTests().policy();p['lan_ingress']=value()
        files=build_bundle(p,api_secret='x'*32,options={'default_filtering':False,'lan_adapter':True})
        validate_bundle(files);config=json.loads(files['config.json'])
        lan_ingress.validate_config(config,lan_ingress.settings(p))
        inbound=config['inbounds'][-1]
        self.assertEqual(inbound['type'],'tproxy');self.assertEqual(inbound['routing_mark'],lan_ingress.REPLY_MARK)
        self.assertNotEqual(lan_ingress.REPLY_MARK,lan_ingress.CAPTURE_MARK)
        self.assertIn(inbound['tag'],config['route']['rules'][0]['rules'][0]['inbound'])
        self.assertEqual(config['route']['rules'][2],{'inbound':[inbound['tag']],'port':[53],'action':'hijack-dns'})
        self.assertEqual(config['route']['rules'][3]['action'],'sniff')

    def test_service_requires_low_port_reply_capability(self):
        root=Path('/var/lib/okopy-candidate')
        response='ExecStartPre=argv[]=/usr/bin/python3 -E -s -B '+str(root/'lan_runtime.py')+' prepare ; ignore_errors=no\nExecStopPost=argv[]=/usr/bin/python3 -E -s -B '+str(root/'lan_runtime.py')+' cleanup ; ignore_errors=no\nDropInPaths=/etc/systemd/system/okopy-candidate.service.d/30-lan.conf\nNeedDaemonReload=no\nCapabilityBoundingSet=cap_net_admin cap_net_raw'
        with patch('lan_runtime.run',return_value=subprocess.CompletedProcess([],0,response,'')):
            with self.assertRaises(ValueError):lan_runtime.check_service(root)
        with patch('lan_runtime.run',return_value=subprocess.CompletedProcess([],0,response+' cap_net_bind_service','')):
            lan_runtime.check_service(root)

    def test_target_validation_and_collapse_are_general(self):
        v=value();v['transparent_targets']=['192.0.2.0/24','192.0.2.1/32','0.0.0.0/1','128.0.0.0/1']
        self.assertEqual(lan_ingress.settings({'lan_ingress':v})['transparent_targets'],['0.0.0.0/0'])
        for targets in ['0.0.0.0/0',['192.0.2.1/24'],['::/0'],['1.2.3.4; flush ruleset'],['1.1.1.1/32']*65]:
            with self.subTest(targets=targets),self.assertRaises(ValueError):
                lan_ingress.settings({'lan_ingress':{**value(),'transparent_targets':targets}})

    def test_nft_has_drop_after_failed_tproxy_and_preserves_management(self):
        opened=nft.script(value(),True);closed=nft.script(value(False),False)
        self.assertIn('priority -151',opened)
        self.assertIn('tproxy to 192.168.2.43:15456',opened)
        self.assertIn('accept\ndrop',opened)
        self.assertNotIn('tproxy',closed);self.assertIn('drop',closed)
        for address in ('192.168.2.43','192.168.2.1','192.168.2.82/32','127.0.0.0/8'):
            self.assertIn(address,opened.split('return')[0])
        self.assertNotIn('flush ruleset',opened)

    def test_normalization_discards_only_metadata_not_semantics(self):
        raw={'nftables':[{'metainfo':{'version':'x'}},{'rule':{'handle':123,'chain':'capture','expr':[{'drop':None}]}}]}
        self.assertEqual(nft.normalized(json.dumps(raw)),[{'rule':{'chain':'capture','expr':[{'drop':None}]}}])

    def test_atomic_replace_requires_owned_table_and_records_intent_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch('lan_transparent.exists',return_value=True):
                with self.assertRaises(ValueError):nft.set_guard(root,value(),True,lambda *a,**k:None)
                (root/'lan-nft.json').write_text('{}')
                def run(args,**kwargs):
                    if args==['nft','-f','-']:
                        self.assertFalse(json.loads((root/'lan-nft.json').read_text())['ready'])
                        self.assertTrue(kwargs['input'].startswith('delete table ip okopy_lan\ntable ip okopy_lan'))
                        raise RuntimeError('Injected interruption')
                    raise AssertionError(args)
                with self.assertRaises(RuntimeError):nft.set_guard(root,value(),True,run)
                self.assertFalse(json.loads((root/'lan-nft.json').read_text())['ready'])

    def test_cleanup_blocks_before_removing_kernel_routes_and_retains_closed_ownership(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'lan-installed.json').write_text(json.dumps(value()))
            events=[]
            def run(args,check=True,**kwargs):
                events.append(args)
                return subprocess.CompletedProcess(args,1 if '-C' in args else 0,'','')
            with patch('lan_runtime.run',side_effect=run),patch('lan_runtime.vacant',return_value=True),patch('lan_transparent.set_guard',side_effect=lambda *a:events.append(['closed'])):
                lan_runtime.cleanup(root)
            self.assertEqual(events[0],['closed'])
            self.assertTrue(any(a[:4]==['ip','-4','rule','del'] for a in events))
            self.assertEqual(json.loads((root/'lan-installed.json').read_text()),value(False))

    def test_disabled_listener_with_targets_installs_only_closed_guard(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch('lan_runtime.current',return_value=value(False)),patch('lan_runtime.cleanup'),patch('lan_runtime.run') as run,patch('lan_transparent.set_guard') as guard:
                lan_runtime.prepare(root)
                run.assert_not_called();guard.assert_called_once_with(root,value(False),False,run)
            self.assertEqual(lan_runtime.specs(value(False)),([],[],[]))

    def test_health_rejects_modified_guard_or_wrong_open_state(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);rules=[{'rule':{'chain':'selected','expr':[{'drop':None}]}}]
            (root/'lan-nft.json').write_text(json.dumps({'signature':nft.signature(value(),False),'ready':True,'rules':rules}))
            def run(*a,**k):return subprocess.CompletedProcess([],0,json.dumps({'nftables':rules}),'')
            nft.verify(root,value(),False,run)
            with self.assertRaises(ValueError):nft.verify(root,value(),True,run)
            rules[0]['rule']['expr']=[{'accept':None}]
            with self.assertRaises(ValueError):nft.verify(root,value(),False,run)


if __name__=='__main__':unittest.main()
