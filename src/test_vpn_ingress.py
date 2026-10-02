import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import vpn_ingress as ingress
import vpn_runtime as runtime
from candidate_bundle import build_bundle,validate_bundle,encode
from safe_apply import Backend
import test_candidate_config as config_tests
from test_lan_ingress import LAN
import test_web as web_tests

VPN={'enabled':True,'interface':'wg0','clients':['10.9.0.2/32'],'bypass':['10.9.0.0/24','192.168.2.0/24']}


class VpnTests(unittest.TestCase):
    def policy(self):
        value=config_tests.CandidateConfigTests().base();value['vpn_ingress']=copy.deepcopy(VPN)
        return value

    def test_requires_adapter_and_reproduces_both_conditional_guards(self):
        policy=self.policy();policy['lan_ingress']=copy.deepcopy(LAN)
        with self.assertRaisesRegex(ValueError,'адаптера'):
            build_bundle(policy,api_secret='x'*32,options={'default_filtering':False,'lan_adapter':True})
        files=build_bundle(policy,api_secret='x'*32,options={'default_filtering':False,'lan_adapter':True,'vpn_adapter':True})
        validate_bundle(files);config=json.loads(files['config.json'])
        from lan_ingress import validate_config as validate_lan
        validate_lan(config,LAN);ingress.validate_config(config,VPN,LAN)
        self.assertEqual(config['inbounds'][-3]['tag'],ingress.PREFIX+'transparent')
        self.assertNotIn('routing_mark',config['inbounds'][-3])
        prefix=ingress.route_prefix(VPN)
        position=config['route']['rules'].index(prefix[0]);self.assertGreater(position,0)
        config['route']['rules'].pop(position)
        with self.assertRaises(ValueError):ingress.validate_config(config,VPN,LAN)
        files['config.json']=encode(config)
        with self.assertRaises(ValueError):validate_bundle(files)

    def test_absent_adapter_does_not_change_existing_bundle(self):
        policy=config_tests.CandidateConfigTests().base()
        first=build_bundle(policy,api_secret='x'*32)
        second=build_bundle(policy,api_secret='x'*32,options={'default_filtering':False,'vpn_adapter':True})
        self.assertEqual(first['config.json'],second['config.json'])

    def test_no_native_only_listener_bypass(self):
        files=build_bundle(self.policy(),api_secret='x'*32,options={'default_filtering':False,'vpn_adapter':True})
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'config.json';p.write_bytes(files['config.json'])
            with self.assertRaisesRegex(ValueError,'complete bundle'):Backend(Path(d)).validate(p)

    def test_source_and_interface_bounds(self):
        for change in ({'clients':[]},{'clients':['0.0.0.0/0']},{'clients':['10.9.0.1/24']},
                       {'clients':['8.8.8.8/32']},{'clients':['fd00::1/128']},{'enabled':'yes'},
                       {'interface':'wg0;bad'},{'bypass':['0.0.0.0/0']},{'bypass':['bad']},{'listen':'0.0.0.0'}):
            with self.subTest(change=change),self.assertRaises(ValueError):ingress.settings({'vpn_ingress':{**VPN,**change}})
        self.assertEqual(ingress.settings({}),{'enabled':False})
        disabled=ingress.settings({'vpn_ingress':{**VPN,'enabled':False}})
        self.assertTrue(ingress.configured(disabled));self.assertEqual(ingress.inbounds(disabled),[])

    def test_capture_scope_and_closed_state(self):
        script=ingress.nft_script(VPN,True)
        self.assertIn('iifname "wg0" ip saddr { 10.9.0.2/32 }',script)
        self.assertIn('priority -151',script);self.assertIn('tproxy to 127.0.0.1:25456',script)
        self.assertIn('drop',script);self.assertEqual(ingress.MARK & 1,0)
        closed=ingress.nft_script(VPN,False)
        self.assertNotIn('tproxy to',closed);self.assertIn('drop',closed)

    def test_bypass_cannot_silently_enter_legacy(self):
        import ipaddress
        with patch.object(runtime,'legacy_bypass',return_value=[ipaddress.ip_network('10.9.0.0/24')]):
            with self.assertRaisesRegex(ValueError,'старое ядро'):runtime.preflight(VPN)

    def test_interface_may_appear_after_boot_but_apply_requires_it(self):
        with patch.object(runtime,'legacy_bypass',return_value=None),patch.object(runtime,'run',return_value=subprocess.CompletedProcess([],1,'','Device "wg0" does not exist.')):
            self.assertFalse(runtime.preflight(VPN,allow_missing=True))
            with self.assertRaises(ValueError):runtime.preflight(VPN)

    def test_missing_native_table_can_have_incomplete_json(self):
        answers=[subprocess.CompletedProcess([],0,'[]',''),
                 subprocess.CompletedProcess([],2,'[','Error: ipv4: FIB table does not exist.\nDump terminated\n')]
        with patch.object(runtime,'run',side_effect=answers):self.assertEqual(runtime.routing_rows(),([],[]))

    def test_owned_intent_precedes_mutation_and_failure_closes_scope(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);events=[]
            def run(args,*a,**kw):
                events.append(args)
                self.assertEqual(json.loads((root/'vpn-installed.json').read_text())['settings'],VPN)
                if 'add' in args:raise RuntimeError('injected route failure')
                return subprocess.CompletedProcess(args,0,'','')
            with patch.object(runtime,'current',return_value=VPN),patch.object(runtime,'cleanup') as cleanup,patch.object(runtime,'preflight',return_value=True),patch.object(runtime,'vacant',return_value=True),patch.object(runtime,'set_guard') as guard,patch.object(runtime,'run',side_effect=run):
                with self.assertRaises(RuntimeError):runtime.prepare(root)
                guard.assert_called_once_with(root,VPN,False,4)
                self.assertEqual(cleanup.call_count,2)

    def test_web_draft_requires_csrf_and_revision_and_preserves_lan(self):
        fixture=web_tests.WebTests();fixture.setUp()
        try:
            self.assertEqual(fixture.client.post('/vpn-ingress/save').status_code,403)
            csrf=fixture.login()
            data={'csrf':csrf,'revision':fixture.revision(),'enabled':'on','interface':'wg0',
                  'clients':'10.9.0.2/32','bypass':'10.9.0.0/24\n192.168.2.0/24'}
            self.assertEqual(fixture.client.post('/vpn-ingress/save',data={**data,'csrf':'bad'}).status_code,403)
            self.assertEqual(fixture.client.post('/vpn-ingress/save',data=data).status_code,302)
            stored=json.loads((fixture.path/'policy.json').read_text())
            self.assertEqual(stored['vpn_ingress'],VPN);self.assertNotIn('lan_ingress',stored)
            self.assertEqual(fixture.client.post('/vpn-ingress/save',data=data).status_code,409)
            self.assertIn('10.9.0.2/32',fixture.client.get('/lan').text)
        finally:fixture.tearDown()

    def test_web_ipv6_validation_and_stale_form_cannot_erase_sources(self):
        fixture=web_tests.WebTests();fixture.setUp()
        try:
            csrf=fixture.login()
            data={'csrf':csrf,'revision':fixture.revision(),'enabled':'on','interface':'wg0',
                  'clients':'10.9.0.2/32','bypass':'10.9.0.0/24',
                  'clients_v6':'fd42:20::2/128','bypass_v6':'fd42:20::/64'}
            before=(fixture.path/'policy.json').read_bytes()
            for bad in ('::/0','fd42::/48','192.168.2.1/32','fe80::1%wg0/128'):
                self.assertEqual(fixture.client.post('/vpn-ingress/save',data={**data,'clients_v6':bad}).status_code,400)
                self.assertEqual((fixture.path/'policy.json').read_bytes(),before)
            self.assertEqual(fixture.client.post('/vpn-ingress/save',data=data).status_code,302)
            stored=json.loads((fixture.path/'policy.json').read_text())
            self.assertEqual(stored['vpn_ingress']['clients_v6'],['fd42:20::2/128'])
            self.assertIn('fd42:20::2/128',fixture.client.get('/lan').text)
            before=(fixture.path/'policy.json').read_bytes()
            old={k:v for k,v in data.items() if k not in ('clients_v6','bypass_v6')}
            old['revision']=fixture.revision()
            self.assertEqual(fixture.client.post('/vpn-ingress/save',data=old).status_code,409)
            self.assertEqual((fixture.path/'policy.json').read_bytes(),before)
            self.assertEqual(fixture.client.post('/vpn-ingress/save',data={**old,'clients_v6':''}).status_code,400)
            self.assertEqual((fixture.path/'policy.json').read_bytes(),before)
            self.assertEqual(fixture.client.post('/vpn-ingress/save',data={**old,'clients_v6':'','bypass_v6':''}).status_code,302)
            self.assertNotIn('clients_v6',json.loads((fixture.path/'policy.json').read_text())['vpn_ingress'])
        finally:fixture.tearDown()


if __name__=='__main__':unittest.main()
