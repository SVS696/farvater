import ipaddress
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import vpn_ingress as ingress
import vpn_runtime as runtime
import vpn_gate as gate
from candidate_bundle import build_bundle,validate_bundle
from test_vpn_ingress import VpnTests,VPN

class ClientPoolTests(unittest.TestCase):
    def fixture(self,version,source):
        return {**VPN,'clients':[source] if version==4 else ['10.9.0.2/32'],
                **({'clients_v6':[source],'bypass_v6':['fd42:20::/64']} if version==6 else {})}
    def fake(self,args,*a,**kw):
        if args[:2]==['wg','show']:return subprocess.CompletedProcess(args,0,'peer 10.9.0.2/32 fd42:20::2/128\n','')
        if 'link' in args:body=[{'linkinfo':{'info_kind':'wireguard'}}]
        elif 'address' in args:
            body=[{'addr_info':[{'family':'inet','local':'10.9.0.1','prefixlen':24},{'family':'inet6','local':'fd42:20::1','prefixlen':64}]}]
        elif 'route' in args:
            address=args[args.index('get')+1]
            body=[{'dev':'wg0','type':'broadcast' if address in ('10.9.0.0','10.9.0.255') else 'local' if address in ('10.9.0.1','fd42:20::1') else 'unicast'}]
        else:raise AssertionError(args)
        return subprocess.CompletedProcess(args,0,json.dumps(body),'')
    def test_only_exact_interface_network_can_admit_future_ipv4_clients(self):
        with patch.object(runtime,'run',side_effect=self.fake),patch.object(runtime,'legacy_bypass',return_value=None):
            self.assertFalse(runtime.preflight(self.fixture(4,'10.9.0.0/24')))
            for net in ['10.9.0.0/16','10.9.1.0/24','10.9.0.0/25']:
                with self.subTest(net=net),self.assertRaisesRegex(ValueError,'сетью выбранного'):runtime.preflight(self.fixture(4,net))
    def test_ipv6_pool_requires_exact_interface_network_or_real_peer_delegation(self):
        with patch.object(runtime,'run',side_effect=self.fake),patch.object(runtime,'legacy_bypass',return_value=None):
            self.assertFalse(runtime.preflight(self.fixture(6,'fd42:20::/64'),version=6))
            self.assertFalse(runtime.preflight(self.fixture(6,'fd42:20::2/128'),version=6))
            for net in ['fd42:21::/64','fd42:20::/65','fd42:20::88/128']:
                with self.subTest(net=net),self.assertRaisesRegex(ValueError,'не разрешён'):runtime.preflight(self.fixture(6,net),version=6)
    def test_pool_does_not_bypass_return_route_or_management_checks(self):
        for version,net in [(4,'10.9.0.0/24'),(6,'fd42:20::/64')]:
            def wrong(args,*a,**kw):
                if 'route' in args:return subprocess.CompletedProcess(args,0,'[{"dev":"other0"}]','')
                return self.fake(args,*a,**kw)
            with patch.object(runtime,'run',side_effect=wrong),patch.object(runtime,'legacy_bypass',return_value=None),self.assertRaisesRegex(ValueError,'Обратный маршрут'):
                runtime.preflight(self.fixture(version,net),version=version)
            value=self.fixture(version,net);value['bypass' if version==4 else 'bypass_v6']=[]
            with patch.object(runtime,'run',side_effect=self.fake),patch.object(runtime,'legacy_bypass',return_value=None),self.assertRaisesRegex(ValueError,'адреса управления'):
                runtime.preflight(value,version=version)
    def test_compiler_preserves_explicit_pool_scope_and_runtime_guard(self):
        policy=VpnTests().policy();policy['vpn_ingress']=self.fixture(6,'fd42:20::/64');policy['vpn_ingress']['clients']=['10.9.0.0/24']
        files=build_bundle(policy,api_secret='x'*32,options={'default_filtering':False,'vpn_adapter':True});validate_bundle(files)
        config=json.loads(files['config.json']);guards=ingress.route_prefix(policy['vpn_ingress'])
        self.assertEqual(guards[0]['rules'][1]['source_ip_cidr'],['10.9.0.0/24'])
        self.assertIn('iifname "wg0" ip saddr { 10.9.0.0/24 }',ingress.nft_script(policy['vpn_ingress'],True))
    def test_router_gate_recognizes_pool_membership_but_rejects_other_clients(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for n in ['apply.lock','vpn.lock','config.json','transaction.json']:(root/n).write_text('{}')
            (root/'applied-policy.json').write_text(json.dumps({'vpn_ingress':{'clients':['10.9.0.0/24']}}))
            with patch.object(gate,'ROOT',root),patch.object(runtime,'verify_runtime',return_value={'enabled':True}):
                self.assertIsNotNone(gate.runtime_revision({'client':'10.9.0.2'}))
                self.assertIsNone(gate.runtime_revision({'client':'10.9.1.2'}))

if __name__=='__main__':unittest.main()
