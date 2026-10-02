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
import test_vpn_ingress as fixture
VPN=fixture.VPN


DUAL={**VPN,'clients_v6':['fd42:20::2/128','2001:db8:20::/64'],
      'bypass_v6':['fd42:20::/64']}


class IPv6IngressTests(unittest.TestCase):
    def test_ipv6_has_own_source_guard_before_shared_rules(self):
        policy=fixture.VpnTests().policy();policy['vpn_ingress']=copy.deepcopy(DUAL)
        files=build_bundle(policy,api_secret='x'*32,options={'default_filtering':False,'vpn_adapter':True})
        validate_bundle(files)
        config=json.loads(files['config.json'])
        self.assertEqual([i['listen'] for i in config['inbounds'] if i['tag'].startswith(ingress.PREFIX)],['127.0.0.1','::1'])
        guard=ingress.route_prefix(ingress.settings({'vpn_ingress':DUAL}))[3]
        self.assertEqual(guard['rules'][0]['inbound'],['okopy-vpn-transparent6'])
        self.assertEqual(guard['rules'][1]['source_ip_cidr'],sorted(DUAL['clients_v6']))
        config['route']['rules'].remove(guard);files['config.json']=encode(config)
        with self.assertRaises(ValueError):validate_bundle(files)

    def test_ipv6_capture_is_scoped_and_failure_drops_instead_of_using_legacy(self):
        opened=ingress.nft_script(DUAL,True,6)
        self.assertIn('table ip6 okopy_vpn',opened)
        self.assertIn('iifname "wg0" ip6 saddr { fd42:20::2/128, 2001:db8:20::/64 }',opened)
        self.assertIn('tproxy to [::1]:25456',opened)
        self.assertIn('meta l4proto { tcp, udp }',opened)
        closed=ingress.nft_script(DUAL,False,6)
        self.assertNotIn('tproxy to',closed);self.assertIn('drop',closed)
        self.assertNotIn('table ip ',closed)
        self.assertEqual(ingress.nft_script(DUAL,True),ingress.nft_script(VPN,True))

    def test_rejects_broad_nonunicast_and_mixed_family_sources(self):
        for sources in [['::/0'],['ff00::/64'],['fe80::/64'],['::1/128'],['2001:db8::/32'],
                        ['::ffff:192.168.1.2/128'],['10.9.0.3/32'],['fd42::1/64'],
                        ['fd42::1%wg0/128'],['fd42::/64; flush ruleset']]:
            with self.subTest(sources=sources),self.assertRaises(ValueError):
                ingress.settings({'vpn_ingress':{**DUAL,'clients_v6':sources}})
        for change in [{'bypass_v6':['::/0']},{'bypass_v6':['10.0.0.0/8']},
                       {'bypass_v6':['fd42::1%bad/128']},{'clients_v6':[]},{'clients_v6':'fd42::/64'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                ingress.settings({'vpn_ingress':{**DUAL,**change}})
        value={**VPN,'clients_v6':['fd42::2/128']}
        with self.assertRaises(ValueError):ingress.settings({'vpn_ingress':value})

    def test_normalization_does_not_broaden_admitted_prefixes(self):
        value={**DUAL,'clients_v6':['fd42:0:0:0::/64','fd42:0:0:1::/64']}
        normalized=ingress.settings({'vpn_ingress':value})
        self.assertEqual(normalized['clients_v6'],['fd42:0:0:1::/64','fd42::/64'])
        self.assertEqual(ingress.settings({'vpn_ingress':normalized}),normalized)
        self.assertEqual(ingress.settings({'vpn_ingress':VPN}),VPN)

    def test_runtime_requires_ipv6_peer_permission_and_return_route(self):
        value={**DUAL,'clients_v6':['fd42:20::2/128']}
        allowed=False;route_dev='wg0'
        def run(args,*a,**kw):
            if args[:2]==['wg','show']:
                return subprocess.CompletedProcess(args,0,'peer fd42:20::2/128\n' if allowed else 'peer 10.9.0.2/32\n','')
            if 'link' in args:body=[{'linkinfo':{'info_kind':'wireguard'}}]
            elif 'address' in args:body=[{'addr_info':[{'family':'inet6','local':'fd42:20::1'}]}]
            elif 'route' in args:body=[{'dev':route_dev,'type':'unicast'}]
            else:raise AssertionError(args)
            return subprocess.CompletedProcess(args,0,json.dumps(body),'')
        with patch.object(runtime,'run',side_effect=run),patch.object(runtime,'legacy_bypass',return_value=None):
            with self.assertRaisesRegex(ValueError,'не разрешён'):runtime.preflight(value,version=6)
            allowed=True;self.assertFalse(runtime.preflight(value,version=6))
            route_dev='eth0'
            with self.assertRaisesRegex(ValueError,'Обратный маршрут'):runtime.preflight(value,version=6)

    def test_partial_dual_stack_failure_cleans_both_families(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(runtime,'current',return_value=DUAL),patch.object(runtime,'preflight'),patch.object(runtime,'cleanup') as cleanup,patch.object(runtime,'prepare_family',side_effect=[None,RuntimeError('IPv6 failure')]) as prepare:
                with self.assertRaisesRegex(RuntimeError,'IPv6 failure'):runtime.prepare(root)
                self.assertEqual([call.args[-1] for call in prepare.call_args_list],[4,6])
                self.assertEqual(cleanup.call_count,2)
            with patch.object(runtime,'cleanup_family',side_effect=[RuntimeError('IPv4 failure'),None]) as cleanup:
                with self.assertRaisesRegex(RuntimeError,'IPv4 failure'):runtime.cleanup(root)
                self.assertEqual([call.args[-1] for call in cleanup.call_args_list],[4,6])

    def test_connected_lan_return_is_allowed_but_not_an_unrelated_or_gateway_path(self):
        value={**DUAL,'clients_v6':['fd42:99::2/128']}
        route={'dev':'lan0','type':'unicast'}
        lan={'link_type':'ether','flags':['UP'], 'addr_info':[
            {'family':'inet6','local':'fd42:99::1','prefixlen':64}]}
        allowed=True
        def run(args,*a,**kw):
            if args[:2]==['wg','show']:
                body='peer '+('fd42:99::/64' if allowed else 'fd42:20::2/128')+'\n'
            else:
                if 'link' in args:rows=[{'linkinfo':{'info_kind':'wireguard'}}]
                elif 'route' in args:rows=[route]
                elif args[-1]=='lan0':rows=[lan]
                else:rows=[{'addr_info':[{'family':'inet6','local':'fd42:20::1'}]}]
                body=json.dumps(rows)
            return subprocess.CompletedProcess(args,0,body,'')
        with patch.object(runtime,'run',side_effect=run),patch.object(runtime,'legacy_bypass',return_value=None):
            self.assertFalse(runtime.preflight(value,version=6))
            allowed=False
            with self.assertRaisesRegex(ValueError,'не разрешён'):runtime.preflight(value,version=6)
            allowed=True
            for change in [{'gateway':'fd42:99::ff'},{'type':'local'},{'via':{'addr':'fd42:99::ff'}}]:
                with self.subTest(change=change),patch.dict(route,change),self.assertRaisesRegex(ValueError,'Обратный маршрут'):
                    runtime.preflight(value,version=6)
            for change in [{'link_type':'none'},{'flags':[]},{'addr_info':[
                    {'family':'inet6','local':'fd42:88::1','prefixlen':64}]}, {'addr_info':[
                    {'family':'inet6','local':'fd42:99::2','prefixlen':64}]}]:
                with self.subTest(change=change),patch.dict(lan,change),self.assertRaisesRegex(ValueError,'Обратный маршрут'):
                    runtime.preflight(value,version=6)

    def test_family_resources_keep_separate_ownership(self):
        root=Path('/fixture')
        self.assertNotEqual(runtime.stamp_path(root,'nft',4),runtime.stamp_path(root,'nft',6))
        self.assertEqual(runtime.local_route(6),['table',ingress.ROUTE_TABLE,'local','::/0','dev','lo'])
        self.assertEqual(runtime.handoff(6)[0],'SBTP6')
        self.assertEqual(runtime.handoff(4),runtime.HANDOFF)


if __name__=='__main__':unittest.main()
