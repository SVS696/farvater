import unittest
from router_baseline import project

CONFIG='''! router config
ip policy Direct
    permit global ISP
    no permit global Wireguard1
!
ip hotspot
    host 00:11:22:33:44:55 policy Direct
!
dns-proxy
    filter profile Provider description Native-DNS
    filter profile Provider dns53 upstream 77.37.251.33
    filter profile Provider dns53 upstream 77.37.255.30
    filter profile Provider intercept enable
    filter assign host profile 00:11:22:33:44:55 Provider
!
user admin
    password hidden-secret
!
'''
DNS='''server:
 address: 77.37.251.33
 service: Dhcp::Client-GigabitEthernet1
 interface: GigabitEthernet1
server:
 address: 77.37.255.30
 service: Dhcp::Client-GigabitEthernet1
 interface: GigabitEthernet1
'''
STATUS='unsaved: no\ntime-left: 0\n'


class NativeBaselineTests(unittest.TestCase):
    def read(self,config=CONFIG,startup=None,dns=DNS,status=STATUS):
        return project(config,config if startup is None else startup,dns,status)

    def test_declared_pair_is_projected_without_private_config(self):
        result=self.read()
        self.assertTrue(result['startup_matches']);self.assertFalse(result['pending'])
        self.assertEqual(result['direct_clients'],[{'mac':'00:11:22:33:44:55','policy':'Direct','dns_profile':'Provider','dns_servers':['77.37.251.33','77.37.255.30']}])
        self.assertNotIn('hidden-secret',str(result))

    def test_mixed_vpn_policy_is_not_an_independent_direct_pair(self):
        self.assertEqual(self.read(CONFIG.replace('no permit global Wireguard1','permit global Wireguard1'))['direct_clients'],[])

    def test_profile_must_use_exact_current_isp_dns_and_intercept(self):
        for config in [CONFIG.replace('77.37.255.30','1.1.1.1'),CONFIG.replace('intercept enable','intercept no enable'),
                       CONFIG.replace('dns-proxy\n','dns-proxy\n    filter profile Provider https upstream https://example.com/dns-query\n'),
                       CONFIG.replace('dns53 upstream 77.37.255.30','dns53 upstream 77.37.255.30:5353')]:
            with self.subTest(config=config):self.assertEqual(self.read(config)['direct_clients'],[])

    def test_missing_or_other_interface_dns_is_not_green(self):
        for dns in ['',DNS.replace('GigabitEthernet1','Wireguard1')]:
            self.assertEqual(self.read(dns=dns)['direct_clients'],[])

    def test_startup_mismatch_and_native_timer_remain_visible(self):
        result=self.read(startup=CONFIG.replace('Provider','Old'),status='unsaved: yes\ntime-left: 90\n')
        self.assertFalse(result['startup_matches']);self.assertTrue(result['pending'])

    def test_partial_native_responses_fail_closed(self):
        for kwargs in [{'config':'Command failed'}, {'startup':''}, {'status':''}]:
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.read(**kwargs)

    def test_only_generated_banner_and_ansi_are_ignored(self):
        self.assertTrue(self.read(startup='! $$$ generated\n\x1b[K'+CONFIG)['startup_matches'])
        self.assertFalse(self.read(startup=CONFIG.replace('Native-DNS','Other'))['startup_matches'])

    def test_comment_free_native_dump_is_valid(self):
        self.assertEqual(len(self.read(CONFIG.replace('! router config\n','system\n    hostname Router\n!\n'))['direct_clients']),1)
