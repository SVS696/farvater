import copy,json,unittest
from unittest.mock import patch
from wireguard_profile import parse
from wireguard_preflight import conflicts,native
from test_wireguard_profile import BASE,PRIVATE,PSK

class PreflightTests(unittest.TestCase):
    def setUp(self):self.model=parse(BASE)
    def check(self,other=None,addresses=None,routes=None):
        return conflicts('wg0',self.model,other or {},addresses or [],routes or [])
    def codes(self,**kw):return {x['code'] for x in self.check(**kw)['blockers']}
    def test_single_profile_does_not_conflict_with_own_runtime(self):
        self.assertEqual(self.codes(other={'wg0':self.model},routes=[{'dst':'10.9.0.2/32','dev':'wg0'}]),set())
    def test_active_work_networks_collide_in_main(self):
        other=copy.deepcopy(self.model);other['interface'].pop('ListenPort')
        self.assertIn('vpn-network',self.codes(other={'other':other}))
    def test_separate_tables_isolate_allowed_networks(self):
        other=copy.deepcopy(self.model);other['interface'].pop('ListenPort');other['interface']['Table']='242'
        self.model['interface']['Table']='243'
        self.assertEqual(self.codes(other={'other':other}),set())
    def test_duplicate_peer_network_not_silently_stolen(self):
        self.model['peers'].append(copy.deepcopy(self.model['peers'][0]));self.model['peers'][1]['PublicKey']='different'
        self.assertIn('peer-network',self.codes())
    def test_nested_peer_networks_are_deterministic_and_allowed(self):
        self.model['peers'].append({'PublicKey':'another','AllowedIPs':['10.9.0.0/24']})
        self.assertNotIn('peer-network',self.codes())
    def test_port_conflict_independent_of_tables(self):
        other=copy.deepcopy(self.model);other['interface']['Table']='999'
        self.assertIn('listen-port',self.codes(other={'other':other}))
    def test_off_still_checks_connected_addresses_and_reports_external_owner(self):
        self.model['interface']['Table']='off'
        addresses=[{'ifname':'eth0','addr_info':[{'family':'inet','local':'10.9.0.3','prefixlen':24}]}]
        self.assertIn('connected-network',self.codes(addresses=addresses));self.assertTrue(self.check()['warnings'])
    def test_exact_address_collision_on_foreign_interface(self):
        self.assertIn('local-address',self.codes(addresses=[{'ifname':'eth0','addr_info':[{'family':'inet','local':'10.9.0.1','prefixlen':32}]}]))
    def test_default_requires_deliberate_isolation(self):
        self.model['peers'][0]['AllowedIPs']=['::/0'];self.assertIn('default-route',self.codes())
        self.model['interface']['Table']='246';self.assertNotIn('default-route',self.codes())
    def test_foreign_main_route_checked_but_not_default_or_another_table(self):
        self.assertIn('host-route',self.codes(routes=[{'dst':'10.9.0.0/24','dev':'eth0'}]))
        self.assertEqual(self.codes(routes=[{'dst':'default','dev':'eth0'},{'dst':'10.9.0.0/24','dev':'eth0','table':246}]),set())
    def test_unreadable_active_profile_blocks_incomplete_claim(self):
        self.assertIn('unreadable-profile',self.codes(other={'broken':None}))
    def test_native_uses_anonymous_network_namespace_and_keeps_keys_off_argv(self):
        before=copy.deepcopy(self.model)
        with patch('wireguard_preflight.run',return_value=b'') as run:
            self.assertTrue(native(self.model))
        args=run.call_args.args[0];data=run.call_args.kwargs['data'].decode()
        self.assertEqual(args[:3],['/usr/bin/unshare','--net','--'])
        self.assertNotIn(PRIVATE,json.dumps(args));self.assertNotIn(PSK,json.dumps(args))
        self.assertNotIn('Endpoint',data);self.assertIn('PersistentKeepalive = 0',data)
        self.assertNotIn('Address =',data);self.assertEqual(before,self.model)

    def test_large_comparison_is_rejected_instead_of_unbounded_work(self):
        routes=[{'dst':'10.9.0.0/24','dev':'eth0'}]*130000
        with self.assertRaisesRegex(ValueError,'Слишком много'):self.check(routes=routes)

    def test_conflict_messages_are_bounded(self):
        self.model['peers'][0]['AllowedIPs']=['10.0.'+str(i)+'.0/24' for i in range(100)]
        other=copy.deepcopy(self.model)
        result=self.check(other={'other':other})
        self.assertLess(len(json.dumps(result)),2000)
        self.assertIn('ещё',json.dumps(result,ensure_ascii=False))

    def test_failed_profile_without_interface_and_invalid_filenames_are_not_live(self):
        import tempfile
        from pathlib import Path
        from wireguard_preflight import check
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ['wg0.conf','failed.conf','wg0 copy.conf']:(root/name).write_text('unused')
            def observe(names):
                self.assertNotIn('wg0 copy',names)
                return {n:{'service':'active' if n=='wg0' else 'failed','interface':n=='wg0'} for n in names}
            with patch('wireguard_preflight.run',return_value=b'[]') as run,patch('wireguard_preflight.native',return_value=True),patch('wireguard_preflight.conflicts',return_value={'blockers':[],'warnings':[]}) as verify:
                result=check('wg0',self.model,root,observe=observe,read_profile=lambda p:self.fail('failed peer must not be parsed'))
            self.assertFalse(result['blockers']);self.assertEqual(verify.call_args.args[2],{})
            route_commands=[c.args[0] for c in run.call_args_list if 'route' in c.args[0]]
            self.assertEqual(len(route_commands),2)
            self.assertTrue(all('-N' in cmd for cmd in route_commands))

    def test_failed_profile_with_live_interface_remains_conflicting(self):
        import tempfile
        from pathlib import Path
        from wireguard_preflight import check
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ['wg0.conf','failed.conf']:(root/name).write_text('unused')
            def observe(names):return {n:{'service':'failed','interface':True} for n in names}
            with patch('wireguard_preflight.run',return_value=b'[]'),patch('wireguard_preflight.native',return_value=True):
                result=check('wg0',self.model,root,observe=observe,read_profile=lambda p:self.model)
            self.assertIn('vpn-network',{r['code'] for r in result['blockers']})

    def test_numeric_route_tables_are_compared_without_aliases(self):
        self.model['interface']['Table']='246'
        self.assertIn('host-route',self.codes(routes=[{'table':246,'dev':'other','dst':'10.9.0.2/32'}]))
        self.model['interface']['Table']='254'
        self.assertIn('host-route',self.codes(routes=[{'table':254,'dev':'other','dst':'10.9.0.2/32'}]))
        with self.assertRaises(ValueError):parse(BASE.replace('ListenPort = 51820','Table = myvpn'))
