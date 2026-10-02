import tempfile
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import vpn_runtime
import incoming_runtime

class RuntimeCompatibilityTests(unittest.TestCase):
    def test_vpn_hook_survives_later_protocol_hooks(self):
        root=Path('/var/lib/okopy-candidate')
        rows=[]
        for field,action in [('ExecStartPre','prepare'),('ExecStopPost','cleanup')]:
            for module in ('lan_runtime','vpn_runtime','incoming_runtime'):
                rows.append(field+'={ argv[]=/usr/bin/python3 -E -s -B '+str(root/(module+'.py'))+' '+action+' ; ignore_errors=no ; }')
        rows+=['DropInPaths=/etc/systemd/system/okopy-candidate.service.d/40-vpn.conf','NeedDaemonReload=no','CapabilityBoundingSet=cap_net_admin cap_net_raw']
        with patch('vpn_runtime.run',return_value=SimpleNamespace(stdout='\n'.join(rows))),patch('vpn_runtime.legacy_bypass',return_value=None):vpn_runtime.check_service(root)
        rows=[s for s in rows if not ('ExecStartPre=' in s and 'vpn_runtime.py' in s)]
        with patch('vpn_runtime.run',return_value=SimpleNamespace(stdout='\n'.join(rows))),patch('vpn_runtime.legacy_bypass',return_value=None):
            with self.assertRaisesRegex(ValueError,'hook missing'):vpn_runtime.check_service(root)
    def test_no_enabled_modules_never_touches_network(self):
        with patch('incoming_runtime.run') as run,patch('incoming_runtime.awg.preflight') as check:
            incoming_runtime.preflight({'incoming_connections':[]})
            run.assert_not_called();check.assert_not_called()
    def test_boot_preparation_does_not_require_nested_namespace(self):
        from test_amnezia_incoming import entry
        e=entry()
        with patch('incoming_runtime.awg.preflight') as check,patch('incoming_runtime.read_state',return_value={'owned':True}),patch('incoming_runtime.run',return_value=SimpleNamespace(returncode=1)):
            incoming_runtime.preflight({'incoming_connections':[e]},validate_native=False)
            check.assert_called_once_with(e,validate_native=False)
    def test_legacy_awg_receipt_upgrades_without_losing_cleanup_ownership(self):
        from incoming_kernel import interface_name
        s={'ids':['test-awg'],'scopes':[{'interface':interface_name('test-awg'),'sources':['10.99.1.2/32']}],
           'ports':[51830],'digest':'old','opened':True}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'state.json').write_text(json.dumps(s))
            with patch.object(incoming_runtime,'RUNTIME',root),patch('pathlib.Path.stat',return_value=SimpleNamespace(st_uid=0,st_mode=0o100600)):
                state=incoming_runtime.read_state()
            self.assertEqual(state['kinds'],['amneziawg']);self.assertEqual(state['ports'],[{'port':51830,'protocol':'udp'}])
    def test_ocserv_public_ports_follow_dtls_setting(self):
        e={'native':{'type':'openconnect-server','listen_port':19443,'dtls':True}}
        self.assertEqual(incoming_runtime.listeners([e]),[{'port':19443,'protocol':'tcp'},{'port':19443,'protocol':'udp'}])
        e['native']['dtls']=False
        self.assertEqual(incoming_runtime.listeners([e]),[{'port':19443,'protocol':'tcp'}])

    def test_core_ports_follow_protocol_transport_and_listen_address(self):
        active=[{'native':{'type':kind,'listen':'192.0.2.1','listen_port':20000+i,**extra}} for i,(kind,extra) in enumerate([
            ('socks',{}),('http',{}),('vless',{}),('shadowsocks',{}),('shadowsocks',{'network':'udp'}),
            ('openvpn-server',{'network':'tcp'}),('openvpn-server',{'network':'udp'})])]
        ports=incoming_runtime.listeners(active)
        self.assertEqual([(p['port'],p['protocol']) for p in ports],[(20000,'tcp'),(20001,'tcp'),(20002,'tcp'),(20003,'tcp'),(20003,'udp'),(20004,'udp'),(20005,'tcp'),(20006,'udp')])
        state={'scopes':[],'ports':ports}
        self.assertEqual(incoming_runtime.input_rules(state,6),[])
        self.assertTrue(all(rule[:2]==['-d','192.0.2.1'] for rule in incoming_runtime.input_rules(state,4)))
        state['ports']=[{'port':20000,'protocol':'tcp','listen':'::'}]
        self.assertEqual(incoming_runtime.input_rules(state,4),incoming_runtime.input_rules(state,6))
        state['ports'][0]['listen']='::1'
        self.assertEqual(incoming_runtime.input_rules(state,4),[])
        self.assertEqual(incoming_runtime.input_rules(state,6)[0][:2],['-d','::1'])

    def test_disabled_or_all_revoked_core_listener_has_no_firewall_port(self):
        from test_incoming_connections import entry
        e=entry();e['disabled_clients']=[u['username'] for u in e['native']['users']]
        self.assertEqual(incoming_runtime.entries({'incoming_connections':[e]}),[])
        e['disabled_clients']=[];e['enabled']=False
        self.assertEqual(incoming_runtime.entries({'incoming_connections':[e]}),[])

    def test_native_only_prepare_owns_ports_without_kernel_routes_or_engines(self):
        from test_incoming_connections import entry
        e=entry('http');value={'incoming_connections':[e]};saved=[]
        def run(args,**kwargs):
            self.assertIn(args[0],('iptables','ip6tables'))
            self.assertIn('-I',args)
            return SimpleNamespace(returncode=0)
        with patch('incoming_runtime.cleanup'),patch('incoming_runtime.policy',return_value=value),patch('incoming_runtime.preflight'),patch('incoming_runtime.save_state',side_effect=saved.append),patch('incoming_runtime.run',side_effect=run):
            incoming_runtime.prepare(Path('/unused'))
        self.assertEqual(saved[0]['ids'],[]);self.assertEqual(saved[0]['scopes'],[])
        self.assertEqual(len(saved[0]['ports']),1)

    def test_socks_prepare_and_cleanup_own_socket_admission_without_routes(self):
        from test_incoming_connections import entry
        e=entry();saved=[];commands=[]
        def run(args,**kwargs):
            commands.append((args,kwargs));return SimpleNamespace(returncode=1 if '-C' in args or 'list' in args else 0)
        with tempfile.TemporaryDirectory() as d,patch('incoming_runtime.cleanup'),patch('incoming_runtime.policy',return_value={'incoming_connections':[e]}),patch('incoming_runtime.preflight'),patch('incoming_runtime.save_state',side_effect=saved.append),patch('incoming_runtime.run',side_effect=run):
            incoming_runtime.prepare(Path(d))
        self.assertTrue(saved[0]['socks_udp']);self.assertEqual(saved[0]['scopes'],[])
        self.assertFalse(any(a[0]=='ip' for a,k in commands))
        self.assertTrue(any(a[0]=='nft' and 'chain socks_udp' in k.get('data','') for a,k in commands))
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'state.json').write_text('{}')
            with patch.object(incoming_runtime,'RUNTIME',p),patch('incoming_runtime.read_state',return_value=saved[0]),patch('incoming_runtime.run',side_effect=run):incoming_runtime.cleanup()
            self.assertFalse((p/'state.json').exists())
        self.assertTrue(any(a[:2]==['nft','delete'] for a,k in commands))

    def test_partial_firewall_failure_runs_cleanup(self):
        from test_incoming_connections import entry
        with patch('incoming_runtime.cleanup') as cleanup,patch('incoming_runtime.policy',return_value={'incoming_connections':[entry()]}),patch('incoming_runtime.preflight'),patch('incoming_runtime.save_state'),patch('incoming_runtime.run',side_effect=ValueError('insert failed')):
            with self.assertRaisesRegex(ValueError,'insert failed'):incoming_runtime.prepare(Path('/unused'))
            self.assertEqual(cleanup.call_count,2)

if __name__=='__main__':unittest.main()
