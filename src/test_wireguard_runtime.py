import copy,ipaddress,socket,struct,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from wireguard_runtime import LinuxBackend,probe_values
from wireguard_profile import parse
from test_wireguard_profile import BASE

class LinuxRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.backend=LinuxBackend(Path('/unused'));self.model=parse(BASE)
        self.snapshot={'active':True,'enabled':'enabled','unit_files':{}}
        self.props={'UnitFileState':'enabled','NeedDaemonReload':'no','ActiveState':'active','SubState':'exited'}
        self.backend.props=Mock(return_value=self.props);self.backend.unit_signature=Mock(return_value={})
        self.backend.interface=Mock(return_value={'mtu':1420,'addr_info':[
            {'family':'inet','local':'10.9.0.1','prefixlen':24,'scope':'global'},
            {'family':'inet6','local':'fd90::1','prefixlen':64,'scope':'global'}]})
        self.kernel='\n'.join(l for l in BASE.splitlines() if not l.startswith('Address'))
    def command(self,args,**kwargs):
        if args[:2]==['wg','showconf']:return 0,self.kernel.encode()
        return 0,b'public-key\n'
    def test_kernel_keys_networks_addresses_and_port_are_checked(self):
        with patch('wireguard_runtime.command',side_effect=self.command):
            self.assertTrue(self.backend.matches('wg0',BASE.encode(),self.snapshot))
            self.kernel=self.kernel.replace('10.9.0.2/32','10.9.0.3/32')
            self.assertFalse(self.backend.matches('wg0',BASE.encode(),self.snapshot))
    def test_missing_address_or_explicit_mtu_mismatch_rejects_runtime(self):
        with patch('wireguard_runtime.command',side_effect=self.command):
            content=BASE.replace('ListenPort = 51820','ListenPort = 51820\nMTU = 1400').encode()
            self.assertFalse(self.backend.matches('wg0',content,self.snapshot))
            self.backend.interface.return_value['addr_info'].pop()
            self.assertFalse(self.backend.matches('wg0',BASE.encode(),self.snapshot))
    def test_tcp_is_bound_to_device_and_unsigned_mark(self):
        value={'address':'10.9.0.2','port':443,'mark':4294967295}
        with patch.object(socket,'SO_BINDTODEVICE',25,create=True),patch.object(socket,'SO_MARK',36,create=True),patch('wireguard_runtime.socket.socket') as factory:
            conn=factory.return_value.__enter__.return_value
            result=self.backend.probe('wg0',value,self.model)
        conn.setsockopt.assert_any_call(socket.SOL_SOCKET,25,b'wg0\0')
        conn.setsockopt.assert_any_call(socket.SOL_SOCKET,36,struct.pack('=I',4294967295))
        conn.connect.assert_called_once_with(('10.9.0.2',443));self.assertEqual(result['status'],'connected')
    def test_local_ip_cannot_be_a_fake_peer_probe(self):
        self.model['peers'][0]['AllowedIPs']=['10.9.0.0/24']
        with patch('wireguard_runtime.socket.socket') as factory:
            with self.assertRaisesRegex(ValueError,'самом сервере'):
                self.backend.probe('wg0',{'address':'10.9.0.1','port':443,'mark':0},self.model)
        factory.assert_not_called()
    def test_probe_refuses_domain_zone_and_ip_outside_allowed_networks(self):
        for address in ['example.com','2001:db8::1%eth0',1234]:
            with self.assertRaises(ValueError):probe_values({'address':address,'port':443,'mark':0})
        with patch('wireguard_runtime.socket.socket') as factory:
            with self.assertRaises(ValueError):self.backend.probe('wg0',{'address':'10.10.10.1','port':443,'mark':0},self.model)
        factory.assert_not_called()
    def test_tcp_failure_is_not_replaced_with_unbound_fallback(self):
        with patch.object(socket,'SO_BINDTODEVICE',25,create=True),patch('wireguard_runtime.socket.socket') as factory:
            factory.return_value.__enter__.return_value.connect.side_effect=OSError('unreachable')
            with self.assertRaises(ValueError):self.backend.probe('wg0',{'address':'10.9.0.2','port':443,'mark':0},self.model)
        self.assertEqual(factory.call_count,1)
    def test_failed_unit_with_leftover_interface_uses_known_profile_for_cleanup(self):
        self.backend.props.return_value={'ActiveState':'failed'}
        self.backend.interface.side_effect=[{'ifname':'wg0'},None]
        with patch('wireguard_runtime.command',return_value=(0,b'')) as run:self.backend.stop('wg0')
        self.assertEqual(run.call_args_list[1].args[0],['wg-quick','down','wg0'])
    def test_running_stop_job_prevents_competing_direct_down(self):
        self.backend.props.return_value={'ActiveState':'deactivating'}
        with patch('wireguard_runtime.command',return_value=(0,b'')) as run:
            with self.assertRaises(ValueError):self.backend.stop('wg0')
        self.assertEqual(run.call_count,1)
