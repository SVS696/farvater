import copy
import re
import unittest
from incoming_kernel import awg_scope,inbounds,route_prefix,nft_script,validate,interface_name
from test_amnezia_incoming import entry

class IncomingKernelTests(unittest.TestCase):
    def test_capture_mark_is_applied_after_mangle_and_before_destination_nat(self):
        script=nft_script([awg_scope(entry())],True)
        priority=int(re.search(r'hook prerouting priority (-?\d+)',script).group(1))
        self.assertGreater(priority,-150)
        self.assertLess(priority,-100)

    def test_disabled_client_removed_from_admitted_sources(self):
        e=entry();s=awg_scope(e)
        self.assertEqual(len(inbounds([s])),2);self.assertEqual(len(route_prefix([s])),6)
        e['disabled_clients']=['phone'];closed=awg_scope(e)
        self.assertEqual(inbounds([closed]),[]);self.assertEqual(route_prefix([closed]),[])
        self.assertNotIn('tproxy',nft_script([closed],True));self.assertIn('drop',nft_script([closed],True))
    def test_capture_is_limited_to_owned_interface_and_sources(self):
        s=awg_scope(entry());opened=nft_script([s],True);closed=nft_script([s],False)
        self.assertIn('iifname "'+s['interface']+'"',opened)
        self.assertIn('10.212.0.2/32',opened);self.assertIn('fd12:212::2/128',opened)
        self.assertNotIn('tproxy',closed);self.assertNotIn('0.0.0.0/0',opened)
        self.assertNotIn('forward',opened)
    def test_reject_cross_interface_address_overlap(self):
        s=awg_scope(entry());other=copy.deepcopy(s);other['interface']=interface_name('other')
        with self.assertRaisesRegex(ValueError,'пересекаются'):validate([s,other])
        for name in ('eth0','fi"bad','fi0123456789*'):
            with self.assertRaises(ValueError):validate([{**s,'interface':name}])
    def test_empty_has_no_core_listeners(self):
        self.assertEqual(inbounds([]),[]);self.assertEqual(route_prefix([]),[])

    def test_udp_admission_matches_owned_socket_only_after_activation(self):
        from incoming_kernel import SOCKS_UDP_MARK
        opened=nft_script([],True,True);closed=nft_script([],False,True)
        self.assertIn('socket mark '+str(SOCKS_UDP_MARK),opened)
        self.assertNotIn('socket mark',closed)
        self.assertNotIn('socket mark',nft_script([],True))
        self.assertNotIn('tproxy',opened);self.assertNotIn('dport',opened)

if __name__=='__main__':unittest.main()
