import unittest
from failover import PrioritySelector


class FailoverTests(unittest.TestCase):
    def make(self):
        return PrioritySelector(['vpn','reserve','provider'],'vpn',3,30)

    def test_one_bad_check_does_not_flap(self):
        s=self.make()
        self.assertFalse(s.sample({'vpn':False,'reserve':True,'provider':True},0)['changed'])
        self.assertFalse(s.sample({'vpn':True,'reserve':True,'provider':True},5)['changed'])

    def test_failover_uses_priority_not_fastest_latency(self):
        s=self.make()
        for t in [0,5,10]:r=s.sample({'vpn':False,'reserve':True,'provider':True},t)
        self.assertEqual(r['selected'],'reserve')

    def test_direct_is_last_and_must_be_healthy(self):
        s=self.make()
        for t in [0,5,10]:r=s.sample({'vpn':False,'reserve':False,'provider':True},t)
        self.assertEqual(r['selected'],'provider')
        for t in [15,20,25]:r=s.sample({'vpn':False,'reserve':False,'provider':False},t)
        self.assertFalse(r['healthy'])
        self.assertFalse(r['changed'])

    def test_recovery_waits_and_resets_after_new_failure(self):
        s=self.make()
        for t in [0,5,10]:s.sample({'vpn':False,'reserve':False,'provider':True},t)
        s.sample({'vpn':True,'reserve':False,'provider':True},15)
        self.assertEqual(s.sample({'vpn':True,'reserve':False,'provider':True},40)['selected'],'provider')
        s.sample({'vpn':False,'reserve':False,'provider':True},41)
        s.sample({'vpn':True,'reserve':False,'provider':True},42)
        self.assertEqual(s.sample({'vpn':True,'reserve':False,'provider':True},71)['selected'],'provider')
        self.assertEqual(s.sample({'vpn':True,'reserve':False,'provider':True},72)['selected'],'vpn')

    def test_manual_selection_is_never_overwritten_by_auto(self):
        s=self.make();s.manual='vpn'
        for t in range(10):r=s.sample({'vpn':False,'reserve':True,'provider':True},t)
        self.assertEqual(r['selected'],'vpn');self.assertFalse(r['healthy'])

    def test_protected_group_never_introduces_provider(self):
        s=PrioritySelector(['work-primary','work-reserve'],'work-primary')
        for t in range(10):r=s.sample({'work-primary':False,'work-reserve':False},t)
        self.assertFalse(r['healthy']);self.assertEqual(r['selected'],'work-primary')

    def test_missing_probe_is_not_assumed_healthy(self):
        with self.assertRaises(ValueError):self.make().sample({'vpn':True},0)


if __name__=='__main__':unittest.main()
