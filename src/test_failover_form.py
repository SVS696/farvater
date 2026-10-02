import unittest
from werkzeug.datastructures import MultiDict
from failover_form import parse_failover,default_group
from group_modes import compile_group_modes
from policy import validate_policy

class PairedFailoverTests(unittest.TestCase):
    def setUp(self):
        self.policy={'default_exit':'vpn','default_dns':'vpn-dns','profiles':[],
                     'exits':{'vpn':{'scope':'public'},'direct':{'scope':'public'},'work':{'scope':'work'}},
                     'dns':{'vpn-dns':{'scope':'public'},'isp':{'scope':'public'},'work-dns':{'scope':'work'}}}
    def form(self,pairs):
        return MultiDict([('failures','3'),('recovery','30')]+
                         [(key,value) for pair in pairs for key,value in zip(('exit','dns'),pair)])

    def test_ui_pairs_compile_to_matching_dns_and_exit_states(self):
        result=parse_failover(self.form([('vpn','vpn-dns'),('direct','isp'),('','')]),self.policy)
        output=compile_group_modes([default_group(result)],self.policy['exits'],self.policy['dns'])
        self.assertEqual(output['dns_rules'],[
            {'clash_mode':'default-vpn','action':'route','server':'vpn-dns'},
            {'clash_mode':'default-direct','action':'route','server':'isp'}])
        self.assertEqual([r['outbound'] for r in output['route_rules']],['vpn','direct'])

    def test_missing_half_pair_is_not_silently_inferred(self):
        for pair in [('vpn',''),('','isp')]:
            with self.subTest(pair=pair),self.assertRaises(ValueError):
                parse_failover(self.form([pair]),self.policy)

    def test_reordering_moves_dns_with_its_explicit_exit(self):
        result=parse_failover(self.form([('direct','isp'),('vpn','vpn-dns')]),self.policy)
        self.assertEqual(result['priority'],['direct','vpn'])
        self.assertEqual(result['dns_by_exit'],{'direct':'isp','vpn':'vpn-dns'})

    def test_protected_resources_cannot_enter_public_failover(self):
        for pair in [('work','isp'),('vpn','work-dns'),('vpn','missing')]:
            with self.subTest(pair=pair),self.assertRaises(ValueError):
                parse_failover(self.form([pair]),self.policy)

    def test_duplicate_exit_and_empty_queue_are_rejected(self):
        for pairs in [[('vpn','vpn-dns'),('vpn','isp')],[('','')]]:
            with self.subTest(pairs=pairs),self.assertRaises(ValueError):
                parse_failover(self.form(pairs),self.policy)

    def test_later_scope_change_is_reported_as_blocking_conflict(self):
        self.policy['failover']=parse_failover(self.form([('vpn','vpn-dns')]),self.policy)
        self.policy['dns']['vpn-dns']['scope']='work'
        self.assertTrue(any(i['profile']=='Общее резервирование' and i['severity']=='error'
                            for i in validate_policy(self.policy)))

    def test_legacy_exit_only_queue_cannot_compile(self):
        with self.assertRaises(ValueError):default_group({'priority':['vpn','direct']})

if __name__=='__main__':unittest.main()
