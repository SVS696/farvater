import copy
import unittest
from group_modes import compile_group_modes


class GroupModeTests(unittest.TestCase):
    def setUp(self):
        self.exits={'vpn':{'scope':'public'},'direct':{'scope':'public'},'work':{'scope':'work'}}
        self.dns={'vpn-dns':{'scope':'public'},'isp':{'scope':'public'},'private':{'scope':'work'}}
        self.groups=[{'id':'google','kind':'public','domains':['*.example.com'],
          'states':{'vpn':{'exit':'vpn','dns':'vpn-dns'},'provider':{'exit':'direct','dns':'isp'}}},
          {'id':'main','kind':'public','states':{'vpn':{'exit':'vpn','dns':'vpn-dns'},'provider':{'exit':'direct','dns':'isp'}}}]

    def test_two_groups_have_four_atomic_combinations(self):
        original=copy.deepcopy(self.groups)
        result=compile_group_modes(self.groups,self.exits,self.dns)
        self.assertEqual(len(result['modes']),4)
        target='google-provider__main-vpn'
        mode=next(m for m in result['modes'] if m['name']==target)
        self.assertEqual(mode['selection'],{'google':'provider','main':'vpn'})
        pairs=[(d,r) for d,r in zip(result['dns_rules'],result['route_rules']) if d.get('clash_mode')==target or any(c.get('clash_mode')==target for c in d.get('rules',[]))]
        self.assertEqual([(d['server'],r['outbound']) for d,r in pairs],[('isp','direct'),('vpn-dns','vpn')])
        self.assertEqual(self.groups,original)

    def test_protected_group_rejects_public_fallback(self):
        self.groups[0]['kind']='work'
        with self.assertRaisesRegex(ValueError,'Защищённая'):compile_group_modes(self.groups,self.exits,self.dns)

    def test_explicit_block_rejects_dns_and_traffic(self):
        self.groups[0]['states']={'off':{'blocked':True}}
        r=compile_group_modes(self.groups,self.exits,self.dns)
        self.assertEqual(r['dns_rules'][0]['action'],'reject')
        self.assertEqual(r['route_rules'][0]['action'],'reject')

    def test_state_space_is_bounded_before_generation(self):
        self.groups=[]
        for n in range(7):self.groups.append({'id':'group-'+str(n),'kind':'public','domains':['x'+str(n)+'.example'],
            'states':{'a':{'blocked':True},'b':{'blocked':True}}})
        with self.assertRaisesRegex(ValueError,'64'):compile_group_modes(self.groups,self.exits,self.dns)

    def test_unknown_reference_and_early_default_are_rejected(self):
        self.groups[0]['states']['vpn']['dns']='missing'
        with self.assertRaises(ValueError):compile_group_modes(self.groups,self.exits,self.dns)
        del self.groups[0]['domains']
        with self.assertRaises(ValueError):compile_group_modes(self.groups,self.exits,self.dns)

    def test_public_overlap_cannot_shadow_protected_or_blocked_group(self):
        protected={'id':'work','kind':'work','domains':['*.corp.example.com'],'states':{'off':{'blocked':True}}}
        self.groups.insert(1,protected)
        with self.assertRaisesRegex(ValueError,'перекрывает'):compile_group_modes(self.groups,self.exits,self.dns)
        protected['domains']=['corp.example.com']
        self.groups[0]['exclude_domains']=['corp.example.com']
        self.assertEqual(len(compile_group_modes(self.groups,self.exits,self.dns)['modes']),4)

    def test_unknown_category_and_unsupported_networks_are_not_silently_ignored(self):
        for patch in [{'kind':'Work'},{'networks':['10.0.0.0/8']}]:
            groups=copy.deepcopy(self.groups);groups[0].update(patch)
            with self.assertRaises(ValueError):compile_group_modes(groups,self.exits,self.dns)


if __name__=='__main__':unittest.main()
