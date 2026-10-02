import copy,json,unittest
from candidate_bundle import build_bundle
from routing_decision import choices,decide,validate_preferences
import test_candidate_config as fixtures

class RoutingDecisionTests(unittest.TestCase):
    def setUp(self):
        self.policy=fixtures.CandidateConfigTests().base();self.policy['profiles']=[]
        self.policy['failover'].update(failures=3,recovery_seconds=30)
        self.manifest=json.loads(build_bundle(self.policy,api_secret='x'*32)['policy-manifest.json'])
        self.pairs=choices(self.manifest)['default'];self.manifest['probes']=copy.deepcopy(self.pairs)
        self.prefs={'enabled':True,'pins':{}};self.epoch={'config':self.manifest['config_sha256'],'transaction':'test-id','preferences':'one','boot':'boot'}
        self.previous={};self.mode=self.manifest['modes'][0]['name']
    def sample(self,values,t,now=None):
        snapshot={'checks':[{'id':p['id'],'status':v,'observed_at':t,'config_sha256':self.epoch['config'],'transaction_id':self.epoch['transaction']} for p,v in zip(self.pairs,values)]}
        r=decide(self.manifest,self.policy,self.prefs,snapshot,self.previous,self.mode,self.epoch,t if now is None else now)
        self.previous=r['state'];self.mode=next(m['name'] for m in self.manifest['modes'] if m['selection']==r['selection']);return r
    def test_only_distinct_measurements_count_toward_failover(self):
        for _ in range(5):self.assertFalse(self.sample(['down','up'],100)['changed'])
        self.assertFalse(self.sample(['down','up'],105)['changed'])
        self.assertTrue(self.sample(['down','up'],110)['changed'])
        self.assertEqual(self.previous['queues']['default']['health'][self.pairs[0]['id']]['failures'],3)
    def test_unknown_stale_and_wrong_revision_break_streak(self):
        for case in ('unknown','stale','revision'):
            self.setUp();self.sample(['down','up'],100);self.sample(['down','up'],105)
            if case=='unknown':self.sample(['unknown','up'],110)
            elif case=='stale':self.sample(['down','up'],110,now=160)
            else:self.epoch['transaction']='new';self.sample(['down','up'],110)
            self.assertFalse(self.sample(['down','up'],115)['changed'])
    def test_recovery_needs_continuous_observed_health(self):
        for t in (100,105,110):self.sample(['down','up'],t)
        self.assertFalse(self.sample(['up','up'],120)['changed'])
        self.assertFalse(self.sample(['up','up'],149)['changed'])
        self.assertTrue(self.sample(['up','up'],150)['changed'])
    def test_long_gap_does_not_prove_continuous_recovery(self):
        for t in (100,105,110):self.sample(['down','up'],t)
        self.sample(['up','up'],115)
        self.assertFalse(self.sample(['up','up'],180)['changed'])
    def test_manual_pin_overrides_health_even_when_auto_is_disabled(self):
        self.prefs={'enabled':False,'pins':{'default':self.pairs[1]['id']}}
        self.assertEqual(self.sample(['unknown','down'],100)['selection']['default'],1)
        self.assertFalse(self.sample(['up','down'],200)['changed'])
    def test_all_down_does_not_invent_healthy_fallback(self):
        for t in (100,105,110,115):self.assertFalse(self.sample(['down','down'],t)['changed'])
    def test_boot_or_preference_revision_resets_failures(self):
        self.sample(['down','up'],100);self.sample(['down','up'],105)
        self.epoch['boot']='next';self.assertFalse(self.sample(['down','up'],110)['changed'])
    def test_enabling_requires_complete_coverage_and_pins_are_exact(self):
        validate_preferences(self.prefs,self.manifest)
        self.manifest['probes'].pop()
        with self.assertRaisesRegex(ValueError,'каждой пары'):validate_preferences(self.prefs,self.manifest)
        with self.assertRaises(ValueError):validate_preferences({'enabled':False,'pins':{'default':'wrong'}},self.manifest)
