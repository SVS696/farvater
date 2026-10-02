"""Run the actual portable AWK state machine, including gaps and malformed input."""
import pathlib,subprocess,unittest

SCRIPT=pathlib.Path(__file__).parent/'router'/'decision.awk'
EPOCH='a'*64


class RouterDecisionTests(unittest.TestCase):
    def tick(self,previous='',now=100,status='up',**overrides):
        values={'epoch':EPOCH,'now':str(now),'sample_at':str(now),'sample_state':status,
                'requested':'auto','integrity':'1','failures_limit':'3','recovery_seconds':'60','max_age':'15',**overrides}
        args=['awk']
        for key,value in values.items():args+=['-v',key+'='+str(value)]
        result=subprocess.run([*args,'-f',str(SCRIPT)],input=previous,text=True,capture_output=True,check=True)
        self.assertEqual(len(result.stdout.rstrip('\n').split('\t')),8)
        return result.stdout

    def field(self,s,index):return s.rstrip('\n').split('\t')[index]
    def ready(self):
        state=''
        for now in range(100,161,5):state=self.tick(state,now)
        self.assertEqual(self.field(state,1),'home');return state

    def test_boot_stays_direct_until_full_stable_window(self):
        state=''
        for now in range(100,160,5):
            state=self.tick(state,now);self.assertEqual(self.field(state,1),'provider')
        self.assertEqual(self.field(self.tick(state,160),1),'home')

    def test_three_distinct_failures_then_recovery_hold(self):
        state=self.ready()
        for now in (165,170):
            state=self.tick(state,now,'down');self.assertEqual(self.field(state,1),'home')
        state=self.tick(state,175,'down');self.assertEqual(self.field(state,1),'provider')
        for now in range(180,240,5):
            state=self.tick(state,now);self.assertEqual(self.field(state,1),'provider')
        self.assertEqual(self.field(self.tick(state,240),1),'home')

    def test_duplicate_failure_is_not_counted_twice(self):
        state=self.tick(self.ready(),165,'down')
        duplicate=self.tick(state,166,'down',sample_at=165)
        self.assertEqual(self.field(duplicate,2),'1');self.assertEqual(self.field(duplicate,1),'home')

    def test_missing_stale_future_or_unknown_health_reverts_to_direct(self):
        for values in [{'status':'unknown'},{'sample_at':140},{'sample_at':200},{'sample_at':'oops'}]:
            with self.subTest(values=values):
                state=self.tick(self.ready(),165,**values)
                self.assertEqual(self.field(state,1),'provider');self.assertEqual(self.field(state,3),'-1')

    def test_long_gap_cannot_count_as_stable_recovery_or_keep_home(self):
        state=self.tick('',100)
        self.assertEqual(self.field(self.tick(state,200),1),'provider')
        self.assertEqual(self.field(self.tick(self.ready(),200),1),'provider')

    def test_manual_provider_and_reenable_restart_recovery(self):
        state=self.tick(self.ready(),165,requested='provider')
        self.assertEqual(self.field(state,1),'provider')
        state=self.tick(state,170)
        self.assertEqual(self.field(state,1),'provider');self.assertEqual(self.field(state,3),'170')

    def test_config_clock_and_firewall_reset_start_direct(self):
        for now,values in [(165,{'epoch':'b'*64}),(10,{}),(165,{'integrity':'0'})]:
            with self.subTest(now=now,values=values):self.assertEqual(self.field(self.tick(self.ready(),now,**values),1),'provider')

    def test_corrupt_prior_state_is_not_trusted(self):
        for state in ['garbage\n',self.ready()+self.ready(),self.ready().replace('\t0\t','\tnan\t',1)]:
            with self.subTest(state=state):self.assertEqual(self.field(self.tick(state,165),1),'provider')

    def test_a_good_sample_resets_failure_streak(self):
        state=self.tick(self.ready(),165,'down');state=self.tick(state,170)
        state=self.tick(state,175,'down');self.assertEqual(self.field(state,2),'1');self.assertEqual(self.field(state,1),'home')

    def test_invalid_configuration_has_no_decision(self):
        for values in [{'failures_limit':'0'},{'epoch':'bad'},{'requested':'home;reboot'}, {'recovery_seconds':'nan'}]:
            with self.subTest(values=values),self.assertRaises(subprocess.CalledProcessError):self.tick(**values)
