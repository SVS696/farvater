import unittest
from connection_dns import connection_resolve_rule, required_mode
from policy_modes import in_mode
import json


def matches(rule, domain, mode):
    if rule.get('type')=='logical':
        children=[matches(child,domain,mode) for child in rule['rules']]
        value=all(children) if rule['mode']=='and' else any(children)
    else:
        value=('domain' not in rule or domain in rule['domain']) and ('clash_mode' not in rule or mode==rule['clash_mode'])
    return not value if rule.get('invert') else value


class ConnectionDNSTests(unittest.TestCase):
    def test_fakeip_skip_respects_earlier_dns_only_override_and_mode(self):
        rules=[{'domain':['override.test'],'action':'route','server':'private'},
               {'type':'logical','mode':'and','rules':[{'domain':['special.test','override.test']},{'clash_mode':'remote'}],
                'action':'route','server':'fake'},
               {'action':'route','server':'isp'}]
        rule=connection_resolve_rule(rules,[{'type':'fakeip','tag':'fake'}])
        self.assertFalse(matches(rule,'special.test','remote'))
        self.assertTrue(matches(rule,'override.test','remote'))
        self.assertTrue(matches(rule,'special.test','direct'))
        self.assertTrue(matches(rule,'ordinary.test','remote'))

    def test_typed_suppression_stays_inside_dns_policy(self):
        rules=[{'type':'logical','mode':'and','rules':[{'domain':['special.test']},{'query_type':[28]}],
                'action':'predefined','rcode':'NOERROR'},
               {'domain':['special.test'],'action':'route','server':'fake'},
               {'action':'reject','no_drop':True}]
        rule=connection_resolve_rule(rules,[{'type':'fakeip','tag':'fake'}])
        self.assertFalse(matches(rule,'special.test','any'))
        self.assertNotIn('query_type',str(rule))

    def test_prior_whole_query_reject_prevents_remote_resolution(self):
        rules=[{'domain':['blocked.test'],'action':'reject','no_drop':True},
               {'domain':['blocked.test','special.test'],'action':'route','server':'fake'},
               {'action':'reject','no_drop':True}]
        rule=connection_resolve_rule(rules,[{'type':'fakeip','tag':'fake'}])
        self.assertTrue(matches(rule,'blocked.test','any'))
        self.assertFalse(matches(rule,'special.test','any'))

    def test_mode_partition_keeps_precedence_and_scales_linearly(self):
        def make(count):
            rules=[]
            for index in range(count):
                mode='m'+str(index)
                rules.extend([in_mode({'domain':['override.test'],'action':'route','server':'private'},mode),
                              in_mode({'domain':['override.test','remote.test'],'action':'route','server':'fake'},mode),
                              {'clash_mode':mode,'action':'route','server':'isp'}])
            return connection_resolve_rule([*rules,{'action':'reject'}],[{'type':'fakeip','tag':'fake'}])
        rule=make(64)
        for mode in ['m0','m31','m63','unknown']:
            self.assertTrue(matches(rule,'override.test',mode))
            self.assertEqual(matches(rule,'remote.test',mode),mode=='unknown')
        self.assertLess(len(json.dumps(rule)),len(json.dumps(make(32)))*2.1)

    def test_inverted_and_disjunctive_guards_do_not_claim_a_required_mode(self):
        self.assertIsNone(required_mode({'clash_mode':'x','invert':True}))
        self.assertIsNone(required_mode({'type':'logical','mode':'or','rules':[{'clash_mode':'x'},{'domain':['a.test']}]}))
