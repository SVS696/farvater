import unittest
from unittest.mock import patch
from health_collect import probe,probe_pair,pair_checks,collect,checked
from contextlib import contextmanager
import subprocess

class PairHealthTests(unittest.TestCase):
    def record(self):return {'id':'pair-stable','queue':'default','index':1,'exit':'reserve','effective_dns':'reserve-dns','dns_port':12002,'proxy_port':12003,'dns_name':'example.com','urls':['https://example.com/'],'codes':[200]}
    def test_both_dns_transports_and_all_urls_are_required(self):
        calls=[]
        def fake(check):
            calls.append(check)
            return ('down','failed') if check.get('tcp') else ('up','ok')
        with patch('health_collect.probe',side_effect=fake):status,detail=probe_pair(self.record())
        self.assertEqual(status,'down');self.assertIn('DNS TCP',detail)
        self.assertEqual(len(calls),3);self.assertEqual(next(c for c in calls if c['kind']=='https')['proxy'],'127.0.0.1:12003')
    def test_success_does_not_claim_auto_switching(self):
        with patch('health_collect.probe',return_value=('up','ok')):status,detail=probe_pair(self.record())
        self.assertEqual(status,'up');self.assertIn('резервирования',detail)
    def test_resource_exhaustion_is_unknown_not_a_failed_channel(self):
        with patch('health_collect.run',return_value=subprocess.CompletedProcess([], -6, '', 'resource error')):
            self.assertEqual(probe({'kind':'dns','server':'127.0.0.1','port':12000,'domain':'example.com'})[0],'unknown')
        with patch('health_collect.probe',return_value=('unknown','resource error')):
            self.assertEqual(probe_pair(self.record())[0],'unknown')
    def test_identity_and_revision_are_bound_to_generated_manifest(self):
        check=pair_checks({'config_sha256':'a'*64,'probes':[self.record()]})[0]
        self.assertEqual(check['id'],'pair-stable');self.assertEqual(check['config_sha256'],'a'*64)
    def test_all_8_pairs_fit_beside_64_base_checks(self):
        checks=[{'id':'test-'+str(i),'name':'Test','scope':'candidate','kind':'pair','action':'Inspect'} for i in range(72)]
        with patch('health_collect.probe',return_value=('up','ok')):result,_=collect(checks)
        self.assertEqual(len(result['checks']),72)
    def test_wrapper_timeout_is_not_a_network_failure(self):
        check={'id':'pair','name':'Pair','scope':'candidate','kind':'pair','action':'Inspect'}
        with patch('health_collect.probe',side_effect=subprocess.TimeoutExpired('dig',4)):
            self.assertEqual(checked(check)['status'],'unknown')
    def test_network_io_releases_lock_and_same_hash_reapply_invalidates_sample(self):
        held=[];calls=[];manifest={'config_sha256':'a'*64,'probes':[self.record()]}
        @contextmanager
        def inputs(root):
            calls.append(1);held.append(1)
            try:yield {},manifest,{'id':str(len(calls))}
            finally:held.pop()
        def network(record):
            self.assertFalse(held);return 'up','ok'
        with patch('health_collect.candidate_runtime_inputs',inputs),patch('health_collect.probe_pair',network):
            result=probe({'kind':'pair','id':'pair-stable','config_sha256':'a'*64,'transaction_id':'1'})
        self.assertEqual(result[0],'unknown');self.assertEqual(len(calls),2)
