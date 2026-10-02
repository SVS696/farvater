import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
import urllib.error
import json
import hashlib
import fcntl
import threading
from mode_client import ModeClient


class ModeClientTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.modes=[{'name':str(a)+str(b),'selection':{'rule:x':a,'default':b},'pairs':{}}
                    for a in (0,1) for b in (0,1)]
        self.client=ModeClient(self.modes,api_secret='private-secret',lock_path=Path(self.temp.name)/'mode.lock',require_bundle=False)

    def tearDown(self):self.temp.cleanup()
    def actual(self,mode='00'):return {'mode':mode,'mode-list':[m['name'] for m in self.modes]}

    def test_one_queue_change_preserves_current_other_queue_and_reads_back(self):
        self.client._request=Mock(side_effect=[self.actual('01'),None,self.actual('11')])
        result=self.client.choose({'rule:x':1})
        self.assertTrue(result['changed']);self.assertEqual(result['selection'],{'rule:x':1,'default':1})
        self.assertEqual(self.client._request.call_args_list[1].args,('PATCH',{'mode':'11'}))

    def test_http_success_with_unchanged_mode_is_not_success(self):
        self.client._request=Mock(side_effect=[self.actual(),None,self.actual()])
        with self.assertRaisesRegex(RuntimeError,'не подтверждено'):self.client.choose({'default':1})

    def test_lost_patch_acknowledgement_is_resolved_by_readback_without_retry(self):
        self.client._request=Mock(side_effect=[self.actual(),urllib.error.URLError('timeout'),self.actual('01')])
        self.assertTrue(self.client.choose({'default':1})['changed'])
        self.assertEqual([c.args[0] for c in self.client._request.call_args_list],['GET','PATCH','GET'])

    def test_stale_form_and_unknown_choice_do_not_mutate_runtime(self):
        for choice,expected in [({'default':1},'11'),({'missing':1},None),({'default':True},None),({'default':2},None)]:
            self.client._request=Mock(return_value=self.actual())
            with self.subTest(choice=choice,expected=expected),self.assertRaises(ValueError):
                self.client.choose(choice,expected_mode=expected)
            self.assertEqual(self.client._request.call_count,1)

    def test_mode_missing_from_runtime_manifest_blocks_switch(self):
        self.client._request=Mock(return_value={'mode':'00','mode-list':['00']})
        with self.assertRaisesRegex(ValueError,'отсутствует'):self.client.choose({'default':1})
        self.assertEqual(self.client._request.call_count,1)

    def test_unchanged_selection_does_not_send_patch(self):
        self.client._request=Mock(return_value=self.actual())
        self.assertFalse(self.client.choose({'default':0})['changed'])
        self.assertEqual(self.client._request.call_count,1)

    def test_unknown_current_mode_does_not_guess_other_queues(self):
        self.client._request=Mock(return_value=self.actual('unknown'))
        with self.assertRaisesRegex(ValueError,'не соответствует'):self.client.choose({'default':1})

    def test_mode_request_waits_for_configuration_writer(self):
        entered=threading.Event();requested=threading.Event();errors=[]
        def request(*args):requested.set();return self.actual()
        self.client._request=request
        def choose():
            entered.set()
            try:self.client.choose({'default':0})
            except Exception as error:errors.append(error)
        with (Path(self.temp.name)/'apply.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX);worker=threading.Thread(target=choose);worker.start()
            self.assertTrue(entered.wait(1));self.assertFalse(requested.wait(0.05))
        worker.join(2);self.assertFalse(worker.is_alive());self.assertTrue(requested.is_set());self.assertEqual(errors,[])

    def test_incomplete_apply_and_failed_rollback_block_api_requests(self):
        self.client._request=Mock(return_value=self.actual());root=Path(self.temp.name)
        for state in [{'status':'prepared'},{'status':'pending','runtime_ready':False},{'status':'rollback_failed'}]:
            (root/'transaction.json').write_text(json.dumps(state))
            with self.assertRaises(ValueError):self.client.choose({'default':0})
        self.client._request.assert_not_called()
    def test_same_hash_new_transaction_and_pending_runtime_block_auto_writer(self):
        self.client._request=Mock(return_value=self.actual());root=Path(self.temp.name)
        self.client.bound_transaction='one';self.client.require_settled=True
        for state in ({'id':'two','status':'confirmed'}, {'id':'one','status':'pending','runtime_ready':True}):
            (root/'transaction.json').write_text(json.dumps(state))
            with self.assertRaises(ValueError):self.client.choose({'default':1})
        self.client._request.assert_not_called()

    def test_mode_manifest_must_match_current_bound_configuration(self):
        root=Path(self.temp.name);(root/'config.json').write_bytes(b'current')
        (root/'applied-policy.json').write_text('{}')
        manifest={'bundle_version':1,'modes':self.modes,'config_sha256':hashlib.sha256(b'old').hexdigest()}
        (root/'policy-manifest.json').write_text(json.dumps(manifest));self.client._request=Mock(return_value=self.actual())
        hashes={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('config.json','policy-manifest.json','applied-policy.json')}
        (root/'transaction.json').write_text(json.dumps({'status':'confirmed','next_files':hashes}))
        with self.assertRaises(ValueError):self.client.choose({'default':0})
        self.client._request.assert_not_called()

    def test_policy_only_drift_blocks_mode_request_even_with_unchanged_config(self):
        root=Path(self.temp.name);(root/'config.json').write_bytes(b'current');(root/'applied-policy.json').write_text('{}')
        manifest={'bundle_version':1,'modes':self.modes,'config_sha256':hashlib.sha256(b'current').hexdigest()}
        (root/'policy-manifest.json').write_text(json.dumps(manifest))
        hashes={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('config.json','policy-manifest.json','applied-policy.json')}
        (root/'transaction.json').write_text(json.dumps({'status':'confirmed','next_files':hashes}))
        self.client._request=Mock(return_value=self.actual());self.client.choose({'default':0})
        self.client._request.reset_mock();(root/'applied-policy.json').write_text('{"changed":true}')
        with self.assertRaises(ValueError):self.client.choose({'default':0})
        self.client._request.assert_not_called()

    def test_missing_manifest_is_rejected_by_default_before_api_request(self):
        client=ModeClient(self.modes,api_secret='private-secret',lock_path=Path(self.temp.name)/'mode.lock',bound_config_sha256='0'*64)
        client._request=Mock(return_value=self.actual())
        with self.assertRaises(ValueError):client.choose({'default':0})
        client._request.assert_not_called()

    def test_bound_current_revision_allows_verified_switch(self):
        root=Path(self.temp.name);(root/'config.json').write_bytes(b'current');(root/'applied-policy.json').write_text('{}')
        current=hashlib.sha256(b'current').hexdigest()
        (root/'policy-manifest.json').write_text(json.dumps({'bundle_version':1,'config_sha256':current,'modes':self.modes}))
        hashes={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('config.json','policy-manifest.json','applied-policy.json')}
        (root/'transaction.json').write_text(json.dumps({'status':'confirmed','next_files':hashes}))
        client=ModeClient(self.modes,api_secret='private-secret',lock_path=root/'mode.lock',bound_config_sha256=current)
        client._request=Mock(side_effect=[self.actual(),None,self.actual('01')])
        self.assertTrue(client.choose({'default':1})['changed'])

    def test_same_modes_cannot_authorize_action_for_a_new_policy_revision(self):
        root=Path(self.temp.name);(root/'config.json').write_bytes(b'new revision');(root/'applied-policy.json').write_text('{}')
        current=hashlib.sha256(b'new revision').hexdigest()
        (root/'policy-manifest.json').write_text(json.dumps({'bundle_version':1,'config_sha256':current,'modes':self.modes}))
        hashes={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('config.json','policy-manifest.json','applied-policy.json')}
        (root/'transaction.json').write_text(json.dumps({'status':'confirmed','next_files':hashes}))
        client=ModeClient(self.modes,api_secret='private-secret',lock_path=root/'mode.lock',bound_config_sha256=hashlib.sha256(b'old revision').hexdigest())
        client._request=Mock(return_value=self.actual())
        with self.assertRaises(ValueError):client.choose({'default':0})
        client._request.assert_not_called()
