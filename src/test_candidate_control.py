import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from candidate_bundle import build_bundle
from candidate_control import handle,ControlError,decode_request,FRAME
from safe_apply import digest
import test_candidate_config as fixtures
import test_bundle_apply as safety


class CandidateControlTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        # Isolate the independent WG journal as well as the candidate files.
        wg_state=patch('wireguard_apply.Transaction.state',return_value={'status':'confirmed'})
        wg_state.start();self.addCleanup(wg_state.stop)
        oc_state=patch('openconnect_apply.state',return_value={})
        oc_state.start();self.addCleanup(oc_state.stop)
        client_state=patch('wg_client_ops.operation_state',return_value={})
        client_state.start();self.addCleanup(client_state.stop)
        self.policy=fixtures.CandidateConfigTests().base();self.files=build_bundle(self.policy,api_secret='private-test-secret-123456789') # gitleaks:allow -- synthetic fixture for redaction assertions
        for n,d in self.files.items():(self.root/n).write_bytes(d)
        self.backend=safety.BundleBackend();self.verify=Mock(return_value={'dns_udp':True,'dns_tcp':True,'https':True})
        self.save_state({'status':'confirmed','id':'a'*32,'next_files':{n:digest(d) for n,d in self.files.items()}})
    def tearDown(self):self.temp.cleanup()
    def save_state(self,v):(self.root/'transaction.json').write_text(json.dumps(v))
    def call(self,action,**fields):return handle({'version':1,'action':action,**fields},root=self.root,backend=self.backend,verify=self.verify)
    def apply(self):
        p=copy.deepcopy(self.policy);p['profiles'][0]['name']='Edited through panel'
        return self.call('apply',policy=p,expected_config_sha256=digest(self.files['config.json']))
    def test_apply_confirm_and_sanitized_readback(self):
        result=self.apply();self.assertEqual(result['transaction']['status'],'pending')
        self.assertTrue(result['integrity']);self.assertNotIn('private-test-secret',json.dumps(result))
        result=self.call('confirm',transaction=result['transaction']['id'],expected_config_sha256=result['config_sha256'])
        self.assertEqual(result['transaction']['status'],'confirmed');self.verify.assert_called_once()
    def test_probe_failure_leaves_pending_transaction_for_independent_rollback(self):
        result=self.apply();self.verify.side_effect=ControlError('probe_failed','Failed')
        with self.assertRaises(ControlError):self.call('confirm',transaction=result['transaction']['id'],expected_config_sha256=result['config_sha256'])
        self.assertEqual(self.call('status')['transaction']['status'],'pending');self.assertNotIn('cancel',self.backend.events)
    def test_stale_baseline_rejects_write_before_restart(self):
        with self.assertRaises(ControlError):self.call('apply',policy=self.policy,expected_config_sha256='0'*64)
        self.assertEqual(self.backend.events,[])
    def test_incomplete_or_extra_request_cannot_select_path_or_unit(self):
        for fields in ({'path':'/etc/passwd'},{'unit':'sing-box'},{'version':2}):
            with self.assertRaises(ControlError):self.call('status',**fields)
        with self.assertRaises(ControlError):self.call('apply',policy=self.policy)
    def test_status_stays_usable_when_metadata_is_corrupt_and_rollback_repairs_it(self):
        result=self.apply();(self.root/'policy-manifest.json').write_text('broken')
        status=self.call('status');self.assertFalse(status['integrity'])
        status=self.call('rollback',transaction=result['transaction']['id'],expected_config_sha256=status['config_sha256'])
        self.assertTrue(status['integrity']);self.assertEqual(status['transaction']['status'],'rolled_back')
        self.assertEqual({n:(self.root/n).read_bytes() for n in self.files},self.files)
    def test_missing_config_can_be_rolled_back_from_status(self):
        result=self.apply();(self.root/'config.json').unlink();status=self.call('status')
        self.assertIsNone(status['config_sha256'])
        result=self.call('rollback',transaction=result['transaction']['id'],expected_config_sha256=None)
        self.assertTrue(result['integrity'])
    def test_unready_process_cannot_confirm_even_with_valid_files(self):
        result=self.apply();state=json.loads((self.root/'transaction.json').read_text());state['runtime_ready']=False;self.save_state(state)
        with self.assertRaises(ControlError):self.call('confirm',transaction=result['transaction']['id'],expected_config_sha256=result['config_sha256'])
        self.verify.assert_not_called()
    def test_valid_json_with_invalid_policy_shape_keeps_status_and_rollback_available(self):
        result=self.apply();(self.root/'applied-policy.json').write_text('[]')
        status=self.call('status');self.assertFalse(status['integrity'])
        status=self.call('rollback',transaction=result['transaction']['id'],expected_config_sha256=status['config_sha256'])
        self.assertTrue(status['integrity'])
    def test_corrupt_or_missing_journal_is_visible_and_never_guessed(self):
        for value in ('broken','{}','[]'):
            self.save_state({})
            (self.root/'transaction.json').write_text(value)
            result=self.call('status');self.assertFalse(result['journal_ok']);self.assertFalse(result['integrity'])
            self.assertEqual(result['config_sha256'],digest(self.files['config.json']))
            with self.assertRaises(ControlError):self.call('apply',policy=self.policy,expected_config_sha256=result['config_sha256'])
        self.assertEqual(self.backend.events,[])
    def test_request_frame_handles_consumed_and_unconsumed_sudo_password(self):
        request={'version':1,'action':'status'};payload=json.dumps(request).encode()
        for prefix in (b'',b'private-test-password\n',FRAME+b'\n'):
            self.assertEqual(decode_request(prefix+FRAME+b'\n'+payload+b'\n'),request)
    def test_unframed_or_extra_lines_never_become_requests(self):
        for raw in (b'password\n{}',FRAME+b'\n{}\nextra',b'one\ntwo\n'+FRAME+b'\n{}'):
            with self.assertRaises(ControlError):decode_request(raw)

    def test_unconfirmed_wireguard_blocks_candidate_apply(self):
        with patch('wireguard_apply.Transaction.state',return_value={'status':'pending'}):
            with self.assertRaisesRegex(ControlError,'WireGuard'):self.apply()
        self.assertEqual(self.backend.events,[])

    def test_unfinished_client_change_blocks_candidate_apply(self):
        with patch('wg_client_ops.operation_state',return_value={'status':'pending'}):
            with self.assertRaisesRegex(ControlError,'клиента WireGuard'):self.apply()
        self.assertEqual(self.backend.events,[])
