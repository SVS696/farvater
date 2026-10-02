"""Real status/request seams for closeout section metadata and recovery dispatch."""
import json
import unittest
from unittest.mock import patch

import test_candidate_control as fixture
from candidate_control import ControlError, handle
from candidate_remote import CandidateLocal, FRAME
from policy_sections import section_hashes


class CloseoutControlTests(unittest.TestCase):
    setUp = fixture.CandidateControlTests.setUp
    tearDown = fixture.CandidateControlTests.tearDown
    call = fixture.CandidateControlTests.call
    save_state = fixture.CandidateControlTests.save_state

    def test_validated_status_has_only_section_digests_and_corruption_is_unknown(self):
        result = self.call('status')
        self.assertEqual(result['policy_section_sha256'], section_hashes(self.policy))
        self.assertNotIn('private-test-secret', json.dumps(result))
        (self.root / 'applied-policy.json').write_text('[]')
        result = self.call('status')
        self.assertFalse(result['integrity'])
        self.assertIsNone(result['policy_section_sha256'])

    def test_recovery_boundary_dispatches_only_fixed_request(self):
        request = {'version': 1, 'action': 'restore-status', 'job_id': 'a' * 32}
        with patch('recovery_control.control', return_value={'status': 'not_prepared'}) as call:
            self.assertEqual(handle(request), {'status': 'not_prepared'})
            call.assert_called_once_with(request)
        with patch('recovery_control.control', side_effect=ValueError('invalid request')):
            with self.assertRaises(ControlError):
                handle({**request, 'path': '/etc/passwd'})

    def test_uncertain_restore_mutation_is_not_retried(self):
        import subprocess
        with patch('candidate_remote.subprocess.run', side_effect=subprocess.TimeoutExpired('fixed', 50)) as run:
            with self.assertRaisesRegex(Exception, 'Повтор'):
                CandidateLocal().call('restore-start', job_id='a' * 32, transaction='a' * 32)
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
