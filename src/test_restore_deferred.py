"""Restored administrative writers remain stopped until guarded confirmation."""

import unittest
from unittest.mock import patch
from contextlib import contextmanager
from pathlib import Path

import restore_files as files


def unit(active):
    return {'Id': 'unused', 'LoadState': 'loaded', 'ActiveState': active,
            'UnitFileState': 'enabled'}


class DeferredServicesTests(unittest.TestCase):
    def setUp(self):
        self.services = {'before': {'core.service': {'mode': 'start', 'boot': 'enabled'},
                                    'panel.service': {'mode': 'start', 'boot': 'enabled'}},
                         'after': {'core.service': {'mode': 'start', 'boot': 'enabled'},
                                   'panel.service': {'mode': 'start', 'boot': 'enabled'}},
                         'deferred_writers': ['panel.service'],
                         'before_checks': [], 'after_checks': [], 'mutable_paths': []}

    def test_apply_stage_starts_core_but_not_panel(self):
        actual = {'core.service': unit('active'), 'panel.service': unit('inactive')}
        with patch.object(files, 'service_capture', return_value=actual), patch.object(files.subprocess, 'run') as run:
            files.start_services(self.services, 'after', pending=True)
        starts = [call.args[0] for call in run.call_args_list if call.args[0][:2] == ['systemctl', 'start']]
        self.assertEqual(starts, [['systemctl', 'start', 'core.service']])

    def test_pending_match_requires_panel_stopped(self):
        actual = {'core.service': unit('active'), 'panel.service': unit('inactive')}
        with patch.object(files, 'service_capture', return_value=actual):
            self.assertTrue(files.service_matches(self.services, 'after', pending=True))
        actual['panel.service']['ActiveState'] = 'active'
        with patch.object(files, 'service_capture', return_value=actual):
            self.assertFalse(files.service_matches(self.services, 'after', pending=True))

    def test_failed_precommit_panel_start_requests_same_journal_rollback(self):
        journal = Path('/unused/journal')
        plan = {'entries': {'config': {'after': {'kind': 'file'}}}, 'services': self.services}
        @contextmanager
        def locked(_):
            yield journal, plan, Path('/unused'), {'status': 'awaiting_confirmation'}
        with (patch.object(files, 'locked', side_effect=locked),
              patch.object(files, 'check_window'), patch.object(files, 'check_persistent_guard'),
              patch.object(files, 'inspect', return_value={'kind': 'file'}),
              patch.object(files, 'service_matches', return_value=True),
              patch.object(files, 'run_checks'),
              patch.object(files, 'start_deferred_services', side_effect=ValueError('panel failed')),
              patch.object(files, 'rollback') as rollback,
              patch.object(files, 'save') as save):
            with self.assertRaisesRegex(ValueError, 'panel failed'):
                files.confirm(journal)
        rollback.assert_called_once_with(journal)
        save.assert_not_called()


if __name__ == '__main__':
    unittest.main()
