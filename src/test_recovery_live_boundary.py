"""Fixed-root recovery authorization without touching the host root."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import restore_files as files


class LiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.target = base / 'target'
        self.capsules = base / 'capsules'
        self.jobs = base / 'jobs'
        self.job_id = 'a' * 32
        self.source = self.jobs / self.job_id / 'materialized'
        self.journal = self.capsules / self.job_id
        for path in (self.target, self.capsules, self.jobs, self.source.parent, self.source):
            path.mkdir(mode=0o700, exist_ok=True)
            path.chmod(0o700)
        (self.target / 'settings').write_text('old')
        (self.source / 'settings').write_text('new')
        self.patches = [
            patch.object(files, 'LIVE_ROOT', self.target),
            patch.object(files, 'CAPSULE_ROOT', self.capsules),
            patch.object(files, 'BACKUP_JOBS_ROOT', self.jobs),
            patch.object(files.os, 'geteuid', return_value=self.target.stat().st_uid),
            patch.object(files.os, 'listxattr', return_value=[], create=True),
            patch.object(files, 'boot_id', return_value='boot-test'),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])

    def test_live_prepare_is_fixed_to_job_and_capsule_and_frozen_status(self):
        result = files.prepare(self.target, self.source, ['settings'], ['settings'], self.journal, live=True)
        self.assertTrue(result['live_root_supported'])
        plan = json.loads((self.journal / 'plan.json').read_text())
        self.assertEqual(plan['root'], str(self.target))
        self.assertTrue(plan['live_root'])
        self.assertEqual(files.status(self.journal)['status'], 'prepared')
        self.assertNotIn('root', files.status(self.journal))
        with self.assertRaisesRegex(ValueError, 'загрузочн'):
            files.check_persistent_guard(self.journal, plan)

    def test_live_prepare_rejects_untrusted_source_or_journal_without_writes(self):
        for source, journal in [
            (self.source, self.capsules / ('b' * 32)),
            (self.source.parent / 'other', self.journal),
            (self.source, self.target / self.job_id),
        ]:
            with self.subTest(source=source, journal=journal), self.assertRaises(ValueError):
                files.prepare(self.target, source, ['settings'], ['settings'], journal, live=True)
            self.assertEqual((self.target / 'settings').read_text(), 'old')

    def test_live_prepare_rejects_recovery_and_backup_tree_in_scope(self):
        for name in ('var/lib/okopy-recovery/x', 'var/lib/okopy-backup/jobs/x',
                     'usr/local/lib/systemd/system/infrastructure-recovery-x.service'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                files.prepare(self.target, self.source, [name], ['settings'], self.journal, live=True)
            self.assertFalse(self.journal.exists())
        self.assertFalse(files.protected_live_path('var/lib/okopy-backup/signing.key'))


if __name__ == '__main__':
    unittest.main()
