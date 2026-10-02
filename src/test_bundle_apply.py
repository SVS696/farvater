import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import safe_apply
from candidate_bundle import build_bundle,validate_bundle
import test_candidate_config as fixtures
import test_safe_apply as safety


class BundleBackend(safety.FakeBackend):
    def validate_bundle(self,files):validate_bundle(files)


class BundleApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        policy=fixtures.CandidateConfigTests().base()
        self.old=build_bundle(policy,api_secret='x'*32)
        policy['profiles'][0]['name']='Updated policy'
        self.new=build_bundle(policy,api_secret='x'*32)
        for name,data in self.old.items():(self.root/name).write_bytes(data)
        self.backend=BundleBackend();self.coord=safe_apply.Coordinator(self.root,self.backend)
    def tearDown(self):self.temp.cleanup()
    def actual(self):return {name:(self.root/name).read_bytes() for name in self.old}

    def test_rollback_restores_policy_manifest_and_config_byte_for_byte(self):
        state=self.coord.apply_bundle(self.new,30)
        self.assertTrue(state['runtime_ready']);self.assertEqual(self.actual(),self.new)
        self.coord.rollback(state['id']);self.assertEqual(self.actual(),self.old)

    def test_partial_write_failure_restores_entire_previous_package(self):
        write=safe_apply.atomic_write
        def interrupted(path,data):
            if path==self.root/'policy-manifest.json' and data==self.new[path.name]:raise OSError('simulated failure')
            write(path,data)
        with patch('safe_apply.atomic_write',side_effect=interrupted),self.assertRaises(OSError):
            self.coord.apply_bundle(self.new,30)
        self.assertEqual(self.actual(),self.old);self.assertEqual(self.coord.state()['status'],'rolled_back')

    def test_corrupt_metadata_backup_does_not_partially_restore_other_files(self):
        state=self.coord.apply_bundle(self.new,30)
        (self.root/'revisions'/(state['id']+'.applied-policy.json')).write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.coord.rollback(state['id'])
        self.assertEqual(self.actual(),self.new)

    def test_boot_recovery_restores_whole_package_without_recursive_restart(self):
        self.coord.apply_bundle(self.new,600);events=list(self.backend.events)
        self.backend.current_boot='boot-B';self.coord.recover_before_start()
        self.assertEqual(self.actual(),self.old);self.assertEqual(events,self.backend.events)

    def test_metadata_drift_refuses_confirmation_and_preserves_rollback(self):
        state=self.coord.apply_bundle(self.new,30)
        (self.root/'applied-policy.json').write_bytes(b'{}')
        with self.assertRaises(ValueError):self.coord.confirm(state['id'])
        self.assertNotIn('cancel',self.backend.events)
        self.coord.rollback(state['id']);self.assertEqual(self.actual(),self.old)

    def test_unverified_restart_cannot_be_confirmed_even_with_all_files_present(self):
        state=self.coord.apply_bundle(self.new,30);state['runtime_ready']=False;self.coord.save(state)
        with self.assertRaises(ValueError):self.coord.confirm(state['id'])
        self.assertNotIn('cancel',self.backend.events)
        self.coord.rollback(state['id']);self.assertEqual(self.actual(),self.old)

    def test_config_only_apply_cannot_detach_bound_metadata(self):
        with self.assertRaises(ValueError):self.coord.apply(self.new['config.json'],30)
        self.assertEqual(self.actual(),self.old);self.assertEqual(self.backend.events,[])

    def test_first_bundle_rollback_removes_only_metadata_it_created(self):
        for name in ('applied-policy.json','policy-manifest.json'):(self.root/name).unlink()
        state=self.coord.apply_bundle(self.new,30);self.coord.rollback(state['id'])
        self.assertEqual((self.root/'config.json').read_bytes(),self.old['config.json'])
        self.assertFalse((self.root/'applied-policy.json').exists())
        self.assertFalse((self.root/'policy-manifest.json').exists())
