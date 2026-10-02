"""Fixed recovery request and checked-job rejection paths use no host writes."""

import json
from contextlib import contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import recovery_control as recovery


def restored_unit(name,active='active',kind='simple',triggered_by=''):
    return {'Id':name,'LoadState':'loaded','ActiveState':active,'UnitFileState':'enabled',
            'Type':kind,'TriggeredBy':triggered_by}


class RecoveryControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'recovery'
        self.root.mkdir(mode=0o700)
        self.backup = self.base / 'backup'
        (self.backup / 'jobs' / ('a' * 32) / 'staged').mkdir(parents=True)
        self.value = 'a' * 32
        self.manifest = 'f' * 64
        self.job = self.backup / 'jobs' / self.value
        (self.job / 'state.json').write_text(json.dumps({
            'kind': 'import', 'status': 'checked', 'manifest_sha256': self.manifest,
            'sha256': 'encrypted-hash', 'anchor_id': None, 'anchor_digest': 'trusted-hash',
            'summary': {'unsupported': 0, 'accounts': {'ready': True}},
        }))
        (self.job / 'uploaded.age').write_text('encrypted')
        (self.job / 'staged' / 'manifest.json').write_text('{}')

    def test_request_rejects_caller_paths_units_and_unknown_transaction(self):
        for request in [
            {'version': 1, 'action': 'restore-status', 'job_id': self.value, 'path': '/etc/shadow'},
            {'version': 1, 'action': 'restore-prepare', 'job_id': self.value,
             'expected_manifest_sha256': self.manifest, 'unit': 'ssh.service'},
            {'version': 1, 'action': 'restore-start', 'job_id': self.value,
             'transaction': 'b' * 32},
        ]:
            with self.subTest(request=request['action']), self.assertRaises(ValueError):
                recovery.control(request, root=self.root, backup_root=self.backup, host=self.base)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_accounts_and_anchor_drift_block_before_materialize(self):
        with (patch.object(recovery.system_backup, 'sha', return_value='encrypted-hash'),
              patch.object(recovery.system_backup, 'verification_identity', return_value={
                  'digest': 'other-hash', 'public_key': b'x' * 32,
              }),
              patch.object(recovery.backup_restore_tree, 'materialize') as materialize):
            with self.assertRaisesRegex(ValueError, 'идентичность'):
                recovery.checked_job(self.value, self.manifest, backup_root=self.backup, host=self.base)
            materialize.assert_not_called()
        state = json.loads((self.job / 'state.json').read_text())
        state['summary']['accounts']['ready'] = False
        (self.job / 'state.json').write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError, 'Владельцы'):
            recovery.checked_job(self.value, self.manifest, backup_root=self.backup, host=self.base)

    def test_foreign_signature_and_platform_block_before_target_mutation(self):
        with (patch.object(recovery.system_backup, 'sha', side_effect=['encrypted-hash', self.manifest]),
              patch.object(recovery.system_backup, 'verification_identity', return_value={
                  'digest': 'trusted-hash', 'public_key': b'x' * 32,
                  'host_id': 'old-host', 'scope': 'server',
              }),
              patch.object(recovery.backup_restore_tree, 'signed_manifest', side_effect=ValueError('bad signature')),
              patch.object(recovery.backup_restore_tree, 'materialize') as materialize):
            with self.assertRaisesRegex(ValueError, 'signature'):
                recovery.checked_job(self.value, self.manifest, backup_root=self.backup, host=self.base)
            materialize.assert_not_called()

    def test_os_release_mismatch_blocks_before_materialize(self):
        os_release=self.base/'os-release';os_release.write_text('ID=ubuntu\nVERSION_ID=24.04\n')
        native_path=Path
        def mapped(value):
            return os_release if value=='/etc/os-release' else native_path(value)
        signed={'metadata':{'host_id':'old-host','scope':'server',
                'platform':{'architecture':'x86_64','os_release':{'ID':'ubuntu','VERSION_ID':'22.04'}}},
                'files':[]}
        with (patch.object(recovery.system_backup,'sha',side_effect=['encrypted-hash',self.manifest]),
              patch.object(recovery.system_backup,'verification_identity',return_value={
                  'digest':'trusted-hash','public_key':b'x'*32,'host_id':'old-host','scope':'server'}),
              patch.object(recovery.backup_restore_tree,'signed_manifest',return_value=signed),
              patch.object(recovery.system_backup,'settings',return_value={'scope':'server'}),
              patch.object(recovery.os,'uname',return_value=SimpleNamespace(machine='x86_64')),
              patch.object(recovery,'Path',side_effect=mapped),
              patch.object(recovery.backup_restore_tree,'materialize') as materialize):
            with self.assertRaisesRegex(ValueError,'Версия системы'):
                recovery.checked_job(self.value,self.manifest,backup_root=self.backup,host=self.base)
            materialize.assert_not_called()

    def test_foreign_architecture_blocks_before_materialize(self):
        signed = {'metadata': {'host_id': 'old-host', 'scope': 'server',
                   'platform': {'architecture': 'foreign-architecture', 'os_release': {}}},
                  'files': [], 'total_bytes': 0}
        with (patch.object(recovery.system_backup, 'sha', side_effect=['encrypted-hash', self.manifest]),
              patch.object(recovery.system_backup, 'verification_identity', return_value={
                  'digest': 'trusted-hash', 'public_key': b'x' * 32,
                  'host_id': 'old-host', 'scope': 'server',
              }),
              patch.object(recovery.backup_restore_tree, 'signed_manifest', return_value=signed),
              patch.object(recovery.system_backup, 'settings', return_value={'scope': 'server'}),
              patch.object(recovery.backup_restore_tree, 'materialize') as materialize):
            with self.assertRaisesRegex(ValueError, 'Архитектура'):
                recovery.checked_job(self.value, self.manifest, backup_root=self.backup, host=self.base)
            materialize.assert_not_called()

    def test_pending_journal_blocks_deletion_and_repeated_start(self):
        journal = self.root / self.value
        journal.mkdir(mode=0o700)
        with patch.object(recovery.restore_files, 'status', return_value={'status': 'awaiting_confirmation'}):
            self.assertTrue(recovery.job_active(self.value, root=self.root))
        with patch.object(recovery.restore_files, 'status', return_value={'status': 'confirmed'}):
            self.assertFalse(recovery.job_active(self.value, root=self.root))
        with patch.object(recovery, 'frozen', return_value={'status': 'awaiting_confirmation'}), patch.object(recovery.restore_files, 'start_guarded') as start:
            response = recovery.control({'version': 1, 'action': 'restore-start',
                'job_id': self.value, 'transaction': self.value}, root=self.root, backup_root=self.backup, host=self.base)
            self.assertEqual(response['status'], 'awaiting_confirmation')
            start.assert_not_called()

    def test_drill_is_unknown_until_valid_evidence_record_exists(self):
        self.assertIsNone(recovery.last_drill(self.root))
        path=self.root/'last-drill.json'
        path.write_text(json.dumps({'status':'passed','at':123,'platform':'linux-amd64',
            'scope':'isolated-full-systemd','evidence_sha256':'a'*64}));path.chmod(0o600)
        self.assertEqual(recovery.last_drill(self.root)['status'],'passed')
        path.write_text(json.dumps({'status':'passed','at':123,'platform':'linux-amd64',
            'scope':'mocked','evidence_sha256':'a'*64}))
        with self.assertRaises(ValueError):recovery.last_drill(self.root)

    def test_restore_is_not_advertised_from_settings_alone(self):
        with patch.object(recovery, 'settings', return_value={'version': 1}):
            self.assertFalse(recovery.available(self.root))

    def test_settings_cannot_omit_panel_from_pending_barrier(self):
        checks=[{'url':'http://127.0.0.1/health','codes':[200],'timeout':1}]
        options={'version':1,'before_checks':checks,'after_checks':checks,
                 'deferred_writers':['okopy-candidate.service'],
                 'tls_chain_source':'/etc/letsencrypt/live/example/fullchain.pem',
                 'tls_key_source':'/etc/letsencrypt/live/example/privkey.pem'}
        (self.root/'settings.json').write_text(json.dumps(options))
        with self.assertRaisesRegex(ValueError,'Панель'):
            recovery.settings(self.root)
        options['deferred_writers']=sorted(recovery.REQUIRED_DEFERRED_WRITERS)
        (self.root/'settings.json').write_text(json.dumps(options))
        self.assertEqual(set(recovery.settings(self.root)['deferred_writers']),
                         recovery.REQUIRED_DEFERRED_WRITERS)

    def test_interrupted_prepare_reuses_one_journal_and_installs_missing_guard(self):
        journal=self.root/self.value;journal.mkdir(mode=0o700)
        source=self.job/'materialized';source.mkdir(mode=0o700)
        plan={'live_root':True,'source':str(source)}
        @contextmanager
        def locked(_):yield journal,plan,self.base,{'status':'prepared'}
        manifest={'metadata':{'service_registry':{'units':[restored_unit('okopy-panel.service')]}}}
        with (patch.object(recovery.restore_files,'status',side_effect=[
                {'status':'prepared'},{'status':'prepared','boot_guard':'installed'}]),
              patch.object(recovery,'checked_job',return_value=(self.job,{},manifest,{'units':[]})),
              patch.object(recovery,'settings',return_value={'before_checks':[],'after_checks':[],
                  'deferred_writers':sorted(recovery.REQUIRED_DEFERRED_WRITERS)}),
              patch.object(recovery.restore_files,'locked',side_effect=locked),
              patch.object(recovery.system_backup,'selected_paths',return_value=['etc/systemd/system/okopy-panel.service']),
              patch.object(recovery.backup_services,'capture',return_value={'units':[{'Id':'okopy-panel.service'}]}),
              patch.object(recovery.restore_files,'attach_services') as attach,
              patch.object(recovery.restore_files,'prepare') as create_second,
              patch.object(recovery.restore_boot,'install') as boot):
            result=recovery.prepare(self.value,self.manifest,root=self.root,backup_root=self.backup,host=self.base)
        self.assertEqual(result['boot_guard'],'installed')
        attach.assert_called_once();boot.assert_called_once_with(journal);create_second.assert_not_called()

    def test_interrupted_prepare_after_guard_armed_fails_closed(self):
        journal=self.root/self.value;journal.mkdir(mode=0o700)
        source=self.job/'materialized';source.mkdir(mode=0o700)
        (journal/'guard.json').write_text('{}')
        plan={'live_root':True,'source':str(source),'services':{'before':{},'after':{}}}
        @contextmanager
        def locked(_):yield journal,plan,self.base,{'status':'prepared'}
        with (patch.object(recovery.restore_files,'status',return_value={'status':'prepared'}),
              patch.object(recovery,'checked_job',return_value=(self.job,{}, {},{})),
              patch.object(recovery,'settings',return_value={}),
              patch.object(recovery.restore_files,'locked',side_effect=locked),
              patch.object(recovery.restore_boot,'install') as boot):
            with self.assertRaisesRegex(ValueError,'уже запускалось'):
                recovery.prepare(self.value,self.manifest,root=self.root,backup_root=self.backup,host=self.base)
        boot.assert_not_called()

    def test_interrupted_prepare_rejects_changed_writer_contract(self):
        journal=self.root/self.value;journal.mkdir(mode=0o700)
        source=self.job/'materialized';source.mkdir(mode=0o700)
        plan={'live_root':True,'source':str(source),'services':{
            'before_checks':[],'after_checks':[],'deferred_writers':['okopy-candidate.service']}}
        @contextmanager
        def locked(_):yield journal,plan,self.base,{'status':'prepared'}
        with (patch.object(recovery.restore_files,'status',return_value={'status':'prepared'}),
              patch.object(recovery,'checked_job',return_value=(self.job,{},
                  {'metadata':{'service_registry':{'units':[restored_unit('okopy-panel.service')]}}},{})),
              patch.object(recovery,'settings',return_value={'before_checks':[],'after_checks':[],
                  'deferred_writers':sorted(recovery.REQUIRED_DEFERRED_WRITERS)}),
              patch.object(recovery.restore_files,'locked',side_effect=locked),
              patch.object(recovery.restore_boot,'install') as boot):
            with self.assertRaisesRegex(ValueError,'Контрольные условия'):
                recovery.prepare(self.value,self.manifest,root=self.root,backup_root=self.backup,host=self.base)
        boot.assert_not_called()

    def test_active_routing_timer_is_deferred_but_candidate_dataplane_is_not(self):
        units={row['Id']:row for row in (
            restored_unit('okopy-panel.service'),
            restored_unit('okopy-candidate.service'),
            restored_unit('okopy-routing.service','inactive','oneshot','okopy-routing.timer'),
            restored_unit('okopy-routing.timer','active','timer'))}
        selected=recovery.deferred_for_registry(units,
            {'deferred_writers':sorted(recovery.REQUIRED_DEFERRED_WRITERS)})
        self.assertEqual(selected,['okopy-panel.service','okopy-routing.timer'])

    def test_terminal_status_resumes_only_timer_and_boot_cleanup(self):
        journal=self.root/self.value;journal.mkdir(mode=0o700)
        (journal/'guard.json').write_text('{}')
        before={'status':'confirmed','boot_guard':'installed','id':self.value}
        after={'status':'confirmed','boot_guard':'removed','id':self.value}
        def systemd(args,**kwargs):
            return SimpleNamespace(stdout='loaded\n' if args[1]=='show' else '')
        with (patch.object(recovery,'frozen',side_effect=[before,after]) as frozen,
              patch.object(recovery.restore_files,'guard_info',return_value={'timer':'okopy-restore-undo-'+self.value}),
              patch.object(recovery.subprocess,'run',side_effect=systemd) as command,
              patch.object(recovery.restore_boot,'remove') as remove,
              patch.object(recovery.restore_files,'start_guarded') as start):
            result=recovery.control({'version':1,'action':'restore-status','job_id':self.value},
                                    root=self.root,backup_root=self.backup,host=self.base)
        self.assertEqual(result['boot_guard'],'removed')
        self.assertEqual(command.call_count,2)
        self.assertEqual(command.call_args_list[0].args[0][:2],['systemctl','show'])
        self.assertEqual(command.call_args_list[1].args[0][:2],['systemctl','stop'])
        remove.assert_called_once_with(journal);start.assert_not_called()
        self.assertEqual(frozen.call_count,2)

    def test_terminal_cleanup_after_reboot_accepts_missing_transient_timer(self):
        journal=self.root/self.value;journal.mkdir(mode=0o700)
        (journal/'guard.json').write_text('{}')
        terminal={'status':'rolled_back','boot_guard':'removed','id':self.value}
        with (patch.object(recovery,'frozen',side_effect=[terminal,terminal]),
              patch.object(recovery.restore_files,'guard_info',return_value={'timer':'okopy-restore-undo-'+self.value}),
              patch.object(recovery.subprocess,'run',return_value=SimpleNamespace(stdout='not-found\n')) as command,
              patch.object(recovery.restore_boot,'remove') as remove):
            result=recovery.control({'version':1,'action':'restore-status','job_id':self.value},
                                    root=self.root,backup_root=self.backup,host=self.base)
        self.assertEqual(result['status'],'rolled_back')
        self.assertNotIn('boot_guard_cleanup_pending',result)
        command.assert_called_once();remove.assert_not_called()


if __name__ == '__main__':
    unittest.main()
