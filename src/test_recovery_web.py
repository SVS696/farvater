"""Primary backup recovery page uses native forms and the fixed candidate API."""

import unittest
from unittest.mock import Mock

import test_web as base
import recovery_web
from web import create_app


class RecoveryWebTests(unittest.TestCase):
    setUp=base.WebTests.setUp
    tearDown=base.WebTests.tearDown
    login=base.WebTests.login

    def setup_recovery(self,status='not_prepared'):
        backend=Mock()
        job={'id':'a'*32,'kind':'import','status':'checked','created_at':1000,
             'manifest_sha256':'f'*64,'summary':{'same':1,'changed':0,'missing':0,'unsupported':0,
                                                  'accounts':{'ready':True}}}
        def call(action,**fields):
            if action=='backup-status':return {'jobs':[job],'restore_application_available':True}
            if action=='restore-status':return {'id':job['id'],'status':status,'boot_guard':'installed'}
            return {'id':job['id'],'status':'prepared'}
        backend.call.side_effect=call
        self.app=create_app(self.path,backend)
        self.app.testing=True
        self.client=self.app.test_client()
        return backend,job

    def test_authenticated_native_prepare_requires_explicit_confirmation(self):
        backend,job=self.setup_recovery()
        self.assertEqual(self.client.get('/backups/restore/'+job['id']).status_code,302)
        csrf=self.login()
        page=self.client.get('/backups/restore/'+job['id'])
        self.assertEqual(page.status_code,200)
        self.assertIn('name="manifest_sha256"',page.text)
        self.assertIn('name="confirm" required',page.text)
        path='/backups/'+job['id']+'/restore/prepare'
        self.assertEqual(self.client.post(path,data={'csrf':csrf,'manifest_sha256':job['manifest_sha256']}).status_code,400)
        self.assertEqual(self.client.post(path,data={'csrf':csrf,'manifest_sha256':job['manifest_sha256'],'confirm':'on'}).status_code,302)
        backend.call.assert_any_call('restore-prepare',job_id=job['id'],expected_manifest_sha256=job['manifest_sha256'])

    def test_unknown_job_and_runbook(self):
        self.setup_recovery();self.login()
        self.assertEqual(self.client.get('/backups/restore/'+'b'*32).status_code,404)
        guide=self.client.get('/backups/recovery/help')
        self.assertEqual(guide.status_code,200)
        self.assertIn('ключ age',guide.text)

    def test_malformed_job_path_is_rejected_before_backend(self):
        backend,_=self.setup_recovery();self.login();backend.call.reset_mock()
        for identifier in ('bad','A'*32,'a'*33,'неверный'):
            with self.subTest(identifier=identifier):
                self.assertEqual(self.client.get('/backups/restore/'+identifier).status_code,404)
        backend.call.assert_not_called()

    def test_malformed_start_id_is_rejected_before_redirect_or_backend(self):
        backend,_=self.setup_recovery();csrf=self.login();backend.call.reset_mock()
        response=self.client.post('/backups/bad/restore/start',data={'csrf':csrf,'confirm':'on'})
        self.assertEqual(response.status_code,404)
        self.assertNotIn('Location',response.headers)
        backend.call.assert_not_called()

    def test_prepared_page_moves_start_to_independent_rescue(self):
        backend,job=self.setup_recovery('prepared');csrf=self.login()
        page=self.client.get('/backups/restore/'+job['id'])
        self.assertIn('/recovery/'+job['id'],page.text)
        self.assertNotIn('/backups/'+job['id']+'/restore/start',page.text)
        backend.call.reset_mock()
        response=self.client.post('/backups/'+job['id']+'/restore/start',
                                  data={'csrf':csrf,'confirm':'on'})
        self.assertEqual(response.status_code,303)
        self.assertEqual(response.location,'/recovery/'+job['id'])
        backend.call.assert_not_called()


if __name__=='__main__':unittest.main()
