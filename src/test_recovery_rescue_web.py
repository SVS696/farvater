import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from werkzeug.security import generate_password_hash
import recovery_rescue_web as rescue


class RescueWebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        Path(self.temp.name).chmod(0o750)
        group=patch.object(rescue.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=os.getegid()))
        group.start();self.addCleanup(group.stop)
        path=Path(self.temp.name)/'auth.json'
        path.write_text(json.dumps({'username':'admin','password_hash':generate_password_hash('secret-password'),
                                    'session_secret':'test-only-session-secret'}));path.chmod(0o640)
        self.runner=Mock(return_value={'status':'awaiting_confirmation','seconds_left':120})
        with patch.object(rescue,'AUTH_OWNER',os.geteuid()):
            self.app=rescue.create_app(auth_path=path,runner=self.runner,trusted_hosts=['localhost'])
        self.app.testing=True;self.client=self.app.test_client()
        self.job='a'*32

    def csrf(self):
        with self.client.session_transaction() as session:return session['csrf']

    def login(self):
        self.client.get('/recovery/'+self.job,base_url='https://localhost')
        self.client.get('/recovery/login?job='+self.job,base_url='https://localhost')
        r=self.client.post('/recovery/login?job='+self.job,data={'csrf':self.csrf(),'username':'admin','password':'secret-password'},
            headers={'Origin':'https://localhost'},base_url='https://localhost')
        self.assertEqual(r.status_code,302)

    def test_same_admin_and_csrf_required_for_frozen_confirm(self):
        self.assertEqual(self.client.get('/recovery/'+self.job,base_url='https://localhost').status_code,302)
        self.login()
        self.assertIn('120 секунд',self.client.get('/recovery/'+self.job,base_url='https://localhost').text)
        url='/recovery/'+self.job+'/confirm'
        self.assertEqual(self.client.post(url,data={'csrf':self.csrf()},headers={'Origin':'https://localhost'},base_url='https://localhost').status_code,400)
        self.assertEqual(self.client.post(url,data={'csrf':'bad','confirm':'on'},headers={'Origin':'https://localhost'},base_url='https://localhost').status_code,403)
        self.assertEqual(self.client.post(url,data={'csrf':self.csrf(),'confirm':'on'},headers={'Origin':'https://other.example'},base_url='https://localhost').status_code,403)
        self.assertEqual(self.client.post(url,data={'csrf':self.csrf(),'confirm':'on'},headers={'Origin':'https://localhost'},base_url='https://localhost').status_code,302)
        self.runner.assert_any_call('confirm',self.job)

    def test_unknown_host_and_bad_job_never_call_root_helper(self):
        self.assertEqual(self.client.get('/recovery/'+self.job,base_url='https://evil.example').status_code,400)
        self.login();self.runner.reset_mock()
        self.assertEqual(self.client.get('/recovery/not-a-job',base_url='https://localhost').status_code,404)
        self.runner.assert_not_called()

    def test_caddy_access_check_is_fail_closed_and_never_calls_root_helper(self):
        with patch.object(rescue,'main_access_allowed',return_value=False):
            response=self.client.get('/recovery/access-check',base_url='https://localhost')
            self.assertEqual(response.status_code,503)
            self.assertNotIn('Set-Cookie',response.headers)
        with patch.object(rescue,'main_access_allowed',return_value=True):
            self.assertEqual(self.client.get('/recovery/access-check',base_url='https://localhost').status_code,200)
            self.assertEqual(self.client.get('/recovery/access-check',base_url='https://evil.example').status_code,400)
        self.runner.assert_not_called()

    def test_nojs_start_survives_replacement_of_main_panel(self):
        state={'status':'prepared','boot_guard':'installed'}
        def frozen(action,job):
            self.assertEqual(job,self.job)
            if action=='start':
                state.clear();state.update(status='awaiting_confirmation',seconds_left=290)
                return {'status':'started'}
            return dict(state)
        # Register a fresh rescue app with only the frozen runner; no main app process exists.
        path=Path(self.temp.name)/'auth.json'
        with patch.object(rescue,'AUTH_OWNER',os.geteuid()):
            app=rescue.create_app(auth_path=path,runner=frozen,trusted_hosts=['localhost'])
        app.testing=True;client=app.test_client()
        client.get('/recovery/'+self.job,base_url='https://localhost')
        client.get('/recovery/login?job='+self.job,base_url='https://localhost')
        with client.session_transaction() as session:csrf=session['csrf']
        login=client.post('/recovery/login?job='+self.job,data={'csrf':csrf,'username':'admin','password':'secret-password'},
                          headers={'Origin':'https://localhost'},base_url='https://localhost')
        self.assertEqual(login.status_code,302)
        page=client.get('/recovery/'+self.job,base_url='https://localhost')
        self.assertIn('Начать восстановление',page.text)
        with client.session_transaction() as session:csrf=session['csrf']
        response=client.post('/recovery/'+self.job+'/start',data={'csrf':csrf,'confirm':'on'},
                             headers={'Origin':'https://localhost'},base_url='https://localhost')
        self.assertEqual(response.status_code,302)
        self.assertIn('290 секунд',client.get(response.location,base_url='https://localhost').text)

    def test_parallel_login_failure_and_success_do_not_crash(self):
        path=Path(self.temp.name)/'auth.json'
        with patch.object(rescue,'AUTH_OWNER',os.geteuid()):
            app=rescue.create_app(auth_path=path,runner=self.runner,trusted_hosts=['localhost'])
        app.testing=True;good=app.test_client();bad=app.test_client()
        clients=[]
        for client in (good,bad):
            client.get('/recovery/login',base_url='https://localhost')
            with client.session_transaction() as session:clients.append((client,session['csrf']))
        original=rescue.check_password_hash;barrier=threading.Barrier(2)
        def concurrent_check(stored,entered):
            barrier.wait(timeout=5)
            result=original(stored,entered)
            if not result:time.sleep(.05)  # Success may evict the same source first.
            return result
        results=[]
        def post(client,csrf,password):
            response=client.post('/recovery/login',data={'csrf':csrf,'username':'admin','password':password},
                                 headers={'Origin':'https://localhost'},base_url='https://localhost')
            results.append(response.status_code)
        with patch.object(rescue,'check_password_hash',side_effect=concurrent_check):
            threads=[threading.Thread(target=post,args=(clients[0][0],clients[0][1],'secret-password')),
                     threading.Thread(target=post,args=(clients[1][0],clients[1][1],'bad-password'))]
            for thread in threads:thread.start()
            for thread in threads:thread.join(timeout=10)
        self.assertEqual(sorted(results),[200,403])

    def test_lost_pid1_response_is_controlled_and_never_retried(self):
        self.login()
        with patch.object(rescue.subprocess,'run',side_effect=subprocess.TimeoutExpired('sudo rescue',1)) as command:
            with self.assertRaisesRegex(ValueError,'обновите независимый статус'):
                rescue.fixed_run('status',self.job)
            self.assertEqual(command.call_count,1)
        self.runner.side_effect=ValueError('Ответ восстановления не получен; обновите независимый статус')
        status=self.client.get('/recovery/'+self.job,base_url='https://localhost')
        self.assertEqual(status.status_code,503)
        action=self.client.post('/recovery/'+self.job+'/rollback',
            data={'csrf':self.csrf(),'confirm':'on'},headers={'Origin':'https://localhost'},
            base_url='https://localhost')
        self.assertEqual(action.status_code,409)
        self.assertEqual(self.runner.call_count,2)

    def test_terminal_and_missing_timer_states_are_plain_and_actionable(self):
        self.login()
        self.runner.return_value={'status':'confirmed','seconds_left':30}
        terminal=self.client.get('/recovery/'+self.job,base_url='https://localhost')
        self.assertIn('восстановление подтверждено',terminal.text)
        self.assertNotIn('30 секунд',terminal.text)
        self.assertNotIn('>confirmed<',terminal.text)
        self.runner.return_value={'status':'recovery_required','guard_registration':'missing'}
        missing=self.client.get('/recovery/'+self.job,base_url='https://localhost')
        self.assertIn('Таймер возврата не подтвердил запуск',missing.text)
        self.assertIn('Выполнить возврат',missing.text)
        self.assertNotIn('Начать восстановление',missing.text)


if __name__=='__main__':unittest.main()
