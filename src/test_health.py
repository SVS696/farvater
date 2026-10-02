import copy
import json
from pathlib import Path
import subprocess
import tempfile
import time
import errno
import urllib.error
import hashlib
import fcntl
import unittest
from unittest.mock import patch

from health_model import present_snapshot,validate_snapshot,transport_message
from health_collect import service_result,checked,collect,probe,candidate_runtime_inputs,RuntimeNotReady
from health_pull import pull_once


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.row={'id':'dns','name':'DNS','scope':'Кандидат','detail':'Успешно','action':'Проверьте DNS',
                  'status':'up','observed_at':1000,'duration_ms':2}
        self.snapshot={'version':1,'generated_at':1000,'checks':[self.row]}
        self.path=self.root/'health.json';self.path.write_text(json.dumps(self.snapshot))
    def tearDown(self):self.temp.cleanup()

    def test_edit_invalidates_local_success_after_inflight_old_fetch_finishes(self):
        import threading
        from health_pull import invalidate_local_check
        entered=threading.Event();release=threading.Event();errors=[]
        response=subprocess.CompletedProcess([],0,json.dumps(self.snapshot).encode(),b'')
        def fetch(*args,**kwargs):
            entered.set();release.wait(2);return response
        def invalidate():
            try:invalidate_local_check(self.root,'dns',1001)
            except Exception as error:errors.append(error)
        with patch('server_connection.read',return_value={'targets':[{'host':'server.example.test','port':22,'username':'operator','identity_file':''}]}),patch('health_pull.subprocess.run',side_effect=fetch):
            reader=threading.Thread(target=pull_once,args=(self.root,));reader.start();self.assertTrue(entered.wait(1))
            editor=threading.Thread(target=invalidate);editor.start();release.set();reader.join(2);editor.join(2)
        self.assertFalse(reader.is_alive() or editor.is_alive());self.assertEqual(errors,[])
        rendered=present_snapshot(self.path,now=1002)
        self.assertEqual(rendered['checks'][0]['status'],'unknown')
        self.assertIn('изменены',rendered['checks'][0]['detail'])

    def test_good_old_snapshot_never_stays_green(self):
        self.assertEqual(present_snapshot(self.path,now=1010)['status'],'up')
        old=present_snapshot(self.path,now=1156)
        self.assertEqual(old['status'],'stale');self.assertEqual(old['checks'][0]['status'],'stale')

    def test_inflight_oneshot_keeps_completed_result_without_refreshing_time(self):
        check={**self.row,'kind':'service','unit':'example.service'}
        busy={**self.row,'status':'unknown','detail':'Проверка сейчас выполняется',
              'service_unit':'example.service','in_progress':True,'observed_at':1050}
        for status in ('up','down','degraded'):
            prior={**self.snapshot,'checks':[{**self.row,'status':status,'service_unit':'example.service'}]}
            with patch('health_collect.checked',return_value=busy):
                result,events=collect([check],prior)
                again,events_again=collect([check],result)
            self.assertEqual(result['checks'][0]['status'],status)
            self.assertEqual(again['checks'][0]['observed_at'],1000)
            self.assertEqual(events,[]);self.assertEqual(events_again,[])
            result['generated_at']=1050;self.path.write_text(json.dumps(result))
            self.assertEqual(present_snapshot(self.path,now=1156)['checks'][0]['status'],'stale')

    def test_inflight_oneshot_without_same_source_stays_unknown(self):
        busy={**self.row,'status':'unknown','service_unit':'new.service','in_progress':True}
        for prior in (None,self.snapshot,{**self.snapshot,'checks':[{**self.row,'service_unit':'old.service'}]}):
            with patch('health_collect.checked',return_value=busy):
                result,_=collect([{**self.row,'kind':'service'}],prior)
            self.assertEqual(result['checks'][0]['status'],'unknown')

    def test_completed_failure_replaces_inflight_previous_success_and_logs(self):
        prior={**self.snapshot,'checks':[{**self.row,'service_unit':'example.service','in_progress':True}]}
        failed={**self.row,'service_unit':'example.service','in_progress':False,'status':'down','observed_at':1050}
        with patch('health_collect.checked',return_value=failed):
            result,events=collect([{**self.row,'kind':'service'}],prior)
        self.assertEqual(result['checks'][0],failed);self.assertEqual(events[0]['status'],'down')

    def test_future_clock_and_corrupted_snapshot_do_not_claim_health(self):
        self.assertEqual(present_snapshot(self.path,now=900)['status'],'stale')
        for value in ['broken',json.dumps({'version':1,'generated_at':1e300,'checks':[]})]:
            self.path.write_text(value);self.assertEqual(present_snapshot(self.path,now=1000)['status'],'unknown')

    def test_duplicate_ids_and_nonfinite_measurements_are_rejected(self):
        value=copy.deepcopy(self.snapshot);value['checks']*=2
        with self.assertRaises(ValueError):validate_snapshot(value)
        value=copy.deepcopy(self.snapshot);value['checks'][0]['duration_ms']=float('nan')
        with self.assertRaises(ValueError):validate_snapshot(value)

    def test_oneshot_inactive_is_success_only_when_recent_and_successful(self):
        fields={'LoadState':'loaded','Type':'oneshot','ActiveState':'inactive','Result':'success',
                'ExecMainStatus':'0','ExecMainExitTimestampMonotonic':'1000000000'}
        self.assertEqual(service_result(fields,1010)[0],'up')
        self.assertEqual(service_result(fields,1100)[0],'unknown')
        fields['Result']='exit-code';self.assertEqual(service_result(fields,1010)[0],'down')

    def test_dns_exit_zero_with_servfail_is_not_success(self):
        check={'kind':'dns','server':'127.0.0.1','port':5301,'domain':'test.invalid'}
        with patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,';; status: SERVFAIL','')):
            self.assertEqual(probe(check)[0],'down')

    def test_wg_persistent_oneshot_is_distinct_from_periodic_job(self):
        fields={'LoadState':'loaded','Type':'oneshot','ActiveState':'active','RemainAfterExit':'yes',
                'Result':'success','ExecMainStatus':'0','ExecMainExitTimestampMonotonic':'1000000'}
        self.assertEqual(service_result(fields,100000)[0],'up')
        fields['ActiveState']='inactive'
        self.assertEqual(service_result(fields,100000)[0],'unknown')

    def test_https_rejects_http_error_and_does_not_follow_redirect_to_unchecked_url(self):
        with patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,'500\t0.001\t0.01\t0.05\t0.06\t0.07','')) as run:
            self.assertEqual(probe({'kind':'https','url':'https://example.com','proxy':'127.0.0.1:2081'})[0],'down')
            self.assertNotIn('--location',run.call_args.args[0])

    def test_http_failures_distinguish_causes_without_echoing_transport_text(self):
        for rc,body,expected in [(6,'000','имя сервера'),(28,'000','время ожидания'),
                                 (60,'000','сертификат'),(97,'000','прокси'),
                                 (0,'503','HTTP 503')]:
            with self.subTest(rc=rc,body=body),patch('health_collect.run',return_value=subprocess.CompletedProcess([],rc,body+'\t0.001\t0.01\t0\t0\t2','secret-password https://private.example/token')):
                status,detail=probe({'kind':'https','url':'https://example.com'})
                self.assertEqual(status,'down');self.assertIn(expected,detail)
                self.assertNotIn('secret-password',detail);self.assertNotIn('private.example',detail)

    def test_http_partial_body_timeout_is_not_success_even_after_200(self):
        response=subprocess.CompletedProcess([],28,'200\t0.001\t0.01\t0.05\t0.06\t6','')
        with patch('health_collect.run',return_value=response):
            status,detail=probe({'kind':'https','url':'https://example.com'})
        self.assertEqual(status,'down');self.assertIn('curl 28',detail)
        self.assertIn('TLS: 50.0 мс',detail);self.assertIn('Первый байт: 60.0 мс',detail)

    def test_socks_connect_does_not_claim_origin_connect_or_dns_success(self):
        response=subprocess.CompletedProcess([],28,'000\t0.000001\t0.0001\t0\t0\t2','')
        with patch('health_collect.run',return_value=response):
            status,detail=probe({'kind':'https','url':'https://example.com','proxy':'127.0.0.1:2081'})
        self.assertEqual(status,'down');self.assertIn('TCP к прокси: 0.1 мс',detail)
        self.assertIn('не подтверждает DNS',detail);self.assertNotIn('TCP к серверу:',detail)
        self.assertNotIn('DNS:',detail);self.assertIn('TLS: завершение не зафиксировано',detail)

    def test_incomplete_or_untrusted_measurement_cannot_turn_green(self):
        for output in ('200','200\t0\t0\t0\tNaN\t1','200\t0\t0\t0\t0\t3601',
                       '200\t0\t0\t0\t0\tsecret-password','200\t0\t0\t0\t0\t1\nprivate-token'):
            with self.subTest(output=output),patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,output,'')):
                status,detail=probe({'kind':'https','url':'http://example.com'})
                self.assertEqual(status,'unknown');self.assertNotIn('secret',detail);self.assertNotIn('private',detail)

    def test_plain_http_progress_does_not_claim_tls(self):
        with patch('health_collect.run',return_value=subprocess.CompletedProcess([],28,'000\t0\t0.01\t0\t0\t6','')):
            status,detail=probe({'kind':'https','url':'http://example.com'})
        self.assertEqual(status,'down');self.assertNotIn('TLS:',detail)

    def test_transport_failure_survives_missing_timing_and_nonstandard_code_is_down(self):
        for rc,output,expected in ((28,'','curl 28'),(7,'private-token','curl 7'),
                                   (0,'999\t0\t0.1\t0.2\t0.3\t0.4','допустимый HTTP-код')):
            with self.subTest(rc=rc,output=output),patch('health_collect.run',return_value=subprocess.CompletedProcess([],rc,output,'')):
                status,detail=probe({'kind':'https','url':'https://example.com'})
                self.assertEqual(status,'down');self.assertIn(expected,detail);self.assertNotIn('private-token',detail)

    def test_probe_errors_do_not_disclose_secrets(self):
        with patch('health_collect.probe',side_effect=OSError('secret-password')):
            result=checked({**self.row,'kind':'dns'})
        self.assertEqual(result['status'],'unknown');self.assertNotIn('secret-password',json.dumps(result))

    def test_exit_ip_probe_reports_only_valid_public_ipv4(self):
        check={'kind':'https','url':'https://api.ipify.org','proxy':'127.0.0.1:2081','observe_ip':True}
        with patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,'92.42.99.188\n200','')) as run:
            status,detail=probe(check)
        self.assertEqual(status,'up');self.assertIn('92.42.99.188',detail)
        self.assertIn('--max-filesize',run.call_args.args[0]);self.assertNotIn('--location',run.call_args.args[0])

    def test_exit_ip_probe_rejects_private_invalid_and_http_error_responses(self):
        check={'kind':'https','url':'https://api.ipify.org','observe_ip':True}
        for body,expected in [('127.0.0.1\n200','unknown'),('10.0.0.1\n200','unknown'),('secret-in-html\n200','unknown'),('92.42.99.188\n503','down'),('x'*133,'down')]:
            with self.subTest(body=body),patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,body,'')):
                status,detail=probe(check);self.assertEqual(status,expected);self.assertNotIn('secret-in-html',detail)

    def test_exit_ip_probe_does_not_accept_body_after_curl_failure(self):
        with patch('health_collect.run',return_value=subprocess.CompletedProcess([],28,'92.42.99.188\n200','')):
            self.assertEqual(probe({'kind':'https','url':'https://api.ipify.org','observe_ip':True})[0],'down')

    def test_changed_exit_ip_is_logged_even_when_https_stays_healthy(self):
        check={**self.row,'kind':'https','observe_ip':True};new={**self.row,'detail':'Фактический внешний IPv4: 92.42.99.188'}
        with patch('health_collect.checked',return_value=new):
            _,events=collect([check],self.snapshot)
        self.assertEqual(len(events),1)

    def test_sinkhole_and_loopback_answers_do_not_pass_dns_health(self):
        check={'kind':'dns','server':'127.0.0.1','port':5301,'domain':'test.invalid'}
        for address in ('0.0.0.0','127.0.0.1','255.255.255.255','224.0.0.1'):
            response=';; status: NOERROR\ntest.invalid. 60 IN A '+address
            with patch('health_collect.run',return_value=subprocess.CompletedProcess([],0,response,'')):
                self.assertEqual(probe(check)[0],'down')

    def test_recent_auto_restart_is_degraded_even_when_process_is_active(self):
        fields={'LoadState':'loaded','Type':'simple','ActiveState':'active','NRestarts':'2',
                'ActiveEnterTimestampMonotonic':'1000000000'}
        self.assertEqual(service_result(fields,1020)[0],'degraded')
        self.assertEqual(service_result(fields,1200)[0],'up')

    def test_unexpected_probe_error_does_not_drop_other_results_or_leak_text(self):
        with patch('health_collect.probe',side_effect=[IndexError('sensitive'),('up','ok')]):
            snapshot,_=collect([{**self.row,'kind':'resources'},{**self.row,'id':'next','kind':'dns'}])
        self.assertEqual([r['status'] for r in snapshot['checks']],['unknown','up'])
        self.assertNotIn('sensitive',json.dumps(snapshot))

    def test_collection_deadline_keeps_completed_checks_and_marks_slow_unknown(self):
        def controlled(check):
            if check['id']=='slow':time.sleep(0.08)
            return {**self.row,'id':check['id']}
        with patch('health_collect.checked',side_effect=controlled):
            result,_=collect([{**self.row,'id':'fast','kind':'dns'},{**self.row,'id':'slow','kind':'dns'}],deadline_seconds=0.03)
        self.assertEqual([r['status'] for r in result['checks']],['up','unknown'])

    def test_stopped_pull_is_visible_even_after_last_transport_success(self):
        p=self.root/'health-transport.json';p.write_text(json.dumps({'at':1000,'ok':True}))
        self.assertIsNone(transport_message(p,now=1050))
        self.assertIsNotNone(transport_message(p,now=1100))

    def test_tcp_drop_and_missing_route_are_down_not_collector_fault(self):
        check={**self.row,'kind':'tcp','host':'192.0.2.1','port':5083}
        for error in (TimeoutError(),OSError(errno.EHOSTUNREACH,'no route'),ConnectionRefusedError()):
            with patch('socket.create_connection',side_effect=error):
                self.assertEqual(checked(check)['status'],'down')

    def test_runtime_wrapped_network_error_is_down_without_secret_output(self):
        config={'experimental':{'clash_api':{'secret':'private-test-secret'}}}
        with patch('health_collect.candidate_runtime_inputs') as inputs, \
             patch('health_collect.urllib.request.build_opener') as opener:
            inputs.return_value.__enter__.return_value=(config,{'modes':[]},{'status':'confirmed'})
            opener.return_value.open.side_effect=urllib.error.URLError(ConnectionRefusedError('private-test-secret'))
            result=checked({**self.row,'kind':'runtime'})
        self.assertEqual(result['status'],'down')
        self.assertNotIn('private-test-secret',json.dumps(result))

    def test_runtime_snapshot_refuses_partial_package_and_busy_writer(self):
        (self.root/'apply.lock').touch()
        payload={'config.json':{},'policy-manifest.json':{'bundle_version':1},'applied-policy.json':{}}
        for name,value in payload.items():(self.root/name).write_text(json.dumps(value))
        hashes={name:hashlib.sha256((self.root/name).read_bytes()).hexdigest() for name in payload}
        (self.root/'transaction.json').write_text(json.dumps({'status':'confirmed','next_files':hashes}))
        with candidate_runtime_inputs(self.root) as values:self.assertEqual(values[2]['status'],'confirmed')
        with (self.root/'apply.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            with self.assertRaises(RuntimeNotReady),candidate_runtime_inputs(self.root):pass
        (self.root/'applied-policy.json').write_text('{"changed":true}')
        with self.assertRaises(RuntimeNotReady),candidate_runtime_inputs(self.root):pass

    def test_failed_transport_preserves_original_observation_time(self):
        old=self.path.read_bytes()
        with patch('health_pull.subprocess.run',side_effect=subprocess.TimeoutExpired('ssh',6)):
            self.assertFalse(pull_once(self.root))
        self.assertEqual(self.path.read_bytes(),old)
        self.assertFalse(json.loads((self.root/'health-transport.json').read_text())['ok'])

    def test_transport_uses_external_fallback_and_does_not_refresh_server_timestamp(self):
        with patch('server_connection.read',return_value={'targets':[{'host':h,'port':2222,'username':'operator','identity_file':''} for h in ['lan.example.test','backup.example.test']]}),patch('health_pull.subprocess.run',side_effect=[subprocess.CompletedProcess([],1,b'',b'no route'),
                subprocess.CompletedProcess([],0,json.dumps(self.snapshot).encode(),b'')]) as run:
            self.assertTrue(pull_once(self.root))
        self.assertIn('operator@backup.example.test',run.call_args.args[0]);self.assertEqual(json.loads(self.path.read_text())['generated_at'],1000)

    def test_runtime_pair_changes_are_logged_even_while_healthy(self):
        check={**self.row,'kind':'runtime'};new={**self.row,'detail':'Новая пара'}
        with patch('health_collect.checked',return_value=new):
            snapshot,events=collect([check],self.snapshot)
        self.assertEqual(len(events),1);self.assertEqual(events[0]['detail'],'Новая пара')
        with patch('health_collect.checked',return_value=new):
            snapshot,events=collect([check],snapshot)
        self.assertEqual(events,[])
