"""Read-only host and path checks. Runs as a bounded systemd oneshot on Linux.

No service mutation, route mutation, mode switch or configuration write. The
only writes are the result snapshot and a bounded history of status changes.
"""
import argparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
import fcntl
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import urllib.error
import uuid

from health_model import MAX_BYTES, validate_snapshot, read_snapshot
from health_settings import fingerprint,read_settings,pending_row


class RuntimeNotReady(Exception):
    pass


@contextmanager
def candidate_runtime_inputs(root):
    with (root/'apply.lock').open('r') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeNotReady('Сейчас применяется конфигурация; дождитесь окончания') from None
        state=json.loads((root/'transaction.json').read_text())
        if state.get('status') in ('prepared','rollback_failed') or (
                state.get('status')=='pending' and state.get('runtime_ready') is not True):
            raise RuntimeNotReady('Применение не завершено или откат требует восстановления')
        config_bytes=(root/'config.json').read_bytes()
        manifest_bytes=(root/'policy-manifest.json').read_bytes()
        config=json.loads(config_bytes);manifest=json.loads(manifest_bytes)
        if manifest.get('bundle_version')==1:
            name='next_files' if state.get('status') in ('confirmed','pending') else 'previous_files'
            expected=state.get(name,{})
            files={'config.json':config_bytes,'policy-manifest.json':manifest_bytes,
                   'applied-policy.json':(root/'applied-policy.json').read_bytes()}
            if set(expected)!=set(files) or any(hashlib.sha256(data).hexdigest()!=expected[key] for key,data in files.items()):
                raise RuntimeNotReady('Файлы политики не совпадают с принятой ревизией; проверьте применение')
        yield config,manifest,state


def atomic_json(path, value):
    path=Path(path);temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(value,stream,ensure_ascii=False);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)


def run(args, timeout=8):
    return subprocess.run(args,text=True,capture_output=True,timeout=timeout,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/nonexistent'})


def http_failure(returncode,output):
    # Fixed classifications only: stderr may contain URLs or credentials.
    reasons={5:'не разрешено имя прокси',6:'не разрешено имя сервера',
             7:'не установлено TCP-соединение',28:'превышено время ожидания',
             35:'не завершено TLS-соединение',51:'не подтверждён сертификат сервера',
             52:'сервер закрыл соединение без HTTP-ответа',55:'ошибка отправки данных',
             56:'ошибка получения данных',60:'не подтверждён сертификат сервера',
             97:'ошибка согласования с прокси'}
    if returncode:return 'HTTP(S) не прошёл: '+reasons.get(returncode,'ошибка передачи')+' (curl '+str(returncode)+')'
    code=output.strip()
    if re.fullmatch('[1-5][0-9]{2}',code):return 'Получен HTTP '+code+'; этот код не входит в ожидаемые'
    return 'Измеритель не вернул допустимый HTTP-код'


HTTP_MEASUREMENT = '%{http_code}\t%{time_namelookup}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}'


def http_measurement(output, check):
    """Only fixed code/numeric fields; no transport text, URLs or body."""
    if len(output)>200:return None
    fields=output.strip().split('\t')
    if len(fields)!=6 or not re.fullmatch('[0-9]{3}',fields[0]):return None
    if any(not re.fullmatch('[0-9]{1,5}(?:\\.[0-9]{1,9})?',v) for v in fields[1:]):return None
    dns,connect,tls,first,total=map(float,fields[1:])
    if any(v>3600 for v in (dns,connect,tls,first,total)):return None
    def elapsed(label,value):return label+': '+format(value*1000,'.1f')+' мс от начала'
    milestones=[]
    if not check.get('proxy') and dns:milestones.append(elapsed('DNS',dns))
    peer='TCP к прокси' if check.get('proxy') else 'TCP к серверу'
    milestones.append(elapsed(peer,connect) if connect else peer+': завершение не зафиксировано')
    if check['url'].startswith('https://'):
        milestones.append(elapsed('TLS',tls) if tls else 'TLS: завершение не зафиксировано')
    milestones.append(elapsed('Первый байт',first) if first else 'Первый байт: не получен')
    milestones.append(elapsed('Всего',total))
    if check.get('proxy') and not tls and not first:
        milestones.append('TCP к прокси не подтверждает DNS и соединение с сайтом за ним')
    return fields[0],'; '.join(milestones)


def service_result(fields, now_monotonic):
    if fields.get('LoadState')!='loaded':
        return 'unknown','Служба не найдена'
    if fields.get('Type')=='oneshot':
        if fields.get('ActiveState')=='activating':return 'unknown','Проверка сейчас выполняется'
        if fields.get('Result')!='success' or fields.get('ExecMainStatus')!='0':return 'down','Последний запуск завершился ошибкой'
        if fields.get('ActiveState')=='active' and fields.get('RemainAfterExit')=='yes':
            return 'up','Настройка интерфейса применена; доступ по туннелю проверяется отдельно'
        finished=int(fields.get('ExecMainExitTimestampMonotonic','0'))/1_000_000
        if finished<=0 or now_monotonic-finished>90:return 'unknown','Нет свежего результата одноразовой службы'
        return 'up','Последний запуск завершился успешно'
    if fields.get('ActiveState')=='active':
        active_since=int(fields.get('ActiveEnterTimestampMonotonic','0'))/1_000_000
        if int(fields.get('NRestarts','0'))>0 and now_monotonic-active_since<90:
            return 'degraded','Служба недавно автоматически перезапускалась; проверьте журнал и сетевые проверки'
        return 'up','Процесс активен; доступ по сети проверяется отдельно'
    return 'down','Состояние службы: '+fields.get('ActiveState','неизвестно')


def probe(check):
    kind=check['kind']
    if kind=='vpn_gate':
        import socket
        try:
            with socket.create_connection((check['host'],check['port']),timeout=2):
                return 'up','Порт готовности открыт после проверки VPN-входа, DNS и HTTPS'
        except OSError:
            return 'down','Порт готовности закрыт; роутер должен выбрать провайдера. Проверьте параметры пути и сам роутер'
    if kind in ('candidate_adguard','candidate_lan','candidate_vpn'):
        adapter={'candidate_adguard':'adguard','candidate_lan':'lan','candidate_vpn':'vpn'}[kind]
        response=run(['/usr/bin/python3','-E','-s','-B','/var/lib/okopy-candidate/'+adapter+'_runtime.py','health'],6)
        if response.returncode or len(response.stdout)>4096:
            return 'unknown','Не удалось выполнить сверку адаптера '+adapter+'; проверьте сборщик'
        value=json.loads(response.stdout)
        if value.get('status') not in ('up','down','unknown') or not isinstance(value.get('detail'),str):
            raise ValueError('Invalid adapter health response')
        return value['status'],value['detail'][:1000]
    if kind=='udp_stun':
        from udp_health import probe as udp_probe
        return udp_probe(check)
    if kind=='dns_filter':
        return probe_dns_filter(check)
    if kind=='pair':
        root=Path('/var/lib/okopy-candidate')
        try:
            with candidate_runtime_inputs(root) as (config,manifest,state):
                if manifest.get('config_sha256')!=check['config_sha256']:
                    return 'unknown','Политика изменилась во время опроса; ожидается новая проверка'
                if check.get('transaction_id')!=state.get('id'):
                    return 'unknown','Применение изменилось до начала опроса; ожидается новая проверка'
                record=next((p for p in manifest.get('probes',[]) if p['id']==check['id']),None)
                if record is None:return 'unknown','Проверяемая пара больше не настроена'
                epoch=(manifest.get('config_sha256'),state.get('id'))
            result=probe_pair(record)
            # Never hold the writer's lock while waiting for network I/O.
            # A same-hash reapply is also a new epoch and invalidates the sample.
            with candidate_runtime_inputs(root) as (_,after,transaction):
                if epoch!=(after.get('config_sha256'),transaction.get('id')):
                    return 'unknown','Политика применялась во время измерения; ожидается новая проверка'
            return result
        except RuntimeNotReady as error:return 'unknown',str(error)
    if kind=='service':
        response=run(['systemctl','show',check['unit'],'--property=LoadState,Type,ActiveState,RemainAfterExit,Result,ExecMainStatus,ExecMainExitTimestampMonotonic,NRestarts,ActiveEnterTimestampMonotonic'],4)
        fields=dict(line.split('=',1) for line in response.stdout.splitlines() if '=' in line)
        if response.returncode and fields.get('LoadState')!='not-found':return 'unknown','Не удалось прочитать состояние службы'
        return service_result(fields,time.monotonic())
    if kind=='dns':
        timeout=check.get('timeout_seconds',2)
        args=['dig','+time='+str(timeout),'+tries=1','+noall','+comments','+answer','@'+check['server'],'-p',str(check['port']),check['domain'],'A']
        if check.get('tcp'):args.append('+tcp')
        response=run(args,timeout+2)
        if response.returncode not in (0,9):
            return 'unknown','DNS-проверка не выполнена: ошибка запуска или ресурсов измерителя'
        addresses=[]
        for line in response.stdout.splitlines():
            fields=line.split()
            if len(fields)>=5 and fields[-2]=='A':
                try:
                    address=ipaddress.IPv4Address(fields[-1])
                    if not (address.is_unspecified or address.is_loopback or address.is_multicast or str(address)=='255.255.255.255'):
                        addresses.append(str(address))
                except ValueError:pass
        passed=response.returncode==0 and 'status: NOERROR' in response.stdout and bool(addresses)
        return ('up','Получен IPv4-ответ через заданный DNS') if passed else ('down','Нет ожидаемого успешного DNS-ответа')
    if kind in ('https','https_slow'):
        observe_ip=check.get('observe_ip',False)
        timeout=check.get('timeout_seconds',6)
        args=['curl','--globoff','--noproxy','','--silent','--show-error','--connect-timeout',str(check.get('connect_timeout_seconds',2)),'--max-time',str(timeout),
              '--output','-' if observe_ip else '/dev/null','--write-out','\n%{http_code}' if observe_ip else HTTP_MEASUREMENT]
        if observe_ip:args+=['--ipv4','--max-filesize','128']
        if check.get('proxy'):args+=['--socks5-hostname',check['proxy']]
        else:args+=['--noproxy','*']
        args+=['--url',check['url']]
        response=run(args,timeout+2)
        if response.returncode<0 or response.returncode in (1,2,3,4,27,48):
            return 'unknown','HTTP-проверка не выполнена: ошибка запуска, параметров или ресурсов измерителя'
        if observe_ip:
            if response.returncode or len(response.stdout)>132:
                return 'down','Не удалось измерить внешний IPv4: ошибка HTTPS или недопустимый размер ответа'
            body,separator,code=response.stdout.rpartition('\n')
            if not separator or code.strip()!='200':return 'down','Измеритель внешнего IPv4 вернул неожиданный HTTP-ответ'
            try:address=ipaddress.IPv4Address(body.strip())
            except ValueError:return 'unknown','HTTPS доступен, но ответ измерителя не содержит единственный IPv4'
            if not address.is_global:return 'unknown','Измеритель не вернул публичный IPv4'
            return 'up','Фактический внешний IPv4 этого HTTPS-запроса: '+str(address)+' · соответствие другим правилам и резервам этим не проверяется'
        measurement=http_measurement(response.stdout,check)
        if measurement is None:
            if response.returncode:return 'down',http_failure(response.returncode,'')
            return 'unknown','HTTP-измеритель вернул неполные или некорректные данные; проверьте сборщик'
        code,progress=measurement
        passed=response.returncode==0 and code in check.get('codes',['200','204'])
        success='TLS и HTTP-ответ проверены' if check['url'].startswith('https://') else 'HTTP-ответ проверен; этот URL не использует TLS'
        return ('up',success) if passed else ('down',http_failure(response.returncode,code)+'. '+progress)
    if kind=='tcp':
        import socket
        address=str(ipaddress.ip_address(check['host']))
        try:
            with socket.create_connection((address,check['port']),timeout=check.get('timeout_seconds',2)):pass
        except OSError:
            return 'down','TCP-порт недоступен: нет ответа, отказ соединения или маршрута'
        return 'up','TCP-порт доступен; это не сквозная проверка клиентского трафика'
    if kind=='icmp':
        address=str(ipaddress.ip_address(check['host']))
        timeout=check.get('timeout_seconds',2)
        result=run(['ping','-n','-c','1','-W',str(timeout),address],timeout+2)
        return ('up','Узел отвечает на ICMP; доступ к приложениям и интернету этим не проверяется') if result.returncode==0 else ('down','Нет ICMP-ответа от узла')
    if kind=='resources':
        stat=os.statvfs('/')
        free=stat.f_bavail*stat.f_frsize/2**30
        mem=dict((line.split(':')[0],int(line.split()[1])) for line in Path('/proc/meminfo').read_text().splitlines())
        detail=f"Диск: {free:.1f} GiB свободно · RAM: {mem['MemAvailable']/2**20:.1f} GiB доступно · нагрузка 1 мин: {os.getloadavg()[0]:.2f}"
        return ('degraded' if free<check.get('disk_warning_gib',5) or mem['MemAvailable']/1024<check.get('memory_warning_mib',0) else 'up'),detail
    if kind=='runtime':
        root=Path('/var/lib/okopy-candidate')
        try:
            with candidate_runtime_inputs(root) as (config,manifest,state):
                secret=config['experimental']['clash_api']['secret']
                request=urllib.request.Request('http://127.0.0.1:9091/configs',headers={'Authorization':'Bearer '+secret})
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
                try:
                    with opener.open(request,timeout=2) as response:raw=response.read(MAX_BYTES+1)
                except urllib.error.HTTPError:
                    return 'unknown','API вернул ошибку HTTP: проверьте настройку доступа и журнал кандидата'
                except (urllib.error.URLError,TimeoutError,ConnectionError):
                    return 'down','Нет соединения с API кандидата или истекло время ожидания'
                if len(raw)>MAX_BYTES:raise ValueError('Oversized API response')
                actual=json.loads(raw)
                mode=next((m for m in manifest['modes'] if m['name']==actual.get('mode')),None)
                if mode is None:return 'unknown','Текущий режим не соответствует сохранённой политике'
                pairs='; '.join(key+': '+pair['exit']+' / '+pair['dns'] for key,pair in mode['pairs'].items())
                pending=state.get('status')=='pending'
                prefix='Ожидает подтверждения. ' if pending else ''
                return ('degraded' if pending else 'up'),prefix+('Режим распознан. Политика ожидает: '+pairs)[:750]+' · выход отдельного HTTPS-запроса измеряется отдельно; все вложенные селекторы и резервы не проверены; режим автоматики и закрепления показаны в разделе резервирования'
        except RuntimeNotReady as error:return 'unknown',str(error)
    raise ValueError('Unknown probe kind')


def probe_dns_filter(check):
    """Differential DNS check: a block alone cannot prove filtering works.

    All three queries run concurrently within the existing per-job bound.
    A failed or already-blocking reference resolver makes the result unknown.
    """
    def binding_matches():
        binding=check.get('config_binding')
        if binding is None:return True
        with Path(binding['path']).open('rb') as stream:data=stream.read(1024*1024+1)
        return len(data)<=1024*1024 and hashlib.sha256(data).hexdigest()==binding['sha256']
    if not binding_matches():
        return 'unknown','Настройки фильтра изменились; нужно заново сверить контрольные имена и исходный DNS'
    def lookup(endpoint,domain):
        response=run(['dig','+time=2','+tries=1','+noall','+comments','+answer',
                      '@'+endpoint['server'],'-p',str(endpoint['port']),domain,'A'],4)
        if response.returncode not in (0,9):return 'unknown',[]
        if response.returncode:return 'unreachable',[]
        statuses=re.findall(r'\bstatus: ([A-Z]+)\b',response.stdout)
        if len(statuses)!=1:return 'unknown',[]
        addresses=[]
        for line in response.stdout.splitlines():
            fields=line.split()
            if len(fields)>=5 and fields[-2]=='A':
                try:addresses.append(ipaddress.IPv4Address(fields[-1]))
                except ValueError:return 'unknown',[]
        return statuses[0],addresses
    requests=[(check['unfiltered'],check['blocked_domain']),
              (check['filtered'],check['blocked_domain']),
              (check['filtered'],check['allowed_domain'])]
    with ThreadPoolExecutor(max_workers=3) as pool:
        reference,blocked,allowed=list(pool.map(lambda item:lookup(*item),requests))
    if not binding_matches():
        return 'unknown','Настройки фильтра изменились во время измерения; результат не подтверждён'
    def public_answer(result):
        return result[0]=='NOERROR' and bool(result[1]) and all(a.is_global for a in result[1])
    if any(r[0]=='unknown' for r in (reference,blocked,allowed)):
        return 'unknown','Проверка фильтрации не выполнена достоверно; проверьте сборщик'
    if not public_answer(reference):
        return 'unknown','Контрольный DNS не вернул публичный IPv4 блокируемого имени; действие фильтра нельзя отделить от ошибки или блокировки выше по цепочке'
    if not public_answer(allowed):
        return 'down','Через фильтрующий DNS не проходит разрешённое контрольное имя; проверьте DNS и список исключений'
    blocked_ok=(blocked[0]=='NXDOMAIN' and not blocked[1]) or (
        blocked[0]=='NOERROR' and bool(blocked[1]) and all(a.is_unspecified for a in blocked[1]))
    if not blocked_ok:
        return 'down','Нет ожидаемой блокировки контрольного имени; проверьте защиту, фильтры и общие исключения'
    return 'up','Блокировка подтверждена сравнением с исходным DNS; разрешённое имя проходит. Это проверка заданного пути, не всех клиентских правил'


def probe_pair(record):
    checks=[{'kind':'dns','server':'127.0.0.1','port':record['dns_port'],'domain':record['dns_name'],'tcp':tcp}
            for tcp in (False,True)]
    checks += [{'kind':'https','proxy':'127.0.0.1:'+str(record['proxy_port']),'url':url,
                'codes':[str(code) for code in record['codes']]} for url in record['urls']]
    # At most five bounded subprocesses; all finish within the existing eight
    # second per-job limit. The caller checks the revision before and after I/O.
    with ThreadPoolExecutor(max_workers=5) as pool:
        results=list(pool.map(probe,checks))
    failed=[('DNS TCP' if c.get('tcp') else 'DNS UDP') if c['kind']=='dns' else 'HTTP(S) '+str(i-1)
            for i,(c,r) in enumerate(zip(checks,results)) if r[0]!='up']
    label=record['exit']+' / '+record['effective_dns']
    if any(r[0]=='unknown' for r in results):return 'unknown',label+' · часть измерений недостоверна; проверьте сборщик'
    if failed:return 'down',label+' · не прошли: '+', '.join(failed)
    return 'up',label+' · DNS UDP/TCP и '+str(len(record['urls']))+' HTTP(S)-проверки прошли независимо от активного режима; активный выбор и закрепления показаны в разделе резервирования'


def pair_checks(manifest,transaction_id=None):
    if len(manifest.get('probes',[]))>8:raise ValueError('More than eight probe pairs are not qualified')
    return [{'id':p['id'],'name':(('Общий трафик' if p['queue']=='default' else 'Правило '+p['queue'].removeprefix('rule:'))+' · пара '+str(p['index']+1))[:1000],
             'scope':'Кандидат · резервные пары','kind':'pair','config_sha256':manifest['config_sha256'],'transaction_id':transaction_id,
             'action':'Проверьте выход и DNS этой пары в разделе резервирования; основной канал может продолжать работать'}
            for p in manifest.get('probes',[])]


def checked(check):
    started=time.monotonic()
    try:status,detail=probe(check)
    except subprocess.TimeoutExpired:
        status,detail='unknown','Измеритель не завершился в установленный срок; проверьте сборщик'
    except ConnectionError:
        status,detail='down','Соединение отклонено'
    except Exception as error:
        # Raw exception text, stderr and request headers never enter snapshots.
        print('Health probe exception: '+type(error).__name__,file=sys.stderr)
        status,detail='unknown','Не удалось получить достоверный результат: проверьте источник измерений и журнал сборщика'
    return {'id':check['id'],'name':check['name'],'scope':check['scope'],'status':status,
            'definition_sha256':fingerprint(check),
            **({'service_unit':check['unit'],'in_progress':detail=='Проверка сейчас выполняется'} if check['kind']=='service' else {}),
            **({k:check.get(k) for k in ('config_sha256','transaction_id')} if check['kind']=='pair' else {}),
            'detail':detail[:1000],'action':check['action'],'observed_at':time.time(),
            'duration_ms':round((time.monotonic()-started)*1000,1)}


def collect(checks, previous=None, *, deadline_seconds=30, reuse=True, workers=4):
    if not 1<=len(checks)<=128:raise ValueError('Expected 1..128 checks')
    completed={};previous_rows={r['id']:r for r in (previous or {}).get('checks',[])}
    now=time.time();scheduled={};due_at={}
    for index,check in enumerate(checks):
        old=previous_rows.get(check['id']);interval=check.get('interval_seconds',5)
        due_at[index]=(old or {}).get('due_since',(old or {}).get('next_check_at',now))
        if (reuse and old and old.get('definition_sha256')==fingerprint(check)
                and 0<=now-(previous or {}).get('generated_at',0)<=150
                and now<old.get('next_check_at',0)<=now+interval):
            scheduled[index]={**old,'scheduled':True}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        jobs={pool.submit(checked,checks[index]):index for index in sorted(due_at,key=due_at.get) if index not in scheduled}
        try:
            for job in as_completed(jobs,timeout=deadline_seconds):completed[jobs[job]]=job.result()
        except FuturesTimeout:
            for job in jobs:job.cancel()
        deadline_at=time.time()
        # Fast probes have <=8s subprocess limits. The separate slow lane has
        # at most four <=32s jobs on two workers and a larger service budget.
    rows=[scheduled.get(index) or completed.get(index) or {'id':check['id'],'name':check['name'],'scope':check['scope'],
        'definition_sha256':fingerprint(check),
        'action':check['action'],'status':'unknown','detail':'Проверка не уложилась в общий лимит опроса',
        'observed_at':deadline_at,'duration_ms':round(deadline_seconds*1000)} for index,check in enumerate(checks)]
    for index,row in enumerate(rows):
        if index in scheduled:continue
        interval=checks[index].get('interval_seconds',5)
        if index not in completed:
            # No completed attempt: preserve its place in the overdue queue,
            # retry next cycle instead of postponing it for its configured period.
            row.update(interval_seconds=interval,due_since=due_at[index])
            continue
        next_check_at=row['observed_at']+interval
        old=previous_rows.get(row['id'])
        if (reuse and row.get('in_progress') is True and old is not None
                and row.get('definition_sha256')==old.get('definition_sha256')
                and old.get('service_unit')==row.get('service_unit')
                and old.get('status') in ('up','down','degraded')):
            # An in-flight oneshot is not a new completed observation. Preserve
            # its original timestamp, including across repeated in-flight polls.
            rows[index]={**old,'in_progress':True,'retained_observation':True}
        rows[index].update(interval_seconds=interval,next_check_at=next_check_at)
        rows[index].pop('scheduled',None)
        rows[index].pop('due_since',None)
    result=validate_snapshot({'version':1,'generated_at':time.time(),'checks':rows})
    return result,events_for(rows,previous,checks)


def events_for(rows,previous,checks):
    prior={r['id']:r['status'] for r in (previous or {}).get('checks',[])}
    prior_details={r['id']:r['detail'] for r in (previous or {}).get('checks',[])}
    runtime_ids={c['id'] for c in checks if c['kind'] in ('runtime','pair','udp_stun') or c.get('observe_ip')}
    events=[{'at':r['observed_at'],'id':r['id'],'name':r['name'],'status':r['status'],'detail':r['detail']}
            for r in rows if prior.get(r['id'])!=r['status'] or (
                r['id'] in runtime_ids and prior_details.get(r['id'])!=r['detail'])]
    return events


def slow_rows(root,checks,boot_id):
    """Import actual slow measurements; reading a cache never refreshes it."""
    try:snapshot=read_snapshot(root/'slow-health.json')
    except (OSError,ValueError,TypeError):snapshot=None
    valid=bool(boot_id and snapshot and snapshot.get('boot_id')==boot_id)
    cached={r['id']:r for r in snapshot['checks']} if valid else {}
    rows=[]
    for check in checks:
        row=cached.get(check['id'])
        if row and row.get('definition_sha256')==fingerprint(check):
            rows.append({**row,'source_generated_at':snapshot['generated_at']})
        else:
            pending=pending_row(check,time.time())
            pending['detail']='Ожидается результат отдельного медленного опроса с текущими параметрами'
            rows.append(pending)
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',default='/var/lib/okopy-monitor')
    parser.add_argument('--lane',choices=('fast','slow'),default='fast')
    parser.add_argument('--interval-seconds',type=int,default=30);args=parser.parse_args()
    if not 2<=args.interval_seconds<=300:raise ValueError('Invalid collection interval')
    root=Path(args.root)
    prefix='slow-' if args.lane=='slow' else ''
    with (root/(prefix+'collect.lock')).open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        with (root/'settings.lock').open('a') as settings_lock:
            fcntl.flock(settings_lock,fcntl.LOCK_SH)
            settings,_=read_settings(root)
        slow=[c for c in settings['checks'] if c['kind']=='https_slow']
        checks=slow if args.lane=='slow' else [c for c in settings['checks'] if c['kind']!='https_slow']
        try:
            if args.lane=='fast':
                with candidate_runtime_inputs(Path('/var/lib/okopy-candidate')) as (_,manifest,state):
                    checks=pair_checks(manifest,state.get('id'))+checks
        except (OSError,ValueError,RuntimeNotReady):
            # The existing runtime check reports the unavailable source. Do not
            # turn a previous policy's measurements into fresh healthy rows.
            pass
        try:previous=read_snapshot(root/(prefix+'health.json'))
        except (OSError,ValueError,TypeError):previous=None
        try:boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        except OSError:boot_id=None
        same_boot=bool(boot_id and previous and previous.get('boot_id')==boot_id)
        if not boot_id:print('Boot ID unavailable; scheduled reuse disabled',file=sys.stderr)
        # Keep the event baseline across boots, but never reuse its measurements.
        options={'deadline_seconds':68,'workers':2} if args.lane=='slow' else {}
        if args.lane=='slow' and not boot_id:
            rows=[pending_row(c,time.time()) for c in checks]
            for row in rows:row['detail']='Не удалось определить загрузку сервера; медленный опрос остановлен'
            result={'version':1,'generated_at':time.time(),'checks':rows};events=events_for(rows,previous,checks)
        else:
            result,events=collect(checks,previous,reuse=same_boot,**options) if checks else ({'version':1,'generated_at':time.time(),'checks':[]},[])
        if args.lane=='fast':
            imported=slow_rows(root,slow,boot_id)
            result['checks']+=imported
            events+=events_for(imported,previous,slow)
        try:
            with (root/(prefix+'events.json')).open('rb') as stream:raw=stream.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:raise ValueError('Oversized history')
            history=json.loads(raw)
            if not isinstance(history,list) or len(history)>200:raise ValueError('Invalid history')
            for i in range(0,len(history),30):
                validate_snapshot({'version':1,'generated_at':0,'checks':[],'events':history[i:i+30]})
        except (OSError,ValueError,TypeError):history=[]
        with (root/'settings.lock').open('a') as settings_lock:
            fcntl.flock(settings_lock,fcntl.LOCK_SH)
            current,_=read_settings(root)
            if args.lane=='slow':current['checks']=[c for c in current['checks'] if c['kind']=='https_slow']
            current_checks={c['id']:c for c in current['checks']}
            original_ids={c['id'] for c in settings['checks']}
            # A removed check must not reappear from an in-flight collection.
            result['checks']=[r for r in result['checks'] if r['id'] not in original_ids or r['id'] in current_checks]
            changed=set()
            for row in result['checks']:
                definition=current_checks.get(row['id'])
                if definition is not None and row.get('definition_sha256')!=fingerprint(definition):
                    row.update(status='unknown',detail='Параметры изменились во время опроса; ожидается новое измерение')
                    row.pop('retained_observation',None);row.pop('in_progress',None)
                    row.pop('scheduled',None);row.pop('next_check_at',None)
                    changed.add(row['id'])
            changed.update(original_ids-set(current_checks))
            events=[e for e in events if e['id'] not in changed]
            present={r['id'] for r in result['checks']}
            result['checks'] += [pending_row(c,time.time()) for c in current['checks'] if c['id'] not in present]
            atomic_json(root/(prefix+'events.json'),(history+events)[-200:])
            result['events']=(history+events)[-30:]
            result['interval_seconds']=args.interval_seconds
            result['boot_id']=boot_id
            atomic_json(root/(prefix+'health.json'),result)


if __name__=='__main__':main()
