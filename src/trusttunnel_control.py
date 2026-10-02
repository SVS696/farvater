"""Private drafts for root-registered existing TrustTunnel clients."""
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time
from safe_apply import atomic_write,digest,remove_created_file
from wireguard_control import read_private
from openconnect_control import regular,identifier
from trusttunnel_profile import parse_client,public,update,import_config,validate,render,MAX_BYTES

ROOT=Path('/var/lib/okopy-trusttunnel')


def binding_for(root,name):
    bindings=json.loads(read_private(root/'connections.json'));b=bindings.get(name) if isinstance(bindings,dict) else None
    keys={'unit','unit_file','config','binary','user','uid','socks_address','dependents'}
    if not isinstance(b,dict) or set(b) not in (keys,keys|{'dependent_files'}):raise ValueError('Не настроена привязка действующей службы TrustTunnel')
    if type(b['uid']) is not int or b['uid']<1 or not isinstance(b['user'],str) or not re.fullmatch('[a-z_][a-z0-9_-]{0,31}',b['user']):raise ValueError('Некорректный пользователь службы')
    if not isinstance(b['dependents'],list) or len(b['dependents'])>8:raise ValueError('Некорректная привязка зависимых служб')
    for value in [b['unit'],*b['dependents']]:
        if not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,100}\.service',value):raise ValueError('Некорректное имя службы')
    if not isinstance(b.get('dependent_files',[]),list) or len(b.get('dependent_files',[]))>16:raise ValueError('Некорректная привязка зависимых файлов')
    for value in b.get('dependent_files',[]):
        if not isinstance(value,str) or not Path(value).is_absolute() or '..' in Path(value).parts:raise ValueError('Некорректный зависимый файл')
    for key in ('unit_file','config','binary'):
        value=b[key]
        if not isinstance(value,str) or not Path(value).is_absolute() or '..' in Path(value).parts or any(c.isspace() for c in value):raise ValueError('Некорректная привязка файлов')
    from trusttunnel_profile import address
    address(b['socks_address'])
    from urllib.parse import urlsplit
    import ipaddress
    if not ipaddress.ip_address(urlsplit('//'+b['socks_address']).hostname).is_loopback:raise ValueError('Локальный SOCKS должен слушать только loopback')
    return b


def config_bytes(binding):
    fd=os.open(binding['config'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        st=os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0,binding['uid']) or st.st_mode&0o077:raise ValueError('Файл настроек TrustTunnel должен быть закрытым и принадлежать службе')
        data=stream.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES:raise ValueError('Файл TrustTunnel превышает 128 КиБ')
    return data


def observe(binding):
    states={}
    for unit in [binding['unit'],*binding['dependents']]:
        q=subprocess.run(['systemctl','show',unit,'-p','ActiveState,SubState,UnitFileState,MainPID,FragmentPath,DropInPaths,NeedDaemonReload'],capture_output=True,text=True,timeout=4)
        if q.returncode or len(q.stdout)>16384:raise ValueError('Не удалось прочитать состояние TrustTunnel')
        values=dict(l.split('=',1) for l in q.stdout.splitlines() if '=' in l)
        if (unit==binding['unit'] and values.get('FragmentPath')!=binding['unit_file']) or not values.get('FragmentPath') or values.get('DropInPaths') or values.get('NeedDaemonReload')!='no':raise ValueError('Служба изменена вне панели или требует daemon-reload')
        states[unit]={'active':values.get('ActiveState','unknown'),'state':values.get('SubState','unknown'),'boot':values.get('UnitFileState','unknown'),'pid':int(values.get('MainPID','0')),'unit_file':values.get('FragmentPath')}
    return {'client':states[binding['unit']],'dependents':{k:v for k,v in states.items() if k!=binding['unit']}}


def load(root,name,binding,*,source='selected'):
    unit=regular(Path(binding['unit_file']));managed=(root/(name+'.active.json')).exists()
    config=read_private(root/(name+'.active.json')) if managed else config_bytes(binding)
    entries={}
    for line in unit.decode().splitlines():
        if line.startswith(('ExecStart=','User=')):
            k,v=line.split('=',1)
            if k in entries:raise ValueError('Неоднозначная служба TrustTunnel')
            entries[k]=v
    if entries.get('User')!=binding['user']:raise ValueError('Пользователь службы TrustTunnel изменился')
    if managed:
        from trusttunnel_runtime import installation,CODE
        if entries.get('ExecStart')!='+/usr/bin/python3 -E -s -B '+str(CODE/'trusttunnel_start.py')+' '+name:raise ValueError('Загрузчик TrustTunnel изменился')
        if json.loads(read_private(root/(name+'.installation.json')))!=installation(root,binding):raise ValueError('Связанные файлы TrustTunnel изменились вне панели')
        model=validate(json.loads(config),ready=True)
    else:
        if shlex.split(entries.get('ExecStart',''))!=[binding['binary'],'--config',binding['config']]:raise ValueError('Команда запуска TrustTunnel не соответствует зарегистрированной привязке')
        model=parse_client(config.decode(),binding)
    active_model=model
    revision=digest(unit+b'\0'+config+b'\0'+json.dumps(binding,sort_keys=True).encode())
    path=root/(name+'.draft.json');view={'id':name,'managed':managed,'file_revision':revision,'draft_revision':'','has_draft':False,'conflict':False,'saved_at':None}
    if os.path.lexists(path):
        raw=read_private(path)
        try:
            d=json.loads(raw)
            if not isinstance(d,dict) or set(d)!={'base_revision','model','saved_at'} or not re.fullmatch('[a-f0-9]{64}',d['base_revision']) or type(d['saved_at']) not in (int,float):raise ValueError()
            model=validate(d['model'])
        except (ValueError,TypeError,KeyError):raise ValueError('Черновик TrustTunnel повреждён; действующая служба не менялась') from None
        view.update(draft_revision=digest(raw),has_draft=True,conflict=d['base_revision']!=revision,saved_at=d['saved_at'])
    view['model']=public(model)
    return view,active_model if source=='active' else model


def control(request,*,root=ROOT,observe_state=observe,backend=None,network=Path('/var/lib/okopy-candidate')):
    action=request.get('action')
    lifecycle=action in ('trusttunnel-start','trusttunnel-stop','trusttunnel-enable','trusttunnel-disable')
    if not lifecycle and action not in ('trusttunnel-status','trusttunnel-export','trusttunnel-save','trusttunnel-import','trusttunnel-discard','trusttunnel-check','trusttunnel-apply','trusttunnel-confirm','trusttunnel-rollback'):raise ValueError('Неизвестное действие TrustTunnel')
    fields={'version','action','connection'}
    if action in ('trusttunnel-confirm','trusttunnel-rollback'):fields|={'transaction'}
    elif action!='trusttunnel-status':fields|={'file_revision','draft_revision'}
    if action in ('trusttunnel-apply','trusttunnel-start','trusttunnel-enable'):fields|={'probe'}
    if lifecycle:fields|={'expected_state'}
    if action=='trusttunnel-export':
        fields|={'source'}
        if 'format' in request:fields|={'format'}
    if action=='trusttunnel-save':fields|={'values'}
    if action=='trusttunnel-import':fields|={'text','format'}
    if set(request)!=fields or request['version']!=1:raise ValueError('Некорректные поля запроса TrustTunnel')
    name=identifier(request['connection'])
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid!=os.geteuid() or root.stat().st_mode&0o077:raise ValueError('Закрытый каталог TrustTunnel недоступен')
    b=binding_for(root,name)
    if lifecycle:
        expected=request['expected_state']
        if not isinstance(expected,dict) or set(expected)!={'active','boot','companions'} or not isinstance(expected['companions'],dict) or set(expected['companions'])!=set(b['dependents']):raise ValueError('Обновите состояние связанных служб перед изменением')
        for item in [{k:expected[k] for k in ('active','boot')},*expected['companions'].values()]:
            if not isinstance(item,dict) or set(item)!={'active','boot'} or type(item['active']) is not bool or item['boot'] not in ('enabled','disabled'):raise ValueError('Некорректное ожидаемое состояние связанных служб')
    fd=os.open(root/'control.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        try:fcntl.flock(lock,(fcntl.LOCK_SH if action=='trusttunnel-status' else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Редактор TrustTunnel занят; обновите страницу') from None
        from trusttunnel_clients import ensure_idle
        if action not in ('trusttunnel-status','trusttunnel-catalog'):ensure_idle(root)
        from trusttunnel_apply import Transaction,state,PENDING,public as public_transaction
        transaction=state(root);tx=Transaction(root,b,name,backend,network)
        if action in ('trusttunnel-confirm','trusttunnel-rollback'):
            if transaction.get('connection')!=name:raise ValueError('Операция относится к другому подключению')
            result=tx.confirm(request['transaction']) if action=='trusttunnel-confirm' else tx.rollback(request['transaction'])
            return {'transaction':result}
        if action!='trusttunnel-status' and transaction.get('status') in PENDING:raise ValueError('Сначала подтвердите или восстановите изменение TrustTunnel')
        if action=='trusttunnel-export' and request['source'] not in ('active','draft'):raise ValueError('Выберите действующие настройки или сохранённый черновик')
        runtime={}
        try:runtime=observe_state(b);view,model=load(root,name,b,source=request['source'] if action=='trusttunnel-export' else 'selected')
        except (ValueError,OSError) as error:
            if action!='trusttunnel-status':raise
            return {'id':name,'model':None,'runtime':runtime,'transaction':public_transaction(transaction) if transaction.get('connection')==name else {},'error':str(error) if isinstance(error,ValueError) else 'Не удалось безопасно прочитать службу'}
        view['transaction']=public_transaction(transaction) if transaction.get('connection')==name else {}
        view['lifecycle_available']=all(v.get('active') in ('active','inactive','failed') and v.get('boot') in ('enabled','disabled') for v in [runtime['client'],*runtime['dependents'].values()])
        view['lifecycle_state']={'active':runtime['client'].get('active')=='active','boot':runtime['client'].get('boot'),
            'companions':{u:{'active':v.get('active')=='active','boot':v.get('boot')} for u,v in runtime['dependents'].items()}}
        flags=[view['lifecycle_state'],*view['lifecycle_state']['companions'].values()]
        view['can_start']=any(not v['active'] for v in flags);view['can_stop']=any(v['active'] for v in flags)
        view['can_enable']=any(v['boot']!='enabled' for v in flags);view['can_disable']=any(v['boot']!='disabled' for v in flags)
        if transaction.get('connection')==name and transaction.get('status') in PENDING:
            view['awaiting_confirmation']=True
            if transaction.get('draft_revision')==view['draft_revision'] and (root/(name+'.active.json')).exists() and digest(read_private(root/(name+'.active.json')))==transaction.get('next_sha256'):view['conflict']=False
        if action!='trusttunnel-status':
            if any(request[k]!=view[k] for k in ('file_revision','draft_revision')):raise ValueError('Настройки или черновик изменились; обновите страницу')
            if action!='trusttunnel-discard' and view['conflict']:raise ValueError('Служба изменена вне панели; удалите устаревший черновик и перечитайте настройки')
            if lifecycle:
                from openconnect_apply import runtime_signature
                if not view['managed'] or view['has_draft']:raise ValueError('Сначала примените или удалите черновик; управление службами использует действующие настройки')
                original=read_private(root/(name+'.active.json'));snapshot=tx.backend.capture()
                if expected!=runtime_signature(snapshot):raise ValueError('Состояние связанных служб изменилось; обновите страницу')
                if action in ('trusttunnel-start','trusttunnel-stop'):
                    return {'transaction':tx.apply(original,original,request.get('probe'),target_active=action=='trusttunnel-start',expected_state=expected)}
                enabled=action=='trusttunnel-enable';target='enabled' if enabled else 'disabled'
                if all(v['boot']==target for v in [snapshot,*snapshot['companions'].values()]):raise ValueError('Автозапуск всех связанных служб уже находится в выбранном состоянии')
                if enabled:
                    if not all(v['active'] for v in [snapshot,*snapshot['companions'].values()]):raise ValueError('Сначала запустите и проверьте все связанные службы; затем включите автозапуск')
                    tx.backend.validate(model);tx.backend.probe(request['probe'])
                if read_private(root/(name+'.active.json'))!=original or tx.backend.capture()!=snapshot:raise ValueError('Состояние изменилось во время проверки')
                try:tx.backend.set_enabled(enabled)
                except (ValueError,OSError):raise ValueError('Не получено подтверждение всех флагов автозапуска. Перечитайте состояния клиента и входящих служб: часть настроек могла сохраниться. Соединения не перезапускались; автоматического повтора и возврата нет') from None
                wanted={**snapshot,'boot':target,'companions':{u:{**v,'boot':target} for u,v in snapshot['companions'].items()}}
                if read_private(root/(name+'.active.json'))!=original or tx.backend.capture()!=wanted:raise ValueError('Не подтверждено изменение всех флагов автозапуска. Перечитайте состояния служб; соединения не перезапускались, автоматического повтора нет')
                return {'enabled':target,'runtime_changed':False,'companions_included':True}
            if action=='trusttunnel-export':
                if request['source']=='draft' and not view['has_draft']:raise ValueError('Сохранённого черновика нет')
                kind=request.get('format','client')
                if kind not in ('client','endpoint','deeplink'):raise ValueError('Выберите формат экспорта TrustTunnel')
                from trusttunnel_link import export
                return {'filename':name+'-'+request['source']+('.txt' if kind=='deeplink' else '.toml'),'encoding':'utf-8','content':render(model,b) if kind=='client' else export(model,kind),'mimetype':'text/plain' if kind=='deeplink' else 'application/toml'}
            path=root/(name+'.draft.json')
            if action=='trusttunnel-apply':
                if not view['managed'] or not view['has_draft']:raise ValueError('Нужен сохранённый черновик службы с подключённым безопасным применением')
                original=read_private(root/(name+'.active.json'));proposed=json.dumps(validate(model,ready=True),ensure_ascii=False).encode()
                return {'transaction':tx.apply(original,proposed,request['probe'],draft_revision=view['draft_revision'])}
            if action=='trusttunnel-check':
                render(validate(model,ready=True),b);view['check']={'parameters':True,'authentication_tested':False,'network_unchanged':True}
            elif action=='trusttunnel-discard':remove_created_file(path);view,_=load(root,name,b)
            else:
                proposed=update(model,request['values']) if action=='trusttunnel-save' else import_config(request['text'],model,request['format'],b)
                content=json.dumps({'base_revision':view['file_revision'],'model':proposed,'saved_at':time.time()},ensure_ascii=False).encode()
                if len(content)>MAX_BYTES:raise ValueError('Черновик TrustTunnel превышает 128 КиБ')
                atomic_write(path,content);view,_=load(root,name,b)
        view.update(runtime=runtime,observed_at=time.time());return view
