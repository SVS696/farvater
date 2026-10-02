"""Root-owned OpenConnect bindings and private drafts; never accept caller paths."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from safe_apply import atomic_write,remove_created_file
from wireguard_control import read_private
from openconnect_profile import validate,public,update,import_config,from_legacy_unit

ROOT=Path('/var/lib/okopy-openconnect')


def digest(data):return hashlib.sha256(data).hexdigest()


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}',value):raise ValueError('Некорректное имя подключения OpenConnect')
    return value


def binding_for(root,name):
    bindings=json.loads(read_private(root/'connections.json'))
    if not isinstance(bindings,dict) or name not in bindings:raise ValueError('Для этого подключения ещё не настроен редактор действующей службы')
    b=bindings[name]
    keys={'unit','unit_file','password_file','interface','script','binary'}
    if not isinstance(b,dict) or set(b)!=keys or not all(isinstance(v,str) for v in b.values()):raise ValueError('Повреждена привязка службы OpenConnect')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,100}\.service',b['unit']):raise ValueError('Некорректная служба OpenConnect')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}',b['interface']):raise ValueError('Некорректный интерфейс службы OpenConnect')
    for field in ('unit_file','password_file','script','binary'):
        path=Path(b[field])
        if not path.is_absolute() or '..' in path.parts or any(c.isspace() for c in str(path)):raise ValueError('Некорректная привязка файлов OpenConnect')
    return b


def regular(path,limit=128*1024):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        st=os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o022:raise ValueError('Файл службы доступен для посторонней записи')
        data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('Файл службы слишком большой')
    return data


def observe(binding):
    q=subprocess.run(['systemctl','show',binding['unit'],'-p','ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,MainPID'],capture_output=True,text=True,timeout=4)
    if q.returncode or len(q.stdout)>16384:raise ValueError('Не удалось прочитать состояние службы')
    fields=dict(line.split('=',1) for line in q.stdout.splitlines() if '=' in line)
    if fields.get('FragmentPath')!=binding['unit_file'] or fields.get('DropInPaths') or fields.get('NeedDaemonReload')!='no':
        raise ValueError('Служба изменена вне панели или требует daemon-reload; сначала согласуйте действующие настройки')
    return {'active':fields.get('ActiveState','unknown'),'state':fields.get('SubState','unknown'),'boot':fields.get('UnitFileState','unknown'),'pid':int(fields.get('MainPID','0'))}


def load(root,name,binding,*,source='selected'):
    unit=regular(Path(binding['unit_file']));script=regular(Path(binding['script']))
    managed=(root/(name+'.active.json')).exists()
    if managed:
        password=read_private(root/(name+'.active.json'))
        receipt=json.loads(read_private(root/(name+'.installation.json')))
        if receipt!={'unit_sha256':digest(unit),'script_sha256':digest(script)}:raise ValueError('Служба или сетевой обработчик изменены вне панели')
        model=validate(json.loads(password),ready=True)
    else:
        password=read_private(Path(binding['password_file']))
        model=from_legacy_unit(unit.decode(),password.decode(),binding)
    revision=digest(unit+b'\x00'+password+b'\x00'+script+b'\x00'+json.dumps(binding,sort_keys=True).encode())
    draft_path=root/(name+'.draft.json');raw=None
    result={'id':name,'managed':managed,'file_revision':revision,'draft_revision':'','has_draft':False,'conflict':False,'saved_at':None}
    if os.path.lexists(draft_path):
        raw=read_private(draft_path)
        try:
            draft=json.loads(raw)
            if set(draft)!={'base_revision','model','saved_at'} or not re.fullmatch('[a-f0-9]{64}',draft['base_revision']) or type(draft['saved_at']) not in (int,float):raise ValueError()
            selected=validate(draft['model'])
        except (ValueError,TypeError,KeyError):raise ValueError('Черновик OpenConnect повреждён; действующая служба не менялась') from None
        result.update(draft_revision=digest(raw),has_draft=True,conflict=draft['base_revision']!=revision,saved_at=draft['saved_at'])
    else:selected=model
    result['model']=public(selected)
    return result,model if source=='active' else selected


def control(request,*,root=ROOT,observe_state=observe,backend=None,network=Path('/var/lib/okopy-candidate')):
    action=request.get('action')
    allowed={'openconnect-status','openconnect-export','openconnect-save','openconnect-discard','openconnect-import','openconnect-check','openconnect-apply','openconnect-confirm','openconnect-rollback','openconnect-start','openconnect-stop','openconnect-enable','openconnect-disable'}
    if action not in allowed:raise ValueError('Неизвестное действие OpenConnect')
    lifecycle=action in ('openconnect-start','openconnect-stop','openconnect-enable','openconnect-disable')
    fields={'version','action','connection'}
    if action in ('openconnect-confirm','openconnect-rollback'):fields|={'transaction'}
    elif action!='openconnect-status':fields|={'file_revision','draft_revision'}
    if action in ('openconnect-apply','openconnect-start','openconnect-enable'):fields|={'probe'}
    if lifecycle:fields|={'expected_state'}
    if action=='openconnect-export':fields|={'source'}
    if action=='openconnect-save':fields|={'values'}
    if action=='openconnect-import':fields|={'text','format'}
    if set(request)!=fields or request.get('version')!=1:raise ValueError('Некорректные поля запроса OpenConnect')
    name=identifier(request['connection'])
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid!=os.geteuid() or root.stat().st_mode&0o077:raise ValueError('Закрытый каталог OpenConnect недоступен')
    b=binding_for(root,name)
    fd=os.open(root/'control.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        try:fcntl.flock(lock,(fcntl.LOCK_SH if action=='openconnect-status' else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Редактор OpenConnect занят; обновите страницу') from None
        from openconnect_apply import Transaction,state,PENDING,public as public_transaction
        tx=Transaction(root,b,name,backend,network);transaction=state(root)
        if action in ('openconnect-confirm','openconnect-rollback'):
            if transaction.get('connection')!=name:raise ValueError('Операция относится к другому подключению')
            result=tx.confirm(request['transaction']) if action=='openconnect-confirm' else tx.rollback(request['transaction'])
            return {'transaction':result}
        if action!='openconnect-status' and transaction.get('status') in PENDING:raise ValueError('Сначала подтвердите или восстановите изменение OpenConnect')
        if action=='openconnect-export' and request['source'] not in ('active','draft'):raise ValueError('Выберите действующие настройки или сохранённый черновик')
        runtime={'active':'unknown','state':'unknown','boot':'unknown'}
        try:
            runtime=observe_state(b);view,model=load(root,name,b,source=request['source'] if action=='openconnect-export' else 'selected')
        except (ValueError,OSError) as error:
            if action!='openconnect-status':raise
            return {'id':name,'error':str(error) if isinstance(error,ValueError) else 'Не удалось безопасно прочитать настройки службы','model':None,'runtime':runtime,'transaction':public_transaction(transaction) if transaction.get('connection')==name else {}}
        view['transaction']=public_transaction(transaction) if transaction.get('connection')==name else {}
        if transaction.get('connection')==name and transaction.get('status') in PENDING:
            view['awaiting_confirmation']=True
            if transaction.get('draft_revision')==view['draft_revision'] and (root/(name+'.active.json')).exists() and digest(read_private(root/(name+'.active.json')))==transaction.get('next_sha256'):view['conflict']=False
        if action!='openconnect-status':
            if request['file_revision']!=view['file_revision'] or request['draft_revision']!=view['draft_revision']:raise ValueError('Подключение или черновик изменились; обновите страницу')
            if action!='openconnect-discard' and view['conflict']:raise ValueError('Служба изменена вне панели; удалите устаревший черновик и перечитайте настройки')
            if action=='openconnect-export':
                if request['source']=='draft' and not view['has_draft']:raise ValueError('Сохранённого черновика нет')
                from openconnect_export import export_bundle
                return {'filename':name+'-'+request['source']+'.zip','encoding':'base64','content':export_bundle(model),'mimetype':'application/zip'}
            path=root/(name+'.draft.json')
            if lifecycle:
                if not view['managed'] or view['has_draft']:raise ValueError('Для управления службой нужны действующие настройки без неприменённого черновика')
                expected=request['expected_state']
                if not isinstance(expected,dict) or set(expected)!={'active','boot'} or type(expected['active']) is not bool or expected['boot'] not in ('enabled','disabled'):raise ValueError('Некорректное ожидаемое состояние службы')
                original=read_private(root/(name+'.active.json'))
                if action in ('openconnect-start','openconnect-stop'):
                    return {'transaction':tx.apply(original,original,request.get('probe'),target_active=action=='openconnect-start',expected_state=expected)}
                snapshot=tx.backend.capture()
                if expected!={k:snapshot[k] for k in ('active','boot')}:raise ValueError('Состояние службы изменилось; обновите страницу')
                enable=action=='openconnect-enable';target='enabled' if enable else 'disabled'
                if snapshot['boot']==target:raise ValueError('Автозапуск уже находится в выбранном состоянии')
                if enable:
                    if not snapshot['active']:raise ValueError('Сначала запустите и проверьте VPN; затем включите автозапуск')
                    tx.backend.validate(model);tx.backend.probe(request['probe'])
                if read_private(root/(name+'.active.json'))!=original or tx.backend.capture()!=snapshot:raise ValueError('Состояние изменилось во время проверки')
                tx.backend.set_enabled(enable)
                if read_private(root/(name+'.active.json'))!=original or tx.backend.capture()!={**snapshot,'boot':target}:raise ValueError('Результат автозапуска не подтверждён; перечитайте состояние перед повтором')
                return {'enabled':target,'runtime_changed':False}
            if action=='openconnect-apply':
                if not view['managed']:raise ValueError('Сначала завершите подключение службы к безопасному применению')
                if not view['has_draft']:raise ValueError('Сначала сохраните черновик подключения')
                original=read_private(root/(name+'.active.json'));proposed=json.dumps(validate(model,ready=True),ensure_ascii=False).encode()
                return {'transaction':tx.apply(original,proposed,request['probe'],draft_revision=view['draft_revision'])}
            if action=='openconnect-discard':remove_created_file(path)
            elif action=='openconnect-check':
                validate(model,ready=True)
                view['check']={'parameters':True,'authentication_tested':False,'network_unchanged':True}
                view.update(runtime=runtime,observed_at=time.time());return view
            else:
                proposed=update(model,request['values']) if action=='openconnect-save' else import_config(request['text'],model,request['format'])
                content=json.dumps({'base_revision':view['file_revision'],'model':proposed,'saved_at':time.time()},ensure_ascii=False).encode()
                if len(content)>128*1024:raise ValueError('Черновик OpenConnect превышает 128 КиБ')
                atomic_write(path,content)
            view,_=load(root,name,b)
        view.update(runtime=runtime,observed_at=time.time());return view
