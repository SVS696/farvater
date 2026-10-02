"""Private WG drafts and guarded application through the existing SSH boundary."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from safe_apply import atomic_write
import wireguard_profile as wg_codec
from wireguard_profile import MAX_BYTES, parse, public_view, render, update

PROFILES = Path('/etc/wireguard')
DRAFTS = Path('/var/lib/okopy-wireguard')
MAX_PUBLIC = 96 * 1024


def profile_name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',value):
        raise ValueError('Некорректное имя интерфейса WireGuard')
    return value


def read_private(path):
    """Reject links, nonregular and publicly accessible secret files."""
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            st=os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o077:
                raise ValueError('Файл должен принадлежать владельцу службы и иметь права 0600')
            data=stream.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES:raise ValueError('Файл WireGuard превышает 256 КиБ')
        return data
    except OSError:raise ValueError('Не удалось безопасно прочитать файл WireGuard') from None


def revision(data):return hashlib.sha256(data).hexdigest()


def visible(model,codec=wg_codec):
    result=codec.public_view(model)
    if len(json.dumps(result).encode())>MAX_PUBLIC:
        raise ValueError('Профиль слишком велик для веб-редактора; исходный файл сохранён')
    return result


def runtime(names,unit_prefix="wg-quick"):
    """Bounded read-only observations, separate from traffic health."""
    result={name:{'service':'unknown','substate':'unknown','boot':'unknown','interface':None} for name in names}
    if not names:return result
    units=[unit_prefix+'@'+name+'.service' for name in names]
    try:
        command=['systemctl','show',*units,'--property=Id,ActiveState,SubState,UnitFileState']
        response=subprocess.run(command,capture_output=True,text=True,timeout=3)
        if response.returncode==0 and len(response.stdout)<64*1024:
            by_unit={unit:name for name,unit in zip(names,units)}
            for block in response.stdout.strip().split('\n\n'):
                fields=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
                name=by_unit.get(fields.get('Id'))
                if name:
                    for target,source in [('service','ActiveState'),('substate','SubState'),('boot','UnitFileState')]:
                        value=fields.get(source,'unknown')
                        result[name][target]=value if re.fullmatch('[a-z-]{1,32}',value) else 'unknown'
    except (OSError,subprocess.TimeoutExpired):pass
    try:
        response=subprocess.run(['ip','-j','link','show'],capture_output=True,text=True,timeout=3)
        if response.returncode==0 and len(response.stdout)<256*1024:
            interfaces={item['ifname'] for item in json.loads(response.stdout)}
            for name in names:result[name]['interface']=name in interfaces
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired):pass
    return result


def load(name,profiles,drafts,codec=wg_codec):
    parse=codec.parse
    original=read_private(profiles/(name+'.conf'))
    file_revision=revision(original)
    draft_path=drafts/(name+'.json')
    data=None;draft_revision=''
    # lexists also catches a dangling symlink, which read_private rejects.
    if os.path.lexists(draft_path):
        data=read_private(draft_path)
        draft_revision=revision(data)
    view={'name':name,'file_revision':file_revision,'draft_revision':draft_revision,
          'has_draft':data is not None,'conflict':False,'saved_at':None,'model':None,'error':None}
    # Raw revisions remain available when parsing fails. Discard can then
    # remove exactly the observed private draft, without guessing its contents.
    try:
        try:model=parse(original.decode())
        except UnicodeError:raise ValueError('Файл WireGuard имеет неверную кодировку') from None
        selected=model
        if data is not None:
            try:
                draft=json.loads(data)
                if set(draft)!={'version','base_revision','profile','saved_at'} or draft['version']!=1 or not re.fullmatch('[0-9a-f]{64}',draft['base_revision']):
                    raise ValueError()
                selected=parse(draft['profile'])
                if type(draft['saved_at']) not in (int,float) or not 0<=draft['saved_at']<=253402300799:raise ValueError()
            except (KeyError,TypeError,ValueError):raise ValueError('Черновик WireGuard повреждён; исходный профиль не изменён') from None
            view.update(conflict=draft['base_revision']!=file_revision,saved_at=draft['saved_at'])
        view['model']=visible(selected,codec)
        return view,selected
    except ValueError as error:
        view['error']=str(error)
        return view,None


def control(request,*,profiles=PROFILES,drafts=DRAFTS,observe=runtime,backend=None,network_lock=Path('/var/lib/okopy-candidate/apply.lock'),codec=wg_codec,prepare_create=None,peer_roots=(DRAFTS,Path("/var/lib/okopy-amnezia"))):
    parse,render,update=codec.parse,codec.render,codec.update
    action=request.get('action')
    if action not in ('wireguard-status','wireguard-export','wireguard-import','wireguard-create','wireguard-save','wireguard-discard','wireguard-check','wireguard-apply','wireguard-confirm','wireguard-rollback','wireguard-start','wireguard-stop','wireguard-enable','wireguard-disable','wireguard-abandon'):
        raise ValueError('Неизвестное действие WireGuard')
    fields={'version','action','profile'}
    if action=='wireguard-create':fields|={'values'}
    elif action in ('wireguard-confirm','wireguard-rollback','wireguard-abandon'):fields|={'transaction'}
    elif action!='wireguard-status':fields|={'file_revision','draft_revision'}
    lifecycle=action in ('wireguard-start','wireguard-stop','wireguard-enable','wireguard-disable')
    if action in ('wireguard-apply','wireguard-start','wireguard-enable'):fields|={'probe'}
    if lifecycle:fields|={'expected_state'}
    if action=='wireguard-export':fields|={'source'}
    if action=='wireguard-import':fields|={'text'}
    if action=='wireguard-save':fields|={'values'}
    if set(request)!=fields or request.get('version')!=1:raise ValueError('Некорректные поля запроса WireGuard')
    if lifecycle:
        expected=request['expected_state']
        if not isinstance(expected,dict) or set(expected)!={'active','enabled'} or type(expected['active']) is not bool or expected['enabled'] not in ('enabled','disabled'):
            raise ValueError('Некорректное ожидаемое состояние WireGuard')
    name=request['profile']
    if name is not None:profile_name(name)
    elif action!='wireguard-status' and not (action=='wireguard-create' and prepare_create):raise ValueError('Выберите профиль WireGuard')
    for directory in (profiles,drafts):
        if directory.is_symlink() or not directory.is_dir():raise ValueError('Каталог WireGuard недоступен')
        st=directory.stat()
        if st.st_uid!=os.geteuid() or st.st_mode & 0o022:raise ValueError('Каталог WireGuard доступен для посторонней записи')
    fd=os.open(drafts/'control.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        try:fcntl.flock(lock,(fcntl.LOCK_SH if action in ('wireguard-status','wireguard-export') else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Редактор WireGuard занят. Обновите страницу') from None
        from wireguard_apply import Transaction,PENDING
        tx=Transaction(drafts,profiles,backend,parser=codec.parse)
        if action not in ('wireguard-status','wireguard-export'):tx.reconcile_runtime_boot()
        transaction=tx.state()
        client_job=drafts/'client-operation.json'
        if action!='wireguard-status' and client_job.exists() and json.loads(read_private(client_job)).get('status')=='pending':
            raise ValueError('Сначала завершите изменение клиента WireGuard в разделе устройств')
        if action=='wireguard-create':
            if transaction.get('status') in PENDING:
                raise ValueError('Сначала завершите применение или возврат WireGuard')
            from wireguard_create import create
            values=request['values']
            if prepare_create:name,values=prepare_create(name,values,profiles,drafts)
            return create(name,values,profiles,drafts,observe,codec=codec)
        if action in ('wireguard-confirm','wireguard-rollback','wireguard-abandon'):
            if transaction.get('profile')!=name or transaction.get('id')!=request['transaction']:
                raise ValueError('Операция WireGuard изменилась; перечитайте состояние')
            if action=='wireguard-rollback' and transaction.get('status') not in (*PENDING,'rolled_back'):
                raise ValueError('Эта операция уже завершена; возврат не выполнялся')
            if action=='wireguard-abandon':result=tx.abandon_runtime(request['transaction'])
            else:result=tx.confirm(request['transaction']) if action=='wireguard-confirm' else tx.rollback(request['transaction'],manual=True)
            if action=='wireguard-confirm':
                draft=drafts/(name+'.json')
                if draft.exists() and revision(read_private(draft))==transaction.get('draft_revision'):
                    from safe_apply import remove_created_file
                    remove_created_file(draft)
            return {'transaction':result}
        if action!='wireguard-status' and transaction.get('profile')==name and transaction.get('status') in PENDING:
            raise ValueError('Идёт проверка изменения WireGuard. Подтвердите результат или дождитесь возврата')
        if name is None:
            names=sorted(p.stem for p in profiles.glob('*.conf') if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',p.stem))
            if len(names)>64:raise ValueError('Поддерживается до 64 файлов WireGuard')
            observed=observe(names);items=[]
            for item in names:
                row={'name':item,'runtime':observed[item]}
                try:
                    view,model=load(item,profiles,drafts,codec)
                    row.update({k:view[k] for k in ('file_revision','has_draft','conflict')})
                    row['peers']=len(model['peers']) if model is not None else None
                    row['editable']=model is not None;row['error']=view['error']
                except ValueError as error:row.update(editable=False,error=str(error))
                items.append(row)
            return {'profiles':items,'observed_at':time.time(),'transaction':tx.public(transaction)}
        try:view,model=load(name,profiles,drafts,codec)
        except ValueError as error:
            if action!='wireguard-status' or transaction.get('profile')!=name:raise
            view={'name':name,'error':str(error),'model':None,'has_draft':False,'conflict':False,
                  'file_revision':'','draft_revision':'','saved_at':None};model=None
        view['transaction']=tx.public(transaction)
        if action!='wireguard-status':
            if request['file_revision']!=view['file_revision'] or request['draft_revision']!=view['draft_revision']:
                raise ValueError('Файл или черновик WireGuard изменился. Обновите страницу')
            if action=='wireguard-export':
                if view['error']:raise ValueError(view['error'])
                if view['conflict']:raise ValueError('Исходный файл изменился; сначала перечитайте настройки')
                source=request['source']
                if source not in ('active','draft'):raise ValueError('Выберите действующие настройки или сохранённый черновик')
                if source=='draft' and not view['has_draft']:raise ValueError('Сохранённого черновика нет')
                selected=parse(read_private(profiles/(name+'.conf')).decode()) if source=='active' else model
                return {'filename':name+'-'+source+'.conf','encoding':'utf-8','content':render(selected),'mimetype':'text/plain'}
            if lifecycle and (view['error'] or view['has_draft']):
                raise ValueError('Для переключения состояния нужен рабочий профиль без неприменённого черновика')
            if action in ('wireguard-enable','wireguard-disable'):
                if transaction.get('status') in PENDING:raise ValueError('Сначала завершите применение или возврат WireGuard')
                original=read_private(profiles/(name+'.conf'));snapshot=tx.backend.capture(name,original)
                if request['expected_state']!={k:snapshot[k] for k in ('active','enabled')}:raise ValueError('Состояние службы изменилось. Обновите страницу')
                enable=action=='wireguard-enable'
                if snapshot['enabled']==('enabled' if enable else 'disabled'):raise ValueError('Автозапуск уже находится в выбранном состоянии')
                if enable:
                    if not snapshot['active']:raise ValueError('Сначала включите и проверьте туннель; затем разрешите автозапуск')
                    tx.backend.validate(name,model,activation=True)
                    tx.backend.probe(name,request['probe'],model)
                if read_private(profiles/(name+'.conf'))!=original or not tx.backend.matches(name,original,snapshot):raise ValueError('Состояние изменилось во время проверки')
                tx.backend.set_enabled(name,enable)
                target={**snapshot,'enabled':'enabled' if enable else 'disabled'}
                if read_private(profiles/(name+'.conf'))!=original or not tx.backend.matches(name,original,target):raise ValueError('Результат настройки автозапуска не подтверждён. Обновите страницу и проверьте службу; повторять действие вслепую нельзя')
                return {'profile':name,'enabled':target['enabled'],'runtime_changed':False,'observed_at':time.time()}
            if action in ('wireguard-apply','wireguard-start','wireguard-stop'):
                if view['error']:raise ValueError(view['error'])
                if action=='wireguard-apply' and (not view['has_draft'] or view['conflict']):raise ValueError('Нужен сохранённый черновик без конфликта с рабочим файлом')
                original=read_private(profiles/(name+'.conf'))
                if revision(original)!=view['file_revision']:raise ValueError('Рабочий файл уже изменился')
                with network_lock.open('a') as network:
                    try:fcntl.flock(network,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError:raise ValueError('Сетевая политика сейчас изменяется; применение WireGuard не началось') from None
                    for other in peer_roots:
                        if other!=drafts and Transaction(other).state().get('status') in PENDING:raise ValueError('Сначала завершите изменение другого WG/AWG')
                    from openconnect_apply import state as openconnect_state,PENDING as OPENCONNECT_PENDING
                    if openconnect_state().get('status') in OPENCONNECT_PENDING or openconnect_state(Path('/var/lib/okopy-trusttunnel')).get('status') in OPENCONNECT_PENDING:raise ValueError('Сначала завершите изменение VPN')
                    try:
                        candidate_state=json.loads(read_private(network_lock.parent/'transaction.json'))
                        if not isinstance(candidate_state,dict):raise ValueError()
                    except (ValueError,OSError):
                        raise ValueError('Журнал сетевой политики недоступен или повреждён; восстановите его перед применением WireGuard') from None
                    if candidate_state.get('status') not in ('confirmed','rolled_back','schedule_failed'):
                        raise ValueError('Сначала завершите применение или возврат сетевой политики')
                    if lifecycle:
                        result=tx.apply(name,original,original,request.get('probe'),runtime_active=action=='wireguard-start',expected_state=request['expected_state'])
                    else:result=tx.apply(name,original,render(model).encode(),request['probe'],draft_revision=view['draft_revision'])
                return {'transaction':result}
            if action=='wireguard-check':
                if view['error']:raise ValueError(view['error'])
                if view['conflict']:raise ValueError('Исходный файл изменён вне панели. Перечитайте его перед проверкой')
                from wireguard_preflight import check
                view['preflight']=(backend.preflight(name,model) if backend is not None and hasattr(backend,'preflight') else check(name,model,profiles,observe=observe,
                                        read_profile=lambda path:parse(read_private(path).decode())))
                view['runtime']=observe([name])[name];view['observed_at']=time.time()
                return view
            if action in ('wireguard-save','wireguard-import'):
                if view['error']:raise ValueError(view['error'])
                if view['conflict']:raise ValueError('Исходный файл изменён вне панели. Сначала удалите устаревший черновик и перечитайте файл')
                proposed=parse(request['text']) if action=='wireguard-import' else update(model,request['values'])
                if hasattr(codec,'prepare_managed'):proposed=codec.prepare_managed(proposed,model)
                visible(proposed,codec)
                data=json.dumps({'version':1,'base_revision':view['file_revision'],'profile':render(proposed),'saved_at':time.time()}).encode()
                if len(data)>MAX_BYTES:raise ValueError('Черновик WireGuard слишком большой')
                atomic_write(drafts/(name+'.json'),data)
            else:
                (drafts/(name+'.json')).unlink(missing_ok=True)
                directory_fd=os.open(drafts,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(directory_fd)
                finally:os.close(directory_fd)
            # Do not include the model in mutation responses or query the live
            # service after saving. The redirected GET reads the current state.
            return {'name':name,'saved':action in ('wireguard-save','wireguard-import'),'runtime_changed':False}
        view['runtime']=observe([name])[name];view['observed_at']=time.time()
        if model is not None:
            from wireguard_create import public_key
            try:view['public_key']=public_key(model['interface']['PrivateKey'])
            except (ValueError,OSError):view['public_key']=None
        return view
