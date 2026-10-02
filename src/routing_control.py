"""One candidate-only writer for automatic and owner-pinned mode selection."""
from contextlib import contextmanager
import fcntl,hashlib,json,os,time,uuid
from pathlib import Path
from candidate_bundle import read_bundle
from safe_apply import ROOT,atomic_write
from mode_client import ModeClient
from health_model import read_snapshot
from routing_decision import choices,validate_preferences,decide

MONITOR=Path('/var/lib/okopy-monitor/health.json')


def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def read_json(path,default=None):
    try:
        with path.open('rb') as stream:raw=stream.read(512*1024+1)
        if len(raw)>512*1024:raise ValueError('Слишком большой файл управления резервированием')
        return json.loads(raw)
    except FileNotFoundError:
        if default is not None:return default
        raise


def save(path,value):atomic_write(path,(json.dumps(value,ensure_ascii=False)+'\n').encode())


@contextmanager
def writer(root):
    with (root/'routing.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Управление резервированием занято; обновите состояние') from None
        yield


def inputs(root):
    with (root/'apply.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Сейчас применяется или откатывается политика') from None
        state=read_json(root/'transaction.json')
        if state.get('status') not in ('confirmed','rolled_back') or not state.get('id'):
            raise ValueError('Автоматика доступна только для подтверждённой или восстановленной политики')
        files=read_bundle(root);expected=state.get('next_files' if state['status']=='confirmed' else 'previous_files',{})
        if set(files)!=set(expected) or any(hashlib.sha256(v).hexdigest()!=expected[n] for n,v in files.items()):
            raise ValueError('Пакет не совпадает с принятой ревизией')
        config=json.loads(files['config.json']);manifest=json.loads(files['policy-manifest.json'])
        if manifest.get('config_sha256')!=hashlib.sha256(files['config.json']).hexdigest():raise ValueError('Манифест не соответствует конфигурации')
        return config,manifest,json.loads(files['applied-policy.json']),state


def preferences(root):
    value=read_json(root/'routing-preferences.json',{'revision':'absent','enabled':False,'pins':{}})
    if not isinstance(value,dict) or set(value)!={'revision','enabled','pins'} or not isinstance(value['revision'],str) or type(value['enabled']) is not bool or not isinstance(value['pins'],dict):
        raise ValueError('Настройки управления повреждены; автоматическое переключение остановлено')
    return value


def client_for(root,config,manifest,state):
    return ModeClient(manifest['modes'],api_secret=config['experimental']['clash_api']['secret'],lock_path=root/'mode.lock',api_port=9091,bound_config_sha256=manifest['config_sha256'],bound_transaction=state['id'],require_settled=True)


def current(client,manifest):
    actual=client._request('GET')
    mode=next((m for m in manifest['modes'] if m['name']==actual.get('mode')),None)
    if mode is None:raise ValueError('Текущий режим не принадлежит применённой политике')
    return mode


def view(root,config,manifest,state,prefs,mode):
    try:runtime=read_json(root/'routing-state.json',{})
    except (OSError,ValueError):runtime={}
    if not isinstance(runtime,dict):runtime={}
    decision=runtime.get('decision',{})
    if not isinstance(decision,dict):decision={}
    epoch=decision.get('epoch',{})
    if not isinstance(epoch,dict):epoch={}
    bound=(epoch.get('config')==manifest['config_sha256'] and epoch.get('transaction')==state['id'] and epoch.get('preferences')==prefs['revision'])
    counters=decision.get('queues',{}) if bound else {}
    if not isinstance(counters,dict):counters={}
    try:events=read_json(root/'routing-events.json',[])
    except (OSError,ValueError):events=[]
    if not isinstance(events,list):events=[]
    events=[{'at':e['at'],'reasons':e['reasons']} for e in events[-10:]
            if isinstance(e,dict) and type(e.get('at')) in (int,float) and isinstance(e.get('reasons'),dict)
            and all(isinstance(v,str) for v in e['reasons'].values())]
    return {'config_sha256':manifest['config_sha256'],'transaction_id':state['id'],
            'preferences':prefs,'mode':mode['name'],'selection':mode['selection'],'queues':choices(manifest),
            'coverage_complete':{p['id'] for q in choices(manifest).values() for p in q}=={p['id'] for p in manifest.get('probes',[])},
            'runtime':{k:runtime[k] for k in ('checked_at','reasons','changed_at','error','observed_mode') if k in runtime},
            'controller_fresh':bound and type(runtime.get('checked_at')) in (int,float) and 0<=time.time()-runtime['checked_at']<=30,'counters':counters,
            'events':list(reversed(events)),
            'observed_at':time.time()}


def control(request,root=ROOT):
    action=request['action']
    required={'version','action'} | (set() if action=='routing-status' else {'expected_config_sha256','expected_transaction_id','expected_preferences_revision','expected_mode','enabled','pins'})
    if set(request)!=required:raise ValueError('Некорректные поля управления резервированием')
    with writer(root):
        config,manifest,policy,state=inputs(root);prefs=preferences(root);client=client_for(root,config,manifest,state);mode=current(client,manifest)
        if action=='routing-set':
            if (request['expected_transaction_id']!=state['id'] or request['expected_config_sha256']!=manifest['config_sha256'] or request['expected_preferences_revision']!=prefs['revision'] or request['expected_mode']!=mode['name']):
                raise ValueError('Настройки или активный режим изменились; обновите страницу')
            desired=validate_preferences({'enabled':request['enabled'],'pins':request['pins']},manifest)
            prefs={'revision':uuid.uuid4().hex,**desired}
            # Persist owner intent first. If the API becomes unavailable, the
            # reconciler keeps this pin rather than silently restoring automatic.
            save(root/'routing-preferences.json',prefs)
            selection=dict(mode['selection'])
            for queue,pairs in choices(manifest).items():
                pin=prefs['pins'].get(queue)
                if pin is not None:selection[queue]=next(p['index'] for p in pairs if p['id']==pin)
            client.choose(selection,expected_mode=mode['name']);mode=current(client,manifest)
        return view(root,config,manifest,state,prefs,mode)


def append_event(root,event):
    try:events=read_json(root/'routing-events.json',[])
    except (OSError,ValueError):events=[]
    if not isinstance(events,list):events=[]
    events=[e for e in events if isinstance(e,dict)]
    if not any(e.get('id')==event['id'] for e in events):events.append(event)
    save(root/'routing-events.json',events[-100:])


def tick_locked(root,monitor,now):
    config,manifest,policy,transaction=inputs(root);prefs=preferences(root)
    client=client_for(root,config,manifest,transaction);mode=current(client,manifest)
    epoch={'config':manifest['config_sha256'],'transaction':transaction['id'],'preferences':prefs['revision'],
           'boot':boot_id()}
    try:snapshot=read_snapshot(monitor)
    except (OSError,ValueError):snapshot={'checks':[]}
    try:previous=read_json(root/'routing-state.json',{})
    except (OSError,ValueError,TypeError):previous={}
    if not isinstance(previous,dict):previous={}
    prior=previous.get('decision',{})
    if not isinstance(prior,dict):prior={}
    # Recover a crash between API read-back and event persistence. Event ids
    # make replay idempotent if the log write succeeded but its acknowledgement
    # did not. An unconfirmed intent is only logged if its target is live.
    pending=previous.get('transition')
    if isinstance(pending,dict) and pending.get('epoch')==epoch and mode['name']==pending.get('to'):
        append_event(root,pending)
    result=decide(manifest,policy,prefs,snapshot,prior,mode['name'],epoch,now)
    _,after,_,state=inputs(root)
    if state['id']!=transaction['id'] or after['config_sha256']!=manifest['config_sha256']:
        raise ValueError('Политика изменилась во время принятия решения')
    event=None;actual=mode
    if result['changed']:
        target=next(m for m in manifest['modes'] if m['selection']==result['selection'])
        event={'id':uuid.uuid4().hex,'epoch':epoch,'at':now,'from':mode['name'],'to':target['name'],'reasons':result['reasons']}
        # Keep pre-sample counters until the write is verified. Retrying after
        # a crash consumes this sample once, not as another failure.
        save(root/'routing-state.json',{**previous,'transition':event})
        actual=client.choose(result['selection'],expected_mode=mode['name'])
    value={'checked_at':now,'reasons':result['reasons'],'observed_mode':actual['name'],'decision':result['state']}
    if event:value.update(changed_at=now,transition=event)
    elif previous.get('changed_at') is not None:value['changed_at']=previous['changed_at']
    save(root/'routing-state.json',value)
    if event:
        append_event(root,event)
        value.pop('transition');save(root/'routing-state.json',value)
    return value


def tick(root=ROOT,monitor=MONITOR,now=None):
    now=time.time() if now is None else now
    with writer(root):
        try:return tick_locked(root,monitor,now)
        except Exception:
            try:
                previous=read_json(root/'routing-state.json',{})
                if not isinstance(previous,dict):previous={}
                previous.update(checked_at=now,error='Управление приостановлено: проверьте применение, доступ к API и журнал службы')
                save(root/'routing-state.json',previous)
            except (OSError,ValueError):pass
            raise


if __name__=='__main__':
    os.umask(0o077)
    try:tick()
    except Exception as error:
        # Fixed public state; raw diagnostics remain in a private root file.
        atomic_write(ROOT/'last-routing-error.log',(type(error).__name__+': '+str(error)).encode())
        raise SystemExit(1)
