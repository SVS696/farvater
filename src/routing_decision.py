"""Pure selection from fresh, revision-bound measurements; unknown means hold."""
import copy
import hashlib
from dataclasses import asdict
from failover import PrioritySelector,Health


def pair_id(queue,pair):
    return 'pair-'+hashlib.sha256(('\0'.join([queue,pair['exit'],pair['dns']])).encode()).hexdigest()[:20]


def choices(manifest):
    return {queue:[{'id':pair_id(queue,pair),'index':i,**pair} for i,pair in enumerate(pairs)]
            for queue,pairs in manifest['queues'].items()}


def validate_preferences(value,manifest):
    if not isinstance(value,dict) or set(value)!={'enabled','pins'} or type(value['enabled']) is not bool or not isinstance(value['pins'],dict):
        raise ValueError('Нужны режим автоматики и ручные закрепления')
    available=choices(manifest)
    if set(value['pins'])-set(available):raise ValueError('Закрепление ссылается на удалённую очередь')
    for queue,pin in value['pins'].items():
        if pin not in {p['id'] for p in available[queue]}:raise ValueError('Закреплённая пара больше не существует')
    if value['enabled']:
        expected={p['id'] for pairs in available.values() for p in pairs}
        actual={p['id'] for p in manifest.get('probes',[])}
        if expected!=actual:raise ValueError('Для автоматики нужны независимые проверки каждой пары каждой очереди')
    return copy.deepcopy(value)


def decide(manifest,policy,preferences,snapshot,previous,actual_mode,epoch,now):
    """Epoch includes boot/config/transaction/preferences. Never reuse old streaks."""
    available=choices(manifest)
    mode=next((m for m in manifest['modes'] if m['name']==actual_mode),None)
    if mode is None:raise ValueError('Режим отсутствует в применённой политике')
    state=copy.deepcopy(previous) if previous.get('epoch')==epoch else {'epoch':copy.deepcopy(epoch),'queues':{}}
    if now<state.get('checked_at',0):state={'epoch':copy.deepcopy(epoch),'queues':{}}
    state.update(checked_at=now,mode=actual_mode)
    target=dict(mode['selection']);messages={}
    rows={r['id']:r for r in snapshot.get('checks',[])}
    config_sha,transaction=epoch['config'],epoch['transaction']
    failures=policy.get('failover',{}).get('failures',3)
    recovery=policy.get('failover',{}).get('recovery_seconds',30)
    if type(failures) is not int or not 1<=failures<=20 or type(recovery) not in (int,float) or not 0<=recovery<=3600:
        raise ValueError('Некорректные пороги резервирования')
    for queue,pairs in available.items():
        ids=[p['id'] for p in pairs];pin=preferences.get('pins',{}).get(queue)
        if pin is not None:
            state['queues'].pop(queue,None)
            if pin in ids:target[queue]=ids.index(pin);messages[queue]='Ручное закрепление; неисправность не отменяет выбор'
            else:messages[queue]='Закреплённая пара удалена; автоматическое изменение этой очереди запрещено'
            continue
        if not preferences.get('enabled'):
            state['queues'].pop(queue,None);messages[queue]='Автоматика выключена; сохранён текущий выбор';continue
        samples=[rows.get(identifier,{}) for identifier in ids]
        valid=all(r.get('status') in ('up','down') and type(r.get('observed_at')) in (int,float)
                  and 0<=now-r['observed_at']<=45 and r.get('config_sha256')==config_sha
                  and r.get('transaction_id')==transaction for r in samples)
        prior=state['queues'].get(queue,{})
        if not valid:
            state['queues'].pop(queue,None);messages[queue]='Нет свежих достоверных проверок всех пар; выбор сохранён';continue
        stamps={r['id']:r['observed_at'] for r in samples}
        if prior and any(stamps[k]<=prior.get('stamps',{}).get(k,0) for k in stamps):
            messages[queue]=prior.get('reason','Ожидается новый опрос');continue
        # A long measurement gap cannot count as continuous recovery or failures.
        if prior and any(stamps[k]-prior.get('stamps',{}).get(k,0)>45 for k in stamps):prior={}
        selector=PrioritySelector(ids,ids[target[queue]],failures,recovery)
        for identifier,h in prior.get('health',{}).items():
            if identifier in selector.health:selector.health[identifier]=Health(**h)
        measurement_time=min(stamps.values())
        first_success={r['id']:r['observed_at'] for r in samples
                       if r['status']=='up' and selector.health[r['id']].healthy_since is None}
        result=selector.sample({r['id']:r['status']=='up' for r in samples},measurement_time)
        for identifier,stamp in first_success.items():selector.health[identifier].healthy_since=stamp
        target[queue]=ids.index(result['selected'])
        reason={'keep current exit':'Текущая пара сохранена',
            'current exit failed consecutive checks':'Последовательные отказы текущей пары; выбран исправный резерв',
            'all exits unavailable; no false healthy fallback':'Все пары неисправны; исправного резерва нет',
            'higher priority exit recovered and stayed healthy':'Более приоритетная пара стабильно восстановилась'}[result['reason']]
        state['queues'][queue]={'stamps':stamps,'health':{k:asdict(h) for k,h in selector.health.items()},'reason':reason}
        messages[queue]=reason
    return {'selection':target,'changed':target!=mode['selection'],'state':state,'reasons':messages}
