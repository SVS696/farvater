"""Bounded monitoring snapshots with explicit freshness, never sticky green."""
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

STATES = {'up', 'degraded', 'down', 'unknown'}
LABELS = {'up':'Проверка пройдена', 'degraded':'Нестабильно', 'down':'Ошибка',
          'unknown':'Нет данных', 'stale':'Нет свежих данных'}
CLASSES = {'up':'ready', 'degraded':'fallback', 'down':'blocked', 'unknown':'unknown', 'stale':'fallback'}
MAX_BYTES = 512 * 1024
MAX_AGE = 150


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def timestamp(value):
    if not number(value) or value<0:return False
    try:datetime.fromtimestamp(value,timezone.utc)
    except (OSError,OverflowError,ValueError):return False
    return True


def validate_snapshot(value):
    if not isinstance(value, dict) or value.get('version') != 1 or not timestamp(value.get('generated_at')):
        raise ValueError('Неподдерживаемый снимок мониторинга')
    if not isinstance(value.get('checks'), list) or len(value['checks']) > 128:
        raise ValueError('Некорректный список проверок')
    seen=set()
    for check in value['checks']:
        if not isinstance(check, dict) or check.get('status') not in STATES:
            raise ValueError('Некорректный результат проверки')
        for key in ('id','name','scope','detail','action'):
            if not isinstance(check.get(key), str) or len(check[key]) > 1000:
                raise ValueError('Некорректное поле проверки')
        if not check['id'] or check['id'] in seen:
            raise ValueError('Повторяющийся идентификатор проверки')
        seen.add(check['id'])
        if not timestamp(check.get('observed_at')) or not number(check.get('duration_ms')) or check['duration_ms'] < 0:
            raise ValueError('Некорректное время проверки')
        if 'interval_seconds' in check and (type(check['interval_seconds']) is not int or not 5<=check['interval_seconds']<=300):
            raise ValueError('Некорректный период проверки')
        if 'next_check_at' in check and not timestamp(check['next_check_at']):raise ValueError('Некорректное время следующей проверки')
        if 'due_since' in check and not timestamp(check['due_since']):raise ValueError('Некорректное время ожидания проверки')
        if 'source_generated_at' in check and not timestamp(check['source_generated_at']):raise ValueError('Некорректное время источника проверки')
    events=value.get('events',[])
    if not isinstance(events,list) or len(events)>30:raise ValueError('Некорректная история')
    for event in events:
        if not isinstance(event,dict) or not timestamp(event.get('at')) or event.get('status') not in STATES:
            raise ValueError('Некорректное событие')
        if any(not isinstance(event.get(k),str) or len(event[k])>1000 for k in ('id','name','detail')):
            raise ValueError('Некорректное событие')
    return value


def read_snapshot(path):
    with Path(path).open('rb') as stream:raw=stream.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES:
        raise ValueError('Слишком большой снимок мониторинга')
    return validate_snapshot(json.loads(raw))


def present_snapshot(path, *, now=None, max_age=MAX_AGE, excluded_ids=()):
    now=time.time() if now is None else now
    try:
        snapshot=read_snapshot(path)
    except (OSError, ValueError, TypeError):
        return {'status':'unknown','label':LABELS['unknown'],'style':'unknown','checks':[],
                'detail':'Свежий снимок ещё не получен. Это не подтверждает отказ всех узлов.'}
    excluded_ids=set(excluded_ids)
    checks=[]
    for raw in snapshot['checks']:
        if raw['id'] in excluded_ids:continue
        row=dict(raw);age=now-row['observed_at']
        # A due check may wait for the current bounded batch, the next batch,
        # SSH delivery and browser refresh. Keep the same 150s grace as transport.
        row_max_age=max(max_age,row['interval_seconds']+MAX_AGE) if 'interval_seconds' in row else max_age
        stale=age>row_max_age or age < -10 or snapshot['generated_at']>now+10 or now-snapshot['generated_at']>max_age
        if 'source_generated_at' in row:
            stale=stale or row['source_generated_at']>now+10 or now-row['source_generated_at']>max_age
        row.update(status='stale' if stale else row['status'],age_seconds=max(0,round(age)))
        row.update(label=LABELS[row['status']],style=CLASSES[row['status']])
        checks.append(row)
    states={c['status'] for c in checks}
    status=next((s for s in ('down','stale','degraded','unknown') if s in states),'up' if checks else 'unknown')
    problems=[c for c in checks if c['status']!='up']
    label='Все проверки пройдены' if checks and not problems else 'Требуют внимания: '+str(len(problems)) if problems else 'Нет данных'
    detail=' · '.join(c['name']+': '+c['label'].lower() for c in problems[:5])
    if len(problems)>5:detail+=' · ещё '+str(len(problems)-5)
    return {'status':status,'label':label,'style':CLASSES[status],'checks':checks,
            'events':[e for e in reversed(snapshot.get('events',[])) if e['id'] not in excluded_ids],
            'generated_at':snapshot['generated_at'], 'age_seconds':max(0,round(now-snapshot['generated_at'])),
            'interval_seconds':snapshot.get('interval_seconds',30),'problems':problems,
            'detail':detail or 'Состояние по настроенным проверкам.'}


def transport_message(path, *, now=None):
    now=time.time() if now is None else now
    try:
        value=json.loads(Path(path).read_text())
        if value.get('ok') is False:
            return 'Последний опрос по SSH не удался. Проверьте доступ к сборщику; возраст каждой проверки показан отдельно.'
        if not timestamp(value.get('at')) or now-value['at']>90 or value['at']>now+10:
            return 'Нет свежего подтверждения работы SSH-опроса. Проверьте процесс панели; возраст проверок показан отдельно.'
    except (OSError,ValueError,TypeError,AttributeError):pass
    return None


def merge_presented(primary, additional):
    """Combine independent sources without letting one green source hide another."""
    result=dict(primary)
    result['checks']=[*primary['checks'],*additional['checks']]
    states={primary['status'],additional['status']}
    ids=[c['id'] for c in result['checks']]
    if len(ids)!=len(set(ids)):states.add('unknown')
    status=next((s for s in ('down','stale','degraded','unknown') if s in states),'up')
    result.update(status=status,label=LABELS[status],style=CLASSES[status],
                  detail='Серверные проверки и собственные измерения роутеров получены независимо. У каждого результата своё время.')
    result['events']=sorted([*primary.get('events',[]),*additional.get('events',[])],key=lambda e:e['at'],reverse=True)[:30]
    return result
