"""Dashboard presentation preferences; never change probe execution."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
from safe_apply import atomic_write

EXTERNAL_KINDS={'router_lan','vpn_gate'}

CARD_GROUPS = (
    ('Проблемы', ()),
    ('Доступ', ('https', 'https_slow', 'tcp', 'icmp')),
    ('DNS', ('dns', 'dns_filter')),
    ('Выходы', ('pair', 'vpn_gate', 'udp_stun')),
    ('Службы', ('service', 'runtime', 'resources')),
    ('Прочее', ()),
)


def group_cards(rows):
    groups={title:[] for title,_ in CARD_GROUPS}
    by_kind={kind:title for title,kinds in CARD_GROUPS for kind in kinds}
    for row in rows:
        title='Проблемы' if row['status']!='up' else by_kind.get(row.get('kind'),'Прочее')
        groups[title].append(row)
    return [(title,groups[title]) for title,_ in CARD_GROUPS if groups[title]]

def read_view(directory):
    path=directory/'monitor-view.json'
    try:raw=path.read_bytes()
    except FileNotFoundError:return {'order':[],'hidden':[]},'empty'
    value=json.loads(raw)
    if not isinstance(value,dict) or set(value)!={'order','hidden'}:raise ValueError('Повреждены настройки дашборда')
    for key in value:
        rows=value[key]
        if not isinstance(rows,list) or len(rows)>128 or any(not isinstance(x,str) or len(x)>1000 for x in rows) or len(set(rows))!=len(rows):
            raise ValueError('Повреждены настройки дашборда')
    return value,hashlib.sha256(raw).hexdigest()

def arrange(rows,view,visible_only=False):
    order={key:i for i,key in enumerate(view['order'])}
    return sorted((r for r in rows if not visible_only or r['id'] not in view['hidden']),key=lambda r:order.get(r['id'],len(order)))

def save_view(directory,revision,order,visible,known):
    with (directory/'monitor-view.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        _,current=read_view(directory)
        if revision!=current:raise ValueError('Дашборд уже изменён. Обновите страницу.')
        if len(order)!=len(set(order)) or set(order)!=known or len(visible)!=len(set(visible)) or not set(visible)<=known:
            raise ValueError('Список датчиков изменился. Обновите страницу перед сохранением.')
        atomic_write(directory/'monitor-view.json',json.dumps({'order':order,'hidden':[key for key in order if key not in visible]},ensure_ascii=False).encode())
