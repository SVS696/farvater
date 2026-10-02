"""Portable policy documents and dependency-aware draft removal."""
import copy,json,re
from policy import validate_policy
MAX_BYTES=2*1024*1024

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('В JSON повторяется поле: '+key)
        result[key]=value
    return result

def check_shape(policy):
    if not isinstance(policy,dict):raise ValueError('Нужен объект сетевой политики')
    if not {'exits','dns','profiles','default_exit','default_dns'}<=set(policy):raise ValueError('В файле отсутствуют основные разделы политики')
    for group in ('exits','dns'):
        if not isinstance(policy[group],dict) or not 1<=len(policy[group])<=128:raise ValueError('Неверный раздел '+group)
        for key,item in policy[group].items():
            if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}',key) or not isinstance(item,dict):raise ValueError('Некорректная запись '+group)
            if not isinstance(item.get('name'),str) or not 1<=len(item['name'])<=120:raise ValueError('Не указано название '+group)
            if item.get('scope') not in ('public','work','special'):raise ValueError('Неизвестное назначение '+group)
            if 'native' in item and not isinstance(item['native'],dict):raise ValueError('Некорректные параметры протокола')
    if not isinstance(policy['profiles'],list) or len(policy['profiles'])>128 or any(not isinstance(p,dict) for p in policy['profiles']):raise ValueError('Неверный список правил')
    if any(not isinstance(policy[k],str) for k in ('default_exit','default_dns')):raise ValueError('Неверное правило по умолчанию')
    def bounds(value,depth=0):
        if depth>32:raise ValueError('Слишком много уровней вложенности JSON')
        if isinstance(value,dict):
            for v in value.values():bounds(v,depth+1)
        elif isinstance(value,list):
            if len(value)>8192:raise ValueError('Слишком большой список JSON')
            for v in value:bounds(v,depth+1)
    bounds(policy)
    try:issues=validate_policy(policy)
    except (TypeError,KeyError,AttributeError,ValueError,IndexError):raise ValueError('Некорректная структура параметров политики') from None
    errors=[i for i in issues if i['severity']=='error']
    if errors:raise ValueError('Проверка политики: '+'; '.join(i['profile']+': '+i['message'] for i in errors[:5]))
    return issues

def decode(raw):
    if len(raw)>MAX_BYTES:raise ValueError('Файл превышает 2 МиБ')
    try:value=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('Некорректное число JSON')))
    except (UnicodeError,json.JSONDecodeError,RecursionError):raise ValueError('Нужен корректный JSON в UTF-8') from None
    if not isinstance(value,dict) or set(value)!={'format','version','policy'} or value['format']!='network-panel-policy' or type(value['version']) is not int or value['version']!=1:raise ValueError('Нужен файл настроек, экспортированный панелью')
    check_shape(value['policy'])
    return value['policy']

def encode(policy):
    return json.dumps({'format':'network-panel-policy','version':1,'policy':policy},ensure_ascii=False,indent=2)+'\n'

def references(policy,group,key):
    refs=[]
    def add(label,match):
        if match and label not in refs:refs.append(label)
    add('Правило «Весь остальной трафик»',policy.get('default_exit' if group=='exits' else 'default_dns')==key)
    fo=policy.get('failover',{})
    add('Резервы последнего правила',key in fo.get('priority',[]) or key in fo.get('dns_by_exit',{}) if group=='exits' else key in fo.get('dns_by_exit',{}).values())
    for p in policy.get('profiles',[]):
        match=(p.get('exit')==key or key in p.get('fallback',[])) if group=='exits' else p.get('dns')==key
        match=match or any(pair.get('exit' if group=='exits' else 'dns')==key for pair in p.get('fallback_pairs',[]))
        add('Правило «'+p.get('name',p['id'])+'»',match)
    def bootstrap(native):
        value=native.get('domain_resolver');return value.get('server') if isinstance(value,dict) else value
    for other,item in policy.get('dns',{}).items():
        if group=='dns' and other==key:continue
        native=item.get('native',{})
        match=(native.get('detour')==key or native.get('type')=='openvpn' and native.get('endpoint')==key) if group=='exits' else (item.get('bootstrap')==key or bootstrap(native)==key)
        add('DNS «'+item['name']+'»',match)
    for other,item in policy.get('exits',{}).items():
        if group=='exits' and other==key:continue
        native=item.get('native',{})
        match=(native.get('detour')==key or key in native.get('outbounds',[]) or native.get('type')=='selector' and native.get('default')==key) if group=='exits' else bootstrap(native)==key
        add('Подключение «'+item['name']+'»',match)
    return refs

def remove(policy,group,key):
    if group not in ('exits','dns') or key not in policy.get(group,{}):raise ValueError('Запись не найдена')
    used=references(policy,group,key)
    if used:raise ValueError('Сначала замените ссылки: '+'; '.join(used))
    candidate=copy.deepcopy(policy);del candidate[group][key]
    # Preserve pre-existing unrelated draft warnings; deletion must not add broken references.
    before={(i['profile'],i['message']) for i in validate_policy(policy) if i['severity']=='error'}
    errors=[i for i in validate_policy(candidate) if i['severity']=='error' and (i['profile'],i['message']) not in before]
    if errors:raise ValueError('; '.join(i['profile']+': '+i['message'] for i in errors))
    del policy[group][key]
