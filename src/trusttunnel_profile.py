"""Typed settings for the existing TrustTunnel SOCKS client; no caller paths."""
import copy
import ipaddress
import json
import re
import ssl
import tomllib
from urllib.parse import urlsplit
from policy import normalized_domain

MAX_BYTES=128*1024
TEXT={'hostname':253,'username':512,'password':16384,'client_random':129,'custom_sni':253}
FLAGS=('has_ipv6','skip_verification','anti_dpi','post_quantum_group_enabled','killswitch_enabled')
SECRETS=('password','client_random')
DEFAULT={**{k:'' for k in TEXT},'certificate':'','addresses':[],'dns_upstreams':[],
         'has_ipv6':True,'skip_verification':False,'anti_dpi':False,'post_quantum_group_enabled':True,
         'killswitch_enabled':False,'upstream_protocol':'http2','loglevel':'info'}
ENDPOINT=('hostname','addresses','has_ipv6','username','password','client_random','custom_sni','skip_verification','certificate','upstream_protocol','anti_dpi','dns_upstreams')


def text(value,limit,label):
    if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError(label+': недопустимые символы или слишком длинное значение')
    return value


def host(value):
    text(value,253,'Имя сервера')
    if not value or any(c.isspace() for c in value):raise ValueError('Укажите имя сервера без пробелов')
    try:return str(ipaddress.ip_address(value))
    except ValueError:return normalized_domain(value)


def address(value,*,default_port=None):
    text(value,512,'Адрес сервера')
    if any(c.isspace() for c in value):raise ValueError('Адрес сервера не должен содержать пробелы')
    try:
        parsed=urlsplit('//'+value)
        if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:raise ValueError()
        host(parsed.hostname);port=parsed.port
        if port is None and default_port is None or port is not None and not 1<=port<=65535:raise ValueError()
    except ValueError:raise ValueError('Адрес: нужен сервер:порт; IPv6 задаётся как [адрес]:порт') from None
    return value


def dns(value):
    text(value,2048,'DNS')
    if any(c.isspace() for c in value):raise ValueError('DNS не должен содержать пробелы')
    if value.startswith('sdns://'):
        if not re.fullmatch(r'sdns://[A-Za-z0-9_-]{8,2040}={0,2}',value):raise ValueError('Некорректный DNS stamp')
        return value
    if '://' not in value:
        try:ipaddress.ip_address(value);return value
        except ValueError:return address(value,default_port=53)
    try:
        p=urlsplit(value)
        if p.scheme not in ('https','tls','quic','tcp') or not p.hostname or p.username is not None or p.password is not None or p.fragment:raise ValueError()
        host(p.hostname)
        if p.port is not None and not 1<=p.port<=65535:raise ValueError()
        if p.scheme!='https' and (p.path not in ('','/') or p.query):raise ValueError()
    except ValueError:raise ValueError('DNS: нужен IP, сервер:порт, HTTPS, TLS, QUIC, TCP или DNS stamp') from None
    return value


def validate(model,*,ready=False):
    if not isinstance(model,dict) or set(model)!=set(DEFAULT):raise ValueError('Неполный набор параметров TrustTunnel')
    model=copy.deepcopy(model)
    for key,limit in TEXT.items():text(model[key],limit,key)
    host(model['hostname'])
    if model['custom_sni']:host(model['custom_sni'])
    for key in FLAGS:
        if type(model[key]) is not bool:raise ValueError('Некорректный переключатель '+key)
    for key,checker,minimum,maximum in [('addresses',address,1,16),('dns_upstreams',dns,0,16)]:
        values=model[key]
        if not isinstance(values,list) or not minimum<=len(values)<=maximum or any(not isinstance(v,str) for v in values) or len(set(values))!=len(values):raise ValueError(key+': укажите неповторяющийся список, до 16 строк')
        for v in values:checker(v)
    if model['upstream_protocol'] not in ('http2','http3'):raise ValueError('Выберите HTTP/2 или HTTP/3')
    if model['loglevel'] not in ('error','warn','info','debug','trace'):raise ValueError('Выберите уровень журнала')
    random=model['client_random']
    if random and not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,32}(?:/(?:[0-9a-fA-F]{2}){1,32})?',random):raise ValueError('Client random: HEX-префикс до 32 байт и необязательная HEX-маска через /')
    pem=model['certificate']
    if not isinstance(pem,str) or len(pem)>32768 or '\x00' in pem or '\r' in pem or 'PRIVATE KEY' in pem:raise ValueError('Сертификат: нужен PEM до 32 КиБ без закрытого ключа')
    if pem:
        try:ssl.create_default_context(cadata=pem)
        except (ValueError,ssl.SSLError):raise ValueError('Не удалось прочитать сертификат PEM') from None
    if model['skip_verification'] and pem:raise ValueError('Проверка сертификата отключена: заданный PEM использоваться не будет. Выберите один режим')
    if ready and (not model['username'] or not model['password']):raise ValueError('Для подключения нужны логин и пароль')
    return model


def public(model):
    result=validate(model);result['saved_secrets']={k:bool(result[k]) for k in SECRETS}
    for key in SECRETS:result.pop(key)
    return result


def update(model,values):
    if not isinstance(values,dict) or set(values)!=set(DEFAULT)|{k+'_action' for k in SECRETS}:raise ValueError('Неполная форма TrustTunnel')
    proposed=copy.deepcopy(model)
    for key in DEFAULT:
        if key not in SECRETS:proposed[key]=values[key]
    for key in SECRETS:
        action=values[key+'_action'];value=values[key]
        if action not in ('keep','replace','clear'):raise ValueError('Выберите действие для секретного поля')
        if action!='replace' and value:raise ValueError('Для нового секретного значения выберите «Заменить»')
        if action=='replace':
            if not value:raise ValueError('Введите новое секретное значение')
            proposed[key]=value
        elif action=='clear':proposed[key]=''
    return validate(proposed)


def parse_client(raw,binding):
    if not isinstance(raw,str) or len(raw.encode())>MAX_BYTES:raise ValueError('Файл TrustTunnel превышает 128 КиБ')
    try:m=tomllib.loads(raw)
    except tomllib.TOMLDecodeError:raise ValueError('Не удалось прочитать TOML. Проверьте синтаксис файла') from None
    allowed={'loglevel','vpn_mode','killswitch_enabled','post_quantum_group_enabled','exclusions','killswitch_allow_ports','dns_upstreams','endpoint','listener'}
    if set(m)-allowed:raise ValueError('Файл содержит неподдерживаемые настройки TrustTunnel; они не будут молча отброшены')
    if m.get('vpn_mode')!='general' or m.get('exclusions',[]) or m.get('killswitch_allow_ports',[]):raise ValueError('Маршрутизация и исключения задаются в общих правилах панели. Для этого клиента нужен general без внутренних исключений')
    expected={'socks':{'address':binding['socks_address']}}
    if m.get('listener')!=expected:raise ValueError('Файл меняет локальный вход или содержит TUN. Импортируйте только параметры сервера в формате endpoint; локальный вход задаётся установленной привязкой')
    endpoint=m.get('endpoint')
    if not isinstance(endpoint,dict) or set(endpoint)-set(ENDPOINT):raise ValueError('Неизвестные или отсутствующие параметры endpoint')
    if 'dns_upstreams' in m and 'dns_upstreams' in endpoint and m['dns_upstreams']!=endpoint['dns_upstreams']:raise ValueError('Конфликт старого и нового списка DNS')
    model=copy.deepcopy(DEFAULT)
    model.update({k:m[k] for k in ('loglevel','killswitch_enabled','post_quantum_group_enabled') if k in m})
    model.update(endpoint)
    if 'dns_upstreams' in m and 'dns_upstreams' not in endpoint:model['dns_upstreams']=m['dns_upstreams']
    return validate(model,ready=True)


def import_config(raw,model,kind,binding):
    if kind=='client':return parse_client(raw,binding)
    if kind=='deeplink':
        from trusttunnel_link import decode
        return validate({**model,**{k:DEFAULT[k] for k in ENDPOINT},**decode(raw)},ready=True)
    if kind!='endpoint':raise ValueError('Выберите формат TrustTunnel')
    if not isinstance(raw,str) or len(raw.encode())>MAX_BYTES:raise ValueError('Файл превышает 128 КиБ')
    try:values=tomllib.loads(raw)
    except tomllib.TOMLDecodeError:raise ValueError('Не удалось прочитать TOML endpoint') from None
    from trusttunnel_link import endpoint_values
    values=endpoint_values(values)
    return validate({**model,**values})


def render(model,binding):
    m=validate(model,ready=True)
    def field(k,v):return k+' = '+json.dumps(v,ensure_ascii=False)
    lines=[field('loglevel',m['loglevel']),field('vpn_mode','general'),field('killswitch_enabled',m['killswitch_enabled']),field('post_quantum_group_enabled',m['post_quantum_group_enabled']),'exclusions = []','[endpoint]']
    lines += [field(k,m[k]) for k in ENDPOINT]
    lines += ['[listener.socks]',field('address',binding['socks_address'])]
    result='\n'.join(lines)+'\n'
    if parse_client(result,binding)!=m:raise ValueError('Не удалось сохранить параметры без потерь')
    return result


def values_from_form(form):
    values={k:form.get(k,'') for k in DEFAULT if k not in FLAGS}
    values.update({k:form.get(k)=='on' for k in FLAGS})
    for key in ('addresses','dns_upstreams'):values[key]=[v.strip() for v in form.get(key,'').splitlines() if v.strip()]
    values['certificate']=values['certificate'].replace('\r\n','\n').strip()
    values.update({k+'_action':form.get(k+'_action','keep') for k in SECRETS})
    return values
