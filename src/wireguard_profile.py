"""Bounded wg-quick profile format for the forthcoming service editor.

No commands or files are executed here. Hooks and DNS side effects require a
separate owner and are rejected rather than silently removed. Secrets remain
inside the server model; public_view is the only model intended for the UI.
"""
import base64
import copy
import ipaddress
import re

from policy import normalized_domain

INTERFACE_FIELDS={'PrivateKey','Address','ListenPort','MTU','Table'}
PEER_FIELDS={'PublicKey','PresharedKey','AllowedIPs','Endpoint','PersistentKeepalive'}
MAX_BYTES=256*1024


def key(value,label):
    try:
        decoded=base64.b64decode(value,validate=True)
        if len(decoded)!=32 or not any(decoded) or base64.b64encode(decoded).decode()!=value:
            raise ValueError()
    except (ValueError,TypeError):
        raise ValueError(label+': нужен ненулевой ключ WireGuard из 32 байт в base64') from None
    return value


def integer(value,label,low,high):
    if not isinstance(value,str) or not value.isascii() or not value.isdigit() or not low<=int(value)<=high:
        raise ValueError(label+': значение вне допустимого диапазона')
    return int(value)


def endpoint(value):
    if not isinstance(value,str) or len(value)>320 or any(c.isspace() for c in value):
        raise ValueError('Endpoint: нужен адрес сервера и порт')
    match=re.fullmatch(r'\[([^\[\]]+)\]:([0-9]+)|([^:\[\]]+):([0-9]+)',value)
    if not match:raise ValueError('Endpoint: используйте host:port или [IPv6]:port')
    if match.group(1):
        try:host='['+str(ipaddress.IPv6Address(match.group(1)))+']'
        except ValueError:raise ValueError('Endpoint: некорректный IPv6') from None
        if '%' in host:raise ValueError('Endpoint: адрес с зоной интерфейса пока не поддерживается')
        port=match.group(2)
    else:
        host=match.group(3);port=match.group(4)
        try:host=str(ipaddress.IPv4Address(host))
        except ValueError:host=normalized_domain(host)
    return host+':'+str(integer(port,'Порт Endpoint',1,65535))


def addresses(value,*,interface):
    parts=[x.strip() for x in value.split(',')]
    if not 1<=len(parts)<=256 or any(not x or '%' in x for x in parts):
        raise ValueError('Некорректный список адресов WireGuard')
    try:
        parsed=[str(ipaddress.ip_interface(x) if interface else ipaddress.ip_network(x,strict=False)) for x in parts]
    except ValueError:raise ValueError('WireGuard: нужен список IP-адресов с префиксами') from None
    if len(set(parsed))!=len(parsed):raise ValueError('WireGuard: адрес или сеть повторяется')
    return parsed


def parse(raw):
    if not isinstance(raw,str) or len(raw.encode())>MAX_BYTES or '\0' in raw:
        raise ValueError('Профиль WireGuard повреждён или превышает 256 КиБ')
    result={'interface':{},'peers':[]};section=None;target=None
    for number,line in enumerate(raw.splitlines(),1):
        line=line.split('#',1)[0].strip()
        if not line:continue
        if line.startswith('['):
            if line=='[Interface]' and section is None:
                section='interface';target=result['interface']
            elif line=='[Peer]' and section is not None:
                section='peer';target={};result['peers'].append(target)
                if len(result['peers'])>64:raise ValueError('Поддерживается до 64 пиров в одном профиле')
            else:raise ValueError('Строка '+str(number)+': неверный порядок секций WireGuard')
            continue
        if target is None or '=' not in line:raise ValueError('Строка '+str(number)+': ожидается поле WireGuard')
        name,value=(x.strip() for x in line.split('=',1))
        supported=INTERFACE_FIELDS if section=='interface' else PEER_FIELDS
        if name not in supported:raise ValueError('Строка '+str(number)+': поле не поддерживается редактором; исходник не изменён')
        # Address is explicitly repeatable in wg-quick, unlike scalar fields.
        if name in target and name!='Address':raise ValueError('Строка '+str(number)+': скалярное поле повторяется')
        if name in ('PrivateKey','PublicKey','PresharedKey'):parsed=key(value,name)
        elif name in ('Address','AllowedIPs'):
            parsed=addresses(value,interface=name=='Address')
            if name in target:
                parsed=target[name]+parsed
                if len(set(parsed))!=len(parsed):raise ValueError('Адрес интерфейса повторяется')
        elif name=='Endpoint':parsed=endpoint(value)
        elif name=='Table':
            parsed=value if value in ('auto','off') else str(integer(value,'Таблица маршрутизации',1,4294967295))
        elif name=='MTU':parsed=integer(value,'MTU',576,65535)
        elif name=='ListenPort':parsed=integer(value,'Порт прослушивания',0,65535)
        else:parsed=integer(value,'Keepalive',0,65535)
        target[name]=parsed
    interface=result['interface']
    if 'PrivateKey' not in interface or not interface.get('Address'):
        raise ValueError('Для управляемого профиля нужны PrivateKey и Address интерфейса')
    if len(interface['Address'])>32:raise ValueError('Поддерживается до 32 адресов интерфейса')
    if interface.get('MTU',1280)<1280 and any(ipaddress.ip_interface(a).version==6 for a in interface['Address']):
        raise ValueError('IPv6 требует MTU не меньше 1280')
    seen=set()
    for peer in result['peers']:
        if 'PublicKey' not in peer or not peer.get('AllowedIPs'):
            raise ValueError('Для каждого пира нужны PublicKey и AllowedIPs')
        if peer['PublicKey'] in seen:raise ValueError('Открытый ключ пира повторяется')
        if peer['PublicKey']==interface['PrivateKey']:
            raise ValueError('Закрытый ключ интерфейса нельзя использовать как открытый ключ пира')
        seen.add(peer['PublicKey'])
    return result


def render(model):
    if not isinstance(model,dict) or set(model)!={'interface','peers'} or not isinstance(model['interface'],dict) or not isinstance(model['peers'],list) or any(not isinstance(p,dict) for p in model['peers']):
        raise ValueError('Некорректная структура профиля WireGuard')
    lines=[]
    for kind,item in [('Interface',model['interface']),*[('Peer',p) for p in model['peers']]]:
        if lines:lines.append('')
        lines.append('['+kind+']')
        order=('PrivateKey','Address','ListenPort','MTU','Table') if kind=='Interface' else ('PublicKey','PresharedKey','AllowedIPs','Endpoint','PersistentKeepalive')
        if set(item)-set(order):raise ValueError('Модель WireGuard содержит неподдерживаемые поля')
        for name in order:
            if name not in item:continue
            value=item[name]
            if name in ('Address','AllowedIPs'):
                if not isinstance(value,list) or any(not isinstance(x,str) for x in value):raise ValueError('Некорректный список адресов')
                value=', '.join(value)
            elif type(value) not in (str,int):raise ValueError('Некорректный тип поля WireGuard')
            if any(c in str(value) for c in '\r\n\0#'):raise ValueError('Недопустимый символ поля WireGuard')
            lines.append(name+' = '+str(value))
    raw='\n'.join(lines)+'\n'
    # The same boundary validates imports and generated profiles.
    parse(raw)
    return raw


def public_view(model):
    view=copy.deepcopy(model)
    interface=view['interface']
    interface['private_key_present']=bool(interface.pop('PrivateKey',None))
    for peer in view['peers']:
        peer['preshared_key_present']=bool(peer.pop('PresharedKey',None))
    return view


def update(previous,values):
    """Replace editable fields, preserving only explicitly unchanged secrets.

    A peer's public key is its identity. A new public key does not inherit an
    old peer's PSK. Missing peers are removed from the proposed profile, which
    still requires a separate guarded application to a running interface.
    """
    if not isinstance(values,dict) or set(values)!={'interface','peers'} or not isinstance(values['interface'],dict) or not isinstance(values['peers'],list):
        raise ValueError('Нужны поля интерфейса и список пиров')
    result=copy.deepcopy(values)
    interface=result['interface']
    if set(interface)-(INTERFACE_FIELDS|{'private_key_present'}):
        raise ValueError('Неизвестное поле интерфейса')
    interface.pop('private_key_present',None)
    private=interface.get('PrivateKey','')
    if not isinstance(private,str):raise ValueError('Закрытый ключ должен быть текстовым полем')
    if private=='':interface['PrivateKey']=previous['interface']['PrivateKey']
    old_peers={p['PublicKey']:p for p in previous['peers']}
    for peer in result['peers']:
        if not isinstance(peer,dict) or set(peer)-(PEER_FIELDS|{'preshared_key_present','clear_preshared_key'}):
            raise ValueError('Неизвестное поле пира')
        peer.pop('preshared_key_present',None)
        clear=peer.pop('clear_preshared_key',False)
        if type(clear) is not bool:raise ValueError('Очистка PSK задаётся переключателем')
        supplied=peer.get('PresharedKey','')
        if not isinstance(supplied,str) or not isinstance(peer.get('PublicKey',''),str):
            raise ValueError('Ключ пира должен быть текстовым полем')
        if supplied and clear:raise ValueError('Нельзя одновременно заменить и удалить PSK')
        if not supplied:
            peer.pop('PresharedKey',None)
            old=old_peers.get(peer.get('PublicKey'),{})
            if not clear and 'PresharedKey' in old:peer['PresharedKey']=old['PresharedKey']
    return parse(render(result))
