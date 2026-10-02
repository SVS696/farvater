"""AmneziaWG .conf codec, retaining DNS and official 3.1 obfuscation fields.

WireGuard fields reuse their existing validator. DNS is profile metadata: an
adapter must attach it to the panel's DNS policy, never rewrite the host resolver.
Native awg validation is still required before activation (especially I1–I5).
"""
import base64
import copy
import ipaddress
import re
import wireguard_profile as wg

NUMBERS=('Jc','Jmin','Jmax','S1','S2','S3','S4')
RANGES=('H1','H2','H3','H4','ContentPaddingAddition','RekeyAfterTime','RekeyTimeout','RejectAfterTime','KeepaliveTimeout','MaxHandshakeAttempts')
CHAINS=('I1','I2','I3','I4','I5')
FLAGS=('RandomTrailers','DisableCookies')
FIELDS=(*NUMBERS,*RANGES,*CHAINS,*FLAGS,'HeaderProtectionKey','DNS')
PEER_EXTRA=('AdvancedSecurity','PersistentKeepalive')
MAX_BYTES=wg.MAX_BYTES


def scalar(value):
    if not isinstance(value,(str,int)) or isinstance(value,bool):raise ValueError('Параметр AWG должен быть строкой или числом')
    value=str(value).strip()
    if not value or len(value)>8192 or any(c in value for c in '\r\n\0#'):
        raise ValueError('Пустой или некорректный параметр AmneziaWG')
    return value


def interval(value,field,maximum):
    parts=value.split('-')
    if len(parts)>2:raise ValueError(field+': нужно число или диапазон минимум-максимум')
    numbers=[wg.integer(p,field,0,maximum) for p in parts]
    if numbers[0]>numbers[-1]:raise ValueError(field+': начало диапазона больше конца')
    return '-'.join(map(str,numbers))


def validate_extra(field,value):
    value=scalar(value)
    if field in NUMBERS:return wg.integer(value,field,0,65535)
    if field in RANGES:return interval(value,field,4294967295 if field.startswith('H') else 65535)
    if field=='HeaderProtectionKey':
        try:
            raw=base64.b64decode(value,validate=True)
            if len(raw)!=32 or base64.b64encode(raw).decode()!=value:raise ValueError()
        except ValueError:raise ValueError('HeaderProtectionKey: нужны 32 байта в Base64') from None
        return value
    if field=='DNS':
        try:
            result=[str(ipaddress.ip_address(x.strip())) for x in value.split(',')]
            if not 1<=len(result)<=16 or len(set(result))!=len(result) or any('%' in x for x in result):raise ValueError()
        except ValueError:raise ValueError('DNS профиля: до 16 неповторяющихся IP-адресов через запятую') from None
        return result
    if field=='PersistentKeepalive':return interval(value,field,65535)
    if field in (*FLAGS,'AdvancedSecurity'):
        if value.lower() not in ('on','off','0','1'):raise ValueError(field+': нужно on/off или 0/1')
        return 'on' if value.lower() in ('on','1') else 'off'
    if field in CHAINS:return value  # Official userspace parser checks the chain grammar.
    raise ValueError('Неизвестное поле AmneziaWG')


def parse(raw):
    if not isinstance(raw,str) or len(raw.encode())>MAX_BYTES or '\0' in raw:raise ValueError('Профиль AWG повреждён или превышает 256 КиБ')
    raw=raw.removeprefix('\ufeff');lines=[];extra={};peer_extra=[];section=None
    for line in raw.splitlines():
        clean=line.split('#',1)[0].strip()
        if clean.startswith('['):
            section=clean
            if section=='[Peer]':peer_extra.append({})
        if '=' in clean:
            name,value=(v.strip() for v in clean.split('=',1))
            if name in PEER_EXTRA:
                if section!='[Peer]' or not peer_extra:raise ValueError('Параметр пира должен находиться в секции Peer')
                if name in peer_extra[-1]:raise ValueError('Параметр пира повторяется')
                peer_extra[-1][name]=validate_extra(name,value);continue
            if name in FIELDS:
                if section!='[Interface]':raise ValueError('Параметры маскировки и DNS задаются в секции Interface')
                if name in extra:raise ValueError('Параметр '+name+' повторяется')
                extra[name]=validate_extra(name,value);continue
        lines.append(line)
    result=wg.parse('\n'.join(lines))
    if 'Jmin' in extra and 'Jmax' in extra and extra['Jmin']>extra['Jmax']:raise ValueError('Jmin не может быть больше Jmax')
    if extra.get('HeaderProtectionKey') and any(base64.b64decode(extra['HeaderProtectionKey'])):
        if any(extra.get(k,0)<12 for k in ('S1','S2','S3','S4')):raise ValueError('Защита заголовков AWG 3.1 требует S1–S4 не меньше 12 байт')
    result['interface'].update(extra)
    for peer,extra_fields in zip(result['peers'],peer_extra):peer.update(extra_fields)
    return result


def render(model,*,runtime=False):
    value=copy.deepcopy(model)
    if not isinstance(value,dict) or not isinstance(value.get('interface'),dict):raise ValueError('Нужны параметры интерфейса AWG')
    extra={k:value['interface'].pop(k) for k in FIELDS if k in value['interface']}
    peer_extra=[{k:peer.pop(k) for k in PEER_EXTRA if k in peer} for peer in value.get('peers',[])]
    raw=wg.render(value)
    lines=[]
    for k,v in extra.items():
        if k=='DNS':
            if not isinstance(v,list) or any(not isinstance(x,str) for x in v):raise ValueError('DNS должен быть списком IP-адресов')
            v=', '.join(v)
        v=validate_extra(k,v)
        lines.append(k+' = '+(', '.join(v) if isinstance(v,list) else str(v)))
    result=raw.replace('[Interface]\n','[Interface]\n'+'\n'.join(lines)+ ('\n' if lines else ''),1)
    expanded=[];index=0
    for line in result.splitlines():
        expanded.append(line)
        if line=='[Peer]':
            for key,val in peer_extra[index].items():expanded.append(key+' = '+str(validate_extra(key,val)))
            index+=1
    result='\n'.join(expanded)+'\n'
    parse(result)
    if runtime:
        if any('AdvancedSecurity' in peer for peer in model['peers']):raise ValueError('AdvancedSecurity поддерживается только модулем ядра AWG; отдельный userspace-клиент этот параметр не принимает')
        # No DNS or shell hooks are handed to awg-quick. DNS belongs to policy.
        result='\n'.join(line for line in result.splitlines() if line.split('=',1)[0].strip()!='DNS')+'\n'
    return result


def public_view(model):
    value=wg.public_view(model)
    value['interface']['header_protection_key_present']=bool(value['interface'].pop('HeaderProtectionKey',None))
    return value


def update(previous,values):
    old=copy.deepcopy(previous);new=copy.deepcopy(values)
    if not isinstance(new,dict) or not isinstance(new.get('interface'),dict):raise ValueError('Нужны параметры интерфейса AWG')
    old_extra={k:old['interface'].pop(k) for k in FIELDS if k in old['interface']}
    new_extra={k:new['interface'].pop(k) for k in FIELDS if k in new['interface']}
    flags=new['interface'];flags.pop('header_protection_key_present',None)
    clear=flags.pop('clear_header_protection_key',False)
    if type(clear) is not bool:raise ValueError('Очистка ключа задаётся переключателем')
    supplied=new_extra.get('HeaderProtectionKey')
    if supplied and clear:raise ValueError('Нельзя одновременно заменить и очистить ключ защиты заголовка')
    if not supplied:
        new_extra.pop('HeaderProtectionKey',None)
        if not clear and 'HeaderProtectionKey' in old_extra:new_extra['HeaderProtectionKey']=old_extra['HeaderProtectionKey']
    peer_extra=[]
    for peer in old['peers']:
        for key in PEER_EXTRA:peer.pop(key,None)
    for peer in new['peers']:peer_extra.append({key:peer.pop(key) for key in PEER_EXTRA if key in peer})
    result=wg.update(old,new);result['interface'].update(new_extra)
    for peer,extra_fields in zip(result['peers'],peer_extra):peer.update(extra_fields)
    return parse(render(result))
