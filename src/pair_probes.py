"""Bounded, target-restricted loopback probes for each configured reserve pair.

Probe traffic uses the same native outbounds and resolvers as the candidate,
without changing its current mode. It is not a general bypass proxy.
"""
import hashlib
import ipaddress
from urllib.parse import urlsplit,urlunsplit

from policy import normalized_domain,domain_matches
from rule_options import normalize_options

BASE_PORT=12000
MAX_PAIRS=8


def probe_queue_labels(policy):
    return {'default':'Общий трафик',**{'rule:'+p['id']:p['name'] for p in policy.get('profiles',[])
        if p.get('enabled',True) and p.get('fallback_pairs')}}


def validate_target_for_queue(policy,queue,value):
    if queue not in probe_queue_labels(policy):raise ValueError('Очередь резервирования больше не существует')
    target=parse_target(value)
    profile=next((p for p in policy.get('profiles',[]) if 'rule:'+p['id']==queue),None)
    if profile is None or profile['kind']=='public':
        names=[target['dns_name'],*(d['domain'] for d in target['destinations'])]
        if any(protected_name(policy,name) for name in names):
            raise ValueError('Публичная проверка не может использовать имя рабочей или специальной сети')
    return target


def parse_target(value):
    if not isinstance(value,dict) or set(value)!={'dns_name','urls','codes'}:
        raise ValueError('Проверке нужны DNS-имя, список URL и ожидаемые HTTP-коды')
    dns_name=normalized_domain(value['dns_name'])
    try:ipaddress.ip_address(dns_name)
    except ValueError:pass
    else:raise ValueError('Для DNS-проверки нужно доменное имя, не IP')
    if not isinstance(value['urls'],list) or not 1<=len(value['urls'])<=3:
        raise ValueError('Укажите от одного до трёх адресов проверки')
    urls=[];destinations=[]
    for url in value['urls']:
        if not isinstance(url,str) or len(url)>2048:raise ValueError('Некорректный URL проверки')
        parsed=urlsplit(url)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError('Проверка допускает HTTP/HTTPS без пароля в URL и без фрагмента')
        domain=normalized_domain(parsed.hostname)
        try:ipaddress.ip_address(domain)
        except ValueError:pass
        else:raise ValueError('URL проверки должен содержать домен, не буквальный IP')
        port=parsed.port or (443 if parsed.scheme=='https' else 80)
        if not 1<=port<=65535:raise ValueError('Некорректный порт проверки')
        normalized=urlunsplit((parsed.scheme,domain+(':'+str(port) if parsed.port else ''),parsed.path or '/',parsed.query,''))
        if normalized in urls:raise ValueError('URL проверки повторяется')
        urls.append(normalized);destinations.append({'domain':domain,'port':port})
    codes=value['codes']
    if not isinstance(codes,list) or not codes or len(codes)>10 or any(type(c) is not int or not 100<=c<=599 for c in codes) or len(set(codes))!=len(codes):
        raise ValueError('Укажите уникальные ожидаемые HTTP-коды от 100 до 599')
    return {'dns_name':dns_name,'urls':urls,'codes':codes,'destinations':destinations}


def protected_name(policy,domain):
    for profile in policy.get('profiles',[]):
        if profile['kind'] not in ('work','special'):continue
        # Conservative for source-scoped protected rules: a public health probe
        # has no client identity with which to justify bypassing that rule.
        if any(domain_matches(pattern,domain) for pattern in profile.get('domains',[])):
            return True
    return False


def compile_pair_probes(policy,queues,servers,*,default_filtering,filtered_resolvers=None):
    settings=policy.get('health_probes',{})
    if not isinstance(settings,dict) or set(settings)-set(queues):
        raise ValueError('Проверка ссылается на отсутствующую очередь резервирования')
    profiles={'rule:'+p['id']:p for p in policy.get('profiles',[])}
    server_types={s['tag']:s['type'] for s in servers}
    inbounds=[];dns_rules=[];route_rules=[];records=[];missing=[]
    for queue,pairs in queues.items():
        if queue not in settings:missing.append(queue);continue
        target=validate_target_for_queue(policy,queue,settings[queue]);profile=profiles.get(queue)
        names=sorted({target['dns_name'],*(d['domain'] for d in target['destinations'])})
        filtering=default_filtering if profile is None else (
            normalize_options(profile)['adguard']=='on' or (normalize_options(profile)['adguard']=='inherit' and default_filtering))
        for pair_index,pair in enumerate(pairs):
            index=len(records)
            if index>=MAX_PAIRS:raise ValueError('Допускается до 8 одновременно проверяемых пар; сократите очередь проверок')
            resolver=(filtered_resolvers or {}).get(pair['dns']) if filtering else pair['dns']
            if resolver not in server_types:raise ValueError('У пары отсутствует проверенный DNS-путь')
            if server_types[resolver]=='fakeip' or server_types.get(pair['dns'])=='fakeip':
                raise ValueError('Независимая проверка FakeIP пока не подтверждена: выдача адреса не доказывает исправность DNS')
            dns_tag='okopy-probe-dns-'+str(index);proxy_tag='okopy-probe-proxy-'+str(index)
            dns_port=BASE_PORT+2*index;proxy_port=dns_port+1
            inbounds.extend([{'type':'direct','tag':dns_tag,'listen':'127.0.0.1','listen_port':dns_port},
                             {'type':'mixed','tag':proxy_tag,'listen':'127.0.0.1','listen_port':proxy_port}])
            dns_rules.extend([{'inbound':[dns_tag,proxy_tag],'domain':names,'action':'route','server':resolver,'disable_cache':True,'disable_optimistic_cache':True,'timeout':'2s'},
                              {'inbound':[dns_tag,proxy_tag],'action':'reject','no_drop':True}])
            route_rules.append({'inbound':[dns_tag],'action':'hijack-dns'})
            # Use the restricted DNS rules above with the inbound metadata.
            route_rules.append({'inbound':[proxy_tag],'action':'resolve'})
            if profile is None or profile['kind']=='public':
                route_rules.append({'inbound':[proxy_tag],'ip_is_private':True,'action':'reject'})
            for destination in target['destinations']:
                route_rules.append({'inbound':[proxy_tag],'network':'tcp','domain':[destination['domain']],
                    'port':[destination['port']],'action':'route','outbound':pair['exit']})
            route_rules.append({'inbound':[proxy_tag],'action':'reject'})
            identity=hashlib.sha256(('\0'.join([queue,pair['exit'],pair['dns']])).encode()).hexdigest()[:20]
            records.append({'id':'pair-'+identity,'queue':queue,'index':pair_index,'exit':pair['exit'],'dns':pair['dns'],
                'effective_dns':resolver,'dns_type':server_types[resolver],'dns_port':dns_port,'proxy_port':proxy_port,
                'dns_name':target['dns_name'],'urls':target['urls'],'codes':target['codes']})
    return {'inbounds':inbounds,'dns_rules':dns_rules,'route_rules':route_rules,'records':records,'missing':missing}


def validate_probe_inbounds(inbounds):
    if len(inbounds)%2 or len(inbounds)>MAX_PAIRS*2:raise ValueError('Invalid probe listener count')
    expected=[]
    for index in range(len(inbounds)//2):
        expected.extend([{'type':'direct','tag':'okopy-probe-dns-'+str(index),'listen':'127.0.0.1','listen_port':BASE_PORT+2*index},
                         {'type':'mixed','tag':'okopy-probe-proxy-'+str(index),'listen':'127.0.0.1','listen_port':BASE_PORT+2*index+1}])
    if inbounds!=expected:raise ValueError('Probe listeners must use their exact reserved loopback ports')
