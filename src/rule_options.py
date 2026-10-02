"""General rule options. No service or device names have special meaning."""
import ipaddress
import re

FAMILIES={'auto':'IPv4 и IPv6','ipv4_only':'Только IPv4','ipv6_only':'Только IPv6'}
FILTERING={'inherit':'По общей настройке','on':'Фильтровать через AdGuard','off':'Не фильтровать это правило'}
DNS_RESPONSES={'forward':'Обычное разрешение','nodata':'Пустой успешный ответ (NODATA)',
               'refused':'Отказ (REFUSED)','nxdomain':'Имя не существует (NXDOMAIN)'}
QUERY_TYPES={'A':1,'AAAA':28,'CNAME':5,'TXT':16,'MX':15,'SRV':33,'PTR':12,'HTTPS':65,'SVCB':64}
NETWORKS={'any':'TCP и UDP','tcp':'TCP','udp':'UDP'}


def port_list(value,label):
    if not isinstance(value,list) or len(value)>64 or any(type(p) is not int or not 1<=p<=65535 for p in value):
        raise ValueError(label+': не более 64 целых чисел от 1 до 65535')
    return list(dict.fromkeys(value))


def form_ports(value,label):
    tokens=re.split(r'[\s,]+',value.strip())
    if any(t and (not t.isascii() or not t.isdecimal() or len(t)>5) for t in tokens):
        raise ValueError(label+': укажите номера через запятую или пробел, например 443, 8443')
    return port_list([int(t) for t in tokens if t],label)


def normalize_options(profile):
    """Validate typed options without altering the caller's document."""
    family=profile.get('ip_family','auto');filtering=profile.get('adguard','inherit')
    if not isinstance(family,str) or family not in FAMILIES:raise ValueError('Неизвестный режим IPv4/IPv6')
    if not isinstance(filtering,str) or filtering not in FILTERING:raise ValueError('Неизвестный режим AdGuard')
    ports=port_list(profile.get('udp_blocked_ports',[]),'Порты UDP')
    route_network=profile.get('route_network','any')
    if not isinstance(route_network,str) or route_network not in NETWORKS:raise ValueError('Неизвестный протокол соединения')
    route_ports=port_list(profile.get('route_ports',[]),'Порты назначения')
    if route_network!='any' or route_ports:
        if profile.get('dns_only'):raise ValueError('У правила только для DNS нет выхода, который можно ограничить протоколом или портом')
        if profile.get('kind') in ('work','special'):
            raise ValueError('Защищённое правило должно охватывать все протоколы и порты, чтобы не отправить остальные соединения в общий маршрут')
    raw_sources=profile.get('source_networks',[])
    if not isinstance(raw_sources,list) or any(not isinstance(v,str) for v in raw_sources):
        raise ValueError('Область устройств должна быть списком IP-адресов или подсетей')
    sources=[]
    for value in raw_sources:
        network=ipaddress.ip_network(value,strict=False)
        if network.prefixlen==0:raise ValueError('Для всех устройств оставьте область пустой; /0 не нужен')
        canonical=str(network)
        if canonical not in sources:sources.append(canonical)
    override=profile.get('dns_response',{})
    if not isinstance(override,dict):raise ValueError('Настройка ответа DNS должна быть объектом')
    mode=override.get('mode','forward');types=override.get('query_types',[])
    if not isinstance(mode,str) or mode not in DNS_RESPONSES:raise ValueError('Неизвестное действие DNS')
    if not isinstance(types,list) or any(not isinstance(t,str) or t not in QUERY_TYPES for t in types):raise ValueError('Неизвестный тип DNS-запроса')
    types=list(dict.fromkeys(types))
    if mode!='forward' and not types:raise ValueError('Выберите типы запросов для особого DNS-ответа')
    if mode=='forward' and types:raise ValueError('Выберите особый DNS-ответ или очистите типы запросов')
    return {'source_networks':sources,'ip_family':family,'adguard':filtering,'udp_blocked_ports':ports,
            'route_network':route_network,'route_ports':route_ports,
            'dns_response':{'mode':mode,'query_types':types}}


def parse_options(form):
    return normalize_options({'source_networks':[s.strip() for s in form.get('source_networks','').splitlines() if s.strip()],
        'kind':form.get('kind'),'dns_only':form.get('dns_only')=='on',
        'route_network':form.get('route_network','any'),
        'route_ports':form_ports(form.get('route_ports',''),'Порты назначения'),
        'udp_blocked_ports':form_ports(form.get('udp_blocked_ports',''),'Порты UDP'),
        'ip_family':form.get('ip_family','auto'),'adguard':form.get('adguard','inherit'),
        'dns_response':{'mode':form.get('dns_response_mode','forward'),'query_types':form.getlist('dns_query_types')}})


def source_matches(profile,source):
    nets=profile.get('source_networks',[])
    if not nets:return True
    if not source:raise ValueError('Для расчёта правила с областью устройств укажите IP устройства')
    address=ipaddress.ip_address(source)
    return any(address in ipaddress.ip_network(n,strict=False) for n in nets)


def source_scopes_overlap(left,right):
    a=left.get('source_networks',[]);b=right.get('source_networks',[])
    if not a or not b:return True
    return any(x.version==y.version and x.overlaps(y)
               for x in (ipaddress.ip_network(n,strict=False) for n in a)
               for y in (ipaddress.ip_network(n,strict=False) for n in b))
