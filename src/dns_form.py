"""Translate the DNS form to sing-box fields, preserving unedited options."""
import copy
import ipaddress
import re
from policy import normalized_domain, hosts_entries

DNS_TYPES={'dhcp':'Автоматически по DHCP','udp':'Обычный DNS (UDP)','tcp':'DNS по TCP','https':'DNS over HTTPS',
           'tls':'DNS over TLS','quic':'DNS over QUIC','fakeip':'FakeIP','local':'Системный DNS','hosts':'Локальные DNS-записи','openvpn':'DNS, выданный сервером OpenVPN'}


def hosts_text(native):
    return ''.join(f'{address} {name}\n' for name, addresses in hosts_entries(native).items() for address in addresses)


def parse_hosts(text):
    if len(text)>131072:raise ValueError('Список DNS-записей слишком большой (максимум 128 КиБ)')
    records={}
    for number,line in enumerate(text.splitlines(),1):
        parts=line.split('#',1)[0].split()
        if not parts:continue
        if len(parts)<2:raise ValueError(f'Строка {number}: укажите IP-адрес и имя через пробел')
        try:
            if '%' in parts[0]:raise ValueError()
            address=str(ipaddress.ip_address(parts[0]))
            for raw in parts[1:]:
                name=normalized_domain(raw);values=records.setdefault(name,[])
                if address not in values:values.append(address)
        except ValueError:raise ValueError(f'Строка {number}: проверьте IP-адрес и полное DNS-имя') from None
    native={'type':'hosts','path':['/dev/null'],'predefined':records}
    native['predefined']=hosts_entries(native)
    return native


def parse_dns(form, previous, identifier, policy):
    kind=form.get('type','');scope=form.get('scope','');name=form.get('name','').strip()
    if kind not in DNS_TYPES:raise ValueError('Неизвестный тип DNS')
    if scope not in ('public','work','special'):raise ValueError('Неизвестное назначение DNS')
    if not name or len(name)>120:raise ValueError('Название должно содержать от 1 до 120 символов')
    old=previous.get('native',{})
    native=copy.deepcopy(old) if old.get('type')==kind else {}
    native.update(type=kind,tag=identifier)
    bootstrap=form.get('bootstrap','')
    if bootstrap and bootstrap not in policy['dns']:raise ValueError('Неизвестный DNS для начального разрешения')
    detour=form.get('detour','')
    if detour and detour not in policy['exits']:raise ValueError('Неизвестный выход DNS')
    address='Системный DNS' if kind=='local' else 'FakeIP'
    if kind=='dhcp':
        interface=form.get('dhcp_interface','').strip()
        if interface and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}',interface):
            raise ValueError('Выберите сетевое подключение сервера для DHCP')
        native={'type':'dhcp','tag':identifier}
        if interface:native['interface']=interface
        address='DHCP · '+(interface or 'основное подключение');bootstrap=''
    elif kind=='hosts':
        native={**parse_hosts(form.get('hosts','')),'tag':identifier}
        address=f"Локальные имена: {len(native['predefined'])}";bootstrap=''
    elif kind=='openvpn':
        endpoint=form.get('endpoint','')
        if policy['exits'].get(endpoint,{}).get('native',{}).get('type')!='openvpn-client':raise ValueError('Выберите подключение OpenVPN для DNS')
        native={'type':kind,'tag':identifier,'endpoint':endpoint,
                'accept_default_resolvers':form.get('accept_default_resolvers')=='on',
                'accept_search_domain':form.get('accept_search_domain')=='on'}
        address=policy['exits'][endpoint].get('name',endpoint);bootstrap=''
    elif kind=='fakeip':
        for field,version in [('inet4_range',4),('inet6_range',6)]:
            raw=form.get(field,'').strip()
            if raw:
                network=ipaddress.ip_network(raw,strict=True)
                if network.version!=version:raise ValueError('Неверная версия IP в диапазоне FakeIP')
                native[field]=str(network)
            else:native.pop(field,None)
        if not any(native.get(f) for f in ('inet4_range','inet6_range')):raise ValueError('Нужен хотя бы один диапазон FakeIP')
    elif kind!='local':
        server=form.get('server','').strip()
        try:server=str(ipaddress.ip_address(server))
        except ValueError:
            server=normalized_domain(server)
            if not bootstrap:raise ValueError('Для имени DNS-сервера выберите начальный DNS (bootstrap)')
        native['server']=server;address=server
        try:port=int(form.get('server_port') or {'https':443,'tls':853,'quic':853}.get(kind,53))
        except ValueError:raise ValueError('Порт DNS должен быть целым числом')
        if not 1<=port<=65535:raise ValueError('Порт DNS должен быть от 1 до 65535')
        native['server_port']=port
        if detour:
            outbound=policy['exits'][detour].get('native',{})
            # sing-box rejects detouring through an empty direct outbound.
            if outbound.get('type')=='direct' and set(outbound)<= {'type','tag'}:
                raise ValueError('Для обычного прямого DNS оставьте выход «Напрямую»; пустой direct нельзя использовать как detour')
            native['detour']=detour
        else:native.pop('detour',None)
        if bootstrap:
            resolver=native.get('domain_resolver')
            native['domain_resolver']={**resolver,'server':bootstrap} if isinstance(resolver,dict) else bootstrap
        else:native.pop('domain_resolver',None)
        if kind in ('https','tls','quic'):
            tls=native.setdefault('tls',{})
            sni=form.get('server_name','').strip()
            if sni:tls['server_name']=normalized_domain(sni)
            else:tls.pop('server_name',None)
        if kind=='https':
            path=form.get('path','').strip() or '/dns-query'
            if not path.startswith('/') or any(c in path for c in '\r\n'):raise ValueError('Путь DoH должен начинаться с /')
            native['path']=path
    if kind in ('local','fakeip'):bootstrap=''
    result={**previous,'name':name,'scope':scope,'address':address,'native':native}
    if bootstrap:result['bootstrap']=bootstrap
    else:result.pop('bootstrap',None)
    return result
