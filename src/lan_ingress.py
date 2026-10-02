"""Opt-in native LAN listeners; source identity stays in the policy engine.

This adapter does not redirect client traffic. Router interception is a separate
deployment step. Fixed ports keep it away from the existing production DNS.
"""
import ipaddress
import re

PREFIX = 'okopy-lan-'
DNS_PORT = 15454
PROXY_PORT = 15458
TPROXY_PORT = 15456
CAPTURE_MARK = 0x4f4b0001
REPLY_MARK = 0x4f4b0002
PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def settings(policy):
    value = policy.get('lan_ingress', {'enabled': False})
    optional = {'return_via_gateway','transparent_targets','gateway_probe_domains'}
    fields = {'enabled','listen','interface','gateway','clients'} | optional
    if not isinstance(value, dict) or set(value)-fields or type(value.get('enabled')) is not bool:
        raise ValueError('Некорректные настройки LAN-входа')
    if value == {'enabled': False}:
        return dict(value)
    if set(value)-optional != fields-optional:
        raise ValueError('Для LAN-входа нужны адрес сервера, интерфейс, шлюз и устройства')
    result = dict(value)
    result['return_via_gateway'] = value.get('return_via_gateway', False)
    if type(result['return_via_gateway']) is not bool:
        raise ValueError('Некорректный выбор обратного пути')
    for key in ('listen','gateway'):
        try: address = ipaddress.IPv4Address(value[key])
        except (ValueError, TypeError): raise ValueError('LAN-вход требует IPv4-адреса') from None
        if not any(address in network for network in PRIVATE):
            raise ValueError('LAN-вход допускает только частные IPv4-адреса')
        result[key] = str(address)
    if result['listen'] == result['gateway']:
        raise ValueError('Адрес сервера и шлюза должны отличаться')
    if not isinstance(value['interface'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', value['interface']):
        raise ValueError('Некорректное имя сетевого интерфейса')
    if not isinstance(value['clients'], list) or not 1 <= len(value['clients']) <= 16:
        raise ValueError('Укажите от 1 до 16 адресов устройств')
    clients = []
    for item in value['clients']:
        try: network = ipaddress.ip_network(item, strict=True)
        except (ValueError, TypeError): raise ValueError('Некорректный адрес устройства') from None
        if network.version != 4 or network.prefixlen != 32 or not any(network.subnet_of(n) for n in PRIVATE):
            raise ValueError('На этапе подключения LAN укажите отдельные частные IPv4-адреса /32')
        if str(network.network_address) in (result['listen'], result['gateway']):
            raise ValueError('Укажите адрес устройства; сервер и шлюз не сохраняют его исходный IP')
        clients.append(str(network))
    result['clients'] = sorted(set(clients))
    targets = value.get('transparent_targets', [])
    if not isinstance(targets, list) or len(targets) > 64:
        raise ValueError('Укажите до 64 IPv4-сетей прозрачного перехвата')
    networks = []
    for target in targets:
        try: network = ipaddress.ip_network(target, strict=True)
        except (ValueError, TypeError): raise ValueError('Некорректная сеть прозрачного перехвата') from None
        if network.version != 4: raise ValueError('Прозрачный LAN-вход пока поддерживает IPv4')
        networks.append(network)
    result['transparent_targets'] = [str(n) for n in ipaddress.collapse_addresses(networks)]
    domains=value.get('gateway_probe_domains',[])
    if not isinstance(domains,list) or len(domains)>8:raise ValueError('Укажите до восьми имён для контрольных запросов роутера')
    normalized=[]
    for domain in domains:
        if (not isinstance(domain,str) or len(domain)>253 or '.' not in domain
                or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',domain)
                or any(not part or len(part)>63 or part.startswith('-') or part.endswith('-') for part in domain.split('.'))):
            raise ValueError('Для контроля роутером нужны точные имена латиницей, без масок')
        try:ipaddress.ip_address(domain)
        except ValueError:pass
        else:raise ValueError('Укажите имя проверочного узла, не его IP')
        normalized.append(domain.lower())
    result['gateway_probe_domains']=sorted(set(normalized))
    return result


def admitted_sources(value):
    return [*value['clients'], *([value['gateway']+'/32'] if value.get('gateway_probe_domains') else [])]


def gateway_guards(value):
    domains=value.get('gateway_probe_domains',[])
    if not domains:return [],[]
    source={'source_ip_cidr':[value['gateway']+'/32']}
    route=[{'type':'logical','mode':'and','rules':[
        {'inbound':[PREFIX+'proxy']},source,
        {'type':'logical','mode':'or','rules':[{'domain':domains,'invert':True},
            {'port':[443],'invert':True},{'network':'udp'}]}], 'action':'reject'}]
    if value.get('transparent_targets'):
        route.insert(0,{'type':'logical','mode':'and','rules':[{'inbound':[PREFIX+'transparent']},source],'action':'reject'})
    dns=[{'type':'logical','mode':'and','rules':[source,{'domain':domains,'invert':True}],
          'action':'predefined','rcode':'REFUSED'}]
    return route,dns


def inbounds(value):
    if not value['enabled']: return []
    result = [{'type':kind,'tag':PREFIX+tag,'listen':value['listen'],'listen_port':port}
            for kind,tag,port in [('direct','dns',DNS_PORT),('mixed','proxy',PROXY_PORT)]]
    if value.get('transparent_targets'):
        result.append({'type':'tproxy','tag':PREFIX+'transparent','listen':value['listen'],
                       'listen_port':TPROXY_PORT,'routing_mark':REPLY_MARK})
    return result


def attach(config, value):
    if not value['enabled']: return
    occupied = {i['listen_port'] for i in config['inbounds']}
    occupied.add(int(config['experimental']['clash_api']['external_controller'].rsplit(':',1)[1]))
    listeners = inbounds(value)
    if occupied & {i['listen_port'] for i in listeners}: raise ValueError('Порты LAN-входа заняты другим адаптером')
    config['inbounds'].extend(listeners)
    gateway_routes,gateway_dns=gateway_guards(value)
    config['dns']['rules']=gateway_dns+config['dns']['rules']
    # First, before probe bypasses, DNS hijacking and FakeIP re-entry rules.
    config['route']['rules'] = [
        {'type':'logical','mode':'and','rules':[
            {'inbound':[i['tag'] for i in listeners]},
            {'source_ip_cidr':admitted_sources(value),'invert':True}], 'action':'reject'},
        *gateway_routes,
        {'inbound':[PREFIX+'dns'],'action':'hijack-dns'},
        *([{'inbound':[PREFIX+'transparent'],'port':[53],'action':'hijack-dns'},
           {'inbound':[PREFIX+'transparent'],'action':'sniff','timeout':'300ms'}]
          if value.get('transparent_targets') else []),
        *config['route']['rules']]


def validate_config(config, value):
    native = config.get('inbounds', [])
    lan = [i for i in native if i.get('tag','').startswith(PREFIX)]
    if lan != inbounds(value) or (lan and native[-len(lan):] != lan):
        raise ValueError('LAN listeners differ from the declared policy')
    if lan:
        expected = {'inbounds': [], 'dns':{'rules':[]}, 'experimental':{'clash_api':{'external_controller':'127.0.0.1:9091'}}, 'route':{'rules':[]}}
        attach(expected, value)
        if config.get('route',{}).get('rules',[])[:len(expected['route']['rules'])] != expected['route']['rules']:
            raise ValueError('LAN source guard must precede every bypass')

        dns_prefix=expected['dns']['rules']
        if config.get('dns',{}).get('rules',[])[:len(dns_prefix)]!=dns_prefix:
            raise ValueError('Gateway DNS guard must precede every bypass')
