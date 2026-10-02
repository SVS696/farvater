"""Routed WireGuard clients use the existing policy and native return route."""
import ipaddress
import re

PREFIX = 'okopy-vpn-'
PORT = 25456
MARK = 0x4f4b1000  # Intentionally does not match legacy INPUT mark 1/1.
TABLE = 'okopy_vpn'
ROUTE_TABLE = '25455'
PREF = '950'
PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def settings(policy):
    value = policy.get('vpn_ingress', {'enabled':False})
    if not isinstance(value,dict) or type(value.get('enabled')) is not bool:
        raise ValueError('Некорректные настройки VPN-входа')
    if value == {'enabled':False}: return dict(value)
    if set(value) - {'clients_v6','bypass_v6','dns_before_bypass'} != {'enabled','interface','clients','bypass'}:
        raise ValueError('Укажите интерфейс VPN, источники и сети обхода')
    if 'dns_before_bypass' in value and type(value['dns_before_bypass']) is not bool:
        raise ValueError('Перехват локального DNS должен быть включён или выключен')
    if not isinstance(value['interface'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',value['interface']):
        raise ValueError('Некорректное имя интерфейса VPN')
    if not isinstance(value['clients'],list) or not 1 <= len(value['clients']) <= 16:
        raise ValueError('Укажите от 1 до 16 частных IPv4-адресов или сетей WireGuard')
    clients=[]
    for item in value['clients']:
        try: network=ipaddress.ip_network(item,strict=True)
        except (ValueError,TypeError): raise ValueError('Некорректный источник VPN') from None
        if network.version != 4 or not any(network.subnet_of(n) for n in PRIVATE):
            raise ValueError('VPN-вход требует частные IPv4-адреса /32 или сеть интерфейса WireGuard')
        clients.append(str(network))
    if not isinstance(value['bypass'],list) or len(value['bypass']) > 32:
        raise ValueError('Укажите до 32 сетей обхода VPN-входа')
    bypass=[]
    for item in value['bypass']:
        try: network=ipaddress.ip_network(item,strict=True)
        except (ValueError,TypeError): raise ValueError('Некорректная сеть обхода VPN-входа') from None
        if network.version != 4 or network.prefixlen == 0:
            raise ValueError('Обход требует конкретные IPv4-сети, без маршрута по умолчанию')
        bypass.append(network)
    result = {'enabled':value['enabled'],'interface':value['interface'],
            'clients':sorted(set(clients)),
            'bypass':[str(n) for n in ipaddress.collapse_addresses(bypass)]}
    if 'dns_before_bypass' in value:result['dns_before_bypass']=value['dns_before_bypass']
    if 'clients_v6' in value or 'bypass_v6' in value:
        if not {'clients_v6','bypass_v6'}.issubset(value):
            raise ValueError('Для IPv6 укажите источники и сети обхода')
        for key,limit in [('clients_v6',16),('bypass_v6',32)]:
            items=value[key]
            if not isinstance(items,list) or len(items)>limit:
                raise ValueError('Слишком много IPv6-сетей или неверный формат списка')
            networks=[]
            for item in items:
                if not isinstance(item,str) or '%' in item:
                    raise ValueError('IPv6-сеть задаётся без идентификатора интерфейса')
                try: network=ipaddress.ip_network(item,strict=True)
                except (ValueError,TypeError): raise ValueError('Некорректная IPv6-сеть') from None
                if network.version!=6 or network.prefixlen==0:
                    raise ValueError('Укажите конкретную IPv6-сеть, без маршрута по умолчанию')
                if key=='clients_v6' and (network.prefixlen<64 or not any(
                        network.subnet_of(ipaddress.ip_network(scope)) for scope in ('2000::/3','fc00::/7'))):
                    raise ValueError('IPv6-источник: глобальная или ULA-сеть /64–/128')
                networks.append(network)
            # Do not merge adjacent /64 clients into a broader, unvalidated /63.
            result[key]=sorted(set(str(n) for n in networks))
        if not result['clients_v6'] and result['bypass_v6']:
            raise ValueError('IPv6-обход задан без источников')
    return result


def configured(value): return 'interface' in value


def inbounds(value):
    if not value['enabled']:return []
    result=[{'type':'tproxy','tag':PREFIX+'transparent','listen':'127.0.0.1','listen_port':PORT}]
    if value.get('clients_v6'):
        result.append({'type':'tproxy','tag':PREFIX+'transparent6','listen':'::1','listen_port':PORT})
    return result


def route_prefix(value):
    if not value['enabled']: return []
    result=[]
    for tag,clients in [(PREFIX+'transparent',value['clients']),
                        (PREFIX+'transparent6',value.get('clients_v6',[]))]:
        if not clients:continue
        result.extend([{'type':'logical','mode':'and','rules':[
                {'inbound':[tag]},{'source_ip_cidr':clients,'invert':True}], 'action':'reject'},
            {'inbound':[tag],'port':[53],'action':'hijack-dns'},
            {'inbound':[tag],'action':'sniff','timeout':'300ms'}])
    return result


def attach(config,value):
    if not value['enabled']:return
    occupied={i['listen_port'] for i in config['inbounds']}
    occupied.add(int(config['experimental']['clash_api']['external_controller'].rsplit(':',1)[1]))
    if PORT in occupied:raise ValueError('Порт VPN-входа занят другим адаптером')
    config['inbounds'].extend(inbounds(value))
    config['route']['rules']=route_prefix(value)+config['route']['rules']


def validate_config(config,value,lan):
    """LAN attaches last; both conditional guards precede common bypasses."""
    from lan_ingress import inbounds as lan_inbounds, attach as attach_lan
    native=config.get('inbounds',[])
    actual=[i for i in native if i.get('tag','').startswith(PREFIX)]
    expected=inbounds(value); tail=expected+lan_inbounds(lan)
    if actual != expected or (tail and native[-len(tail):] != tail):
        raise ValueError('VPN listeners differ from the declared policy')
    if expected:
        sample={'inbounds':[],'dns':{'rules':[]},'route':{'rules':route_prefix(value)},
                'experimental':{'clash_api':{'external_controller':'127.0.0.1:9091'}}}
        attach_lan(sample,lan)
        prefix=sample['route']['rules']
        if config.get('route',{}).get('rules',[])[:len(prefix)] != prefix:
            raise ValueError('VPN source guard must precede common bypasses')


def nft_script(value,opened,version=4):
    if not configured(value):raise ValueError('VPN capture scope missing')
    if version not in (4,6):raise ValueError('Unsupported IP family')
    family='ip' if version==4 else 'ip6'
    clients=value['clients'] if version==4 else value.get('clients_v6',[])
    if not clients:raise ValueError('VPN capture sources missing for IP family')
    # Loopback/multicast are also bypassed by the legacy SBTP. Other explicit
    # bypasses must be checked against that chain before preparing capture.
    networks=(['127.0.0.0/8','224.0.0.0/4',*value['bypass']] if version==4 else
              ['::1/128','fe80::/10','ff00::/8',*value.get('bypass_v6',[])])
    bypass=', '.join(networks)
    target=f'127.0.0.1:{PORT}' if version==4 else f'[::1]:{PORT}'
    action=(f'meta l4proto {{ tcp, udp }} tproxy to {target} meta mark set {MARK} accept\n'
            if opened else '')+'drop\n'
    dns_capture=''
    if value.get('dns_before_bypass',False):
        # Preserve local/multicast safety, but send unicast DNS to the same
        # policy as traffic even when its server is in a management subnet.
        local=', '.join(['127.0.0.0/8','224.0.0.0/4','255.255.255.255/32'] if version==4 else ['::1/128','fe80::/10','ff00::/8'])
        dns_action=f'tproxy to {target} meta mark set {MARK} accept' if opened else 'drop'
        dns_capture=f'  {family} daddr {{ {local} }} return\n  meta l4proto {{ tcp, udp }} th dport 53 {dns_action}\n'
    return f'''table {family} {TABLE} {{
 chain capture {{
  type filter hook prerouting priority -151; policy accept;
  iifname "{value['interface']}" {family} saddr {{ {', '.join(clients)} }} meta l4proto {{ tcp, udp }} jump selected
 }}
 chain selected {{
{dns_capture}  {family} daddr {{ {bypass} }} return
  {action}
 }}
}}
'''
