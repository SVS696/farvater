"""Build a complete sing-box candidate from the canonical draft.

Loopback is the default. Opt-in LAN ingress has a separate lifecycle adapter;
this builder never installs kernel rules or redirects client traffic.
"""
import copy
import ipaddress
from policy_modes import compile_policy_modes
from connection_dns import connection_resolve_rule
from native_endpoints import openconnect_host, split_endpoints, validate_bootstrap


BOOTSTRAP_DENY = 'okopy-bootstrap-deny'


def local_hosts_nodata(rules, servers):
    """Known local names stay existent when their requested RR type is absent."""
    from rule_compiler import conjunction
    groups={}
    for server in servers:
        if server.get('type')!='hosts' or not server.get('predefined'):continue
        by_types={}
        for name,addresses in server['predefined'].items():
            if isinstance(addresses,str):addresses=[addresses]
            types=tuple(sorted({1 if ipaddress.ip_address(a).version==4 else 28 for a in addresses}))
            by_types.setdefault(types,[]).append(name)
        groups[server['tag']]=by_types
    result=[]
    route_fields={'action','server','strategy','disable_cache','disable_optimistic_cache','rewrite_ttl','client_subnet'}
    for rule in rules:
        if rule.get('action')=='route' and rule.get('server') in groups:
            match={k:copy.deepcopy(v) for k,v in rule.items() if k not in route_fields}
            for types,names in groups[rule['server']].items():
                result.append({**conjunction(match,{'domain':names},{'query_type':list(types),'invert':True}),
                               'action':'predefined','rcode':'NOERROR'})
        result.append(rule)
    return result


def validate_filtered_mapping(policy, mapping):
    for original, target in (mapping or {}).items():
        source = policy['dns'].get(original)
        if source is None:
            raise ValueError('Неизвестный исходный DNS фильтрации: '+original)
        if source.get('scope') in ('work', 'special'):
            # A bare additional native entry has no declared scope. Protected
            # backends must be registered in policy so its whole bootstrap and
            # detour chain receives the ordinary protected-DNS validation.
            if policy['dns'].get(target, {}).get('scope') not in ('work', 'special'):
                raise ValueError('Фильтрующий путь защищённого DNS должен быть объявлен защищённым в общей политике')


def validate_fakeip_pairs(policy, servers, queues, filtered_resolvers, default_filtering):
    server_by_tag = {server['tag']: server for server in servers}
    remote_types = {'socks', 'http', 'shadowsocks', 'vless', 'vmess', 'trojan',
                    'hysteria', 'hysteria2', 'tuic', 'anytls', 'ssh', 'tor'}

    def carries_hostname(tag, protected, seen=()):
        if tag in seen:
            return False
        native = policy['exits'][tag]['native']
        kind = native['type']
        if kind in ('selector', 'urltest'):
            members = native.get('outbounds', [])
            return bool(members) and all(carries_hostname(child, protected, (*seen, tag)) for child in members)
        if kind in remote_types:
            return True
        resolver = native.get('domain_resolver')
        if isinstance(resolver, dict):
            resolver = resolver.get('server')
        dns = policy['dns'].get(resolver, {})
        return (kind == 'direct' and bool(resolver) and resolver != BOOTSTRAP_DENY
                and server_by_tag.get(resolver, {}).get('type') not in (None, 'fakeip')
                and (not protected or dns.get('scope') in ('work', 'special')))

    for profile in policy.get('profiles', []):
        if not profile.get('enabled', True):
            continue
        filtering = profile.get('adguard', 'inherit') == 'on' or (
            profile.get('adguard', 'inherit') == 'inherit' and default_filtering)
        pairs = [{'exit': profile['exit'], 'dns': profile['dns']}, *profile.get('fallback_pairs', [])]
        for pair in pairs:
            resolver = (filtered_resolvers or {}).get(pair['dns'], pair['dns']) if filtering else pair['dns']
            if not any(server_by_tag.get(tag, {}).get('type')=='fakeip' for tag in (resolver,pair['dns'])):
                continue
            if profile.get('dns_only') or not carries_hostname(pair['exit'], profile['kind'] in ('work', 'special')):
                raise ValueError(profile['name']+': FakeIP требует собственного выхода с передачей имени либо явным допустимым DNS разрешения')
    for pair in queues['default']:
        resolver = (filtered_resolvers or {}).get(pair['dns'], pair['dns']) if default_filtering else pair['dns']
        if any(server_by_tag.get(tag, {}).get('type')=='fakeip' for tag in (resolver,pair['dns'])) and not carries_hostname(pair['exit'], False):
            raise ValueError('Основной маршрут: FakeIP несовместим с выбранным выходом')


def validate_native_references(servers, outbounds):
    dns_tags = {entry['tag'] for entry in servers}
    exit_tags = {entry['tag'] for entry in outbounds}
    for entry in [*servers, *outbounds]:
        if entry.get('type') == 'openvpn':
            target=next((item for item in outbounds if item['tag']==entry.get('endpoint')),None)
            if target is None or target.get('type')!='openvpn-client':
                raise ValueError(entry['tag']+': DNS OpenVPN требует клиентский endpoint OpenVPN')
        resolver = entry.get('domain_resolver')
        if isinstance(resolver, dict):
            resolver = resolver.get('server')
        if resolver is not None and resolver not in dns_tags:
            raise ValueError(entry['tag']+': неизвестный domain_resolver')
        if entry.get('detour') and entry['detour'] not in exit_tags:
            raise ValueError(entry['tag']+': неизвестный detour')
        if any(tag not in exit_tags for tag in entry.get('outbounds', [])):
            raise ValueError(entry['tag']+': неизвестный выход в списке')
        endpoint = entry.get('server')
        if entry.get('type') == 'openconnect':
            endpoint = openconnect_host(endpoint)
        addresses=[endpoint] if endpoint else []
        if entry.get('type')=='openvpn-client':
            addresses.extend(item.get('server') for item in entry.get('servers',[]) if isinstance(item,dict))
        for endpoint in addresses if entry.get('type') not in ('local','hosts','fakeip') else []:
            try:
                ipaddress.ip_address(endpoint)
            except ValueError:
                if not resolver:
                    raise ValueError(entry['tag']+': для имени сервера нужен явный DNS загрузки (domain_resolver)')


def native_entries(entries, label):
    result = []
    for identifier, item in entries.items():
        native = item.get('native')
        if not isinstance(native, dict) or not native.get('type'):
            raise ValueError(label+': отсутствует полная конфигурация '+identifier)
        if native.get('tag', identifier) != identifier:
            raise ValueError(label+': идентификатор не совпадает с native.tag '+identifier)
        result.append({**copy.deepcopy(native), 'tag': identifier})
    return result


def build_candidate_config(policy, *, api_secret, default_filtering, source_identity=False,
                           filtered_resolvers=None, additional_dns=None, pair_probes=False,adguard_adapter=False,lan_adapter=False,vpn_adapter=False,
                           dns_port=5302, proxy_port=2082, api_port=9092):
    if not isinstance(api_secret, str) or len(api_secret) < 24:
        raise ValueError('Для API кандидата нужен отдельный секрет длиной не менее 24 символов')
    ports = [dns_port, proxy_port, api_port]
    if any(type(port) is not int or not 1024 <= port <= 65535 for port in ports) or len(set(ports)) != 3:
        raise ValueError('Кандидату нужны три разных непривилегированных порта')
    from lan_ingress import settings as lan_settings, attach as attach_lan
    from vpn_ingress import settings as vpn_settings, attach as attach_vpn
    lan = lan_settings(policy)
    vpn = vpn_settings(policy)
    if type(lan_adapter) is not bool or (lan['enabled'] and not lan_adapter):
        raise ValueError('LAN-вход требует установленного адаптера применения')
    if type(vpn_adapter) is not bool or (vpn['enabled'] and not vpn_adapter):
        raise ValueError('VPN-вход требует установленного адаптера применения')
    if source_identity and not (lan_adapter or vpn_adapter):
        for profile in policy.get('profiles', []):
            for source in profile.get('source_networks', []):
                network = ipaddress.ip_network(source, strict=False)
                if network.version != 4 or not network.subnet_of(ipaddress.ip_network('127.0.0.0/8')):
                    raise ValueError('Loopback-кандидат проверяет только тестовые источники 127.0.0.0/8; реальные устройства требуют отдельного входа')
    adapter=None
    if type(adguard_adapter) is not bool:raise ValueError('Некорректный режим адаптера AdGuard')
    if not adguard_adapter and policy.get('filtering',{}).get('default_enabled'):
        raise ValueError('Общий режим фильтрации требует установленного адаптера AdGuard')
    if adguard_adapter:
        if filtered_resolvers or additional_dns:raise ValueError('Нельзя смешивать автоматический и ручной адаптеры фильтрации')
        from adguard_adapter import compile_adapter
        adapter=compile_adapter(policy)
        policy=adapter['policy'];filtered_resolvers=adapter['mapping']
        default_filtering=adapter['settings']['default_enabled']
    validate_filtered_mapping(policy, filtered_resolvers)
    compiled = compile_policy_modes(policy, default_filtering=default_filtering,
        source_identity=source_identity or lan_adapter or vpn_adapter, filtered_resolvers=filtered_resolvers)
    servers = native_entries(policy['dns'], 'DNS')
    for server in additional_dns or []:
        if not isinstance(server, dict) or not server.get('tag') or not server.get('type'):
            raise ValueError('У дополнительного DNS нужны тип и идентификатор')
        if server['tag'] in {s['tag'] for s in servers}:
            raise ValueError('Идентификатор дополнительного DNS повторяется')
        servers.append(copy.deepcopy(server))
    if any(tag not in {s['tag'] for s in servers} for tag in (filtered_resolvers or {}).values()):
        raise ValueError('Фильтрующий DNS отсутствует в полном конфиге кандидата')
    if BOOTSTRAP_DENY in {server['tag'] for server in servers}:
        raise ValueError('Идентификатор '+BOOTSTRAP_DENY+' зарезервирован')
    # An accidental unresolved hostname must not fall back to public DNS.
    servers.append({'type': 'hosts', 'tag': BOOTSTRAP_DENY, 'path': ['/dev/null']})
    outbounds = native_entries(policy['exits'], 'Выход')
    validate_bootstrap(policy)
    validate_native_references(servers, outbounds)
    validate_fakeip_pairs(policy, servers, compiled['queues'], filtered_resolvers, default_filtering)
    outbounds, endpoints = split_endpoints(outbounds)
    config = {'log': {'level': 'warn', 'timestamp': True},
        'inbounds': [
            {'type': 'direct', 'tag': 'candidate-dns', 'listen': '127.0.0.1', 'listen_port': dns_port},
            {'type': 'mixed', 'tag': 'candidate-proxy', 'listen': '127.0.0.1', 'listen_port': proxy_port}],
        'dns': {'servers': servers, 'rules': compiled['dns_rules'], 'reverse_mapping': True,
                'final': BOOTSTRAP_DENY},
        'outbounds': outbounds,
        'route': {'rules': [{'inbound': ['candidate-dns'], 'action': 'hijack-dns'},
                            connection_resolve_rule(compiled['dns_rules'], servers),
                            *compiled['route_rules']],
                  'default_domain_resolver': BOOTSTRAP_DENY},
        'experimental': {'clash_api': {'external_controller': '127.0.0.1:'+str(api_port),
            'secret': api_secret, 'default_mode': compiled['initial_mode']}}}
    if any(s.get('type')=='dhcp' and not s.get('interface') for s in servers):
        config['route']['auto_detect_interface']=True
    if endpoints:
        config['endpoints'] = endpoints
    result={'config': config, 'modes': compiled['modes'], 'queues': compiled['queues']}
    if type(pair_probes) is not bool:raise ValueError('Некорректный режим проверки резервных пар')
    if pair_probes:
        from pair_probes import compile_pair_probes
        probes=compile_pair_probes(policy,compiled['queues'],servers,default_filtering=default_filtering,filtered_resolvers=filtered_resolvers)
        probe_ports={p['listen_port'] for p in probes['inbounds']}
        if probe_ports & set(ports):raise ValueError('Порты кандидата пересекаются с проверочными входами')
        config['inbounds'].extend(probes['inbounds'])
        config['dns']['rules']=probes['dns_rules']+config['dns']['rules']
        config['route']['rules']=probes['route_rules']+config['route']['rules']
        result['probes']=probes['records'];result['unconfigured_probe_queues']=probes['missing']
    if adapter is not None:
        existing_ports={i['listen_port'] for i in config['inbounds']}|{api_port}
        if existing_ports & {i['listen_port'] for i in adapter['inbounds']}:
            raise ValueError('Порты AdGuard пересекаются с другими входами')
        config['inbounds'].extend(adapter['inbounds'])
        # sing-box 1.14 isolates resolver caches by default; its former
        # independent_cache flag was removed. The upstream adapter queries
        # also explicitly disable caching for isolation and live probes.
        config['dns']['rules']=adapter['dns_rules']+config['dns']['rules']
        config['route']['rules']=adapter['route_rules']+config['route']['rules']
        result['adguard']=adapter['records']
    from fakeip_adapter import compile_unmapping
    unmapping=compile_unmapping(policy,config,compiled['queues'],filtered_resolvers,default_filtering,api_secret)
    if unmapping:result['unmapping']=unmapping
    config['dns']['rules']=local_hosts_nodata(config['dns']['rules'],servers)
    from incoming_connections import attach as attach_incoming
    attach_incoming(config, policy.get('incoming_connections', []))
    attach_vpn(config, vpn)
    attach_lan(config, lan)
    from incoming_connections import validate_ports
    validate_ports(config,policy.get('incoming_connections',[]))
    return result
