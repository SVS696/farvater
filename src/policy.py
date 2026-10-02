"""Small, inspectable policy source. Generates DNS and traffic matches together."""
from __future__ import annotations

import ipaddress
from functools import lru_cache
import re
from failover_form import validate_failover, primary_pair
from rule_options import normalize_options, source_matches, source_scopes_overlap
from rule_fallback import validate_pairs


@lru_cache(maxsize=4096)
def normalized_domain(value: str) -> str:
    value = value.strip().rstrip('.').lower()
    if not value or len(value) > 253 or any(c in value for c in '/:@ '):
        raise ValueError('Укажите домен без протокола, порта и пути')
    try:
        result = value.encode('idna').decode('ascii')
    except UnicodeError as error:
        raise ValueError('Некорректное имя домена') from error
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in result.split('.')):
        raise ValueError('Некорректное имя домена')
    return result


def hosts_entries(native: dict) -> dict:
    """Validate local records without granting root-readable file access."""
    records = native.get('predefined', {})
    if native.get('path') != ['/dev/null']:
        raise ValueError('Локальные DNS-записи должны задаваться в панели, без чтения файлов сервера')
    if not isinstance(records, dict) or not 1 <= len(records) <= 1024:
        raise ValueError('Укажите от 1 до 1024 локальных DNS-имён')
    result = {}
    for name, values in records.items():
        if not isinstance(name, str) or normalized_domain(name) != name:
            raise ValueError('Некорректное локальное DNS-имя')
        if isinstance(values, str):values = [values]
        if not isinstance(values, list) or not 1 <= len(values) <= 16:
            raise ValueError('Для каждого имени нужно от 1 до 16 IP-адресов')
        addresses = []
        for value in values:
            if not isinstance(value, str) or '%' in value:
                raise ValueError('Нужен IPv4 или IPv6 без номера интерфейса')
            address = str(ipaddress.ip_address(value))
            if address not in addresses:addresses.append(address)
        result[name] = addresses
    return result


@lru_cache(maxsize=4096)
def domain_pattern(value: str) -> tuple[str, str]:
    value = value.strip()
    if value.startswith('*.'):
        return 'subdomains', normalized_domain(value[2:])
    if '*' in value:
        raise ValueError('Маска разрешена только в начале: *.example.com')
    return 'exact', normalized_domain(value)


def domain_matches(pattern: str, domain: str) -> bool:
    kind, suffix = domain_pattern(pattern)
    domain = normalized_domain(domain)
    return domain == suffix if kind == 'exact' else domain.endswith('.'+suffix)


def patterns_overlap(left: str, right: str) -> bool:
    lk, lv = domain_pattern(left); rk, rv = domain_pattern(right)
    if lk == rk == 'exact':
        return lv == rv
    if lk == 'exact':
        return domain_matches(right, lv)
    if rk == 'exact':
        return domain_matches(left, rv)
    return lv == rv or lv.endswith('.'+rv) or rv.endswith('.'+lv)


def profiles_overlap(left: dict, right: dict) -> bool:
    if not source_scopes_overlap(left,right):return False
    if any(not p.get('domains') and not p.get('networks') for p in (left,right)):return True
    # Exact exclusions on either profile remove an exact intersection. A finite
    # list of exclusions cannot remove an entire wildcard intersection.
    excluded={normalized_domain(x) for p in (left,right) for x in p.get('exclude_domains',[])}
    for a in left.get('domains',[]):
        for b in right.get('domains',[]):
            if not patterns_overlap(a,b):continue
            ak,av=domain_pattern(a);bk,bv=domain_pattern(b)
            exact=av if ak=='exact' else bv if bk=='exact' else None
            if exact is None or exact not in excluded:return True
    return any(a.version==b.version and a.overlaps(b)
               for a in (ipaddress.ip_network(n,strict=False) for n in left.get('networks',[]))
               for b in (ipaddress.ip_network(n,strict=False) for n in right.get('networks',[])))


def singbox_match(patterns: list[str], networks: list[str], exclude_domains: list[str] | None = None) -> dict:
    exact, regex = [], []
    for pattern in patterns:
        kind, domain = domain_pattern(pattern)
        if kind == 'exact': exact.append(domain)
        else: regex.append(r'^.+\.'+re.escape(domain)+r'$')
    parts=[]
    if exact: parts.append({'domain':exact})
    if regex: parts.append({'domain_regex':regex})
    if parts and exclude_domains:
        include=parts[0] if len(parts)==1 else {'type':'logical','mode':'or','rules':parts}
        parts=[{'type':'logical','mode':'and','rules':[include,{'domain':[normalized_domain(x) for x in exclude_domains],'invert':True}]}]
    if networks: parts.append({'ip_cidr':[str(ipaddress.ip_network(n,strict=False)) for n in networks]})
    if not parts: raise ValueError('Нужно хотя бы одно условие правила')
    return parts[0] if len(parts)==1 else {'type':'logical','mode':'or','rules':parts}


def validate_policy(policy: dict) -> list[dict]:
    """Report blocking errors and ordered-overlap warnings without mutating input."""
    issues=[]
    if 'filtering' in policy:
        from adguard_adapter import settings
        try:settings(policy)
        except (ValueError,TypeError) as error:
            issues.append({'severity':'error','profile':'AdGuard','message':str(error)})
    if 'lan_ingress' in policy:
        from lan_ingress import settings
        try:settings(policy)
        except (ValueError,TypeError) as error:
            issues.append({'severity':'error','profile':'LAN-вход','message':str(error)})
    profiles=policy.get('profiles',[])
    if 'vpn_ingress' in policy:
        from vpn_ingress import settings
        try:settings(policy)
        except (ValueError,TypeError) as error:
            issues.append({'severity':'error','profile':'VPN-вход','message':str(error)})
    if 'incoming_connections' in policy:
        from incoming_connections import validate as validate_incoming
        try:validate_incoming(policy['incoming_connections'])
        except (ValueError,TypeError) as error:
            issues.append({'severity':'error','profile':'Входящие подключения','message':str(error)})
    ids=set();known_exits=set(policy.get('exits',{}));known_dns=set(policy.get('dns',{}))
    if policy.get('default_exit') not in known_exits:issues.append({'severity':'error','profile':'Основной маршрут','message':'Неизвестный выход по умолчанию'})
    if policy.get('default_dns') not in known_dns:issues.append({'severity':'error','profile':'Основной маршрут','message':'Неизвестный DNS по умолчанию'})
    for index,p in enumerate(profiles):
        label=p.get('name',p.get('id','Без имени'))
        def error(message):issues.append({'severity':'error','profile':label,'message':message})
        if not p.get('id') or p['id'] in ids: error('Идентификатор правила отсутствует или повторяется')
        ids.add(p.get('id'))
        protected=p.get('kind') in ('work','special')
        enabled=p.get('enabled',True)
        try:
            from domain_document import validate as validate_domain_document
            validate_domain_document(p)
        except (ValueError,TypeError) as e:error(str(e))
        try:normalize_options(p)
        except (ValueError,TypeError) as e:error(str(e))
        if not enabled and not protected: continue
        if p.get('kind') not in ('public','work','special'):error('Неизвестная категория назначения')
        if p.get('exclude_domains') and not p.get('domains'):
            error('Исключённые имена требуют доменных условий; они не исключают IP-подсети или область устройств')
        if p.get('dns_only') and p.get('networks'):
            error('Правило только для DNS не может выбирать запросы по IP назначения; укажите домены')
        if enabled:
            if p.get('exit') not in known_exits:error('Неизвестный выход')
            if p.get('dns') not in known_dns:error('Неизвестный DNS')
            if any(tag not in known_exits for tag in p.get('fallback',[])):error('Неизвестный резервный выход')
            try:validate_pairs(p,policy)
            except ValueError as e:error(str(e))
        try:
            if p.get('domains') or p.get('networks') or not p.get('source_networks'):
                singbox_match(p.get('domains',[]),p.get('networks',[]),p.get('exclude_domains',[]))
        except (ValueError,TypeError) as e:error(str(e))
        if enabled and protected:
            exits=[p.get('exit')]+p.get('fallback',[])
            if p.get('kind')=='work' and p.get('dns_only'):error('Рабочий профиль должен задавать и DNS, и защищённый выход')
            if not p.get('dns_only') and any(policy.get('exits',{}).get(e,{}).get('scope') not in ('work','special') for e in exits):
                error('Рабочее или специальное правило не может уходить в публичный выход')
            if policy.get('dns',{}).get(p.get('dns'),{}).get('scope') not in ('work','special'):
                error('Рабочие и специальные имена не должны уходить в публичный DNS')
        for prior in profiles[:index]:
            if not prior.get('enabled',True) and prior.get('kind') not in ('work','special'):continue
            try:
                overlap=profiles_overlap(prior,p)
            except (ValueError,TypeError):continue
            if overlap:
                public_override=protected and prior.get('kind')=='public'
                issues.append({'severity':'error' if public_override else 'warning','profile':label,
                               'message':('Публичное правило перекрывает защищённое: ' if public_override else 'Раньше совпадает правило: ')+prior.get('name',prior.get('id',''))})
    # DNS can depend on another resolver for hostname bootstrap. Detect cycles,
    # including direct self-reference, before passing anything to the engine.
    graph={}
    for key,resolver in policy.get('dns',{}).items():
        native=resolver.get('native',{})
        if native.get('type')=='hosts':
            try:hosts_entries(native)
            except ValueError as error:
                issues.append({'severity':'error','profile':key,'message':str(error)})
        boot=native.get('domain_resolver')
        if isinstance(boot,dict):boot=boot.get('server')
        declared=resolver.get('bootstrap')
        if declared and boot and declared!=boot:
            issues.append({'severity':'error','profile':key,'message':'DNS bootstrap не совпадает с native.domain_resolver'})
        graph[key]=boot or declared
        detour=native.get('endpoint') if native.get('type')=='openvpn' else native.get('detour')
        if detour and detour not in known_exits:
            issues.append({'severity':'error','profile':key,'message':'Неизвестный выход DNS: '+detour})
        if native and resolver.get('scope') in ('work','special') and native.get('type') not in ('fakeip','hosts'):
            try:local=ipaddress.ip_address(native.get('server','')).is_loopback
            except ValueError:local=False
            if not local and policy.get('exits',{}).get(detour,{}).get('scope') not in ('work','special'):
                issues.append({'severity':'error','profile':key,'message':'Для защищённого DNS нужен защищённый выход либо локальный DNS-backend'})
    for node in graph:
        seen=set();current=node
        while current:
            if current in seen:
                issues.append({'severity':'error','profile':node,'message':'Цикл DNS bootstrap: '+current});break
            seen.add(current)
            if current not in graph:
                issues.append({'severity':'error','profile':node,'message':'Неизвестный DNS bootstrap: '+current});break
            if current != node:
                resolver=policy['dns'][current]
                if resolver.get('native',{}).get('type')=='fakeip':
                    issues.append({'severity':'error','profile':node,'message':'FakeIP нельзя использовать для DNS bootstrap: '+current})
                if policy['dns'][node].get('scope') in ('work','special') and resolver.get('scope') not in ('work','special'):
                    issues.append({'severity':'error','profile':node,'message':'Bootstrap защищённого DNS должен оставаться защищённым: '+current})
            current=graph[current]
    # A protected selector/detour must remain protected through every hop.
    exit_graph={}
    for tag,outbound in policy.get('exits',{}).items():
        native=outbound.get('native',{})
        links=list(native.get('outbounds',[])) if native.get('type') in ('selector','urltest') else []
        if native.get('detour'):links.append(native['detour'])
        exit_graph[tag]=links
        if native.get('type')=='direct' and outbound.get('scope') in ('work','special') and not native.get('bind_interface'):
            issues.append({'severity':'error','profile':tag,'message':'Защищённый прямой выход должен быть привязан к интерфейсу VPN'})
        if outbound.get('scope') not in ('public','work','special'):
            issues.append({'severity':'error','profile':tag,'message':'Неизвестное назначение выхода'})
    for root in exit_graph:
        pending=[(root,())];visited=set()
        while pending:
            current,path=pending.pop()
            if current in path:
                issues.append({'severity':'error','profile':root,'message':'Цикл выходов: '+current});continue
            if current in visited:continue
            visited.add(current)
            if current not in exit_graph:
                issues.append({'severity':'error','profile':root,'message':'Неизвестный связанный выход: '+current});continue
            if policy['exits'][root].get('scope') in ('work','special') and policy['exits'][current].get('scope') not in ('work','special'):
                issues.append({'severity':'error','profile':root,'message':'Защищённая цепочка содержит публичный или неопределённый выход: '+current})
            pending.extend((child,path+(current,)) for child in exit_graph[current])
    if policy.get('failover'):
        try:validate_failover(policy['failover'],policy)
        except ValueError as error:
            issues.append({'severity':'error','profile':'Общее резервирование','message':str(error)})
    return issues


def explain(policy: dict, value: str, source: str | None = None, *, network=None, port=None) -> dict:
    if network is not None and network not in ('tcp','udp'):raise ValueError('Выберите протокол TCP или UDP')
    if port is not None and (type(port) is not int or not 1<=port<=65535):raise ValueError('Укажите порт от 1 до 65535')
    try:
        address=ipaddress.ip_address(value);domain=None
    except ValueError:
        address=None;domain=normalized_domain(value)
    dns_override=None
    for index,p in enumerate(policy.get('profiles',[])):
        if not p.get('enabled',True) and p.get('kind') not in ('work','special'):continue
        matched=bool(p.get('source_networks') and not p.get('domains') and not p.get('networks')) or (domain is not None and domain not in {normalized_domain(x) for x in p.get('exclude_domains',[])}
                 and any(domain_matches(x,domain) for x in p.get('domains',[])))
        if address is not None and p.get('networks'):
            matched=any(address in ipaddress.ip_network(n,strict=False) for n in p.get('networks',[]))
        if not matched:continue
        if not source_matches(p,source):continue
        if not p.get('enabled',True):
            if p.get('kind') in ('work','special'):
                return {'matched':True,'order':index+1,'name':p['name']+' · доступ выключен','exit':'blocked','dns':'blocked' if domain is not None else None,'kind':p['kind']}
            continue
        if domain is not None and dns_override is None:dns_override=p['dns']
        options=normalize_options(p)
        if address is not None and options['ip_family']!='auto' and address.version==(6 if options['ip_family']=='ipv4_only' else 4):
            return {'matched':True,'order':index+1,'name':p['name']+' · семейство адресов запрещено','exit':'blocked','dns':None,'kind':p['kind']}
        if network=='udp' and options['udp_blocked_ports']:
            if port is None:raise ValueError('Для проверки запрета UDP укажите порт назначения')
            if port in options['udp_blocked_ports']:
                return {'matched':True,'order':index+1,'name':p['name']+' · UDP-порт запрещён','exit':'blocked','dns':dns_override,'kind':p['kind']}
        if p.get('dns_only'):continue
        if options['route_network']!='any':
            if network is None:raise ValueError('Для этого правила укажите протокол соединения: TCP или UDP')
            if network!=options['route_network']:continue
        if options['route_ports']:
            if port is None:raise ValueError('Для этого правила укажите порт назначения')
            if port not in options['route_ports']:continue
        return {'matched':True,'order':index+1,'name':p['name'],'exit':p['exit'],'dns':dns_override,'kind':p['kind']}
    default = primary_pair(policy)
    return {'matched':False,'name':'Основной маршрут','exit':default['exit'],
            'dns':(dns_override or default['dns']) if domain is not None else None}
