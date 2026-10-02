"""Deterministic native AdGuard paths derived from the existing policy bundle.

One running AdGuard engine, one client per used resolver. Both engines must be
stopped before applying another mapping; no persistent slot registry is needed.
"""
import copy
import hashlib
from urllib.parse import urlsplit

DNS_PORT=15300
HTTP_PORT=18300
UPSTREAM_BASE=16300
MAX_RESOLVERS=128
PREFIX='okopy-adguard-'


def list_id(url):
    # A URL never inherits a different source's on-disk cache after an edit.
    return int(hashlib.sha256(url.encode()).hexdigest()[:13],16)+1


def settings(policy):
    value=policy.get('filtering',{'default_enabled':False,'blocklists':[],'allowlists':[],'rules':[]})
    if not isinstance(value,dict) or set(value)!={'default_enabled','blocklists','allowlists','rules'}:
        raise ValueError('AdGuard: нужны общий режим, списки блокировки/разрешения и правила')
    if type(value['default_enabled']) is not bool:raise ValueError('Некорректный общий режим AdGuard')
    ids=set();urls=set()
    for key in ('blocklists','allowlists'):
        lists=value[key]
        if not isinstance(lists,list) or len(lists)>32:raise ValueError('Допускается до 32 списков каждого типа')
        for item in lists:
            if not isinstance(item,dict) or set(item)!={'id','name','url','enabled'}:
                raise ValueError('У списка нужны ID, название, URL и признак включения')
            if type(item['id']) is not int or not 0<item['id']<2**63 or item['id'] in ids:
                raise ValueError('Идентификаторы списков должны быть уникальными положительными числами')
            ids.add(item['id'])
            if not isinstance(item['name'],str) or not 1<=len(item['name'])<=200:raise ValueError('Укажите название списка до 200 символов')
            url=item['url']
            if not isinstance(url,str) or len(url)>2048:raise ValueError('Некорректный URL списка')
            parsed=urlsplit(url)
            if (parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.fragment or any(c.isspace() for c in url)):
                raise ValueError('Укажите HTTP/HTTPS-адрес списка без пароля и фрагмента')
            if url in urls:raise ValueError('Адрес списка повторяется')
            urls.add(url)
            if item['id']!=list_id(url):raise ValueError('Идентификатор списка не соответствует его адресу; сохраните список через панель')
            if type(item['enabled']) is not bool:raise ValueError('Некорректный признак включения списка')
    rules=value['rules']
    if (not isinstance(rules,list) or len(rules)>1000 or
            any(not isinstance(rule,str) or not rule.strip() or len(rule)>4096 or '\n' in rule or '\r' in rule for rule in rules)):
        raise ValueError('Допускается до 1000 непустых правил AdGuard, каждое одной строкой до 4096 символов')
    # The engine sees resolver identities. Device scope belongs to the policy's
    # common rule editor, not to synthetic AdGuard clients.
    if any('$' in r and any(part.split('=',1)[0].lstrip('~') in ('client','ctag')
            for part in r.rsplit('$',1)[1].split(',')) for r in rules):
        raise ValueError('Исключения для устройств задаются в общих правилах панели; client/ctag в правилах фильтра не поддерживаются')
    return copy.deepcopy(value)


def compile_adapter(policy):
    from failover_form import default_group
    from policy import singbox_match
    from rule_compiler import conjunction
    from rule_options import normalize_options
    value=settings(policy);used=set()
    if value['default_enabled']:
        pairs=(list(default_group(policy['failover'])['states'].values()) if policy.get('failover')
               else [{'dns':policy['default_dns']}])
        used.update(pair['dns'] for pair in pairs)
    for profile in policy.get('profiles',[]):
        if not profile.get('enabled',True):continue
        option=normalize_options(profile)['adguard']
        if option=='on' or (option=='inherit' and value['default_enabled']):
            used.add(profile['dns']);used.update(p['dns'] for p in profile.get('fallback_pairs',[]))
    if len(used)>MAX_RESOLVERS:raise ValueError('Допускается до 128 одновременно фильтруемых DNS')
    if any(tag.startswith(PREFIX) for tag in policy['dns']):raise ValueError('Префикс '+PREFIX+' зарезервирован')
    effective=copy.deepcopy(policy);mapping={};records=[];inbounds=[];dns_rules=[]
    protected=[singbox_match(p['domains'],[]) for p in policy.get('profiles',[])
               if p.get('kind') in ('work','special') and p.get('domains')]
    protected_match=({'type':'logical','mode':'or','rules':protected} if len(protected)>1 else protected[0]) if protected else None
    for index,tag in enumerate(sorted(used)):
        if tag not in policy['dns']:raise ValueError('Неизвестный DNS фильтрации')
        original=policy['dns'][tag]
        identity=PREFIX+hashlib.sha256(tag.encode()).hexdigest()[:20]
        source='127.2.0.'+str(index+1);port=UPSTREAM_BASE+index
        inbound=PREFIX+'upstream-'+str(index)
        mapping[tag]=identity
        effective['dns'][identity]={'name':'AdGuard → '+tag,'scope':original.get('scope'),
            'native':{'type':'udp','server':'127.0.0.1','server_port':DNS_PORT,'inet4_bind_address':source}}
        inbounds.append({'type':'direct','tag':inbound,'listen':'127.0.0.1','listen_port':port})
        if original.get('scope') not in ('work','special') and protected_match:
            dns_rules.append({**conjunction({'inbound':[inbound]},protected_match),'action':'reject','no_drop':True})
        dns_rules.append({'inbound':[inbound],'action':'route','server':tag,'disable_cache':True,'disable_optimistic_cache':True})
        records.append({'dns':tag,'filtered_dns':identity,'source':source,'port':port,'inbound':inbound})
    return {'policy':effective,'mapping':mapping,'records':records,'inbounds':inbounds,'dns_rules':dns_rules,
            'route_rules':[{'inbound':[r['inbound'] for r in records],'action':'hijack-dns'}] if records else [],
            'settings':value}


def validate_inbounds(inbounds):
    if len(inbounds)>MAX_RESOLVERS:raise ValueError('Too many AdGuard upstreams')
    expected=[{'type':'direct','tag':PREFIX+'upstream-'+str(i),'listen':'127.0.0.1','listen_port':UPSTREAM_BASE+i}
              for i in range(len(inbounds))]
    if inbounds!=expected:raise ValueError('AdGuard upstreams must use reserved loopback ports')


def runtime_config(base,adapter):
    """Render mutable AGH YAML from a private base and the authoritative bundle."""
    config=copy.deepcopy(base);value=adapter['settings']
    config['http']['address']='127.0.0.1:'+str(HTTP_PORT)
    config['http']['pprof']={'enabled':False,'port':6060}
    config['http']['doh']={'insecure_enabled':False}
    config['dns'].update({'bind_hosts':['127.0.0.1'],'port':DNS_PORT,
        'upstream_dns':['127.0.0.1:9'],'upstream_dns_file':'','bootstrap_dns':['127.0.0.1:9'],
        'fallback_dns':[],'cache_enabled':False,'cache_size':0,'cache_optimistic':False,
        'use_private_ptr_resolvers':False,'local_ptr_upstreams':[],'hostsfile_enabled':False,
        'use_dns64':False,'ratelimit':0,'allowed_clients':[r['source'] for r in adapter['records']],
        'disallowed_clients':[],'blocked_hosts':[],'upstream_timeout':'3s'})
    # Empty allowed_clients means unrestricted in AGH, so explicitly allow an
    # unused loopback identity when no rule currently needs the filtering path.
    if not config['dns']['allowed_clients']:config['dns']['allowed_clients']=['127.2.255.254']
    config['filters']=value['blocklists'];config['whitelist_filters']=value['allowlists'];config['user_rules']=value['rules']
    config['filtering'].update({'protection_enabled':True,'filtering_enabled':True,
        'blocking_mode':'nxdomain','safebrowsing_enabled':False,'parental_enabled':False,
        'safe_search':{'enabled':False},'rewrites':[],
        'blocked_services':{'schedule':{'time_zone':'Local'},'ids':[]}})
    config['clients']={'runtime_sources':{k:False for k in ['whois','arp','rdns','dhcp','hosts']},
        'persistent':[{'name':r['filtered_dns'],'ids':[r['source']],
            'upstreams':['127.0.0.1:'+str(r['port'])],'upstreams_cache_enabled':False,
            'upstreams_cache_size':0,'use_global_settings':True,'filtering_enabled':True,
            'use_global_blocked_services':True,'ignore_querylog':True,'ignore_statistics':False}
            for r in adapter['records']]}
    config['dhcp']['enabled']=False;config['tls']['enabled']=False
    config['querylog']['enabled']=False
    config['log']={'enabled':True,'file':'','max_size':1,'max_backups':1,'max_age':1,'verbose':False}
    return config
