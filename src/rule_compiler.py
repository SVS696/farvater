"""Compile ordered general profiles into paired sing-box DNS and route rules.

Filtering is a named resolver path supplied by the deployment adapter. It is
never faked by silently choosing a raw DNS when filtering was requested.
"""
import copy
from policy import singbox_match, validate_policy
from rule_options import normalize_options,QUERY_TYPES


def conjunction(*parts):
    parts=[p for p in parts if p]
    if not parts:return {}
    return parts[0] if len(parts)==1 else {'type':'logical','mode':'and','rules':parts}


def compile_profiles(policy,*,source_identity=False,filtered_resolvers=None,default_filtering=None):
    if not isinstance(default_filtering,bool):raise ValueError('Общий режим AdGuard должен быть задан явно')
    errors=[i for i in validate_policy(policy) if i['severity']=='error']
    if errors:raise ValueError('; '.join(i['profile']+': '+i['message'] for i in errors))
    filtered_resolvers=filtered_resolvers or {}
    dns_rules=[];route_rules=[];origins=[]
    for profile in policy.get('profiles',[]):
        protected=profile['kind'] in ('work','special')
        if not profile.get('enabled',True) and not protected:continue
        options=normalize_options(profile)
        source={'source_ip_cidr':options['source_networks']} if options['source_networks'] else {}
        if source and not source_identity:
            raise ValueError(profile['name']+': путь DNS не подтверждает исходный IP устройства; нельзя расширять правило на всех')
        domain=singbox_match(profile['domains'],[],profile.get('exclude_domains')) if profile.get('domains') else None
        destination=singbox_match(profile.get('domains',[]),profile.get('networks',[]),profile.get('exclude_domains')) if profile.get('domains') or profile.get('networks') else {}
        route_match=conjunction(destination,source)
        dns_match=conjunction(domain,source) if domain or (source and not profile.get('networks')) else None
        dstart=len(dns_rules);rstart=len(route_rules)
        if not profile.get('enabled',True):
            if dns_match is not None:dns_rules.append({**dns_match,'action':'reject','no_drop':True})
            route_rules.append({**route_match,'action':'reject'})
        else:
            if profile.get('fallback'):
                raise ValueError(profile['name']+': генерация резерва требует связанных DNS/выходов; одиночный список выходов нельзя применять')
            if profile.get('fallback_pairs'):
                raise ValueError(profile['name']+': используйте общий генератор согласованных режимов резервирования')
            if dns_match is not None:
                dns_response=options['dns_response']
                if dns_response['mode']!='forward':
                    match=conjunction(dns_match,{'query_type':[QUERY_TYPES[t] for t in dns_response['query_types']]})
                    if dns_response['mode']=='refused':dns_rules.append({**match,'action':'reject','no_drop':True})
                    else:dns_rules.append({**match,'action':'predefined','rcode':'NOERROR' if dns_response['mode']=='nodata' else 'NXDOMAIN'})
                family=options['ip_family']
                if family!='auto':
                    dns_rules.append({**conjunction(dns_match,{'query_type':[28 if family=='ipv4_only' else 1]}),
                                      'action':'predefined','rcode':'NOERROR'})
                filtering=options['adguard']=='on' or (options['adguard']=='inherit' and default_filtering)
                resolver=profile['dns']
                if filtering:
                    if resolver not in filtered_resolvers:raise ValueError(profile['name']+': нет проверенного пути AdGuard к выбранному DNS')
                    resolver=filtered_resolvers[resolver]
                dns_rules.append({**dns_match,'action':'route','server':resolver})
            elif options['adguard']!='inherit' or options['dns_response']['mode']!='forward':
                raise ValueError(profile['name']+': для фильтрации или особого DNS-ответа нужны доменные условия')
            # DNS-only continues route selection, but does not discard an
            # explicit address-family restriction on a matching connection.
            if options['ip_family']!='auto':
                route_rules.append({**conjunction(route_match,{'ip_version':6 if options['ip_family']=='ipv4_only' else 4}),'action':'reject'})
            if options['udp_blocked_ports']:
                route_rules.append({**conjunction(route_match,{'network':'udp','port':options['udp_blocked_ports']}),
                                    'action':'reject','no_drop':True})
            if not profile.get('dns_only'):
                connection={}
                if options['route_network']!='any':connection['network']=options['route_network']
                if options['route_ports']:connection['port']=options['route_ports']
                route_rules.append({**conjunction(route_match,connection),'action':'route','outbound':profile['exit']})
        origins.append({'id':profile['id'],'name':profile['name'],'dns_indices':list(range(dstart,len(dns_rules))),
                        'route_indices':list(range(rstart,len(route_rules)))})
    return {'dns_rules':copy.deepcopy(dns_rules),'route_rules':copy.deepcopy(route_rules),'origins':origins}
