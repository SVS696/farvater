"""Common policy ingress for authenticated VPN engines with kernel interfaces.

Pure compiler only. Runtime owns interface creation, return routes and capture
activation; this module neither opens public ports nor changes host networking.
"""
import hashlib
import ipaddress
import re

PORT=25457
MARK=0x4f4b2000
SOCKS_UDP_MARK=0x4f4b4000
TABLE='farvater_incoming'
ROUTE_TABLE='25457'
PREF='951'
PREFIX='incoming-kernel-'


def interface_name(identifier):
    if not isinstance(identifier,str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}',identifier):raise ValueError('Некорректный идентификатор входа')
    return 'fi'+hashlib.sha256(identifier.encode()).hexdigest()[:10]


def validate(scopes):
    if not isinstance(scopes,list) or len(scopes)>32:raise ValueError('Некорректный список интерфейсов входа')
    interfaces=set();used=[]
    for s in scopes:
        if not isinstance(s,dict) or set(s)!={'interface','sources'}:raise ValueError('Укажите интерфейс и сети входящих клиентов')
        if not isinstance(s['interface'],str) or not re.fullmatch(r'(?:fi[a-f0-9]{10}|fc[a-f0-9]{8}\*)',s['interface']) or s['interface'] in interfaces:raise ValueError('Интерфейс входа должен принадлежать модулю')
        interfaces.add(s['interface'])
        if not isinstance(s['sources'],list) or len(s['sources'])>128:raise ValueError('Некорректные сети входящих клиентов')
        own=[]
        for value in s['sources']:
            if not isinstance(value,str) or '%' in value:raise ValueError('Некорректная сеть входящего клиента')
            n=ipaddress.ip_network(value,strict=True)
            if n.prefixlen==0 or n.is_loopback or n.is_multicast:raise ValueError('Нужна конкретная сеть входящего клиента')
            if any(n.version==p.version and n.overlaps(p) for p in used):raise ValueError('Адреса клиентов разных входов пересекаются')
            own.append(n)
        used.extend(own)
    return scopes


def awg_scope(entry):
    from amnezia_incoming import validate as validate_awg,server_model
    n=validate_awg(entry['native'])
    return {'interface':interface_name(entry['id']), 'sources':sorted({v for p in server_model(n,entry.get('disabled_clients',[]))['peers'] for v in p['AllowedIPs']})}


def ocserv_scope(entry):
    from ocserv_incoming import validate as validate_ocserv,device_prefix
    n=validate_ocserv(entry['native'])
    return {'interface':device_prefix(entry['id'])+'*', 'sources':list(n['pools'])}


def sources(scopes,version):
    return sorted({v for s in validate(scopes) for v in s['sources'] if ipaddress.ip_network(v).version==version})


def inbounds(scopes):
    return [{'type':'tproxy','tag':PREFIX+str(v),'listen':('127.0.0.1' if v==4 else '::1'),'listen_port':PORT}
            for v in (4,6) if sources(scopes,v)]


def route_prefix(scopes):
    result=[]
    for version in (4,6):
        admitted=sources(scopes,version)
        if not admitted:continue
        tag=PREFIX+str(version)
        result.extend([{'type':'logical','mode':'and','rules':[{'inbound':[tag]}, {'source_ip_cidr':admitted,'invert':True}], 'action':'reject'},
                       {'inbound':[tag],'port':[53],'action':'hijack-dns'},
                       {'inbound':[tag],'action':'sniff','timeout':'300ms'}])
    return result


def nft_script(scopes,opened,socks_udp=False):
    validate(scopes)
    # Apply our routing mark after standard mangle/CONNMARK restore (-150),
    # but before destination NAT (-100). Otherwise established packets can
    # lose the mark and bypass the local policy-routing lookup.
    lines=[f'table inet {TABLE} {{',' chain capture {','  type filter hook prerouting priority -149; policy accept;']
    for index,s in enumerate(scopes):lines.append(f'  iifname "{s["interface"]}" jump client_{index}')
    lines.append(' }')
    for index,s in enumerate(scopes):
        lines.append(f' chain client_{index} {{')
        for version,family,target in [(4,'ip',f'127.0.0.1:{PORT}'),(6,'ip6',f'[::1]:{PORT}')]:
            admitted=sources([s],version)
            if not admitted:continue
            # Link-local, multicast and loopback traffic does not enter policy.
            forbidden='127.0.0.0/8, 224.0.0.0/4, 255.255.255.255/32' if version==4 else '::1/128, fe80::/10, ff00::/8'
            lines.append(f'  {family} daddr {{ {forbidden} }} drop')
            if opened:lines.append(f'  {family} saddr {{ {", ".join(admitted)} }} meta l4proto {{ tcp, udp }} tproxy {family} to {target} meta mark set {MARK} accept')
        # No unauthenticated source and no fallback forwarding around policy.
        lines.extend(['  drop',' }'])
    if socks_udp:
        lines.extend([' chain socks_udp {','  type filter hook input priority -10; policy accept;'])
        # Only UDP sockets created by an authenticated SOCKS association carry this mark.
        # Do not restore marks of unrelated sockets or open an ephemeral port range.
        if opened:lines.append(f'  meta l4proto udp socket mark {SOCKS_UDP_MARK} meta mark set {SOCKS_UDP_MARK}')
        lines.append(' }')
    lines.append('}');return '\n'.join(lines)+'\n'


def entries(policy):
    return [e for e in policy.get('incoming_connections',[]) if e.get('enabled') and e.get('native',{}).get('type') in ('amneziawg','openconnect-server')]


def scopes(entries):
    return validate([(ocserv_scope(e) if e['native']['type']=='openconnect-server' else awg_scope(e)) for e in entries if e.get('enabled') and e.get('native',{}).get('type') in ('amneziawg','openconnect-server')])


def shared_listener_pair(a,b):
    return {a.get('tag'),b.get('tag')}=={PREFIX+'4',PREFIX+'6'} and a.get('listen_port')==b.get('listen_port')==PORT
