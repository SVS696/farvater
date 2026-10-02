"""Read-only projection of declared native IPv4 ISP pairs; never return raw config."""
import hashlib
import ipaddress
import re


def canonical(value):
    if not isinstance(value,str) or len(value)>1024*1024:
        raise ValueError('Invalid native configuration response')
    value=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',value)
    return '\n'.join(line.rstrip() for line in value.splitlines() if not line.startswith('! $$$')).strip()


def fields(value):
    return dict(re.findall(r'^\s*([a-z-]+):[ \t]*([^\n]*)',value,re.M))


def project(running,startup,resolvers,last_change):
    running=canonical(running);startup=canonical(startup)
    if not re.search(r'^dns-proxy$',running,re.M) or not re.search(r'^ip hotspot$',running,re.M) or not startup:
        raise ValueError('Incomplete native configuration')
    isp=set()
    for block in re.split(r'^\s*server:\s*$',canonical(resolvers),flags=re.M):
        row=fields(block)
        if row.get('service')!='Dhcp::Client-GigabitEthernet1' or row.get('interface')!='GigabitEthernet1':continue
        try:address=ipaddress.IPv4Address(row.get('address',''))
        except ValueError:continue
        isp.add(str(address))
    policies={}
    for match in re.finditer(r'^ip policy ([A-Za-z0-9_-]+)\n(.*?)(?=^!)',running,re.M|re.S):
        permits=[line.strip() for line in match[2].splitlines() if line.strip().startswith('permit ')]
        policies[match[1]]=permits==['permit global ISP']
    profiles={};assignments={};routes={}
    for line in running.splitlines():
        parts=line.strip().split()
        if parts[:2]==['filter','profile'] and len(parts)>=4:
            name=parts[2];profile=profiles.setdefault(name,{'servers':set(),'intercept':False,'other':False})
            if parts[3:5]==['dns53','upstream']:
                try:
                    if len(parts)!=6:raise ValueError('Unsupported upstream')
                    profile['servers'].add(str(ipaddress.IPv4Address(parts[5])))
                except ValueError:profile['other']=True
            elif parts[3]=='intercept':profile['intercept']=parts[4:]==['enable']
            elif parts[3]!='description':profile['other']=True
        elif len(parts)==6 and parts[:4]==['filter','assign','host','profile']:
            assignments[parts[4]]=parts[5]
        elif len(parts)==4 and parts[0]=='host' and parts[2]=='policy':routes[parts[1]]=parts[3]
    rows=[]
    for mac,name in sorted(assignments.items()):
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac):continue
        profile=profiles.get(name,{})
        if (isp and profile.get('servers')==isp and profile.get('intercept') is True
                and profile.get('other') is False and policies.get(routes.get(mac)) is True):
            rows.append({'mac':mac,'policy':routes[mac],'dns_profile':name,'dns_servers':sorted(isp)})
    status=fields(canonical(last_change))
    if status.get('unsaved') not in ('yes','no') or not status.get('time-left','').isdigit():
        raise ValueError('Incomplete native change status')
    # Declared settings are not a packet-path test or proof of automatic failover.
    return {'config_sha256':hashlib.sha256(running.encode()).hexdigest(),
            'startup_matches':running==startup,'pending':status['unsaved']=='yes' or int(status['time-left'])>0,
            'isp_dns':sorted(isp),'direct_clients':rows}
