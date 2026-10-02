"""Owned routed ingress lifecycle for the existing candidate service."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess

from safe_apply import ROOT, UNIT, atomic_write, digest, remove_created_file
from vpn_ingress import settings, configured, nft_script, MARK, TABLE, ROUTE_TABLE, PREF
from lan_transparent import normalized

HANDOFF = ['SBTP','-m','mark','--mark',hex(MARK),'-j','RETURN']
INPUT = ['INPUT','-m','mark','--mark',hex(MARK),'-j','ACCEPT']
RULE = ['pref',PREF,'fwmark',hex(MARK),'lookup',ROUTE_TABLE]
ROUTE = ['table',ROUTE_TABLE,'local','0.0.0.0/0','dev','lo']


def run(args,check=True,*,input=None):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=5,input=input,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})


def family(version):
    if version not in (4,6):raise ValueError('Unsupported IP family')
    return 'ip' if version==4 else 'ip6'


def stamp_path(root,kind,version):return root/('vpn'+('6' if version==6 else '')+'-'+kind+'.json')
def sources(value,version):return value.get('clients' if version==4 else 'clients_v6',[])
def declared(value,version):return configured(value) and bool(sources(value,version))
def handoff(version):return [('SBTP' if version==4 else 'SBTP6'),*HANDOFF[1:]]
def local_route(version):return [*ROUTE[:3],('0.0.0.0/0' if version==4 else '::/0'),*ROUTE[4:]]
def bypasses(value,version):
    return (['127.0.0.0/8','224.0.0.0/4',*value['bypass']] if version==4 else
            ['::1/128','fe80::/10','ff00::/8',*value.get('bypass_v6',[])])


def iptables(*args,check=True,version=4):
    family(version)
    return run([('iptables' if version==4 else 'ip6tables'),'-w','2',*args],check)


def legacy_bypass(version=4):
    chain=handoff(version)[0]
    result=iptables('-t','mangle','-S',chain,check=False,version=version)
    if result.returncode:
        if result.returncode==1 and 'No chain/target/match' in result.stderr:return None
        raise ValueError('Cannot inspect legacy '+chain)
    rows=[shlex.split(line) for line in result.stdout.splitlines()]
    if not rows or rows.pop(0)!=['-N',chain]:raise ValueError('Legacy capture has an unexpected form')
    if rows and rows[0]==['-A',*handoff(version)]:rows.pop(0)
    networks=[]
    while rows and len(rows[0])==6 and rows[0][:3]==['-A',chain,'-d'] and rows[0][4:]==['-j','RETURN']:
        network=ipaddress.ip_network(rows.pop(0)[3])
        if network.version!=version:raise ValueError('Legacy bypass family differs')
        networks.append(network)
    expected=[['-A',chain,'-p',protocol,'-j','TPROXY','--on-port','12345','--on-ip',
               ('127.0.0.1' if version==4 else '::1'),'--tproxy-mark','0x1/0x1'] for protocol in ('tcp','udp')]
    if rows!=expected:raise ValueError('Legacy capture changed; review handoff before applying')
    return networks


def preflight(value,*,allow_missing=False,version=4):
    if not declared(value,version):return None
    # The public IPv4 entry point validates both families before any deployment.
    if version==4 and value.get('clients_v6'):
        preflight(value,allow_missing=allow_missing,version=6)
    bypass=legacy_bypass(version)
    if bypass is not None:
        for item in bypasses(value,version):
            if not any(ipaddress.ip_network(item).subnet_of(n) for n in bypass):
                raise ValueError('Сеть обхода по-прежнему попадёт в старое ядро: '+item)
    if not value['enabled']:return bypass is not None
    result=run(['ip','-j','-d','link','show','dev',value['interface']],False)
    if result.returncode:
        if allow_missing and result.returncode==1 and 'does not exist' in result.stderr:return bypass is not None
        raise ValueError('Интерфейс VPN недоступен')
    links=json.loads(result.stdout)
    if len(links)!=1 or links[0].get('linkinfo',{}).get('info_kind')!='wireguard':
        raise ValueError('Выберите существующий интерфейс WireGuard')
    flag='-'+str(version)
    addresses=json.loads(run(['ip','-j',flag,'address','show','dev',value['interface']]).stdout)
    local=[ipaddress.ip_address(a['local']) for link in addresses for a in link.get('addr_info',[])
           if a.get('family')==('inet' if version==4 else 'inet6')]
    # An explicitly admitted interface subnet includes future authenticated
    # peers. WireGuard still enforces every peer's own AllowedIPs. This avoids
    # reloading DNS/routing when creating a client; it grants no VPN credential.
    interface_networks={ipaddress.ip_interface(a['local']+'/'+str(a['prefixlen'])).network
        for link in addresses for a in link.get('addr_info',[])
        if a.get('family')==('inet' if version==4 else 'inet6') and 'prefixlen' in a
        and not a.get('tentative') and not a.get('dadfailed')}
    excluded=[ipaddress.ip_network(n) for n in bypasses(value,version)]
    if not local or any(not any(a in n for n in excluded) for a in local):
        raise ValueError('Добавьте адреса управления WG в сети обхода')
    lan_addresses={}
    def on_link_return(route,network,address):
        # A home LAN client may arrive through the router's WG while replies
        # go directly over their shared Ethernet. Validate that native path;
        # do not force an unnecessary router/WG hop for the return traffic.
        device=route.get('dev')
        if version!=6 or not device or route.get('gateway') or route.get('via'):
            return False
        if device not in lan_addresses:
            # Unfiltered address output includes link_type; `ip -6 address`
            # deliberately omits link-layer metadata on Linux iproute2.
            rows=json.loads(run(['ip','-j','address','show','dev',device]).stdout)
            valid=len(rows)==1 and rows[0].get('link_type')=='ether' and 'UP' in rows[0].get('flags',[])
            lan_addresses[device]=[ipaddress.ip_interface(a['local']+'/'+str(a['prefixlen']))
                for a in rows[0].get('addr_info',[]) if a.get('family')=='inet6'
                and not a.get('tentative') and not a.get('dadfailed')] if valid else []
        addresses=lan_addresses[device]
        return (ipaddress.ip_address(address) not in [a.ip for a in addresses]
                and any(network.subnet_of(a.network) for a in addresses))
    for client in sources(value,version):
        network=ipaddress.ip_network(client)
        if version==4 and network.prefixlen!=32 and network not in interface_networks:
            raise ValueError('IPv4-сеть источников должна совпадать с сетью выбранного интерфейса WireGuard')
        # A complete interface pool includes IPv4 network/broadcast addresses
        # and the server itself. Check the usable client bounds instead.
        first,last=network.network_address,network.broadcast_address
        if network in interface_networks and network.num_addresses>1:
            if version==4 and network.prefixlen<31:first+=1;last-=1
            elif version==6:first+=1
            while first<=last and first in local:first+=1
            while last>=first and last in local:last-=1
            if first>last:raise ValueError('В сети WireGuard нет адресов для клиентов')
        for address in set((str(first),str(last))):
            route=json.loads(run(['ip','-j',flag,'route','get',address,'mark','0']).stdout)
            if (len(route)!=1 or route[0].get('type','unicast')!='unicast'
                    or ipaddress.ip_address(address) in local or not (
                        route[0].get('dev')==value['interface'] or on_link_return(route[0],network,address))):
                expected='выбранный WG или подключённую LAN' if version==6 else 'выбранный WG'
                raise ValueError('Обратный маршрут к источнику не идёт через '+expected+': '+client)
    if version==6:
        peers=[]
        for line in run(['wg','show',value['interface'],'allowed-ips']).stdout.splitlines():
            fields=line.split()
            peers.append([ipaddress.ip_network(n.rstrip(',')) for n in fields[1:] if n!='(none)'])
        for source in sources(value,6):
            network=ipaddress.ip_network(source)
            if network not in interface_networks and not any(any(n.version==6 and network.subnet_of(n) for n in peer) for peer in peers):
                raise ValueError('IPv6-источник не разрешён ни одному пиру WireGuard: '+source)
    return bypass is not None


def check_service(root,value=None):
    raw=run(['systemctl','show',UNIT,'--property=ExecStartPre,ExecStopPost,CapabilityBoundingSet,DropInPaths,NeedDaemonReload']).stdout
    fields={}
    for line in raw.splitlines():
        if '=' in line:
            key,property_value=line.split('=',1)
            fields[key]=(fields[key]+' ' if key in fields else '')+property_value
    for key,action in [('ExecStartPre','prepare'),('ExecStopPost','cleanup')]:
        token='argv[]=/usr/bin/python3 -E -s -B '+str(root/'vpn_runtime.py')+' '+action+' ; ignore_errors=no'
        if token not in fields.get(key,''):raise ValueError('VPN lifecycle hook missing')
    if ('/etc/systemd/system/'+UNIT+'.d/40-vpn.conf' not in fields.get('DropInPaths','').split()
            or fields.get('NeedDaemonReload')!='no'
            or not {'cap_net_admin','cap_net_raw'}.issubset(fields.get('CapabilityBoundingSet','').lower().split())):
        raise ValueError('VPN lifecycle is not installed persistently')
    if legacy_bypass() is not None and 'OKOPY_VPN_HANDOFF_V1' not in Path('/usr/local/sbin/okopy-tproxy-verify').read_text():
        raise ValueError('Legacy verifier has not been upgraded for explicit VPN handoff')
    if value and value.get('clients_v6') and legacy_bypass(6) is not None:
        if 'OKOPY_VPN_HANDOFF_V2_IPV6' not in Path('/usr/local/sbin/okopy-tproxy-verify').read_text():
            raise ValueError('Legacy IPv6 verifier must support explicit VPN handoff')


def guard_present(version=4):
    return 'table '+family(version)+' '+TABLE in run(['nft','list','tables']).stdout.splitlines()


def set_guard(root,value,opened,version=4):
    stamp=stamp_path(root,'nft',version);present=guard_present(version)
    if present and not stamp.exists():raise ValueError('VPN nft table belongs to another owner')
    script=nft_script(value,opened,version);signature=hashlib.sha256(script.encode()).hexdigest()
    atomic_write(stamp,json.dumps({'ready':False,'signature':signature}).encode())
    run(['nft','-f','-'],input=(f'delete table {family(version)} {TABLE}\n' if present else '')+script)
    actual=normalized(run(['nft','-j','list','table',family(version),TABLE]).stdout)
    atomic_write(stamp,json.dumps({'ready':True,'signature':signature,'rules':actual}).encode())


def verify_guard(root,value,opened,version=4):
    stamp=stamp_path(root,'nft',version)
    if not declared(value,version):
        if guard_present(version) or stamp.exists():raise ValueError('Undeclared VPN capture remains')
        return
    expected=json.loads(stamp.read_text())
    if expected.get('ready') is not True or expected.get('signature')!=hashlib.sha256(nft_script(value,opened,version).encode()).hexdigest():
        raise ValueError('VPN guard differs from declared policy')
    if normalized(run(['nft','-j','list','table',family(version),TABLE]).stdout)!=expected.get('rules'):
        raise ValueError('VPN nft rules changed')


def routing_rows(version=4):
    flag='-'+str(version)
    rules=json.loads(run(['ip','-j',flag,'rule','show']).stdout)
    selected=[r for r in rules if str(r.get('priority'))==PREF or r.get('fwmark')==hex(MARK)]
    result=run(['ip','-j',flag,'route','show','table',ROUTE_TABLE],False)
    if result.returncode:
        if result.returncode==2 and 'FIB table does not exist' in result.stderr:return selected,[]
        raise ValueError('Cannot inspect VPN routing table')
    return selected,json.loads(result.stdout)


def has_hook(rule,table=None,version=4):
    response=iptables(*(['-t',table] if table else []),'-C',*rule,check=False,version=version)
    if response.returncode not in (0,1):raise ValueError('Cannot inspect VPN firewall rule')
    return response.returncode==0


def vacant(version=4):
    rules,routes=routing_rows(version)
    return not rules and not routes and not has_hook(INPUT,version=version) and not has_hook(handoff(version),'mangle',version)


def current(root):
    from candidate_bundle import read_bundle,validate_bundle
    files=read_bundle(root);validate_bundle(files)
    state=json.loads((root/'transaction.json').read_text())
    actual={name:digest(data) for name,data in files.items()}
    expected=state.get('next_files' if state.get('status') in ('confirmed','pending') else 'previous_files')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if state.get('restore_boot_id')==boot and actual==state.get('previous_files'):expected=actual
    if actual!=expected:raise ValueError('VPN refuses an inconsistent candidate bundle')
    return settings(json.loads(files['applied-policy.json']))


def cleanup_family(root,version):
    stamp=stamp_path(root,'installed',version)
    if not stamp.exists():return
    owner=json.loads(stamp.read_text());value=settings({'vpn_ingress':owner['settings']})
    if not declared(value,version):raise ValueError('Invalid VPN ownership scope')
    set_guard(root,value,False,version)
    for rule,table in [(INPUT,None),(handoff(version),'mangle')]:
        for _ in range(8):
            if not has_hook(rule,table,version):break
            iptables(*(['-t',table] if table else []),'-D',*rule,version=version)
    run(['ip','-'+str(version),'rule','del',*RULE],False)
    run(['ip','-'+str(version),'route','del',*local_route(version)],False)
    if not vacant(version):raise ValueError('VPN cleanup incomplete; ownership retained')
    atomic_write(stamp,json.dumps({'settings':{**value,'enabled':False},'legacy':False}).encode())


def cleanup(root):
    errors=[]
    for version in (4,6):
        try:cleanup_family(root,version)
        except Exception as error:errors.append(error)
    if errors:raise errors[0]


def prepare_family(root,value,version):
    stamp=stamp_path(root,'installed',version);nft_stamp=stamp_path(root,'nft',version)
    if not declared(value,version):
        if not vacant(version):raise ValueError('Undeclared reserved VPN resources remain')
        if guard_present(version):
            if not nft_stamp.exists():raise ValueError('Unowned VPN nft table')
            run(['nft','delete','table',family(version),TABLE])
        remove_created_file(nft_stamp);remove_created_file(stamp)
        return
    legacy=preflight(value,allow_missing=True,version=version)
    if not vacant(version):raise ValueError('Reserved VPN resources occupied; nothing replaced')
    atomic_write(stamp,json.dumps({'settings':value,'legacy':legacy}).encode())
    set_guard(root,value,False,version)
    if not value['enabled']:return
    run(['ip','-'+str(version),'route','add',*local_route(version)])
    run(['ip','-'+str(version),'rule','add',*RULE])
    first=next((shlex.split(line) for line in iptables('-S','INPUT',version=version).stdout.splitlines() if line.startswith('-A ')),[])
    position='2' if first==['-A','INPUT','-m','mark','--mark','0x1/0x1','-j','ACCEPT'] else '1'
    iptables('-I',INPUT[0],position,*INPUT[1:],version=version)
    if legacy:iptables('-t','mangle','-I',handoff(version)[0],'1',*handoff(version)[1:],version=version)
    set_guard(root,value,True,version)


def prepare(root):
    value=current(root);cleanup(root)
    try:
        preflight(value,allow_missing=True)
        for version in (4,6):prepare_family(root,value,version)
    except Exception:
        cleanup(root)
        raise


def verify_family(root,value,version):
    verify_guard(root,value,value['enabled'],version)
    stamp=stamp_path(root,'installed',version)
    if not value['enabled'] or not declared(value,version):
        if not vacant(version):raise ValueError('Disabled VPN routing remains')
        if not declared(value,version) and stamp.exists():raise ValueError('Undeclared ownership remains')
        return
    legacy=preflight(value,version=version)
    owner=json.loads(stamp.read_text())
    if owner!={'settings':value,'legacy':legacy}:raise ValueError('VPN ownership differs from policy')
    first=next((shlex.split(line) for line in iptables('-t','mangle','-S',handoff(version)[0],version=version).stdout.splitlines() if line.startswith('-A ')),[]) if legacy else []
    if legacy and first!=['-A',*handoff(version)]:raise ValueError('VPN handoff missing or shadowed')
    rows=[shlex.split(line) for line in iptables('-S','INPUT',version=version).stdout.splitlines() if line.startswith('-A ')]
    index=1 if rows and rows[0]==['-A','INPUT','-m','mark','--mark','0x1/0x1','-j','ACCEPT'] else 0
    if rows.count(['-A',*INPUT])!=1 or rows[index:index+1]!=[['-A',*INPUT]]:
        raise ValueError('VPN INPUT delivery missing, duplicated or shadowed')
    rules,routes=routing_rows(version)
    if (len(rules)!=1 or str(rules[0].get('priority'))!=PREF or rules[0].get('src')!='all'
            or rules[0].get('fwmark')!=hex(MARK) or str(rules[0].get('table'))!=ROUTE_TABLE
            or rules[0].get('fwmask','0xffffffff')!='0xffffffff'):
        raise ValueError('VPN policy routing changed')
    if len(routes)!=1 or routes[0].get('type')!='local' or routes[0].get('dst')!='default' or routes[0].get('dev')!='lo':
        raise ValueError('VPN local delivery changed')


def verify_runtime(root):
    """Caller holds apply and VPN locks; raise on either family's mismatch."""
    value=current(root)
    for version in (4,6):verify_family(root,value,version)
    if value['enabled']:run(['systemctl','is-active','--quiet',UNIT])
    return {'status':'up','enabled':value['enabled'],
            'detail':('VPN-вход, передача владения, INPUT и обратные маршруты согласованы; DNS/HTTPS проверяются отдельно'
                      if value['enabled'] else 'VPN-вход выключен; объявленная область закрыта' if configured(value) else 'VPN-вход не подключён')}


def health(root):
    try:
        with (root/'apply.lock').open('r') as lock, (root/'vpn.lock').open('r') as network_lock:
            fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB);fcntl.flock(network_lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
            return verify_runtime(root)
    except BlockingIOError:
        return {'status':'unknown','detail':'Сейчас применяется VPN-вход; ожидается новый опрос'}
    except Exception:
        return {'status':'down','detail':'VPN-вход не совпадает с политикой; проверьте WG, передачу владения, firewall и маршруты'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['prepare','cleanup','health'])
    args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Root required')
    if args.action=='health':print(json.dumps(health(ROOT),ensure_ascii=False));return
    with (ROOT/'vpn.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        (prepare if args.action=='prepare' else cleanup)(ROOT)


if __name__=='__main__':main()
