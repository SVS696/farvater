"""Owned host firewall/return routes for native candidate LAN listeners.

ExecStartPre prepares before listeners open; ExecStopPost removes after they
close. The independent bundle rollback therefore also restores these rules.
A closed transparent guard survives service stop while targets remain declared.
No NAT, router setting or production service is changed here.
"""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess

from lan_ingress import settings, admitted_sources, DNS_PORT, PROXY_PORT, TPROXY_PORT, CAPTURE_MARK, REPLY_MARK
import lan_transparent as transparent
from safe_apply import ROOT, UNIT, atomic_write, digest, remove_created_file

CHAIN = 'OKOPY_LAN_INPUT'
TABLE = '15454'
PREFS = ('900','901','902','903','904')


def run(args, check=True, *, input=None):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=5, input=input,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})


def check_service(root):
    response = run(['systemctl','show',UNIT,'--property=ExecStartPre,ExecStopPost,CapabilityBoundingSet,DropInPaths,NeedDaemonReload'])
    fields = {}
    for line in response.stdout.splitlines():
        key, _, value = line.partition('='); fields[key] = fields.get(key,'')+' '+value
    for field, action in [('ExecStartPre','prepare'),('ExecStopPost','cleanup')]:
        expected = 'argv[]=/usr/bin/python3 -E -s -B '+str(root/'lan_runtime.py')+' '+action+' ; ignore_errors=no'
        if expected not in fields.get(field,''): raise ValueError('LAN lifecycle hook missing')
    if ('/etc/systemd/system/'+UNIT+'.d/30-lan.conf' not in fields.get('DropInPaths','').split()
            or fields.get('NeedDaemonReload','').strip() != 'no'
            or not {'cap_net_admin','cap_net_raw','cap_net_bind_service'}.issubset(fields.get('CapabilityBoundingSet','').lower().split())):
        raise ValueError('LAN lifecycle is not installed persistently')


def preflight(value):
    if not value['enabled']: return
    addresses = json.loads(run(['ip','-j','-4','address','show','dev',value['interface']]).stdout)
    local = [a for link in addresses for a in link.get('addr_info',[]) if a.get('local') == value['listen']]
    if len(local) != 1: raise ValueError('LAN address is not assigned to the selected interface')
    subnet = ipaddress.ip_network(value['listen']+'/'+str(local[0]['prefixlen']), strict=False)
    gateway = ipaddress.ip_address(value['gateway'])
    if gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address):
        raise ValueError('LAN gateway is not on the selected interface subnet')
    if not value.get('return_via_gateway') and any(ipaddress.ip_network(c).network_address not in subnet for c in value['clients']):
        raise ValueError('Direct LAN clients must belong to the selected interface subnet')


def specs(value):
    if not value['enabled']: return [], [], []
    address, interface = value['listen'], value['interface']
    hooks = [['INPUT','-d',address+'/32','-p','udp','--dport',str(DNS_PORT),'-j',CHAIN],
             ['INPUT','-d',address+'/32','-p','tcp','-m','multiport','--dports',f'{DNS_PORT},{PROXY_PORT}','-j',CHAIN]]
    rules = [['pref',pref,'from',address+'/32','ipproto',proto,'sport',str(port),'lookup',TABLE]
             for pref,proto,port in zip(PREFS,('udp','tcp','tcp'),(DNS_PORT,DNS_PORT,PROXY_PORT))]
    hop = ['via',value['gateway'],'dev',interface,'onlink'] if value.get('return_via_gateway') else ['dev',interface,'scope','link']
    routes = [['table',TABLE,client,*hop] for client in value['clients']]
    if transparent.configured(value):
        hooks[0] = ['INPUT','-d',address+'/32','-p','udp','-m','multiport','--dports',f'{DNS_PORT},{TPROXY_PORT}','-j',CHAIN]
        hooks[1] = ['INPUT','-d',address+'/32','-p','tcp','-m','multiport','--dports',f'{DNS_PORT},{PROXY_PORT},{TPROXY_PORT}','-j',CHAIN]
        hooks.append(['INPUT','-m','mark','--mark',hex(CAPTURE_MARK)+'/0xffffffff','-j',CHAIN])
        rules.extend([['pref','903','fwmark',hex(CAPTURE_MARK),'lookup',transparent.LOCAL_TABLE],
                      ['pref','904','fwmark',hex(REPLY_MARK),'lookup',TABLE]])
        routes.append(['table',transparent.LOCAL_TABLE,'local','0.0.0.0/0','dev','lo'])
    return hooks, rules, routes


def vacant():
    if '-N '+CHAIN in run(['iptables','-w','2','-S']).stdout.splitlines(): return False
    for table in (TABLE,transparent.LOCAL_TABLE):
        if run(['ip','-4','route','show','table',table],False).stdout.strip(): return False
    rules = run(['ip','-4','rule','show']).stdout
    return not any(line.partition(':')[0] in PREFS for line in rules.splitlines())


def hook_position():
    # The installed production TPROXY verifier requires its mark accept first.
    # LAN traffic is not TPROXY-marked; the native source guard additionally
    # rejects non-admitted clients before DNS or outbound selection.
    rules = [shlex.split(line) for line in run(['iptables','-w','2','-S','INPUT']).stdout.splitlines()
             if line.startswith('-A ')]
    return 2 if rules and rules[0] == ['-A','INPUT','-m','mark','--mark','0x1/0x1','-j','ACCEPT'] else 1


def cleanup(root):
    path = root/'lan-installed.json'
    if not path.exists(): return
    # Only remove a deployment recorded before this adapter's first mutation.
    value = settings({'lan_ingress':json.loads(path.read_text())})
    hooks, rules, routes = specs(value)
    if transparent.configured(value):
        # Keep selected traffic blocked while sockets/routes are absent.
        transparent.set_guard(root,value,False,run)
    for rule in hooks:
        for _ in range(8):
            exists = run(['iptables','-w','2','-C',*rule],False)
            if exists.returncode == 1: break
            if exists.returncode: raise ValueError('Cannot inspect LAN firewall hook')
            run(['iptables','-w','2','-D',*rule])
    if run(['iptables','-w','2','-S',CHAIN],False).returncode == 0:
        run(['iptables','-w','2','-F',CHAIN]);run(['iptables','-w','2','-X',CHAIN])
    for rule in rules: run(['ip','-4','rule','del',*rule],False)
    for route in routes: run(['ip','-4','route','del',*route],False)
    if not vacant(): raise ValueError('LAN cleanup incomplete; ownership record retained')
    if transparent.configured(value):
        atomic_write(path,json.dumps({**value,'enabled':False}).encode())
    else:
        remove_created_file(path)


def current(root):
    from candidate_bundle import read_bundle, validate_bundle
    files = read_bundle(root); validate_bundle(files)
    state = json.loads((root/'transaction.json').read_text())
    actual = {name:digest(data) for name,data in files.items()}
    expected = state.get('next_files' if state.get('status') in ('confirmed','pending') else 'previous_files')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if state.get('restore_boot_id') == boot and actual == state.get('previous_files'): expected = actual
    if actual != expected: raise ValueError('LAN refuses an inconsistent candidate bundle')
    return settings(json.loads(files['applied-policy.json']))


def prepare(root):
    value = current(root)
    cleanup(root)
    if not value['enabled']:
        if transparent.configured(value):
            atomic_write(root/'lan-installed.json',json.dumps(value).encode())
            transparent.set_guard(root,value,False,run)
        else:
            transparent.clear(root,run);remove_created_file(root/'lan-installed.json')
        return
    preflight(value)
    if not vacant(): raise ValueError('Reserved LAN resources are occupied; nothing replaced')
    # Durable ownership precedes every kernel operation, including partial start.
    atomic_write(root/'lan-installed.json',json.dumps(value).encode())
    hooks, rules, routes = specs(value)
    try:
        run(['iptables','-w','2','-N',CHAIN])
        for client in admitted_sources(value):
            run(['iptables','-w','2','-A',CHAIN,'-i',value['interface'],'-s',client,'-j','ACCEPT'])
        run(['iptables','-w','2','-A',CHAIN,'-j','DROP'])
        for route in routes: run(['ip','-4','route','add',*route])
        for rule in rules: run(['ip','-4','rule','add',*rule])
        position = str(hook_position())
        for rule in hooks: run(['iptables','-w','2','-I',rule[0],position,*rule[1:]])
        if transparent.configured(value):transparent.set_guard(root,value,True,run)
        else:transparent.clear(root,run)
    except Exception:
        cleanup(root)
        raise


def verify_runtime(root):
    """Verify LAN state while the caller owns apply.lock and lan.lock."""
    value = current(root)
    if not value['enabled']:
        transparent.verify(root,value,False,run)
        if (not transparent.configured(value) and (root/'lan-installed.json').exists()) or not vacant():
            raise ValueError('LAN выключен, но сетевые правила не очищены')
        return {'status':'up','detail':('LAN-вход выключен; прозрачные назначения заблокированы до восстановления входа или удаления списка'
                if transparent.configured(value) else 'LAN-вход выключен; его сетевые правила отсутствуют')}
    if settings({'lan_ingress':json.loads((root/'lan-installed.json').read_text())}) != value:
        raise ValueError('Runtime differs from policy')
    hooks, rules, routes = specs(value)
    actual = [shlex.split(line) for line in run(['iptables','-w','2','-S',CHAIN]).stdout.splitlines()]
    expected = [['-N',CHAIN], *[['-A',CHAIN,'-s',client,'-i',value['interface'],'-j','ACCEPT'] for client in admitted_sources(value)], ['-A',CHAIN,'-j','DROP']]
    if actual != expected: raise ValueError('LAN ACL drift')
    for hook in hooks: run(['iptables','-w','2','-C',*hook])
    actual_rules = json.loads(run(['ip','-j','-4','rule','show']).stdout)
    selected = [r for r in actual_rules if str(r.get('priority')) in PREFS]
    if len(selected) != (5 if transparent.configured(value) else 3): raise ValueError('LAN return rule missing')
    for row,pref,proto,port in zip(sorted(selected,key=lambda r:r['priority']),PREFS,('udp','tcp','tcp'),(DNS_PORT,DNS_PORT,PROXY_PORT)):
        if (row.get('src') != value['listen'] or str(row.get('table')) != TABLE
                or row.get('ipproto') != proto or str(row.get('sport')) != str(port)):
            raise ValueError('LAN return rule drift')
    actual_routes = json.loads(run(['ip','-j','-4','route','show','table',TABLE]).stdout)
    expected_routes = {(c.removesuffix('/32'),value['gateway'] if value.get('return_via_gateway') else None,value['interface']) for c in value['clients']}
    if {(r.get('dst'),r.get('gateway'),r.get('dev')) for r in actual_routes} != expected_routes or len(actual_routes)!=len(expected_routes):
        raise ValueError('LAN return route drift')
    if transparent.configured(value):
        for pref,mark,table in [('903',CAPTURE_MARK,transparent.LOCAL_TABLE),('904',REPLY_MARK,TABLE)]:
            row=next(r for r in selected if str(r['priority'])==pref)
            if row.get('src')!='all' or row.get('fwmark')!=hex(mark) or str(row.get('table'))!=table:
                raise ValueError('Transparent policy routing drift')
        local=json.loads(run(['ip','-j','-4','route','show','table',transparent.LOCAL_TABLE]).stdout)
        if len(local)!=1 or local[0].get('type')!='local' or local[0].get('dst')!='default' or local[0].get('dev')!='lo':
            raise ValueError('Transparent local route drift')
    transparent.verify(root,value,True,run)
    run(['systemctl','is-active','--quiet',UNIT])
    return {'status':'up','detail':'LAN-вход: служба, список устройств и обратные маршруты согласованы. Доступ с клиента проверяется отдельно.'}


def health(root):
    try:
        with (root/'apply.lock').open('r') as lock:
            fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
            with (root/'lan.lock').open('r') as network_lock:
                fcntl.flock(network_lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
                return verify_runtime(root)
    except BlockingIOError:
        return {'status':'unknown','detail':'Сейчас меняется конфигурация или LAN-вход; ожидается новый опрос'}
    except Exception as error:
        detail=('LAN выключен, но сетевые правила не очищены' if str(error)=='LAN выключен, но сетевые правила не очищены'
                else 'LAN-вход не совпадает с политикой или недоступен; проверьте службу, firewall и маршруты')
        return {'status':'down','detail':detail}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','cleanup','health'])
    args = parser.parse_args()
    if os.geteuid() != 0: raise SystemExit('Root required')
    if args.action == 'health':
        print(json.dumps(health(ROOT),ensure_ascii=False));return
    with (ROOT/'lan.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        (prepare if args.action == 'prepare' else cleanup)(ROOT)


if __name__ == '__main__': main()
