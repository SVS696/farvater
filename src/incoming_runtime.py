"""Lifecycle and owned firewall ports of incoming protocol modules.

Invoked by the core unit: prepare (closed capture), activate (engines + capture),
cleanup (close capture, stop engines, remove owned networking). Apply rollback
uses the same hooks with the previous canonical policy.
"""
import fcntl
import hashlib
import json
import ipaddress
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

from incoming_kernel import entries as kernel_entries,scopes,validate,nft_script,TABLE,ROUTE_TABLE,PREF,MARK,SOCKS_UDP_MARK
from safe_apply import ROOT,atomic_write
import incoming_awg_runtime as awg
import incoming_ocserv_runtime as ocserv

ENGINES={'amneziawg':awg,'openconnect-server':ocserv}

RUNTIME=Path('/run/farvater/incoming')
COMMENT='farvater-incoming'


def run(args,*,data=None,check=True):
    r=subprocess.run(args,input=data,capture_output=True,text=True,timeout=8)
    if check and r.returncode:raise ValueError('Не выполнена операция входящего модуля: '+args[0])
    return r


def policy(root):return json.loads((root/'applied-policy.json').read_text())
def fingerprint(value):return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
def rule():return ['pref',PREF,'fwmark',hex(MARK),'lookup',ROUTE_TABLE]
def route(v):return ['table',ROUTE_TABLE,'local','0.0.0.0/0' if v==4 else '::/0','dev','lo']
def iptables(v):return ['iptables' if v==4 else 'ip6tables','-w','2']
def marked():return ['-m','mark','--mark',hex(MARK),'-m','comment','--comment',COMMENT,'-j','ACCEPT']
def public(port):
    destination=['-d',port['listen']] if isinstance(port,dict) and port.get('listen') and not ipaddress.ip_address(port['listen']).is_unspecified else []
    return destination+['-p',port['protocol'] if isinstance(port,dict) else 'udp','--dport',str(port['port'] if isinstance(port,dict) else port),'-m','comment','--comment',COMMENT,'-j','ACCEPT']


def entries(value):
    from incoming_connections import compile_entries, PREFIX
    compiled={n['tag'] for n in compile_entries(value.get('incoming_connections',[]))}
    return [e for e in value.get('incoming_connections',[]) if e['enabled'] and
            (e['native']['type'] in ENGINES or PREFIX+e['id'] in compiled)]


def listeners(active):
    result=[]
    for e in active:
        n=e['native'];kind=n['type']
        if kind=='amneziawg':protocols=['udp']
        elif kind=='openconnect-server':protocols=['tcp','udp'] if n['dtls'] else ['tcp']
        elif kind=='openvpn-server':protocols=[n.get('network','udp')]
        elif kind=='shadowsocks':protocols=[n['network']] if n.get('network') else ['tcp','udp']
        else:protocols=['tcp']
        for protocol in protocols:
            port={'port':n['listen_port'],'protocol':protocol}
            if kind not in ENGINES:port['listen']=n['listen']
            result.append(port)
    return result


def input_rules(s,version):
    rules=[marked()] if s['scopes'] else []
    if s.get('socks_udp'):rules.append(['-p','udp','-m','mark','--mark',hex(SOCKS_UDP_MARK),'-m','comment','--comment',COMMENT,'-j','ACCEPT'])
    for p in s['ports']:
        address=ipaddress.ip_address(p['listen']) if 'listen' in p else None
        # A wildcard IPv6 Go listener also accepts IPv4 on Linux.
        if address is None or address.version==version or str(address)=='::':rules.append(public(p))
    return rules


def directory():
    RUNTIME.mkdir(mode=0o700,parents=True,exist_ok=True)
    if RUNTIME.is_symlink() or RUNTIME.stat().st_uid!=0 or RUNTIME.stat().st_mode&0o077:raise ValueError('Небезопасный каталог состояния входов')


def read_state():
    p=RUNTIME/'state.json'
    if not p.exists():return None
    if p.is_symlink() or p.stat().st_uid!=0 or p.stat().st_mode&0o077:raise ValueError('Небезопасная запись состояния входов')
    s=json.loads(p.read_text());validate(s['scopes'])
    required={'scopes','ids','ports','digest','opened'}
    if not required<=set(s) or set(s)-required-{'kinds','socks_udp'} or type(s['opened']) is not bool or type(s.get('socks_udp',False)) is not bool:raise ValueError('Повреждена запись состояния входов')
    s.setdefault('kinds',['amneziawg']*len(s['ids']))
    from incoming_kernel import interface_name
    from ocserv_incoming import device_prefix
    if len(s['kinds'])!=len(s['ids']) or any(k not in ENGINES for k in s['kinds']):raise ValueError('Повреждены типы входящих модулей')
    expected=[device_prefix(v)+'*' if k=='openconnect-server' else interface_name(v) for v,k in zip(s['ids'],s['kinds'])]
    if expected!=[v['interface'] for v in s['scopes']]:raise ValueError('Интерфейсы не соответствуют записи запуска')
    s['ports']=[{'port':p,'protocol':'udp'} if type(p) is int else p for p in s['ports']]
    for p in s['ports']:
        if not isinstance(p,dict) or set(p) not in ({'port','protocol'},{'port','protocol','listen'}) or p['protocol'] not in ('tcp','udp') or type(p['port']) is not int or not 1<=p['port']<=65535:raise ValueError('Повреждены порты входов')
        if 'listen' in p:ipaddress.ip_address(p['listen'])
    return s


def save_state(s):directory();atomic_write(RUNTIME/'state.json',json.dumps(s).encode())


def capture(s,opened):
    if not s['scopes'] and not s.get('socks_udp'):return
    exists=run(['nft','list','table','inet',TABLE],check=False).returncode==0
    script=('delete table inet '+TABLE+'\n' if exists else '')+nft_script(s['scopes'],opened,s.get('socks_udp',False))
    run(['nft','-f','-'],data=script)


def check_service(root):
    expected=str(root/'incoming_runtime.py')
    unit=run(['systemctl','cat','okopy-candidate.service']).stdout
    for action in ('prepare','activate','cleanup'):
        if expected+' '+action not in unit:raise ValueError('Сначала установите системный адаптер входящих модулей')


def preflight(value,*,validate_native=True):
    active=entries(value);declared=scopes(active)
    if not active:return
    socks_udp=any(e['native']['type']=='socks' for e in active)
    for e in active:
        if e['native']['type'] in ENGINES:ENGINES[e['native']['type']].preflight(e,validate_native=validate_native)
    state=read_state()
    if not state:
        if (declared or socks_udp) and run(['nft','list','table','inet',TABLE],check=False).returncode==0:raise ValueError('Таблица входов уже существует без записи владения')
        for v in (4,6):
            if declared:
                rows=json.loads(run(['ip','-'+str(v),'-N','-j','rule','show']).stdout)
                if any(str(r.get('priority'))==PREF or str(r.get('table'))==ROUTE_TABLE for r in rows):raise ValueError('Приоритет или таблица маршрутизации входов уже заняты')
                rows=json.loads(run(['ip','-'+str(v),'-N','-j','route','show','table','all']).stdout)
                if any(str(r.get('table'))==ROUTE_TABLE for r in rows):raise ValueError('Таблица маршрутизации входов уже занята')
            for rule_value in input_rules({'scopes':declared,'ports':listeners(active),'socks_udp':socks_udp},v):
                if run([*iptables(v),'-C','INPUT',*rule_value],check=False).returncode==0:raise ValueError('Правило сетевого экрана входов уже существует без записи владения')
    ports=[e['native']['listen_port'] for e in active]
    if len(set(ports))!=len(ports):raise ValueError('Входящие VPN-серверы используют одинаковый порт')
    # Validate generated nft syntax without applying it.
    prefix='delete table inet '+TABLE+'\n' if (declared or socks_udp) and state and run(['nft','list','table','inet',TABLE],check=False).returncode==0 else ''
    if declared or socks_udp:run(['nft','--check','-f','-'],data=prefix+nft_script(declared,True,socks_udp))


def cleanup():
    s=read_state()
    if s is None:return
    capture(s,False)
    for identifier,kind in reversed(list(zip(s['ids'],s['kinds']))):ENGINES[kind].stop(identifier)
    for v in (4,6):
        for r in input_rules(s,v):
            if run([*iptables(v),'-C','INPUT',*r],check=False).returncode==0:run([*iptables(v),'-D','INPUT',*r])
        if s['scopes']:
            run(['ip','-'+str(v),'rule','del',*rule()],check=False)
            run(['ip','-'+str(v),'route','del',*route(v)],check=False)
    if s['scopes'] or s.get('socks_udp'):run(['nft','delete','table','inet',TABLE])
    (RUNTIME/'state.json').unlink()


def prepare(root):
    cleanup()
    active=entries(policy(root))
    if not active:return
    preflight(policy(root),validate_native=False)
    engines=kernel_entries(policy(root))
    s={'ids':[e['id'] for e in engines],'kinds':[e['native']['type'] for e in engines],'scopes':scopes(active),'ports':listeners(active), 'digest':fingerprint(active),'opened':False,'socks_udp':any(e['native']['type']=='socks' for e in active)}
    save_state(s)
    try:
        capture(s,False)
        for v in (4,6):
            if s['scopes']:
                run(['ip','-'+str(v),'route','add',*route(v)])
                run(['ip','-'+str(v),'rule','add',*rule()])
            for r in input_rules(s,v):run([*iptables(v),'-I','INPUT','1',*r])
    except Exception:cleanup();raise


def wait_core(root):
    c=json.loads((root/'config.json').read_text())['experimental']['clash_api']
    request=urllib.request.Request('http://'+c['external_controller']+'/version',headers={'Authorization':'Bearer '+c['secret']})
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        try:
            with urllib.request.urlopen(request,timeout=.4) as response:json.loads(response.read())
            return
        except (OSError,ValueError):time.sleep(.1)
    raise ValueError('Ядро политики не готово; входящие модули остаются закрыты')


def activate(root):
    s=read_state();active=entries(policy(root))
    if not active:
        if s is not None:raise ValueError('Осталась запись запуска удалённых входов')
        return
    if s is None or s['digest']!=fingerprint(active) or s['opened']:raise ValueError('Сначала подготовьте текущую конфигурацию входов')
    wait_core(root)
    try:
        for e in active:
            if e['native']['type'] in ENGINES:ENGINES[e['native']['type']].start(e)
        capture(s,True);s['opened']=True;save_state(s)
    except Exception:cleanup();raise


def verify(root):
    active=entries(policy(root));s=read_state()
    if not active:
        if s is not None:raise ValueError('Удалённые входящие модули ещё запущены')
        return
    if s is None or not s['opened'] or s['digest']!=fingerprint(active):raise ValueError('Входящие модули не соответствуют применённой политике')
    if s.get('socks_udp',False)!=any(e['native']['type']=='socks' for e in active):raise ValueError('Повторно примените настройки входящих SOCKS для поддержки UDP')
    for v in (4,6):
        for r in input_rules(s,v):run([*iptables(v),'-C','INPUT',*r])
    if s['scopes'] or s.get('socks_udp'):run(['nft','list','table','inet',TABLE])
    for e in active:
        if e['native']['type'] not in ENGINES:continue
        if e['native']['type']=='openconnect-server':
            ocserv.verify(e);continue
        path,state=awg.receipt(e['id'])
        raw=awg.stripped(awg.server_model(e['native'],e.get('disabled_clients',[])))
        if not state or state['digest']!=hashlib.sha256(raw.encode()).hexdigest():raise ValueError('Сервер AmneziaWG не соответствует применённым настройкам')
        run(['ip','link','show','dev',state['interface']])


def main():
    if os.geteuid()!=0:raise ValueError('Нужны права root')
    action=sys.argv[1]
    if action not in ('prepare','activate','cleanup'):raise ValueError('Неизвестное действие')
    directory()
    with (RUNTIME/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        (cleanup() if action=='cleanup' else (prepare if action=='prepare' else activate)(ROOT))

if __name__=='__main__':
    try:main()
    except Exception as error:
        # Errors contain operation names and validated networks, never config keys.
        print(str(error),file=sys.stderr);sys.exit(1)
