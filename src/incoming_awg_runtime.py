"""One optional AWG server engine, with owned interfaces and return routes.

The common ingress controller must close capture before start/stop and open it
only after the shared policy core is ready. No host DNS or default route writes.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from amnezia_incoming import validate,server_model
from amnezia_native import BIN,stripped,native as native_check
from incoming_kernel import awg_scope,interface_name
from safe_apply import atomic_write

RUNTIME=Path('/run/farvater/incoming-awg')
PROTOCOL='187'


def command(args,*,data=None,required=True,timeout=8):
    result=subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout)
    if required and result.returncode:raise ValueError('Операция движка AmneziaWG не выполнена: '+str(args[0]))
    return result


def private_directory():
    RUNTIME.mkdir(mode=0o700,parents=True,exist_ok=True)
    if RUNTIME.is_symlink() or RUNTIME.stat().st_uid!=0 or RUNTIME.stat().st_mode&0o077:raise ValueError('Каталог состояния AmneziaWG должен принадлежать root и быть закрытым')


def receipt(identifier):
    private_directory();path=RUNTIME/(interface_name(identifier)+'.json')
    if not path.exists():return path,None
    if path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode&0o077:raise ValueError('Небезопасная запись состояния AmneziaWG')
    value=json.loads(path.read_text())
    if value.get('id')!=identifier or value.get('interface')!=interface_name(identifier):raise ValueError('Запись состояния другого интерфейса')
    return path,value


def preflight(entry,*,validate_native=True):
    n=validate(entry['native']);scope=awg_scope(entry);name=scope['interface']
    for executable in ('awg','amneziawg-go'):
        if not (BIN/executable).is_file():raise ValueError('Установите движок модуля AmneziaWG')
    path,state=receipt(entry['id'])
    exists=command(['ip','link','show','dev',name],required=False).returncode==0
    if exists and not state:raise ValueError('Имя интерфейса занято вне этого модуля')
    # Return routes must not capture an existing LAN, VPN or local host address.
    claims=[ipaddress.ip_network(v) for v in scope['sources']]
    claims.extend(ipaddress.ip_interface(v).network for v in n['interface']['Address'])
    for family in ('-4','-6'):
        rows=json.loads(command(['ip',family,'-N','-j','route','show','table','all']).stdout)
        for row in rows:
            if row.get('dev')==name and state:continue
            value=row.get('dst','default')
            if value=='default':continue
            try:network=ipaddress.ip_network(value,strict=False)
            except ValueError:continue
            if any(network.version==c.version and network.overlaps(c) for c in claims):
                raise ValueError('Пул AmneziaWG пересекается с существующим маршрутом: '+str(network))
    current_port=int(command([str(BIN/'awg'),'show',name,'listen-port']).stdout.strip()) if exists else None
    if current_port!=n['listen_port']:
        # AWG listens on wildcard UDP. A collision must fail before apply.
        with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as probe:
            probe.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
            try:probe.bind(('::',n['listen_port']))
            except OSError:raise ValueError('UDP-порт сервера AmneziaWG уже занят') from None
    if validate_native:native_check(server_model(n,entry.get('disabled_clients',[])))
    return scope


def stop(identifier):
    path,state=receipt(identifier);name=interface_name(identifier)
    if state is None:
        if command(['ip','link','show','dev',name],required=False).returncode==0:raise ValueError('Нет записи владения интерфейсом; удаление запрещено')
        return
    # Kernel removes only this interface's connected and explicit return routes.
    command(['ip','link','delete','dev',name],required=False)
    if command(['ip','link','show','dev',name],required=False).returncode==0:raise ValueError('Интерфейс AmneziaWG не остановлен')
    for _ in range(40):
        if not Path('/run/amneziawg',name+'.sock').exists():break
        time.sleep(.05)
    else:raise ValueError('Движок AmneziaWG ещё завершает работу')
    path.unlink()


def start(entry):
    if entry.get('enabled') is not True:raise ValueError('Сервер AmneziaWG выключен')
    # setconf below validates the official engine directly. The service does
    # not need CAP_SYS_ADMIN for an additional nested validation namespace.
    scope=preflight(entry,validate_native=False);name=scope['interface'];path,state=receipt(entry['id'])
    if state is not None:raise ValueError('Сначала остановите предыдущий экземпляр сервера')
    model=server_model(entry['native'],entry.get('disabled_clients',[]))
    raw=stripped(model)
    atomic_write(path,json.dumps({'id':entry['id'],'interface':name,'digest':hashlib.sha256(raw.encode()).hexdigest()}).encode())
    try:
        command([str(BIN/'amneziawg-go'),name],timeout=6)
        for _ in range(60):
            if Path('/run/amneziawg',name+'.sock').exists():break
            time.sleep(.05)
        else:raise ValueError('Управляющий сокет сервера не появился')
        command([str(BIN/'awg'),'setconf',name,'/dev/stdin'],data=raw)
        for address in model['interface']['Address']:command(['ip','address','add',address,'dev',name,'noprefixroute'])
        command(['ip','link','set','dev',name,'addrgenmode','none'])
        Path('/proc/sys/net/ipv4/conf',name,'rp_filter').write_text('2')
        command(['ip','link','set','dev',name,'mtu',str(model['interface'].get('MTU',1280)),'up'])
        for network in scope['sources']:
            command(['ip','-6' if ':' in network else '-4','route','add',network,'dev',name,'proto',PROTOCOL])
    except Exception:
        stop(entry['id']);raise
    return scope
