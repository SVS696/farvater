"""Optional ocserv instance lifecycle. Common ingress owns capture and ports.

ocserv runs in its own restricted unit because its unprivileged workers need
uid/gid separation. The policy core keeps its existing capability boundary.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from ocserv_incoming import validate,render_config,device_prefix
from incoming_kernel import ocserv_scope
from safe_apply import atomic_write

ENGINE=Path('/opt/farvater/engines/ocserv/current')
RUNTIME=Path('/run/farvater/incoming-ocserv')
FILES=Path('/run/farvater-ocserv')


def command(args,*,data=None,required=True,timeout=8):
    result=subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout,
        env={**os.environ,'LD_LIBRARY_PATH':str(ENGINE/'usr/lib/x86_64-linux-gnu')})
    if required and result.returncode:raise ValueError('Операция сервера OpenConnect не выполнена: '+str(args[0]))
    return result


def unit(identifier):device_prefix(identifier);return 'farvater-incoming-ocserv@'+identifier+'.service'
def digest(entry):return hashlib.sha256(json.dumps(entry,sort_keys=True).encode()).hexdigest()


def directory(path,mode):
    try:
        path.mkdir(parents=True,mode=mode)
        path.chmod(mode)
    except FileExistsError:pass
    if path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode&0o777!=mode:
        raise ValueError('Небезопасные права каталога сервера OpenConnect')


def receipt(identifier):
    device_prefix(identifier);directory(RUNTIME,0o700);path=RUNTIME/(identifier+'.json')
    if not path.exists():return path,None
    if path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode&0o077:
        raise ValueError('Небезопасная запись запуска OpenConnect')
    s=json.loads(path.read_text())
    if set(s)!={'id','prefix','digest','listen','listen_port','dtls'} or s['id']!=identifier or s['prefix']!=device_prefix(identifier):
        raise ValueError('Некорректная запись запуска OpenConnect')
    ipaddress.ip_address(s['listen'])
    if type(s['listen_port']) is not int or not 1<=s['listen_port']<=65535 or type(s['dtls']) is not bool:
        raise ValueError('Некорректные порты записи запуска OpenConnect')
    return path,s


def interfaces(prefix):
    rows=json.loads(command(['ip','-j','link','show']).stdout)
    return [r['ifname'] for r in rows if r['ifname'].startswith(prefix)]


def write_files(entry,path):
    n=validate(entry['native']);directory(path,0o711)
    for name,value in [('ocserv.conf',render_config(n,path,device_prefix(entry['id']))),
                       ('server.pem',n['certificate']),('key.pem',n['private_key'])]:
        atomic_write(path/name,value.encode())
    atomic_write(path/'ocpasswd',b'')
    for user in n['users']:
        if user['username'] not in entry.get('disabled_clients',[]):
            if user['password']:
                command([str(ENGINE/'usr/bin/ocpasswd'),'-c',str(path/'ocpasswd'),user['username']],data=user['password']+'\n'+user['password']+'\n')
            else:
                with (path/'ocpasswd').open('a') as stream:stream.write(user['username']+':*:'+user['password_hash']+'\n')
    (path/'ocpasswd').chmod(0o600)


def preflight(entry,*,validate_native=True):
    n=validate(entry['native']);scope=ocserv_scope(entry);prefix=device_prefix(entry['id'])
    for name in ('usr/sbin/ocserv','usr/sbin/ocserv-worker','usr/bin/ocpasswd','usr/bin/occtl'):
        if not (ENGINE/name).is_file():raise ValueError('Установите движок модуля OpenConnect (ocserv)')
    path,state=receipt(entry['id'])
    existing=interfaces(prefix)
    if existing and not state:raise ValueError('Префикс интерфейсов OpenConnect занят другим подключением')
    claims=[ipaddress.ip_network(p) for p in n['pools']]
    for family in ('-4','-6'):
        rows=json.loads(command(['ip',family,'-N','-j','route','show','table','all']).stdout)
        for row in rows:
            if state and row.get('dev') in existing:continue
            value=row.get('dst','default')
            if value=='default':continue
            try:network=ipaddress.ip_network(value,strict=False)
            except ValueError:continue
            if any(network.version==p.version and network.overlaps(p) for p in claims):
                raise ValueError('Пул OpenConnect пересекается с существующим маршрутом: '+str(network))
    for transport,socktype in [('tcp',socket.SOCK_STREAM),('udp',socket.SOCK_DGRAM)]:
        if transport=='udp' and not n['dtls']:continue
        if state and state['listen']==n['listen'] and state['listen_port']==n['listen_port'] and (transport=='tcp' or state['dtls']):continue
        family=socket.AF_INET6 if ':' in n['listen'] else socket.AF_INET
        with socket.socket(family,socktype) as probe:
            # Match TCP listener restart semantics: a closed session in
            # TIME_WAIT is not another server occupying the port.
            if transport=='tcp':probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try:
                probe.bind((n['listen'],n['listen_port']))
                if transport=='tcp':probe.listen(1)
            except OSError:raise ValueError('Адрес или '+transport.upper()+'-порт OpenConnect уже занят или недоступен') from None
    if validate_native:
        directory(FILES,0o711)
        with tempfile.TemporaryDirectory(prefix='validate-',dir=FILES) as temporary:
            p=Path(temporary);p.chmod(0o711);write_files(entry,p)
            command([str(ENGINE/'usr/sbin/ocserv'),'-t','-c',str(p/'ocserv.conf')])
    return scope


def stop(identifier):
    path,state=receipt(identifier)
    if state is None:
        if command(['systemctl','is-active','--quiet',unit(identifier)],required=False).returncode==0 or interfaces(device_prefix(identifier)):
            raise ValueError('Нет записи владения сервером OpenConnect; остановка запрещена')
        return
    command(['systemctl','stop',unit(identifier)],timeout=15)
    if command(['systemctl','is-active','--quiet',unit(identifier)],required=False).returncode==0:
        raise ValueError('Сервер OpenConnect не остановлен')
    for name in interfaces(state['prefix']):command(['ip','link','delete','dev',name])
    target=FILES/identifier
    if target.is_symlink():raise ValueError('Небезопасный каталог экземпляра OpenConnect')
    if target.exists():shutil.rmtree(target)
    path.unlink()


def start(entry):
    if entry.get('enabled') is not True:raise ValueError('Сервер OpenConnect выключен')
    scope=preflight(entry,validate_native=False);identifier=entry['id'];path,state=receipt(identifier)
    if state is not None:raise ValueError('Сначала остановите предыдущий экземпляр сервера OpenConnect')
    target=FILES/identifier;directory(FILES,0o711)
    if target.exists():raise ValueError('Каталог экземпляра OpenConnect уже существует без записи запуска')
    if command(['systemctl','is-active','--quiet',unit(identifier)],required=False).returncode==0:
        raise ValueError('Служба OpenConnect уже запущена без записи владения')
    n=entry['native']
    atomic_write(path,json.dumps({'id':identifier,'prefix':device_prefix(identifier),'digest':digest(entry),
        'listen':n['listen'],'listen_port':n['listen_port'],'dtls':n['dtls']}).encode())
    try:
        write_files(entry,target)
        command(['systemctl','start',unit(identifier)],timeout=15)
        for _ in range(50):
            if (target/'occtl.sock').exists():break
            time.sleep(.1)
        else:raise ValueError('Сервер OpenConnect не создал сокет управления')
        verify(entry)
    except Exception:
        stop(identifier);raise
    return scope


def verify(entry):
    path,state=receipt(entry['id'])
    if state is None or state['digest']!=digest(entry):raise ValueError('Сервер OpenConnect не соответствует применённой политике')
    command(['systemctl','is-active','--quiet',unit(entry['id'])])
    # The occtl socket belongs to the unprivileged worker account. The policy
    # core deliberately lacks DAC_OVERRIDE, so check the actual TLS listener
    # and certificate instead of widening that core's filesystem privileges.
    n=entry['native'];host={'0.0.0.0':'127.0.0.1','::':'::1'}.get(n['listen'],n['listen'])
    first=n['certificate'].split('-----END CERTIFICATE-----',1)[0]+'-----END CERTIFICATE-----'
    expected=hashlib.sha256(ssl.PEM_cert_to_DER_cert(first)).digest()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    try:
        with socket.create_connection((host,n['listen_port']),timeout=3) as connection:
            with context.wrap_socket(connection,server_hostname=None) as secured:
                if hashlib.sha256(secured.getpeercert(binary_form=True)).digest()!=expected:raise ValueError('OpenConnect отвечает с другим сертификатом')
    except OSError:raise ValueError('Сервер OpenConnect не завершил TLS-проверку готовности') from None
