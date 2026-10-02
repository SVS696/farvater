"""Prepare the private runtime config, then drop privileges and exec the client."""
import fcntl
import json
import os
from pathlib import Path
import pwd
import sys
import time
from safe_apply import atomic_write,digest
from wireguard_control import read_private
from openconnect_control import identifier
from trusttunnel_apply import Transaction,state,PENDING
from trusttunnel_runtime import ROOT,LinuxBackend,installation
from trusttunnel_profile import validate,render

RUNTIME=Path('/run/okopy-trusttunnel')


def prepare(root,name,binding,backend=None,runtime=RUNTIME):
    backend=backend or LinuxBackend(root,binding,name);tx=state(root)
    relevant=tx.get('connection')==name and tx.get('status') in PENDING
    if relevant and (tx['boot_id']!=backend.boot_id() or time.time()>=tx['deadline']):
        with (root/'control.lock').open('a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('Возврат TrustTunnel ещё занят; вход не выполнялся') from None
            Transaction(root,binding,name,backend).rollback(tx['id'],before_start=True)
        relevant=False
    raw=read_private(root/(name+'.active.json'));model=validate(json.loads(raw),ready=True)
    if json.loads(read_private(root/(name+'.installation.json')))!=installation(root,binding):raise ValueError('Установка TrustTunnel изменена вне панели')
    if relevant:
        expected=tx['previous_sha256'] if tx.get('recovering') else tx['next_sha256']
        if digest(raw)!=expected:raise ValueError('Модель TrustTunnel не соответствует операции')
        if not tx.get('recovering'):
            if not tx['target_active']:raise ValueError('Служба должна оставаться выключенной')
            path=root/'revisions'/tx['id']/'attempted'
            try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            except FileExistsError:raise ValueError('Повторный вход с неподтверждёнными параметрами остановлен') from None
            with os.fdopen(fd,'w') as f:f.write('attempted');f.flush();os.fsync(f.fileno())
    account=pwd.getpwnam(binding['user'])
    if account.pw_uid!=binding['uid'] or account.pw_uid==0:raise ValueError('Непривилегированный пользователь клиента изменился')
    runtime.mkdir(mode=0o755,exist_ok=True)
    if runtime.is_symlink() or runtime.stat().st_uid!=0 or runtime.stat().st_mode&0o022:raise ValueError('Небезопасный каталог запуска TrustTunnel')
    runtime.chmod(0o755)
    directory=runtime/name;directory.mkdir(mode=0o750,exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid!=0 or directory.stat().st_mode&0o027:raise ValueError('Небезопасный каталог параметров TrustTunnel')
    os.chown(directory,0,account.pw_gid);directory.chmod(0o750)
    config=directory/'client.toml';atomic_write(config,render(model,binding).encode());os.chown(config,0,account.pw_gid);config.chmod(0o640)
    atomic_write(root/(name+'.started.json'),json.dumps({'model_sha256':digest(raw),'boot_id':backend.boot_id(),'pid':os.getpid(),'started_at':time.time()}).encode())
    return config,account


def main():
    if os.geteuid()!=0 or len(sys.argv)!=2:raise SystemExit(64)
    from trusttunnel_control import binding_for
    os.umask(0o077);name=identifier(sys.argv[1]);binding=binding_for(ROOT,name)
    config,account=prepare(ROOT,name,binding)
    os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
    os.execv(binding['binary'],[binding['binary'],'--config',str(config)])


if __name__=='__main__':main()
