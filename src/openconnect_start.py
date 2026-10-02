"""Launch the native client from one validated active model; never a daemon."""
import fcntl
import json
import os
from pathlib import Path
import sys
import time

from safe_apply import atomic_write,digest
from wireguard_control import read_private
from openconnect_apply import ROOT,PENDING,state,Transaction
from openconnect_control import binding_for,identifier,regular
from openconnect_profile import validate
from openconnect_render import render_files


def prepare(root,name,binding,backend=None):
    from openconnect_runtime import LinuxBackend
    backend=backend or LinuxBackend(root,binding,name)
    tx=state(root)
    relevant=tx.get('connection')==name and tx.get('status') in PENDING
    if relevant and (tx['boot_id']!=backend.boot_id() or time.time()>=tx['deadline']):
        with (root/'control.lock').open('a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('Незавершённая операция занята; новый вход на VPN не выполнялся') from None
            Transaction(root,binding,name,backend).rollback(tx['id'],before_start=True)
        tx=state(root);relevant=False
    raw=read_private(root/(name+'.active.json'));model=validate(json.loads(raw),ready=True)
    receipt=json.loads(read_private(root/(name+'.installation.json')))
    if receipt!={'unit_sha256':digest(regular(Path(binding['unit_file']))),'script_sha256':digest(regular(Path(binding['script'])))}:
        raise ValueError('Установленная служба или сетевой обработчик изменились')
    if relevant:
        expected=tx['previous_sha256'] if tx.get('recovering') else tx['next_sha256']
        if digest(raw)!=expected:raise ValueError('Файл подключения не соответствует незавершённой операции')
        if not tx.get('recovering'):
            if not tx['target_active']:raise ValueError('В текущей операции служба должна оставаться выключенной')
            # A mistyped password gets one connection attempt, not an automatic loop.
            token=root/'revisions'/tx['id']/'attempted'
            try:fd=os.open(token,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            except FileExistsError:raise ValueError('Повторный вход с неподтверждёнными настройками остановлен; ожидается возврат') from None
            with os.fdopen(fd,'w') as stream:stream.write('attempted');stream.flush();os.fsync(stream.fileno())
    directory=root/(name+'.runtime');directory.mkdir(mode=0o700,exist_ok=True)
    if directory.is_symlink() or directory.stat().st_mode&0o077:raise ValueError('Каталог запуска должен быть закрытым')
    files=render_files(model,binding,directory)
    for file,data in files.items():atomic_write(directory/file,data)
    atomic_write(root/(name+'.started.json'),json.dumps({'model_sha256':digest(raw),'boot_id':backend.boot_id(),'pid':os.getpid(),'started_at':time.time()}).encode())
    return directory


def main():
    if os.geteuid()!=0 or len(sys.argv)!=2:raise SystemExit(64)
    os.umask(0o077);name=identifier(sys.argv[1]);binding=binding_for(ROOT,name)
    directory=prepare(ROOT,name,binding)
    fd=os.open(directory/'stdin.txt',os.O_RDONLY|os.O_NOFOLLOW);os.dup2(fd,0)
    if fd!=0:os.close(fd)
    os.execv(binding['binary'],[binding['binary'],'--config='+str(directory/'client.conf')])


if __name__=='__main__':main()
