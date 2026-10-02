"""Explicit SSH transport settings shared by control and snapshot reads."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

DEFAULT_PATH=Path('/var/lib/okopy-panel/server.json')


def connection_path():
    return Path(os.environ.get('OKOPY_SERVER_CONNECTION',str(Path(os.environ['OKOPY_STATE_DIR'])/'server.json' if os.environ.get('OKOPY_STATE_DIR') else DEFAULT_PATH)))


def validate(value):
    if not isinstance(value,dict) or set(value)!={'version','targets','sudo_password'} or type(value['version']) is not int or value['version']!=1:
        raise ValueError('Неверный формат настроек сервера')
    password=value['sudo_password']
    if not isinstance(password,str) or any(c in password for c in '\r\n\0') or len(password.encode())>4096:
        raise ValueError('Некорректный пароль sudo')
    targets=value['targets']
    if not isinstance(targets,list) or not 1<=len(targets)<=8:
        raise ValueError('Укажите от 1 до 8 адресов доступа к одному серверу')
    for target in targets:
        if not isinstance(target,dict) or set(target)!={'host','port','username','identity_file'}:
            raise ValueError('Неполный адрес подключения')
        host=target['host']
        if not isinstance(host,str) or len(host)>253:raise ValueError('Некорректный адрес сервера')
        try:ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',host):raise ValueError('Нужен IP или имя сервера без схемы и пути') from None
        user=target['username']
        if not isinstance(user,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',user):raise ValueError('Некорректный пользователь SSH')
        if type(target['port']) is not int or not 1<=target['port']<=65535:raise ValueError('Порт SSH: от 1 до 65535')
        identity=target['identity_file']
        if not isinstance(identity,str) or len(identity)>4096 or any(c in identity for c in '\0\r\n') or (identity and not Path(identity).is_absolute()):raise ValueError('Укажите абсолютный путь к ключу SSH или оставьте поле пустым')
    if len({(t['host'],t['port'],t['username']) for t in targets})!=len(targets):raise ValueError('Адреса подключения повторяются')
    return value


def read(path=None):
    fd=os.open(path or connection_path(),os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
            raise ValueError('Настройки сервера должны принадлежать пользователю панели и иметь права 0600')
        raw=stream.read(32769)
    if len(raw)>32768:raise ValueError('Слишком большой файл настроек сервера')
    return validate(json.loads(raw))


def ssh(target,timeout=4):
    command=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout='+str(timeout),'-o','ConnectionAttempts=1','-p',str(target['port'])]
    if target['identity_file']:command+=['-o','IdentitiesOnly=yes','-i',target['identity_file']]
    return command+['--',target['username']+'@'+target['host']]


def snapshot(path=None):
    import hashlib
    path=Path(path or connection_path())
    if not os.path.lexists(path):return None,'empty'
    value=read(path)
    # Hash the validated semantic document, without depending on whitespace.
    return value,hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def save(path,revision,form):
    import fcntl
    from safe_apply import atomic_write
    path=Path(path)
    fd=os.open(str(path)+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        old,current=snapshot(path)
        if revision!=current:raise ValueError('Настройки сервера изменились. Обновите страницу.')
        columns=[form.getlist('target_'+key) for key in ('host','port','username','identity_file')]
        if not len(columns[0]) or len({len(c) for c in columns})!=1:raise ValueError('Неполный список адресов')
        targets=[]
        for host,port,user,identity in zip(*columns):
            if not host.strip() and not user.strip() and not identity.strip():continue
            try:port=int(port or '22')
            except ValueError:raise ValueError('Порт SSH должен быть числом') from None
            targets.append(dict(host=host.strip(),port=port,username=user.strip(),identity_file=identity.strip()))
        password=form.get('sudo_password','') or (old['sudo_password'] if old else '')
        if form.get('clear_password')=='on':password=''
        value=validate({'version':1,'targets':targets,'sudo_password':password})
        atomic_write(path,json.dumps(value,ensure_ascii=False,indent=2).encode())
