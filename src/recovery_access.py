"""Freeze admin login and TLS material outside the restored file scope.

Values never enter JSON status, browser payloads or audit logs. The installer
owns access to this root-only store and its HTTPS proxy configuration.
"""

import hashlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import ssl
import stat
import tempfile
import uuid


UI_AUTH_ROOT=Path('/var/lib/okopy-recovery-ui')
AUTH_SOURCE=Path('/var/lib/okopy-panel/auth.json')
RESCUE_USER='okopy-recovery'
PANEL_USER='okopy-panel'
TLS_ROOT=UI_AUTH_ROOT/'tls'
LIVE_ROOT=Path('/etc/letsencrypt/live')
CERT_ROOT=Path('/etc/letsencrypt/archive')
OWNER=0


def atomic_private(path,data,mode,gid=0):
    path=Path(path)
    if path.is_symlink():raise ValueError('Защищённый файл занят символической ссылкой')
    temporary=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as out:
            os.fchown(out.fileno(),OWNER,gid);os.fchmod(out.fileno(),mode)
            out.write(data);out.flush();os.fsync(out.fileno())
        os.replace(temporary,path)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:temporary.unlink(missing_ok=True)


def stage_auth(root=UI_AUTH_ROOT,source=AUTH_SOURCE):
    source=Path(source);root=Path(root)
    account=pwd.getpwnam(RESCUE_USER)
    panel=pwd.getpwnam(PANEL_USER)
    if root.resolve()!=root or root.is_symlink():raise ValueError('Каталог независимого входа изменён')
    owner=root.stat()
    if not stat.S_ISDIR(owner.st_mode) or owner.st_uid!=OWNER or owner.st_gid!=account.pw_gid or owner.st_mode&0o027:
        raise ValueError('Небезопасный каталог независимого входа')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        st=os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid not in (OWNER,panel.pw_uid) or st.st_mode&0o077 or st.st_size>32768:
            raise ValueError('Администратор панели не может быть безопасно сохранён')
        data=stream.read(32769)
    if len(data)>32768:raise ValueError('Файл администратора слишком велик')
    value=json.loads(data)
    required=('username','password_hash','session_secret')
    if not isinstance(value,dict) or not set(required)<=set(value) or any(not isinstance(value[k],str) or not value[k] for k in required):
        raise ValueError('Файл администратора повреждён')
    # The main panel knows its own session MAC key. Never reuse it for rescue.
    data=json.dumps({'username':value['username'],'password_hash':value['password_hash'],
                     'session_secret':secrets.token_urlsafe(48)},ensure_ascii=False,separators=(',',':')).encode()
    atomic_private(root/'auth.json',data,0o640,account.pw_gid)
    return hashlib.sha256(data).hexdigest()


def stage_tls(chain_source,key_source,*,tls_root=TLS_ROOT,live_root=LIVE_ROOT,cert_root=CERT_ROOT):
    tls_root=Path(tls_root);live_root=Path(live_root);cert_root=Path(cert_root)
    if tls_root.resolve()!=tls_root or tls_root.is_symlink():raise ValueError('Каталог recovery TLS изменён')
    parent=tls_root.parent.stat();owner=tls_root.stat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=OWNER or stat.S_IMODE(parent.st_mode)!=0o750
        or not stat.S_ISDIR(owner.st_mode) or owner.st_uid!=OWNER or stat.S_IMODE(owner.st_mode)!=0o700):
        raise ValueError('TLS копия должна лежать в закрытом root-owned recovery каталоге')
    lock_fd=os.open(tls_root/'tls.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(lock_fd,'r+b') as lock:
        s=os.fstat(lock.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=OWNER or stat.S_IMODE(s.st_mode)!=0o600:
            raise ValueError('Блокировка recovery TLS изменена')
        fcntl.flock(lock,fcntl.LOCK_EX)
        material={}
        for name,source in [('chain.pem',chain_source),('key.pem',key_source)]:
            source=Path(source)
            if not source.is_absolute() or not source.is_relative_to(live_root) or source==live_root:
                raise ValueError('TLS источник должен быть фиксированной live-ссылкой certbot')
            resolved=source.resolve(strict=True)
            if not resolved.is_relative_to(cert_root) or not resolved.is_file() or resolved.stat().st_uid!=OWNER:
                raise ValueError('TLS источник вышел за доверенный каталог сертификатов')
            material[name]=resolved.read_bytes()
            if not 1<=len(material[name])<=128*1024:raise ValueError('TLS файл превышает предел')
        temporary=[]
        try:
            for name in ('chain.pem','key.pem'):
                fd,path=tempfile.mkstemp(prefix='.tls-check-',dir=tls_root)
                temporary.append(path)
                with os.fdopen(fd,'wb') as out:
                    os.fchmod(out.fileno(),0o600);out.write(material[name]);out.flush();os.fsync(out.fileno())
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:context.load_cert_chain(temporary[0],temporary[1])
            except (ssl.SSLError,OSError):raise ValueError('TLS цепочка и приватный ключ не совпадают') from None
        finally:
            for path in temporary:Path(path).unlink(missing_ok=True)
        # Publish a complete pair with ONE atomic pointer update. A crash before
        # the symlink swap leaves the old pair; a crash after sees the new pair.
        generation='generation-'+uuid.uuid4().hex
        directory=tls_root/generation
        directory.mkdir(mode=0o700)
        try:
            digests={}
            for name in ('chain.pem','key.pem'):
                atomic_private(directory/name,material[name],0o600)
                digests[name]=hashlib.sha256(material[name]).hexdigest()
            parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(parent)
            finally:os.close(parent)
            current=tls_root/'current'
            if current.exists() and not current.is_symlink():raise ValueError('TLS pointer занят чужим файлом')
            if current.is_symlink():
                previous=os.readlink(current)
                if (current.lstat().st_uid!=OWNER or not re.fullmatch('generation-[a-f0-9]{32}',previous)
                    or not (tls_root/previous).is_dir() or (tls_root/previous).stat().st_uid!=OWNER
                    or stat.S_IMODE((tls_root/previous).stat().st_mode)!=0o700):
                    raise ValueError('Текущий TLS pointer вышел за защищённый каталог')
            pointer=tls_root/('.current-'+uuid.uuid4().hex)
            try:
                pointer.symlink_to(generation,target_is_directory=True)
                os.replace(pointer,current)
                parent=os.open(tls_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(parent)
                finally:os.close(parent)
            finally:pointer.unlink(missing_ok=True)
            return digests
        except BaseException:
            # An unpublished generation cannot affect the active certificate.
            if not (tls_root/'current').is_symlink() or os.readlink(tls_root/'current')!=generation:
                for name in ('chain.pem','key.pem'):(directory/name).unlink(missing_ok=True)
                directory.rmdir()
            raise
