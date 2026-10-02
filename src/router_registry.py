"""Private per-installation router inventory. Empty is a valid installation."""
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid
from urllib.parse import urlsplit
from safe_apply import atomic_write

CAPABILITIES={'monitor','ipv6'}


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}',value):raise ValueError('Некорректный идентификатор роутера')
    return value


def validate(value):
    fields={'id','name','driver','host','port','username','password','host_key','web_url','enabled','capabilities'}
    if not isinstance(value,dict) or set(value)!=fields:raise ValueError('Неполная запись роутера')
    identifier(value['id'])
    for key in ('name','host','username','password','host_key','web_url'):
        if not isinstance(value[key],str) or len(value[key])>4096 or '\0' in value[key]:raise ValueError('Некорректное поле роутера')
    if not 1<=len(value['name'])<=120:raise ValueError('Название: от 1 до 120 символов')
    if value['driver'] not in ('web','keenetic'):raise ValueError('Выберите поддерживаемый способ подключения')
    if type(value['enabled']) is not bool or type(value['port']) is not int or not 1<=value['port']<=65535:raise ValueError('Проверьте порт SSH и признак включения')
    caps=value['capabilities']
    if not isinstance(caps,list) or any(c not in CAPABILITIES for c in caps) or len(set(caps))!=len(caps):raise ValueError('Неизвестная функция роутера')
    if value['driver']=='web' and caps:raise ValueError('Функции SSH доступны только интеграции Keenetic')
    if value['driver']=='keenetic':
        host=value['host']
        try:ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',host):raise ValueError('Укажите IP или имя роутера без схемы и пути') from None
        if not value['username'] or len(value['username'])>64 or any(c in value['username'] for c in '\r\n'):raise ValueError('Укажите имя пользователя SSH')
        if value['host_key']:
            import paramiko
            try:
                entry=paramiko.hostkeys.HostKeyEntry.from_line('router '+value['host_key'])
                if entry is None or entry.key is None:raise ValueError()
            except Exception:raise ValueError('SSH-ключ: тип ключа и значение Base64 из known_hosts') from None
    if value['web_url']:
        try:
            url=urlsplit(value['web_url']);port=url.port
            if url.scheme not in ('https','http') or not url.hostname or url.username or url.password or any(c.isspace() for c in value['web_url']):raise ValueError()
        except ValueError:raise ValueError('Для веб-панели нужен HTTP(S)-адрес без логина и пароля в ссылке') from None
    elif value['driver']=='web':raise ValueError('Укажите адрес веб-панели роутера')
    return value


def public(value):
    result=copy.deepcopy(value);result['password_present']=bool(result.pop('password'))
    return result


class RouterRegistry:
    def __init__(self,directory):
        self.directory=Path(directory);self.path=self.directory/'routers.json'

    def read(self):
        if not os.path.lexists(self.path):return [],'empty'
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Файл роутеров должен принадлежать панели и иметь права 0600')
            raw=stream.read(256*1024+1)
        if len(raw)>256*1024:raise ValueError('Слишком большой список роутеров')
        value=json.loads(raw)
        if not isinstance(value,dict) or set(value)!={'version','routers'} or type(value['version']) is not int or value['version']!=1 or not isinstance(value['routers'],list) or len(value['routers'])>32:raise ValueError('Повреждён список роутеров')
        rows=[validate(row) for row in value['routers']]
        if len({r['id'] for r in rows})!=len(rows):raise ValueError('Повторяются идентификаторы роутеров')
        return rows,hashlib.sha256(raw).hexdigest()

    def get(self,key,capability=None):
        identifier(key)
        row=next((r for r in self.read()[0] if r['id']==key),None)
        if row is None:raise ValueError('Роутер не найден')
        if capability and (not row['enabled'] or row['driver']!='keenetic' or capability not in row['capabilities']):raise ValueError('Эта функция для роутера не включена')
        return row

    def save(self,revision,form,*,remove=False):
        fd=os.open(self.directory/'routers.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            rows,current=self.read()
            if current!=revision:raise ValueError('Список роутеров изменился; обновите страницу')
            key=form.get('id') or 'router-'+uuid.uuid4().hex[:12]
            old=next((r for r in rows if r['id']==key),None)
            if form.get('id') and old is None:raise ValueError('Роутер уже удалён')
            if remove:
                if old is None:raise ValueError('Выберите существующий роутер')
                rows=[r for r in rows if r['id']!=key]
            else:
                try:port=int(form.get('port','22') or '22')
                except ValueError:raise ValueError('Порт SSH должен быть числом') from None
                password=form.get('password','') or (old['password'] if old else '')
                if form.get('clear_password')=='on' or form.get('driver','web')=='web':password=''
                value=validate(dict(id=key,name=form.get('name','').strip(),driver=form.get('driver','web'),
                    host=form.get('host','').strip(),port=port,username=form.get('username','').strip(),password=password,
                    host_key=form.get('host_key','').strip(),web_url=form.get('web_url','').strip(),enabled=form.get('enabled')=='on',
                    capabilities=[c for c in sorted(CAPABILITIES) if form.get('capability_'+c)=='on']))
                if old:rows=[value if r['id']==key else r for r in rows]
                else:
                    if len(rows)>=32:raise ValueError('Поддерживается до 32 роутеров')
                    rows.append(value)
            atomic_write(self.path,json.dumps({'version':1,'routers':rows},ensure_ascii=False,indent=2).encode())
            return key

    def remote(self,key,capability='monitor'):
        row=self.get(key,capability)
        if capability=='ipv6':
            from router_ipv6_remote import RouterIPv6Remote
            return RouterIPv6Remote(row)
        from router_health import RouterRemote
        cache=self.directory/'routers'/key;cache.mkdir(mode=0o700,parents=True,exist_ok=True)
        return RouterRemote(cache,row)

    def enabled(self,capability):return [r for r in self.read()[0] if r['enabled'] and capability in r['capabilities']]

    def pull_once(self):
        from router_health import pull_once
        for row in self.enabled('monitor'):
            cache=self.directory/'routers'/row['id'];cache.mkdir(mode=0o700,parents=True,exist_ok=True)
            pull_once(cache,row)

    def start_pull(self):
        import threading,time
        def loop():
            while True:
                try:self.pull_once()
                except Exception:pass  # Existing observations expire; failures never become green.
                time.sleep(15)
        thread=threading.Thread(target=loop,name='router-observations',daemon=True);thread.start();return thread
