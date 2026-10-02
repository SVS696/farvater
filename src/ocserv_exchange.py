"""Native ocserv archive exchange; parse in memory, never execute imported hooks."""
import copy
import io
import json
from pathlib import PurePosixPath
import re
import secrets
import stat
import subprocess
import zipfile

from ocserv_incoming import validate,render_config,device_prefix,NUMBERS

LIMIT=256*1024


def password_hash(password,encoded=None):
    salt=encoded.split('$')[2] if encoded else secrets.token_urlsafe(12).replace('_','.').replace('-','/')
    algorithm=encoded.split('$')[1] if encoded else '6'
    r=subprocess.run(['openssl','passwd','-'+algorithm,'-salt',salt,'-stdin'],input=password+'\n',capture_output=True,text=True,timeout=5)
    if r.returncode:raise ValueError('Для экспорта ocserv нужен OpenSSL с поддержкой SHA-crypt')
    return r.stdout.strip()


def export_server(entry):
    n=validate(entry['native']);disabled=entry.get('disabled_clients',[])
    config=render_config(n,'/portable',device_prefix(entry['id'])).replace('/portable/','./')
    users=[]
    for u in n['users']:
        if u['username'] not in disabled:
            hashed=password_hash(u['password']) if u['password'] else u['password_hash']
            users.append(u['username']+':*:'+hashed)
    files={'ocserv.conf':config,'server.pem':n['certificate'],'key.pem':n['private_key'],
           'ocpasswd':'\n'.join(users)+'\n',
           'farvater.json':json.dumps({'format':'farvater-ocserv','version':1,'native':n,'disabled_clients':disabled},ensure_ascii=False),
           'README.txt':'Конфигурация содержит ключ сервера и данные клиентов. Храните файлы в закрытом каталоге.\n'
             'Для отдельного ocserv создайте системного пользователя/группу farvater-ocserv, установите движок и запускайте из каталога архива:\n'
             'sudo ocserv --no-chdir -f -c ocserv.conf\n'
             'Маршрутизация и межсетевой экран на отдельном сервере настраиваются отдельно.\n'
             'farvater.json сохраняет исходные пароли и отключённых клиентов для обратного импорта в панель.\n'}
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,value in files.items():
            info=zipfile.ZipInfo(name);info.create_system=3;info.external_attr=(stat.S_IFREG|0o600)<<16
            info.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(info,value.encode())
    raw=stream.getvalue()
    if len(raw)>LIMIT:raise ValueError('Архив сервера превышает 256 КиБ')
    return raw


def read_archive(raw):
    if not isinstance(raw,bytes) or len(raw)>LIMIT:raise ValueError('Архив сервера превышает 256 КиБ')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            rows=archive.infolist();names=[r.filename for r in rows]
            if not 4<=len(rows)<=8 or len(set(names))!=len(names) or sum(r.file_size for r in rows)>4*LIMIT:raise ValueError()
            if any('/' in n or '\\' in n or n in ('.','..') for n in names):raise ValueError()
            if any(r.flag_bits&1 or stat.S_ISLNK(r.external_attr>>16) for r in rows):raise ValueError()
            return {r.filename:archive.read(r).decode('utf-8-sig') for r in rows}
    except (ValueError,UnicodeError,zipfile.BadZipFile,RuntimeError,NotImplementedError,EOFError):
        raise ValueError('Нужен ZIP с ocserv.conf, сертификатом, ключом и ocpasswd в корне архива') from None


def parse_native(files):
    config=files.get('ocserv.conf','');options={}
    for line in config.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([a-z0-9-]+)\s*=\s*(.*?)\s*',line)
        if not match:raise ValueError('Некорректная строка ocserv.conf')
        field,value=match.groups()
        if value.startswith('"') and value.endswith('"'):value=value[1:-1]
        options.setdefault(field,[]).append(value)
    repeated={'dns','route','split-dns'}
    if any(len(v)>1 and k not in repeated for k,v in options.items()):raise ValueError('Повторяющийся параметр ocserv.conf')
    def take(field,default=None):
        values=options.pop(field,None)
        if values is None:
            if default is not None:return default
            raise ValueError('В ocserv.conf отсутствует '+field)
        return values[0]
    def number(field,default=None):
        try:return int(take(field,default))
        except ValueError:raise ValueError('Укажите числовой '+field) from None
    def boolean(field,default='false'):
        value=take(field,default)
        if value not in ('true','false'):raise ValueError(field+': ожидается true или false')
        return value=='true'
    used={'ocserv.conf'}
    def material(path):
        name=PurePosixPath(path).name
        if not name or name not in files:raise ValueError('Добавьте в архив файл '+name)
        used.add(name);return files[name]
    auth=take('auth');match=re.fullmatch(r'plain\[passwd=([^\]\n]+)\]',auth)
    if not match:raise ValueError('Поддерживается plain-авторизация с файлом ocpasswd')
    passwd=material(match[1]);port=number('tcp-port');udp=number('udp-port','0')
    if udp not in (0,port):raise ValueError('Для этого модуля TCP и DTLS должны использовать один номер порта')
    n={'type':'openconnect-server','listen':take('listen-host','0.0.0.0'),'listen_port':port,'dtls':udp!=0,
       'compression':boolean('compression'), 'certificate':material(take('server-cert')),
       'private_key':material(take('server-key')), 'pools':[], 'users':[]}
    for field,default in {'mtu':1400,'max_clients':16,'max_same_clients':1,'keepalive':30,'dpd':30,'mobile_dpd':120}.items():
        n[field]=number(field.replace('_','-'),str(default))
    for field in ('ipv4-network','ipv6-network'):
        if field in options:n['pools'].append(take(field))
    if take('ipv6-subnet-prefix','128')!='128':raise ValueError('Модуль выдаёт IPv6-адреса /128; измените ipv6-subnet-prefix')
    for field,option in [('client_dns','dns'),('client_routes','route'),('split_dns','split-dns')]:
        n[field]=options.pop(option,[])
    # Recover the family's /0 represented in native ocserv by two /1 entries.
    for first,second,whole in [('0.0.0.0/1','128.0.0.0/1','0.0.0.0/0'),('::/1','8000::/1','::/0')]:
        if first in n['client_routes'] and second in n['client_routes']:
            n['client_routes']=[whole if v==first else v for v in n['client_routes'] if v!=second]
    if 'default' in n['client_routes']:
        n['client_routes']=[v for v in n['client_routes'] if v!='default']+(['0.0.0.0/0'] if any(':' not in p for p in n['pools']) else [])+(['::/0'] if any(':' in p for p in n['pools']) else [])
    for field in ('run-as-user','run-as-group','socket-file','occtl-socket-file','device'):
        if field in options:take(field)  # Runtime owns identity, paths and interface names.
    for field in ('predictable-ips','isolate-workers','cisco-client-compat','use-occtl'):
        if not boolean(field,'true'):raise ValueError(field+' должен быть true для управляемого сервера')
    if options:raise ValueError('Неподдержанные параметры ocserv: '+', '.join(sorted(options)))
    for line in passwd.splitlines():
        if not line.strip() or line.startswith('#'):continue
        parts=line.split(':')
        if len(parts)!=3 or parts[1] not in ('','*'):raise ValueError('Импорт ocpasswd поддерживает клиентов без групповых политик')
        n['users'].append({'username':parts[0],'password':'','password_hash':parts[2]})
    if set(files)-used-{'farvater.json','README.txt'}:raise ValueError('В архиве есть лишние файлы, не используемые ocserv.conf')
    return validate(n)


def import_server(raw,entry):
    from policy_exchange import unique
    files=read_archive(raw);native=parse_native(files);disabled=[]
    if 'farvater.json' in files:
        try:
            meta=json.loads(files['farvater.json'],object_pairs_hook=unique)
            if set(meta)!={'format','version','native','disabled_clients'} or meta['format']!='farvater-ocserv' or type(meta['version']) is not int or meta['version']!=1:raise ValueError()
            model=validate(meta['native']);disabled=meta['disabled_clients']
            if not isinstance(disabled,list) or any(not isinstance(v,str) for v in disabled) or len(set(disabled))!=len(disabled) or not set(disabled)<={u['username'] for u in model['users']}:raise ValueError()
            if {k:v for k,v in native.items() if k!='users'}!={k:v for k,v in model.items() if k!='users'}:raise ValueError()
            active=[u for u in model['users'] if u['username'] not in disabled]
            if [u['username'] for u in active]!=[u['username'] for u in native['users']]:raise ValueError()
            for u,hashed in zip(active,native['users']):
                expected=password_hash(u['password'],hashed['password_hash']) if u['password'] else u['password_hash']
                if expected!=hashed['password_hash']:raise ValueError()
            native=model
        except (ValueError,TypeError,KeyError):raise ValueError('Снимок Farvater не соответствует стандартным файлам архива') from None
    result=copy.deepcopy(entry);result['native']=native;result['disabled_clients']=disabled
    return result
