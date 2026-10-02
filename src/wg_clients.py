"""Incoming WireGuard clients: verified inventory and explicit secret export.

The existing per-client files remain the source of keys. Merely reading this
module cannot reconfigure an interface, replace a peer, or restart a service.
"""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

from safe_apply import atomic_write
from wireguard_control import read_private, profile_name, revision
from wireguard_profile import parse, key, endpoint

ROOT = Path('/var/lib/okopy-wireguard')
PROFILES = Path('/etc/wireguard')


def run(args, data=None):
    try:
        result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=4,
                                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        if result.returncode or len(result.stdout.encode()) > 256 * 1024:
            raise ValueError()
        return result.stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ValueError('Не удалось проверить WireGuard на сервере; секреты и вывод команды скрыты') from None


def derive(private, command=run):
    return key(command(['/usr/bin/wg', 'pubkey'], private + '\n').strip(), 'PublicKey')


def client_model(text):
    """Allow DNS in a client file, but never export wg-quick shell hooks."""
    lines=[]; dns=None; section=None
    for line in text.splitlines():
        clean=line.split('#',1)[0].strip()
        if clean.startswith('['):section=clean
        if '=' in clean and clean.split('=',1)[0].strip()=='DNS':
            if section!='[Interface]' or dns is not None:raise ValueError('Повторный DNS в конфиге клиента')
            dns=[str(ipaddress.ip_address(v.strip())) for v in clean.split('=',1)[1].split(',')]
            if not 1<=len(dns)<=4:raise ValueError('Нужен DNS клиента')
        else:lines.append(line)
    model=parse('\n'.join(lines))
    if len(model['peers'])!=1 or dns is None:
        raise ValueError('Для выдачи нужен клиентский конфиг с одним сервером и DNS')
    return model


def settings(root):
    raw=read_private(root/'clients.json'); data=json.loads(raw)
    if set(data)!={'interface','directory','local_endpoint','external_endpoint'}:
        raise ValueError('Настройки клиентов WireGuard повреждены')
    profile_name(data['interface'])
    directory=Path(data['directory'])
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError('Закрытый каталог конфигов клиентов недоступен')
    st=directory.stat()
    if st.st_uid!=os.geteuid() or st.st_mode & 0o077:
        raise ValueError('Каталог конфигов клиентов должен быть закрыт для других пользователей')
    for field in ('local_endpoint','external_endpoint'):data[field]=endpoint(data[field])
    return data,revision(raw)


def peer_id(peer):return hashlib.sha256(peer['PublicKey'].encode()).hexdigest()[:24]


def matches_client(client, peer, server_public):
    target = client['peers'][0]
    addresses = {ipaddress.ip_interface(a).ip for a in client['interface']['Address']}
    networks = [ipaddress.ip_network(n) for n in peer['AllowedIPs']]
    hosts = {n.network_address for n in networks if n.prefixlen == n.max_prefixlen}
    return (target['PublicKey'] == server_public
            and target.get('PresharedKey') == peer.get('PresharedKey')
            and hosts.issubset(addresses)
            and all(any(a in n for n in networks) for a in addresses))


def labels(root):
    path = root / 'client-labels.json'
    return json.loads(read_private(path)) if path.exists() else {}


def inventory(config, profiles, command=run):
    raw=read_private(profiles/(config['interface']+'.conf')); text=raw.decode(); model=parse(text)
    comments=[]
    for block in re.split(r'(?m)^\s*\[Peer\]\s*$',text)[1:]:
        names=re.findall(r'(?m)^\s*#\s*(.+)$',block)
        comments.append(re.sub(r'^roaming\s+','',names[0],flags=re.I) if names else '')
    server_public=derive(model['interface']['PrivateKey'],command)
    files={}; errors=0; duplicates=set()
    for path in sorted(Path(config['directory']).glob('*.conf')):
        if len(files)>=64:raise ValueError('Слишком много клиентских конфигов')
        try:
            raw_client=read_private(path).decode(); client=client_model(raw_client); public=derive(client['interface']['PrivateKey'],command)
            if public in files or public in duplicates:
                files.pop(public,None);duplicates.add(public);raise ValueError('Дубликат ключа клиента')
            files[public]=(path,client,revision(raw_client.encode()))
        except (ValueError,UnicodeError):errors+=1
    live={}; live_error=None
    try:
        for line in command(['/usr/bin/wg','show',config['interface'],'latest-handshakes']).splitlines():
            public,stamp=line.split();live[public]=int(stamp)
    except (ValueError,TypeError):live_error='Нет достоверного состояния туннеля'
    rows=[]
    for i,peer in enumerate(model['peers']):
        match=files.get(peer['PublicKey']); downloadable=False; reason='Клиентский конфиг с закрытым ключом не сохранён'
        networks=[ipaddress.ip_network(n) for n in peer['AllowedIPs']]
        if match:
            if matches_client(match[1], peer, server_public):
                downloadable=True;reason=None
            else:reason='Сохранённый конфиг не совпадает с ключом сервера, адресами или общим ключом пира'
        rows.append({'id':peer_id(peer),'name':comments[i] if i<len(comments) and comments[i] else ', '.join(peer['AllowedIPs']),
                     'addresses':peer['AllowedIPs'],'downloadable':downloadable,'reason':reason,
                     'handshake':live.get(peer['PublicKey']),'in_runtime':peer['PublicKey'] in live if live_error is None else None})
    return rows,files,model,revision(raw),live_error,errors


def control(request, *, root=ROOT, profiles=PROFILES, command=run, network=Path('/var/lib/okopy-candidate')):
    action=request.get('action'); expected={'version','action'}
    if action=='clients-export':expected|={'id','mode','file_revision'}
    elif action=='clients-rename':expected|={'id','file_revision','name','previous_name'}
    elif action=='clients-import':expected|={'id','file_revision','config'}
    elif action=='clients-settings':expected|={'settings_revision','local_endpoint','external_endpoint'}
    elif action=='clients-add':expected|={'file_revision','values'}
    elif action in ('clients-disable','clients-enable'):expected|={'file_revision','id'}
    elif action=='clients-finish':expected|={'operation'}
    elif action!='clients-status':raise ValueError('Неизвестное действие клиентов WireGuard')
    if request.get('version')!=1 or set(request)!=expected:raise ValueError('Некорректный запрос клиентов WireGuard')
    st=root.stat()
    if root.is_symlink() or st.st_uid!=os.geteuid() or st.st_mode & 0o022:
        raise ValueError('Каталог управления WireGuard небезопасен')
    fd=os.open(root/'control.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        try:fcntl.flock(lock,(fcntl.LOCK_SH if action in ('clients-status','clients-export') else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('WireGuard занят изменением. Обновите страницу') from None
        config,config_revision=settings(root)
        if action in ('clients-add','clients-disable','clients-enable'):
            from wg_client_ops import mutate
            return mutate(request,config,root,profiles,command,network)
        if action=='clients-finish':
            from wg_client_ops import finish_locked
            result=finish_locked(root,profiles,request['operation'],command)
            return {'operation':result.get('status','unknown')}
        if action=='clients-settings':
            if request['settings_revision']!=config_revision:raise ValueError('Настройки уже изменены. Обновите страницу')
            for field in ('local_endpoint','external_endpoint'):config[field]=endpoint(request[field])
            atomic_write(root/'clients.json',json.dumps(config,ensure_ascii=False,indent=2).encode())
            return {'saved':True,'runtime_changed':False}
        rows,files,model,file_revision,live_error,errors=inventory(config,profiles,command)
        names=labels(root)
        for row in rows:row['name']=names.get(row['id'],row['name'])
        if action=='clients-status':
            from wg_client_ops import operation_state,defaults
            op=operation_state(root);disabled=[];enabled_ids={r['id'] for r in rows}
            for path in sorted(root.glob('disabled-*.json')):
                record=json.loads(read_private(path));identifier=peer_id(record['peer'])
                if identifier not in enabled_ids:
                    disabled.append({'id':identifier,'name':names.get(identifier,record['name']),'addresses':record['peer']['AllowedIPs']})
            return {'clients':rows,'interface':config['interface'],'file_revision':file_revision,'settings_revision':config_revision,
                    'local_endpoint':config['local_endpoint'],'external_endpoint':config['external_endpoint'],
                    'runtime_error':live_error,'invalid_files':errors,'defaults':defaults(model),'disabled':disabled,
                    'operation':{k:op[k] for k in ('id','status','action','name','created_at','finished_at') if k in op}}
        if request['file_revision']!=file_revision:raise ValueError('Состав клиентов изменился. Обновите страницу')
        row=next((r for r in rows if r['id']==request['id']),None)
        if not row:raise ValueError('Устройство не найдено. Обновите список')
        if action=='clients-rename':
            from wg_client_ops import valid_name
            if request['previous_name']!=row['name']:raise ValueError('Название уже изменено. Обновите страницу')
            names[row['id']]=valid_name(request['name'])
            atomic_write(root/'client-labels.json',json.dumps(names,ensure_ascii=False).encode())
            return {'saved':True,'runtime_changed':False}
        if action=='clients-import':
            raw=request['config']
            if not isinstance(raw,str) or len(raw.encode())>256*1024:raise ValueError('Файл превышает 256 КиБ')
            client=client_model(raw)
            peer=next(p for p in model['peers'] if peer_id(p)==row['id'])
            if (derive(client['interface']['PrivateKey'],command)!=peer['PublicKey']
                    or not matches_client(client,peer,derive(model['interface']['PrivateKey'],command))):
                raise ValueError('Конфиг не соответствует ключу, адресам или PSK выбранного устройства')
            if 'Endpoint' not in client['peers'][0]:raise ValueError('В клиентском конфиге нужен Endpoint')
            match=files.get(peer['PublicKey'])
            path=match[0] if match else Path(config['directory'])/('imported-'+row['id']+'.conf')
            if not match and path.exists():raise ValueError('Ранее сохранённый файл не прошёл проверку; исправьте его перед импортом')
            if revision(read_private(profiles/(config['interface']+'.conf')))!=file_revision:
                raise ValueError('Состав клиентов изменился. Обновите страницу')
            atomic_write(path,raw.encode())
            return {'saved':True,'runtime_changed':False}
        if request['mode'] not in ('local','external'):raise ValueError('Выберите подключение дома или извне')
        row=next((r for r in rows if r['id']==request['id']),None)
        if not row or not row['downloadable']:raise ValueError('Для этого устройства нет проверенного клиентского конфига')
        peer=next(p for p in model['peers'] if peer_id(p)==row['id'])
        path,client,stored_revision=files[peer['PublicKey']]
        # Re-read against the verified model, so an external edit cannot swap a
        # secret between inventory validation and download.
        raw=read_private(path).decode()
        if revision(raw.encode())!=stored_revision:raise ValueError('Конфиг изменился во время чтения. Повторите загрузку')
        raw,count=re.subn(r'(?m)^\s*Endpoint\s*=\s*[^\r\n]+$', 'Endpoint = '+config[request['mode']+'_endpoint'],raw)
        if count!=1:raise ValueError('В клиентском конфиге нужен один Endpoint')
        return {'config':raw,'filename':'home-'+request['mode']+'-'+row['id'][:8]+'.conf','name':row['name']}
