"""Create disabled clients; retain a resumable receipt until registration finishes."""
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import tempfile

from safe_apply import atomic_write
from wireguard_control import read_private
from trusttunnel_control import ROOT, binding_for, observe
from trusttunnel_profile import DEFAULT, update, validate, import_config
from trusttunnel_runtime import CODE, installation
from openconnect_runtime import command


def connection_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'tt-[a-f0-9]{12}', value):
        raise ValueError('Некорректный идентификатор нового подключения')
    return value


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode()


def imported(raw, kind, binding):
    if kind == 'client':
        import tomllib
        import ipaddress
        from urllib.parse import urlsplit
        from trusttunnel_profile import MAX_BYTES, address
        if not isinstance(raw, str) or len(raw.encode()) > MAX_BYTES: raise ValueError('Файл превышает 128 КиБ')
        try:
            config = tomllib.loads(raw)
            endpoint = config['listener']['socks']['address']
            address(endpoint)
            if not ipaddress.ip_address(urlsplit('//'+endpoint).hostname).is_loopback: raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise ValueError('Для создания нужен клиентский TOML с локальным SOCKS; TUN не импортируется') from None
        # Parse every original field before intentionally reallocating only the
        # local socket. The creation form explains this adaptation.
        return import_config(raw, DEFAULT, kind, {**binding, 'socks_address': endpoint})
    return import_config(raw, DEFAULT, kind, binding)


def publish(path, data, mode=0o600):
    """No replacement, including during recovery after an interrupted creation."""
    if os.path.lexists(path):
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o777 != mode or path.read_bytes() != data:
            raise ValueError('Файл нового подключения занят или изменён; существующие данные не заменены')
        return
    fd, temporary = tempfile.mkstemp(prefix='.tt-create-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        os.unlink(temporary)


def assert_inactive(unit, unit_file, run=command):
    _, data = run(['systemctl', 'show', unit, '-p', 'ActiveState,UnitFileState,FragmentPath,DropInPaths'])
    state = dict(line.split('=', 1) for line in data.decode().splitlines() if '=' in line)
    if state.get('ActiveState') != 'inactive' or state.get('UnitFileState') not in ('', 'disabled') or state.get('DropInPaths') or state.get('FragmentPath') not in ('', unit_file):
        raise ValueError('Имя службы занято или служба не выключена; создание остановлено')


def finish(root, path, *, run=command, inspect=observe, fingerprint=installation, inactive=assert_inactive):
    item = json.loads(read_private(path)); name = connection_id(item['id'])
    bindings = json.loads(read_private(root/'connections.json'))
    if item['status'] == 'complete':
        # Already completed: never restore the initial model over later edits.
        binding_for(root, name)
        return {'id': name, 'outbound': item['outbound'], 'created': True, 'runtime_changed': False}
    b = item['binding']
    if name in bindings and bindings[name] != b:
        raise ValueError('Имя подключения занято другой привязкой')
    inactive(b['unit'], b['unit_file'], run)
    publish(root/(name+'.active.json'), encode(validate(item['model'], ready=True)))
    publish(Path(b['unit_file']), item['unit'].encode(), 0o644)
    run(['systemctl', 'daemon-reload'])
    runtime = inspect(b)
    if runtime['client']['active'] != 'inactive' or runtime['client']['boot'] != 'disabled':
        raise ValueError('Не подтверждено выключенное состояние новой службы')
    publish(root/(name+'.installation.json'), encode(fingerprint(root, b)))
    bindings[name] = b
    atomic_write(root/'connections.json', encode(bindings))
    # After the registry commit, only public recovery metadata is needed.
    done = {k: item[k] for k in ('id', 'outbound')}
    done['status'] = 'complete'
    atomic_write(path, encode(done))
    return {'id': name, 'outbound': item['outbound'], 'created': True, 'runtime_changed': False}


def control(request, *, root=ROOT, units=Path('/etc/systemd/system'), run=command,
            inspect=observe, fingerprint=installation, inactive=assert_inactive):
    action = request.get('action')
    fields = {'version', 'action'}
    if action == 'trusttunnel-create': fields |= {'connection', 'name', 'scope', 'values', 'text', 'format'}
    elif action == 'trusttunnel-complete': fields |= {'connection'}
    elif action != 'trusttunnel-catalog': raise ValueError('Неизвестное действие создания TrustTunnel')
    if set(request) != fields or request['version'] != 1: raise ValueError('Некорректные поля создания TrustTunnel')
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077:
        raise ValueError('Закрытый каталог TrustTunnel недоступен')
    fd = os.open(root/'control.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        try: fcntl.flock(lock, (fcntl.LOCK_SH if action == 'trusttunnel-catalog' else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('Редактор TrustTunnel занят; обновите страницу') from None
        receipts = root/'creations'
        if receipts.is_symlink(): raise ValueError('Каталог создания повреждён')
        if action == 'trusttunnel-catalog':
            items = []
            for path in sorted(receipts.glob('tt-*.json')):
                item = json.loads(read_private(path))
                items.append({k: item[k] for k in ('id', 'status', 'outbound')})
            return {'connections': items}
        from trusttunnel_clients import ensure_idle
        if action not in ('trusttunnel-status','trusttunnel-catalog'):ensure_idle(root)
        from trusttunnel_apply import state, PENDING
        if state(root).get('status') in PENDING: raise ValueError('Сначала завершите изменение TrustTunnel')
        name = connection_id(request['connection'])
        path = receipts/(name+'.json')
        if action == 'trusttunnel-complete':
            return finish(root, path, run=run, inspect=inspect, fingerprint=fingerprint, inactive=inactive)
        if os.path.lexists(path): raise ValueError('Подключение уже сохранялось. Откройте список TrustTunnel и завершите его создание')
        label = request['name']; scope = request['scope']
        if not isinstance(label, str) or not label.strip() or len(label) > 120 or any(ord(c) < 32 for c in label):
            raise ValueError('Название должно содержать от 1 до 120 символов')
        if scope not in ('public', 'work', 'special'): raise ValueError('Выберите назначение подключения')
        bindings = json.loads(read_private(root/'connections.json'))
        if name in bindings or len(set(bindings) | {p.stem for p in receipts.glob('*.json')}) >= 64:
            raise ValueError('Имя занято или достигнут предел 64 подключений')
        settings = json.loads(read_private(root/'creation-settings.json'))
        if set(settings) != {'template', 'port_range'}: raise ValueError('Не настроено создание клиентов TrustTunnel')
        source = binding_for(root, settings['template'])
        limits = settings['port_range']
        if not isinstance(limits, list) or len(limits) != 2 or any(type(p) is not int for p in limits) or not 1024 <= limits[0] <= limits[1] <= 65535 or limits[1]-limits[0] > 255:
            raise ValueError('Некорректный диапазон локальных портов')
        reserved = {b['socks_address'] for b in bindings.values()}
        for p in receipts.glob('*.json'):
            item = json.loads(read_private(p))
            if 'binding' in item: reserved.add(item['binding']['socks_address'])
        listener = None
        for port in range(limits[0], limits[1]+1):
            address = '127.0.0.1:'+str(port)
            if address in reserved: continue
            sock = socket.socket()
            try: sock.bind(('127.0.0.1', port))
            except OSError: sock.close(); continue
            listener = sock; break
        if listener is None: raise ValueError('Нет свободного локального порта TrustTunnel')
        try:
            unit = 'okopy-trusttunnel-client-'+name+'.service'
            b = {k: source[k] for k in ('binary', 'user', 'uid')}
            b.update(unit=unit, unit_file=str(units/unit), config=str(root/(name+'.unused.toml')),
                     socks_address=address, dependents=[])
            if request['format'] == 'form':
                if request['text']: raise ValueError('Выберите форму или импорт файла')
                model = update(DEFAULT, request['values'])
            else:
                if request['values'] is not None: raise ValueError('Выберите форму или импорт файла')
                model = imported(request['text'], request['format'], b)
            model = validate(model, ready=True)
            for target in (units/unit, root/(name+'.active.json'), root/(name+'.installation.json'), root/(name+'.draft.json')):
                if os.path.lexists(target): raise ValueError('Файл нового подключения уже существует')
            inactive(unit, str(units/unit), run)
            content = '[Unit]\nDescription=TrustTunnel client\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nUser='+b['user']+'\nExecStart=+/usr/bin/python3 -E -s -B '+str(CODE/'trusttunnel_start.py')+' '+name+'\nRestart=on-failure\nRestartSec=10\nTimeoutStartSec=30\nTimeoutStopSec=10\n[Install]\nWantedBy=multi-user.target\n'
            outbound = {'name': label.strip(), 'scope': scope, 'protocol': 'TrustTunnel',
                        'native': {'type': 'socks', 'tag': name, 'server': '127.0.0.1', 'server_port': port, 'version': '5'}}
            receipts.mkdir(mode=0o700, exist_ok=True)
            publish(path, encode({'id': name, 'status': 'prepared', 'binding': b,
                                 'unit': content, 'model': model, 'outbound': outbound}))
            return finish(root, path, run=run, inspect=inspect, fingerprint=fingerprint, inactive=inactive)
        finally:
            listener.close()
