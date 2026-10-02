"""Native incoming TrustTunnel accounts and exports, with one shared writer lock."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import tomllib
import uuid

from safe_apply import atomic_write, digest
from wireguard_control import read_private
from trusttunnel_control import ROOT, binding_for
from trusttunnel_profile import address, dns
from openconnect_control import identifier, regular

LIMIT = 128 * 1024
ACTIONS = {'tt-clients-status', 'tt-clients-save', 'tt-clients-delete',
           'tt-clients-import', 'tt-clients-export', 'tt-clients-settings', 'tt-clients-recover'}


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode()


def parse(raw):
    if not isinstance(raw, str) or len(raw.encode()) > LIMIT:
        raise ValueError('Список клиентов превышает 128 КиБ')
    try:
        value = tomllib.loads(raw)
    except tomllib.TOMLDecodeError:
        raise ValueError('Некорректный TOML списка клиентов') from None
    if set(value) != {'client'} or not isinstance(value['client'], list) or not 1 <= len(value['client']) <= 64:
        raise ValueError('Нужно от 1 до 64 записей [[client]]')
    names = set()
    for client in value['client']:
        if not isinstance(client, dict) or not {'username', 'password'} <= set(client) or set(client) - {'username', 'password', 'max_http2_conns', 'max_http3_conns'}:
            raise ValueError('У клиента поддерживаются username, password и лимиты max_http2_conns / max_http3_conns')
        for field, maximum in [('username', 128), ('password', 4096)]:
            item = client[field]
            if not isinstance(item, str) or not 1 <= len(item) <= maximum or any(ord(c) < 32 or ord(c) == 127 for c in item):
                raise ValueError('Проверьте длину логина и пароля; управляющие символы запрещены')
        if ':' in client['username'] or client['username'] in names:
            raise ValueError('Логины должны быть уникальными и не содержать двоеточие')
        names.add(client['username'])
        for field in ('max_http2_conns', 'max_http3_conns'):
            if field in client and (type(client[field]) is not int or not 0 <= client[field] <= 65535):
                raise ValueError('Лимит соединений: целое число от 0 до 65535 или пустое поле')
    return value['client']


def render(clients):
    text = '\n\n'.join('[[client]]\n' + '\n'.join(k + ' = ' + json.dumps(v, ensure_ascii=False) for k, v in c.items()) for c in clients) + '\n'
    parse(text)
    return text.encode()


def client_id(client):
    return digest(client['username'].encode())[:24]


def registry(root):
    path = root / 'endpoints.json'
    if not path.exists():
        return {}
    value = json.loads(read_private(path))
    if not isinstance(value, dict) or len(value) > 8:
        raise ValueError('Повреждён реестр входящих серверов TrustTunnel')
    for name, b in value.items():
        identifier(name)
        if not isinstance(b, dict) or set(b) != {'name', 'unit', 'unit_file', 'directory', 'binary', 'config', 'hosts', 'credentials', 'local_address', 'external_address', 'dns_upstreams'}:
            raise ValueError('Некорректная привязка входящего TrustTunnel')
        if not isinstance(b['name'], str) or not 1 <= len(b['name']) <= 80 or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,100}\.service', b['unit']):
            raise ValueError('Некорректное имя входящей службы')
        for key in ('unit_file', 'directory', 'binary', 'config', 'hosts', 'credentials'):
            if not isinstance(b[key], str) or not Path(b[key]).is_absolute() or '..' in Path(b[key]).parts:
                raise ValueError('Некорректные пути входящей службы')
        connection_settings(b)
    return value


def connection_settings(value):
    address(value['local_address']); address(value['external_address'])
    items = value['dns_upstreams']
    if not isinstance(items, list) or len(items) > 16:
        raise ValueError('Не больше 16 DNS-серверов')
    for item in items:
        dns(item)


def operation(root):
    path = root / 'incoming-operation.json'
    return json.loads(read_private(path)) if path.exists() else {}


def ensure_idle(root):
    if operation(root).get('status') in ('pending', 'recovery_required'):
        raise ValueError('Не завершено изменение входящих клиентов TrustTunnel; откройте Устройства → TrustTunnel')


@contextlib.contextmanager
def locked(root, shared=False):
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077:
        raise ValueError('Закрытый каталог TrustTunnel недоступен')
    fd = os.open(root / 'control.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        try:
            fcntl.flock(lock, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('TrustTunnel сейчас изменяется; обновите страницу') from None
        yield


class Native:
    def run(self, args, *, cwd=None, timeout=15):
        try:
            p = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            raise ValueError('Входящий TrustTunnel не ответил; проверьте состояние службы') from None
        if p.returncode or len(p.stdout) > LIMIT:
            raise ValueError('Входящий TrustTunnel отклонил операцию; секреты из диагностики скрыты')
        return p.stdout

    def state(self, b):
        raw = self.run(['systemctl', 'show', b['unit'], '-p', 'ActiveState,MainPID,FragmentPath,DropInPaths,NeedDaemonReload'])
        data = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
        if data.get('FragmentPath') != b['unit_file'] or data.get('DropInPaths') or data.get('NeedDaemonReload') != 'no' or data.get('ActiveState') not in ('active', 'inactive', 'failed'):
            raise ValueError('Привязка службы изменилась или служба запускается; обновите состояние')
        return {'active': data['ActiveState'] == 'active', 'pid': int(data.get('MainPID', '0'))}

    def restart(self, b):
        self.run(['systemctl', 'restart', b['unit']], timeout=25)
        port = str(tomllib.loads(regular(Path(b['config'])).decode())['listen_address']).rsplit(':', 1)[1]
        end = time.monotonic() + 8
        while time.monotonic() < end:
            state = self.state(b)
            raw = self.run(['ss', '-H', '-ltnp']).decode()
            if state['active'] and any(any(field.endswith(':' + port) for field in line.split()) and ('pid=' + str(state['pid']) + ',') in line for line in raw.splitlines()):
                return
            time.sleep(.25)
        raise ValueError('Входящий TrustTunnel не подтвердил запуск слушателя')

    def export(self, b, username, mode, kind):
        args = [b['binary'], b['config'], b['hosts'], '--client_config=' + username, '--address=' + b[mode + '_address'], '--format', kind]
        if kind == 'deeplink':
            args += ['--name', b['name'] + ' · ' + username]
        for item in b['dns_upstreams']:
            args += ['--dns-upstream', item]
        raw = self.run(args, cwd=b['directory'])
        if kind == 'deeplink' and not raw.strip().startswith(b'tt://?'):
            raise ValueError('Сервер не вернул стандартную ссылку TrustTunnel')
        if kind == 'deeplink':
            # The endpoint prints a CLI usage hint after a blank line. It is
            # not part of the URI and must never enter a QR or a link file.
            raw = raw.strip().splitlines()[0]
            from trusttunnel_link import decode
            decode(raw.decode())
        if kind == 'toml':
            try:
                tomllib.loads(raw.decode())
            except (ValueError, UnicodeError):
                raise ValueError('Сервер не вернул стандартный TOML') from None
        return raw.decode().strip() + '\n'

    def fingerprint(self, root, binding):
        from trusttunnel_runtime import installation
        return encode(installation(root, binding))

    def arm(self, token):
        self.run(['systemd-run', '--quiet', '--unit=okopy-tt-clients-' + token, '--on-active=90s', '--property=TimeoutStartSec=60s',
                  '/usr/bin/python3', '-E', '-s', '-B', str(Path(__file__).resolve()), token])

    def cancel(self, token):
        self.run(['systemctl', 'stop', 'okopy-tt-clients-' + token + '.timer'])


def source(b):
    main = tomllib.loads(regular(Path(b['config'])).decode())
    declared = (Path(b['directory']) / main.get('credentials_file', '')).resolve()
    if declared != Path(b['credentials']):
        raise ValueError('Путь к списку клиентов отличается от настроенной привязки')
    raw = read_private(Path(b['credentials']))
    clients = parse(raw.decode())
    return raw, clients


def revision(b, raw):
    return digest(encode(b) + b'\0' + raw + b'\0' + regular(Path(b['unit_file'])) + b'\0' + regular(Path(b['config'])) + b'\0' + regular(Path(b['hosts'])))


def restore(root, token, native):
    job = operation(root)
    if job.get('id') != token or job.get('status') not in ('pending', 'recovery_required'):
        return job
    b = registry(root).get(job['endpoint'])
    if b != job['binding']:
        raise ValueError('Привязка сервера изменилась; автоматический возврат остановлен')
    try:
        if digest(regular(Path(b['unit_file']))) != job['unit_sha']:
            raise ValueError('Служба изменилась вне операции')
        for path, versions in job['files'].items():
            if read_private(Path(path)).decode() not in (versions['before'], versions['after']):
                raise ValueError('Файл изменился вне операции; автоматический возврат остановлен')
        for path, versions in job['files'].items():
            atomic_write(Path(path), versions['before'].encode())
        if job['was_active']:
            native.restart(b)
        job['status'] = 'rolled_back'
        atomic_write(root / 'incoming-operation.json', encode(job))
    except Exception:
        job['status'] = 'recovery_required'
        atomic_write(root / 'incoming-operation.json', encode(job))
        raise
    return job


def mutate(root, endpoint, b, before, after, native):
    """Credentials and dependent receipts move together under the existing TT lock."""
    from openconnect_apply import state, PENDING
    if state(root).get('status') in PENDING:
        raise ValueError('Сначала завершите изменение исходящего TrustTunnel')
    related = {}
    connections = json.loads(read_private(root / 'connections.json')) if (root / 'connections.json').exists() else {}
    for name in connections:
        binding = binding_for(root, name)
        if b['credentials'] in binding.get('dependent_files', []):
            receipt = read_private(root / (name + '.installation.json'))
            if json.loads(receipt) != json.loads(native.fingerprint(root, binding)):
                raise ValueError('Связанные настройки изменены вне панели; список клиентов не менялся')
            # Same fingerprint algorithm with the one proposed credential file substituted.
            material = json.dumps(binding, sort_keys=True).encode()
            for path in binding.get('dependent_files', []):
                material += b'\0' + (after if path == b['credentials'] else regular(Path(path)))
            updated = json.loads(receipt); updated['script_sha256'] = digest(material)
            related[str(root / (name + '.installation.json'))] = {'before': receipt.decode(), 'after': encode(updated).decode()}
    state = native.state(b)
    token = uuid.uuid4().hex
    job = {'id': token, 'status': 'pending', 'endpoint': endpoint, 'binding': b, 'created_at': time.time(),
           'was_active': state['active'], 'unit_sha': digest(regular(Path(b['unit_file']))),
           'files': {b['credentials']: {'before': before.decode(), 'after': after.decode()}, **related}}
    if len(encode(job)) > 256 * 1024:
        raise ValueError('Изменение слишком велико для безопасного журнала; уменьшите список клиентов')
    atomic_write(root / 'incoming-operation.json', encode(job))
    try:
        native.arm(token)
    except Exception:
        job['status'] = 'schedule_failed'; atomic_write(root / 'incoming-operation.json', encode(job)); raise
    try:
        for path, versions in job['files'].items():
            atomic_write(Path(path), versions['after'].encode())
        # Export parses the native config without starting a second listener.
        native.export(b, parse(after.decode())[0]['username'], 'external', 'toml')
        if state['active']:
            native.restart(b)
        if native.state(b)['active'] != state['active']:
            raise ValueError('Состояние сервера изменилось во время операции')
        job['status'] = 'completed'; job['finished_at'] = time.time()
        atomic_write(root / 'incoming-operation.json', encode(job))
    except Exception:
        restore(root, token, native)
        raise
    finally:
        if operation(root).get('status') not in ('pending', 'recovery_required'):
            native.cancel(token)
    return {'operation': 'completed', 'endpoint_restarted': state['active']}


def control(request, *, root=ROOT, native=None, network=Path('/var/lib/okopy-candidate')):
    native = native or Native()
    action = request.get('action')
    fields = {'version', 'action'}
    if action != 'tt-clients-status': fields |= {'endpoint', 'revision'}
    fields |= {'tt-clients-save': {'id', 'values'}, 'tt-clients-delete': {'id'}, 'tt-clients-import': {'text'},
               'tt-clients-export': {'id', 'mode', 'format'}, 'tt-clients-settings': {'values'}, 'tt-clients-recover': {'operation'}}.get(action, set())
    if action not in ACTIONS or request.get('version') != 1 or set(request) != fields:
        raise ValueError('Некорректные поля управления клиентами TrustTunnel')
    with locked(root, action == 'tt-clients-status'):
        registered = registry(root)
        if action == 'tt-clients-status':
            servers = []
            for endpoint, b in registered.items():
                raw, clients = source(b)
                servers.append({'id': endpoint, **{k: b[k] for k in ('name', 'local_address', 'external_address', 'dns_upstreams')},
                                'revision': revision(b, raw), 'runtime': native.state(b),
                                'clients': [{'id': client_id(c), **{k: v for k, v in c.items() if k != 'password'}} for c in clients]})
            job = operation(root)
            return {'servers': servers, 'operation': {k: job[k] for k in ('id', 'status', 'endpoint') if k in job}}
        endpoint = identifier(request['endpoint']); b = registered.get(endpoint)
        if b is None: raise ValueError('Входящий сервер не зарегистрирован')
        if action == 'tt-clients-recover':
            job = operation(root)
            if job.get('endpoint') != endpoint: raise ValueError('Операция относится к другому серверу')
            restore(root, request['operation'], native)
            return {'operation': operation(root).get('status')}
        ensure_idle(root)
        raw, clients = source(b)
        if request['revision'] != revision(b, raw): raise ValueError('Список или настройки сервера изменились; обновите страницу')
        if action == 'tt-clients-export':
            if request['format'] == 'credentials':
                if request['id'] or request['mode']: raise ValueError('Экспорт списка не принимает клиента и адрес')
                return {'content': raw.decode(), 'filename': endpoint + '-credentials.toml'}
            if request['format'] not in ('toml', 'deeplink') or request['mode'] not in ('local', 'external'): raise ValueError('Выберите TOML или ссылку и способ подключения')
            client = next((c for c in clients if client_id(c) == request['id']), None)
            if client is None: raise ValueError('Клиент не найден')
            return {'content': native.export(b, client['username'], request['mode'], request['format']),
                    'filename': endpoint + '-' + request['id'] + '-' + request['mode'] + ('.toml' if request['format'] == 'toml' else '.txt')}
        if action == 'tt-clients-settings':
            values = request['values']
            if not isinstance(values, dict) or set(values) != {'local_address', 'external_address', 'dns_upstreams'}: raise ValueError('Некорректные поля адресов сервера')
            connection_settings(values); registered[endpoint] = {**b, **values}
            atomic_write(root / 'endpoints.json', encode(registered))
            return {'saved': True, 'endpoint_restarted': False}
        if action == 'tt-clients-import':
            clients = parse(request['text'])
        elif action == 'tt-clients-delete':
            remaining = [c for c in clients if client_id(c) != request['id']]
            if len(remaining) == len(clients): raise ValueError('Клиент не найден')
            if not remaining: raise ValueError('Нельзя оставить сервер без учётных записей. Для отзыва последнего доступа смените пароль или выключите входящий сервер')
            clients = remaining
        else:
            values = request['values']
            if not isinstance(values, dict) or set(values) != {'username', 'password', 'max_http2_conns', 'max_http3_conns'}: raise ValueError('Некорректные поля клиента')
            previous = next((c for c in clients if client_id(c) == request['id']), None)
            if request['id'] and previous is None: raise ValueError('Клиент не найден')
            if not isinstance(values['password'], str): raise ValueError('Некорректный пароль')
            client = {'username': values['username'], 'password': values['password'] or (previous['password'] if previous else secrets.token_urlsafe(32))}
            for key in ('max_http2_conns', 'max_http3_conns'):
                if values[key] != '':
                    if not isinstance(values[key], str) or not re.fullmatch(r'[0-9]{1,5}', values[key]): raise ValueError('Лимит соединений: целое число от 0 до 65535')
                    client[key] = int(values[key])
            clients = [client if c is previous else c for c in clients] if previous else clients + [client]
        after = render(clients)
        if after == raw: return {'operation': 'unchanged', 'endpoint_restarted': False}
        with contextlib.ExitStack() as stack:
            if network is not None:
                lock = stack.enter_context((network / 'apply.lock').open('r'))
                try: fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError: raise ValueError('Сетевая политика сейчас изменяется') from None
                if json.loads(read_private(network / 'transaction.json')).get('status') != 'confirmed': raise ValueError('Сначала подтвердите сетевую политику')
            return mutate(root, endpoint, b, raw, after, native)


if __name__ == '__main__':
    os.umask(0o077)
    if os.geteuid() != 0 or len(sys.argv) != 2 or not re.fullmatch('[0-9a-f]{32}', sys.argv[1]): raise SystemExit(64)
    with locked(ROOT):
        restore(ROOT, sys.argv[1], Native())
