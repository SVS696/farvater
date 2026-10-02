"""Authenticated native listener modules, compiled into the existing policy core.

This module never starts processes, opens firewall ports or reads external files.
Server secrets appear only in explicit server exports, never in client configs.
"""
import base64
import copy
import ipaddress
import json
import re
import uuid
from urllib.parse import quote

from policy import normalized_domain
from shadowsocks_uri import native as validate_ss, render as ss_link

PREFIX = 'incoming-'
TYPES = {'socks', 'http', 'shadowsocks', 'vless', 'openvpn-server', 'amneziawg', 'openconnect-server'}
ENDPOINT_TYPES = {'openvpn-server'}

def module_key(kind):
    return {'openvpn-server':'openvpn','amneziawg':'amnezia','openconnect-server':'openconnect'}.get(kind,kind)
MAX_BYTES = 256 * 1024
TLS_FIELDS = {'enabled', 'server_name', 'alpn', 'min_version', 'max_version', 'certificate', 'key'}
TRANSPORT_FIELDS = {
    'ws': {'type', 'path', 'headers', 'max_early_data', 'early_data_header_name'},
    'http': {'type', 'host', 'path', 'method'},
    'httpupgrade': {'type', 'host', 'path', 'headers'},
    'grpc': {'type', 'service_name'},
}


def text(value, label, maximum=4096):
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(label + ': недопустимое значение')
    return value


def host(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return normalized_domain(value)


def validate_native(native):
    if not isinstance(native, dict) or native.get('type') not in TYPES:
        raise ValueError('Неизвестный входящий протокол sing-box')
    kind = native['type']
    if kind == 'openconnect-server':
        from ocserv_incoming import validate as check_ocserv
        return check_ocserv(native)
    if kind == 'amneziawg':
        from amnezia_incoming import validate as validate_awg
        return validate_awg(native)
    common = {'type', 'listen', 'listen_port', 'tag', 'users'}
    if kind == 'openvpn-server':
        from openvpn_incoming import validate as check_openvpn, FIELDS
        check_openvpn(native)
        fields = FIELDS
    else:
        fields = {'socks': set(), 'http': {'tls'}, 'vless': {'tls', 'transport'},
              'shadowsocks': {'method', 'password', 'network'}}[kind]
    if set(native) - common - fields:
        raise ValueError('Неподдержанные параметры входящего подключения: ' + ', '.join(sorted(set(native) - common - fields)))
    try:
        if not isinstance(native.get('listen'), str):raise ValueError()
        ipaddress.ip_address(native['listen'])
    except ValueError:
        raise ValueError('Адрес прослушивания должен быть IP-адресом') from None
    if type(native.get('listen_port')) is not int or not 1 <= native['listen_port'] <= 65535:
        raise ValueError('Порт: целое число от 1 до 65535')
    users = native.get('users', [])
    if not isinstance(users, list) or len(users) > 64 or (kind != 'shadowsocks' and not users):
        raise ValueError('Добавьте от 1 до 64 клиентов; анонимный доступ не разрешён')
    identities = set()
    for user in users:
        allowed = {'username', 'password'} if kind in ('socks', 'http', 'openvpn-server', 'openconnect-server') else {'name', 'uuid', 'flow'} if kind == 'vless' else {'name', 'password'}
        if not isinstance(user, dict) or set(user) - allowed:
            raise ValueError('Некорректные поля клиента')
        identity = text(user.get('username' if kind in ('socks', 'http', 'openvpn-server', 'openconnect-server') else 'name'), 'Имя клиента', 128)
        if identity in identities:
            raise ValueError('Имена клиентов должны быть уникальны')
        identities.add(identity)
        if kind == 'vless':
            try:
                uuid.UUID(user.get('uuid', ''))
            except (ValueError, TypeError, AttributeError):
                raise ValueError('У клиента VLESS нужен UUID') from None
            if user.get('flow', '') not in ('', 'xtls-rprx-vision'):
                raise ValueError('Неизвестный flow VLESS')
            if user.get('flow') and (native.get('transport') or not native.get('tls', {}).get('enabled')):
                raise ValueError('Vision требует TLS без дополнительного транспорта')
        else:
            text(user.get('password'), 'Пароль клиента')
    if kind == 'vless' and len({str(uuid.UUID(u['uuid'])) for u in users}) != len(users):
        raise ValueError('UUID клиентов должны быть уникальны')
    if kind == 'shadowsocks':
        if native.get('network', '') not in ('', 'tcp', 'udp'):
            raise ValueError('Неизвестный транспорт Shadowsocks')
        validate_ss({'type': kind, 'server': '127.0.0.1', 'server_port': native['listen_port'],
                     'method': native.get('method'), 'password': native.get('password')})
        if native['method'].startswith('2022-') and ':' in native['password']:
            raise ValueError('Ключ сервера Shadowsocks 2022 должен быть одиночным')
        if native['method'] == 'none':
            raise ValueError('Входящий Shadowsocks требует аутентификацию')
        if users:
            if native['method'] not in ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm'):
                raise ValueError('Несколько клиентов на одном порту требуют Shadowsocks 2022 AES')
            for user in users:
                if ':' in user['password']:raise ValueError('Ключ клиента Shadowsocks 2022 должен быть одиночным')
                validate_ss({'type': kind, 'server': '127.0.0.1', 'server_port': native['listen_port'],
                             'method': native['method'], 'password': user['password']})
            if len({u['password'] for u in users}) != len(users):
                raise ValueError('Ключи клиентов должны быть уникальны')
    tls = native.get('tls') if kind != 'openvpn-server' else None
    if tls is not None:
        if not isinstance(tls, dict) or set(tls) - TLS_FIELDS or tls.get('enabled') is not True:
            raise ValueError('TLS: нужны встроенные сертификат и ключ, без внешних путей')
        for field, marker in [('certificate', 'CERTIFICATE'), ('key', 'PRIVATE KEY')]:
            lines = tls.get(field)
            if not isinstance(lines, list) or not lines or any(not isinstance(v, str) for v in lines) or marker not in '\n'.join(lines):
                raise ValueError('TLS: укажите PEM ' + field)
        if 'server_name' in tls:
            host(tls['server_name'])
        if 'alpn' in tls and (not isinstance(tls['alpn'], list) or any(not isinstance(s, str) or not s for s in tls['alpn'])):
            raise ValueError('ALPN должен быть списком непустых строк')
        for field in ('min_version', 'max_version'):
            if field in tls and tls[field] not in ('1.2', '1.3'):
                raise ValueError('Поддерживается TLS 1.2 или 1.3')
    transport = native.get('transport')
    if transport is not None:
        if not isinstance(transport, dict) or transport.get('type') not in TRANSPORT_FIELDS or set(transport) - TRANSPORT_FIELDS[transport['type']]:
            raise ValueError('Неизвестные параметры транспорта VLESS')
        # Native core checks exact transport semantics; no paths or executable hooks are admitted.
        json.dumps(transport, allow_nan=False)
    return native


def validate(entries):
    if not isinstance(entries, list) or len(entries) > 32:
        raise ValueError('Не больше 32 входящих подключений')
    ids = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - {'disabled_clients'} != {'id', 'name', 'enabled', 'local_host', 'external_host', 'native'}:
            raise ValueError('Некорректная запись входящего подключения')
        key = entry['id']
        if not isinstance(key, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', key) or key in ids:
            raise ValueError('Идентификаторы входящих подключений должны быть уникальны')
        ids.add(key)
        text(entry['name'], 'Название', 120)
        if type(entry['enabled']) is not bool:
            raise ValueError('Некорректный признак включения')
        for field in ('local_host', 'external_host'):
            text(entry[field], 'Адрес подключения', 253)
            host(entry[field])
        native = validate_native(entry['native'])
        disabled = entry.get('disabled_clients', [])
        field = 'username' if native['type'] in ('socks', 'http', 'openvpn-server', 'openconnect-server') else 'name'
        if not isinstance(disabled,list) or any(not isinstance(v,str) for v in disabled) or len(set(disabled)) != len(disabled) or not set(disabled).issubset({u[field] for u in native.get('users',[])}):
            raise ValueError('Список отключённых клиентов не соответствует подключению')
        if 'tag' in native and native['tag'] != PREFIX + key:
            raise ValueError('Идентификатор входа не совпадает с записью')
    return entries


def compile_entries(entries):
    result=[]
    for e in validate(entries):
        if not e['enabled'] or e['native']['type'] in ('amneziawg','openconnect-server'):continue
        native=copy.deepcopy(e['native']);native['tag']=PREFIX+e['id']
        if native.get('users'):
            field='username' if native['type'] in ('socks','http','openvpn-server','openconnect-server') else 'name'
            native['users']=[u for u in native['users'] if u[field] not in e.get('disabled_clients',[])]
            # Never convert an all-disabled authenticated server to anonymous access.
            if not native['users']:continue
        result.append(native)
    return result


def compile_inbounds(entries):
    from incoming_kernel import inbounds,scopes,SOCKS_UDP_MARK
    native=[n for n in compile_entries(entries) if n['type'] not in ENDPOINT_TYPES]
    for n in native:
        if n['type']=='socks':n['routing_mark']=SOCKS_UDP_MARK
    return native+inbounds(scopes(entries))


def compile_endpoints(entries):
    return [n for n in compile_entries(entries) if n['type'] in ENDPOINT_TYPES]


def validate_ports(config,entries=()):
    from incoming_kernel import shared_listener_pair
    rows=config['inbounds']+config.get('endpoints',[])
    ports={r.get('listen_port') for r in rows}
    api=config.get('experimental',{}).get('clash_api',{}).get('external_controller','')
    if api:ports.add(int(api.rsplit(':',1)[1]))
    for e in entries:
        if e['enabled'] and e['native']['type'] in ('amneziawg','openconnect-server'):
            port=e['native']['listen_port']
            if port in ports:raise ValueError('Порт '+('AmneziaWG' if e['native']['type']=='amneziawg' else 'OpenConnect')+' занят другим входом или адаптером')
            ports.add(port)
    for incoming in rows:
        if not incoming.get('tag','').startswith(PREFIX):continue
        if any(r is not incoming and r.get('listen_port')==incoming['listen_port'] and not shared_listener_pair(r,incoming) for r in rows):
            raise ValueError('Порт входящего подключения занят другим входом или адаптером')


def attach(config, entries):
    new_inbounds = compile_inbounds(entries)
    new_endpoints = compile_endpoints(entries)
    new = new_inbounds + new_endpoints
    existing = config['inbounds'] + config.get('endpoints', [])
    ports = {row.get('listen_port') for row in existing}
    api = config.get('experimental', {}).get('clash_api', {}).get('external_controller', '')
    if api:
        ports.add(int(api.rsplit(':', 1)[1]))
    tags = {row['tag'] for row in existing}
    from incoming_kernel import shared_listener_pair,route_prefix,scopes
    accepted=[]
    for row in new:
        if row['listen_port'] in ports or row['tag'] in tags or any(r['listen_port']==row['listen_port'] and not shared_listener_pair(r,row) for r in accepted):
            raise ValueError('Порт или идентификатор входящего подключения уже занят')
        accepted.append(row);tags.add(row['tag'])
    config['inbounds'].extend(new_inbounds)
    if new_endpoints:config.setdefault('endpoints', []).extend(new_endpoints)
    kernel_rules=route_prefix(scopes(entries))
    from incoming_kernel import PREFIX as KERNEL_PREFIX
    new=[row for row in new if not row['tag'].startswith(KERNEL_PREFIX)]
    if new:
        # Authenticated DNS requests share the exact policy DNS path, including split DNS.
        config['route']['rules'][:0] = [
            {'inbound': [row['tag'] for row in new], 'port': 53, 'action': 'hijack-dns'},
            {'inbound': [row['tag'] for row in new], 'action': 'sniff', 'timeout':'300ms'}]
    config['route']['rules'][:0]=kernel_rules


def client_config(entry, client, mode):
    validate([entry])
    if mode not in ('local', 'external'):
        raise ValueError('Выберите локальное или внешнее подключение')
    n = entry['native']; kind = n['type']; users = n.get('users', [])
    if kind=='openconnect-server':
        from ocserv_incoming import client_model
        return client_model(entry,client,mode)
    if not entry['enabled']:
        raise ValueError('Подключение выключено')
    if client in entry.get('disabled_clients',[]):raise ValueError('Клиент отключён')
    if users:
        field = 'username' if kind in ('socks', 'http', 'openvpn-server', 'openconnect-server') else 'name'
        user = next((u for u in users if u[field] == client), None)
        if user is None:
            raise ValueError('Клиент не найден')
    elif kind == 'shadowsocks' and client == '':
        user = {}
    else:
        raise ValueError('Клиент не найден')
    if kind == 'openvpn-server':
        from openvpn_incoming import client as openvpn_client
        return openvpn_client(n, user, host(entry[mode + '_host']))
    out = {'type': kind, 'server': host(entry[mode + '_host']), 'server_port': n['listen_port']}
    if kind in ('socks', 'http', 'openvpn-server', 'openconnect-server'):
        out.update(username=user['username'], password=user['password'])
        if kind == 'socks':out['version'] = '5'
    elif kind == 'vless':
        out['uuid'] = user['uuid']
        if user.get('flow'):out['flow'] = user['flow']
        if n.get('transport'):out['transport'] = copy.deepcopy(n['transport'])
    else:
        out.update(method=n['method'], password=n['password'] + (':' + user['password'] if users else ''))
        if n.get('network'):out['network'] = n['network']
    if n.get('tls'):
        tls = n['tls']
        out['tls'] = {'enabled': True, 'server_name': tls.get('server_name', out['server']),
                      'certificate': copy.deepcopy(tls['certificate'])}
        if tls.get('alpn'):out['tls']['alpn'] = list(tls['alpn'])
    return out


def client_link(entry, client, mode):
    out = client_config(entry, client, mode)
    if out['type'] == 'openvpn-client':
        raise ValueError('OpenVPN использует стандартный файл .ovpn вместо ссылки или QR')
    if out['type'] == 'shadowsocks':
        if out.get('network'):raise ValueError('Для ограничения TCP/UDP используйте JSON-экспорт без потери настроек')
        return ss_link({'name': entry['name'], 'native': out})
    if out.get('tls') or out.get('transport'):
        raise ValueError('Используйте JSON: ссылка не переносит сертификат доверия и все параметры транспорта')
    address = out['server']
    if ':' in address:address = '[' + address + ']'
    if out['type'] == 'vless':
        return 'vless://' + out['uuid'] + '@' + address + ':' + str(out['server_port']) + '?encryption=none&type=tcp&security=none#' + quote(entry['name']) + '\n'
    scheme = 'socks5' if out['type'] == 'socks' else 'http'
    return scheme + '://' + quote(out['username'], safe='') + ':' + quote(out['password'], safe='') + '@' + address + ':' + str(out['server_port']) + '\n'


def import_native(raw, entry):
    from policy_exchange import unique
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('JSON входа превышает 256 КиБ')
    try:
        value = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Нужен корректный JSON sing-box') from None
    section = 'endpoints' if entry['native']['type'] in ENDPOINT_TYPES else 'inbounds'
    if not isinstance(value, dict) or set(value) != {section} or not isinstance(value[section], list) or len(value[section]) != 1:
        raise ValueError('Импортируйте один входящий сервер sing-box')
    result = copy.deepcopy(entry)
    result['native'] = value[section][0]
    validate_native(result['native'])
    result['native']['tag'] = PREFIX + result['id']
    if 'disabled_clients' in result:
        field='username' if result['native']['type'] in ('socks','http','openvpn-server','openconnect-server') else 'name'
        names={u[field] for u in result['native'].get('users',[])}
        result['disabled_clients']=[v for v in result['disabled_clients'] if v in names]
    validate([result])
    return result
