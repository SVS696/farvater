"""Validated AnyConnect-compatible server settings and portable client export.

Only the optional runtime renders private files or starts ocserv. Names of host
interfaces and executable hooks are owned by that runtime, never by imports.
"""
import base64
import copy
import hashlib
import ipaddress
import re
from pathlib import Path

TYPE = 'openconnect-server'
NUMBERS = {'mtu': (576, 9000), 'max_clients': (1, 4096),
           'max_same_clients': (1, 64), 'keepalive': (1, 3600),
           'dpd': (1, 3600), 'mobile_dpd': (1, 86400)}
FIELDS = {'type', 'listen', 'listen_port', 'dtls', 'pools', 'client_dns',
          'client_routes', 'split_dns', 'certificate', 'private_key',
          'users', 'compression', *NUMBERS}


def validate(native):
    from incoming_connections import text
    from policy import normalized_domain
    if not isinstance(native, dict) or set(native) != FIELDS or native.get('type') != TYPE:
        raise ValueError('OpenConnect: неверная структура серверных настроек')
    try:
        value = native['listen']
        if not isinstance(value, str) or '%' in value: raise ValueError()
        ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('OpenConnect: адрес прослушивания должен быть IP-адресом') from None
    if type(native['listen_port']) is not int or not 1 <= native['listen_port'] <= 65535:
        raise ValueError('OpenConnect: порт от 1 до 65535')
    for field in ('dtls', 'compression'):
        if type(native[field]) is not bool: raise ValueError('OpenConnect: неверный переключатель ' + field)
    for field, (low, high) in NUMBERS.items():
        if type(native[field]) is not int or not low <= native[field] <= high:
            raise ValueError(f'OpenConnect: {field} от {low} до {high}')
    if native['max_same_clients'] > native['max_clients']:
        raise ValueError('Лимит одного клиента не может превышать общий лимит')
    families = set()
    pools = native['pools']
    if not isinstance(pools, list) or not 1 <= len(pools) <= 2:
        raise ValueError('OpenConnect: задайте пул IPv4 и/или IPv6')
    for value in pools:
        if not isinstance(value, str) or '%' in value: raise ValueError('OpenConnect: неверный пул')
        n = ipaddress.ip_network(value, strict=True)
        if (n.version in families or n.num_addresses < 8 or n.prefixlen == 0
                or n.is_loopback or n.is_multicast or n.is_link_local or n.is_unspecified):
            raise ValueError('OpenConnect: нужен отдельный непустой пул каждого семейства')
        families.add(n.version)
    if 6 in families and native['mtu'] < 1400:
        raise ValueError('OpenConnect: для IPv6 задайте MTU внешнего пути не ниже 1400; движок вычитает заголовки туннеля')
    for field in ('client_dns', 'client_routes', 'split_dns'):
        values = native[field]
        if not isinstance(values, list) or len(values) > 128:
            raise ValueError('OpenConnect: неверный список ' + field)
        if field == 'client_routes' and not values:
            raise ValueError('OpenConnect: укажите маршруты клиентов')
        for value in values:
            text(value, field, 253)
            if field == 'client_dns': ipaddress.ip_address(value)
            elif field == 'client_routes': ipaddress.ip_network(value, strict=True)
            else: normalized_domain(value)
    cert, key = native['certificate'], native['private_key']
    if any(not isinstance(v, str) or not v or len(v) > 65536 for v in (cert, key)):
        raise ValueError('OpenConnect: укажите сертификат и ключ PEM')
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import load_pem_private_key,Encoding,PublicFormat
        certificates=x509.load_pem_x509_certificates(cert.encode())
        private=load_pem_private_key(key.encode(),password=None)
        if not certificates or certificates[0].public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)!=private.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo):raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('OpenConnect: сертификат и незашифрованный ключ PEM не подходят друг к другу') from None
    users = native['users']
    if not isinstance(users, list) or len(users) > 64:
        raise ValueError('OpenConnect: до 64 клиентов на сервер')
    names = set()
    for user in users:
        if not isinstance(user, dict) or set(user)-{'password_hash'} != {'username', 'password'}:
            raise ValueError('OpenConnect: нужны логин и пароль клиента')
        name = user['username']
        if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}', name) or name in names:
            raise ValueError('OpenConnect: уникальный логин из букв, цифр, точек, @, _ и -')
        names.add(name)
        if user['password']:text(user['password'], 'Пароль клиента', 4096)
        elif not isinstance(user['password'],str) or not user.get('password_hash'):
            raise ValueError('OpenConnect: задайте пароль или импортируйте его хеш')
        if 'password_hash' in user and not re.fullmatch(r'\$[56]\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{43,86}',user['password_hash']):
            raise ValueError('OpenConnect: поддерживается хеш ocpasswd SHA-256/SHA-512 без дополнительных rounds')
    return native


def device_prefix(identifier):
    # Ten characters leave room for ocserv's per-client numeric suffix.
    from incoming_kernel import interface_name
    interface_name(identifier)
    return 'fc' + hashlib.sha256(identifier.encode()).hexdigest()[:8]


def render_config(native, directory, prefix, *, user='farvater-ocserv', group='farvater-ocserv'):
    """Render only supported settings; runtime paths are trusted arguments."""
    validate(native)
    directory = Path(directory)
    if not directory.is_absolute() or not re.fullmatch(r'/[a-zA-Z0-9_./-]+', str(directory)):
        raise ValueError('Неверный каталог серверного модуля')
    if not re.fullmatch(r'fc[a-f0-9]{8}', prefix): raise ValueError('Неверный префикс интерфейсов')
    if any(not re.fullmatch(r'[a-z_][a-z0-9_-]*', v) for v in (user, group)):
        raise ValueError('Неверный системный пользователь модуля')
    options = [f'auth = "plain[passwd={directory}/ocpasswd]"',
               'listen-host = ' + native['listen'], 'tcp-port = ' + str(native['listen_port']),
               'udp-port = ' + str(native['listen_port'] if native['dtls'] else 0),
               'run-as-user = ' + user, 'run-as-group = ' + group,
               f'socket-file = {directory}/ocserv.sock',
               f'occtl-socket-file = {directory}/occtl.sock', 'use-occtl = true',
               f'server-cert = {directory}/server.pem', f'server-key = {directory}/key.pem',
               'device = ' + prefix, 'predictable-ips = true',
               'isolate-workers = true', 'cisco-client-compat = true',
               'compression = ' + ('true' if native['compression'] else 'false')]
    for field in NUMBERS:
        options.append(field.replace('_', '-') + ' = ' + str(native[field]))
    for pool in native['pools']:
        n = ipaddress.ip_network(pool)
        options.append(('ipv4-network' if n.version == 4 else 'ipv6-network') + ' = ' + str(n))
        if n.version == 6: options.append('ipv6-subnet-prefix = 128')
    for field, option in [('client_dns', 'dns'), ('client_routes', 'route'), ('split_dns', 'split-dns')]:
        for value in native[field]:
            # ocserv rejects /0; two /1 routes preserve each family's explicit
            # choice, whereas its special "default" also affects the other one.
            network = ipaddress.ip_network(value) if field == 'client_routes' else None
            values = [str(n) for n in network.subnets(prefixlen_diff=1)] if network is not None and network.prefixlen == 0 else [value]
            options.extend(option + ' = ' + v for v in values)
    return '\n'.join(options) + '\n'


def client_model(entry, name, mode):
    from incoming_connections import host
    from openconnect_profile import DEFAULT, validate as validate_client
    n = validate(entry['native'])
    if not entry['enabled'] or name in entry.get('disabled_clients', []):
        raise ValueError('Подключение или клиент отключён')
    if mode not in ('local', 'external'): raise ValueError('Выберите локальное или внешнее подключение')
    user = next((u for u in n['users'] if u['username'] == name), None)
    if user is None: raise ValueError('Клиент OpenConnect не найден')
    if not user['password']:raise ValueError('Из серверного файла импортирован только хеш; задайте новый пароль клиента для выдачи профиля')
    hostname = host(entry[mode + '_host'])
    if ':' in hostname: hostname = '[' + hostname + ']'
    first = n['certificate'].split('-----END CERTIFICATE-----', 1)[0] + '-----END CERTIFICATE-----'
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    public = x509.load_pem_x509_certificate(first.encode()).public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    fingerprint = base64.b64encode(hashlib.sha256(public).digest()).decode()
    model = {**copy.deepcopy(DEFAULT), 'server': f'https://{hostname}:{n["listen_port"]}',
             'username': name, 'password': user['password'], 'servercert': 'pin-sha256:' + fingerprint,
             'no_dtls': not n['dtls'], 'disable_ipv6': not any(':' in p for p in n['pools']),
             'compression': 'stateless' if n['compression'] else 'none'}
    return validate_client(model, ready=True)


def parse_form(form,previous=None):
    import secrets
    import uuid
    from incoming_connections import validate as validate_entries
    previous=previous or {};old=previous.get('native',{})
    def number(field,default=None):
        try:return int(form.get(field,'') or default)
        except (TypeError,ValueError):raise ValueError('Укажите целое число: '+field) from None
    def lines(field):return [v.strip() for v in form.get(field,'').splitlines() if v.strip()]
    n={'type':TYPE,'listen':form.get('listen','').strip(),'listen_port':number('listen_port'),
       'dtls':form.get('dtls')=='on','compression':form.get('compression')=='on',
       **{field:lines(field) for field in ('pools','client_dns','client_routes','split_dns')},
       **{field:number(field) for field in NUMBERS},
       'certificate':form.get('certificate','').strip() or old.get('certificate',''),
       'private_key':form.get('private_key','').strip() or old.get('private_key',''),'users':[]}
    columns=[form.getlist('client_'+key) for key in ('original','name','secret')]
    if len({len(v) for v in columns})!=1 or len(columns[0])>64:raise ValueError('Некорректный список клиентов')
    originals=[v for v in columns[0] if v];before={u['username']:u for u in old.get('users',[])}
    if len(set(originals))!=len(originals) or any(v not in before for v in originals):raise ValueError('Исходный клиент изменился')
    for original,name,secret in zip(*columns):
        user=copy.deepcopy(before.get(original,{}));user['username']=name.strip()
        if secret:user['password']=secret;user.pop('password_hash',None)
        elif not original:user['password']=secrets.token_urlsafe(24)
        n['users'].append(user)
    disabled=form.getlist('disabled_client')
    if any(v not in before for v in disabled):raise ValueError('Отключаемый клиент не найден')
    e={'id':previous.get('id') or uuid.uuid4().hex,'name':form.get('name','').strip(),'enabled':form.get('enabled')=='on',
       'local_host':form.get('local_host','').strip(),'external_host':form.get('external_host','').strip(),'native':n,
       'disabled_clients':[name.strip() for original,name in zip(columns[0],columns[1]) if original in disabled]}
    validate_entries([e]);return e
