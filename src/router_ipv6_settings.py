"""Validated settings for the router's IPv6 server/provider switch."""
import hashlib
import ipaddress
import json
import re
import shlex

KEYS = {'policy', 'server_connection', 'provider_connection', 'prefixes',
        'health_address', 'health_port', 'probe_seconds', 'interval_seconds',
        'failures', 'recovery_seconds'}


def validate(value):
    if not isinstance(value, dict) or set(value) != KEYS:
        raise ValueError('Нужен полный набор параметров переключения IPv6')
    value = dict(value)
    for key in ('policy', 'server_connection', 'provider_connection'):
        if not isinstance(value[key], str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', value[key]):
            raise ValueError('Выберите существующую политику и соединения роутера')
    if value['server_connection'] == value['provider_connection']:
        raise ValueError('Соединения сервера и провайдера должны различаться')
    limits = {'health_port': (1, 65535), 'probe_seconds': (1, 3),
              'interval_seconds': (1, 5), 'failures': (1, 20), 'recovery_seconds': (1, 3600)}
    for key, (low, high) in limits.items():
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError('Параметр вне допустимого диапазона: '+key)
    if not isinstance(value['health_address'], str):
        raise ValueError('Адрес проверки должен быть строкой')
    address = ipaddress.ip_address(value['health_address'])
    if '%' in value['health_address'] or address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
        raise ValueError('Нужен адрес проверки сервера, доступный с роутера')
    value['health_address'] = str(address)
    if not isinstance(value['prefixes'], list) or not 1 <= len(value['prefixes']) <= 16:
        raise ValueError('Задайте от 1 до 16 сетей IPv6')
    networks = []
    for raw in value['prefixes']:
        if not isinstance(raw, str):
            raise ValueError('Сеть IPv6 должна быть строкой')
        network = ipaddress.IPv6Network(raw, strict=True)
        if not any(network.subnet_of(ipaddress.IPv6Network(scope)) for scope in ('2000::/3', 'fc00::/7', '200::/7')):
            raise ValueError('Сеть должна относиться к global unicast, ULA или Yggdrasil')
        if any(network.overlaps(previous) for previous in networks):
            raise ValueError('Сети не должны пересекаться')
        networks.append(network)
    value['prefixes'] = [str(n) for n in networks]
    return value


def compile_settings(value):
    value = validate(value)
    revision = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    fields = {key.upper(): ' '.join(item) if isinstance(item, list) else str(item)
              for key, item in value.items()}
    fields['REVISION'] = revision
    fields['SETTINGS_JSON'] = json.dumps(value, sort_keys=True)
    return ('\n'.join(key+'='+shlex.quote(item) for key, item in fields.items())+'\n').encode()


def revision(value):
    return hashlib.sha256(json.dumps(validate(value), sort_keys=True).encode()).hexdigest()


def parse_form(form):
    value = {}
    for key in KEYS:
        raw = form.get(key, '').strip()
        if key == 'prefixes':
            value[key] = raw.split()
        elif key in ('policy', 'server_connection', 'provider_connection', 'health_address'):
            value[key] = raw
        else:
            if not re.fullmatch(r'[0-9]{1,5}', raw):
                raise ValueError('Введите целое число: ' + key)
            value[key] = int(raw)
    return validate(value)


def import_settings(text):
    if len(text.encode()) > 16384:
        raise ValueError('Файл настроек превышает 16 КиБ')
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        raise ValueError('Нужен JSON-файл настроек аварийного режима') from None
    if not isinstance(value, dict) or set(value) != {'version', 'settings'} or type(value['version']) is not int or value['version'] != 1:
        raise ValueError('Неизвестный формат настроек аварийного режима')
    return validate(value['settings'])


def export_settings(value):
    return json.dumps({'version': 1, 'settings': validate(value)}, ensure_ascii=False, indent=2)+'\n'
