"""SIP002 links. Reject settings that cannot be transferred without loss."""
import base64
import ipaddress
import re
from urllib.parse import quote, unquote, urlsplit
from policy import normalized_domain
from tunnel_form import SS_METHODS

LIMIT = 65536
FIELDS = {'type', 'tag', 'server', 'server_port', 'method', 'password'}


def string(value, limit, label):
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(label+': пустое или недопустимое значение')
    return value


def decoded(value):
    if re.search(r'%(?![a-fA-F0-9]{2})', value): raise ValueError('Некорректное percent-кодирование ссылки')
    try: return unquote(value, encoding='utf-8', errors='strict')
    except UnicodeError: raise ValueError('Ссылка должна содержать текст UTF-8') from None


def b64(value):
    if not re.fullmatch(r'[A-Za-z0-9_+/=-]+', value): raise ValueError('Некорректный Base64 в ссылке')
    try: return base64.b64decode(value+'='*((-len(value))%4), altchars=b'-_', validate=True).decode('utf-8')
    except (ValueError, UnicodeError): raise ValueError('Не удалось прочитать Base64 ссылки') from None


def native(value):
    if not isinstance(value, dict) or value.get('type') != 'shadowsocks': raise ValueError('Нужен выход Shadowsocks')
    if set(value)-FIELDS:
        raise ValueError('Ссылка ss:// не передаёт дополнительные настройки этого выхода. Сетевой интерфейс, DNS, transport, плагины и другие параметры нельзя молча потерять при экспорте')
    host = string(value.get('server'), 253, 'Сервер')
    try: host = str(ipaddress.ip_address(host))
    except ValueError: host = normalized_domain(host)
    port = value.get('server_port')
    if type(port) is not int or not 1 <= port <= 65535: raise ValueError('Порт должен быть от 1 до 65535')
    method = value.get('method')
    if method not in SS_METHODS: raise ValueError('Метод Shadowsocks не поддерживается установленным клиентом')
    password = string(value.get('password'), 16384, 'Пароль')
    if method.startswith('2022-'):
        length = 16 if method == '2022-blake3-aes-128-gcm' else 32
        for part in password.split(':'):
            try: key = base64.b64decode(part, validate=True)
            except ValueError: raise ValueError('Ключи Shadowsocks 2022 должны быть в Base64') from None
            if len(key) != length: raise ValueError('Неверная длина ключа Shadowsocks 2022')
    return {'type':'shadowsocks', 'server':host, 'server_port':port, 'method':method, 'password':password}


def parse(raw):
    if not isinstance(raw, str) or len(raw.encode()) > LIMIT: raise ValueError('Ссылка ss:// превышает 64 КиБ')
    raw = raw.strip()
    if not raw.startswith('ss://') or any(c.isspace() for c in raw): raise ValueError('Вставьте одну ссылку ss:// без пробелов; специальные символы кодируются через %')
    try: parts = urlsplit(raw)
    except ValueError: raise ValueError('Некорректный адрес в ссылке ss://') from None
    if parts.scheme != 'ss' or parts.path not in ('', '/') or parts.query or '?' in raw.split('#',1)[0]:
        raise ValueError('Плагины и дополнительные параметры ссылки пока не поддержаны; импорт не выполнен')
    if parts.netloc.count('@') != 1: raise ValueError('Нужна ссылка SIP002 с параметрами входа перед @')
    auth, server = parts.netloc.rsplit('@', 1)
    encoded = ':' not in auth
    auth = b64(decoded(auth)) if encoded else decoded(auth)
    if ':' not in auth: raise ValueError('В ссылке отсутствуют метод или пароль')
    method, password = auth.split(':', 1)
    if encoded and method.startswith('2022-'): raise ValueError('SIP002 для Shadowsocks 2022 требует открытое percent-кодирование метода и ключа, без Base64 оболочки')
    try:
        address = urlsplit('//'+server)
        if not address.hostname or address.port is None or address.username is not None: raise ValueError()
        host = address.hostname; port = address.port
    except ValueError: raise ValueError('В ссылке нужен сервер:порт; IPv6 задаётся в квадратных скобках') from None
    label = decoded(parts.fragment) if parts.fragment else host
    string(label, 120, 'Название')
    return {'name':label, 'protocol':'shadowsocks', 'native':native({'type':'shadowsocks','server':host,'server_port':port,'method':method,'password':password})}


def render(outbound):
    value = native(outbound.get('native')); label = string(outbound.get('name'), 120, 'Название')
    auth = value['method']+':'+value['password']
    if value['method'].startswith('2022-'):
        auth = quote(value['method'], safe='')+':'+quote(value['password'], safe='')
    else: auth = base64.urlsafe_b64encode(auth.encode()).decode().rstrip('=')
    host = value['server']
    if ':' in host: host = '['+host+']'
    result = 'ss://'+auth+'@'+host+':'+str(value['server_port'])+'#'+quote(label, safe='')
    if parse(result)['native'] != value: raise ValueError('Не удалось сохранить параметры ссылки без потерь')
    return result+'\n'
