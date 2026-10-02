"""One native sing-box connection fragment; no process settings or file access."""
import json,copy,ipaddress,uuid
from policy import normalized_domain
from tunnel_form import SS_METHODS
from policy_exchange import unique
from native_endpoints import ENDPOINT_TYPES,validate_endpoint
from tunnel_form import OUTBOUND_TYPES
MAX_BYTES=128*1024

def decode(raw,identifier):
    if len(raw)>MAX_BYTES:raise ValueError('Файл превышает 128 КиБ')
    try:value=json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique)
    except (UnicodeError,ValueError,RecursionError):raise ValueError('Нужен корректный JSON sing-box') from None
    if not isinstance(value,dict) or len(value)!=1 or next(iter(value)) not in ('outbounds','endpoints'):raise ValueError('Нужен фрагмент с одним разделом outbounds или endpoints')
    key=next(iter(value));rows=value[key]
    if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):raise ValueError('Импортируйте одно подключение за раз')
    native=copy.deepcopy(rows[0]);kind=native.get('type')
    if kind not in set(OUTBOUND_TYPES)|ENDPOINT_TYPES:raise ValueError('Этот протокол пока не поддерживается редактором')
    if (key=='endpoints')!=(kind in ENDPOINT_TYPES):raise ValueError('Протокол расположен в неверном разделе sing-box')
    def check(item,depth=0):
        if depth>24:raise ValueError('Слишком много уровней JSON')
        if isinstance(item,dict):
            for name,v in item.items():
                if name.endswith(('_path','_paths')) or name in ('command','script','execute'):
                    raise ValueError('Внешние файлы и исполняемые обработчики не переносятся: '+name)
                check(v,depth+1)
        elif isinstance(item,list):
            if len(item)>2048:raise ValueError('Слишком большой список параметров')
            for v in item:check(v,depth+1)
        elif isinstance(item,float):raise ValueError('Числа параметров должны быть целыми')
    check(native);native['tag']=identifier;validate_endpoint(native)
    if kind in ('socks','http','shadowsocks','vless'):
        server=native.get('server')
        if not isinstance(server,str) or not server.strip():raise ValueError('Укажите адрес подключения')
        try:ipaddress.ip_address(server)
        except ValueError:normalized_domain(server)
        port=native.get('server_port')
        if type(port) is not int or not 1<=port<=65535:raise ValueError('Порт должен быть от 1 до 65535')
        if native.get('network','') not in ('','tcp','udp'):raise ValueError('Неизвестный транспорт сети')
        for field in ('username','password','detour'):
            if field in native and not isinstance(native[field],str):raise ValueError('Поле '+field+' должно быть текстом')
        if kind=='socks' and native.get('version','5') not in ('4','4a','5'):raise ValueError('Неизвестная версия SOCKS')
        if kind=='shadowsocks' and (native.get('method') not in SS_METHODS or not native.get('password')):raise ValueError('Проверьте шифр и пароль Shadowsocks')
        if kind=='vless':
            try:uuid.UUID(native.get('uuid',''))
            except (ValueError,TypeError,AttributeError):raise ValueError('Укажите корректный UUID VLESS') from None
            if native.get('flow','') not in ('','xtls-rprx-vision'):raise ValueError('Неизвестный VLESS flow')
        if 'tls' in native and not isinstance(native['tls'],dict):raise ValueError('Некорректный раздел TLS')
        if 'transport' in native and not isinstance(native['transport'],dict):raise ValueError('Некорректный транспорт')
    if kind=='selector':
        members=native.get('outbounds')
        if not isinstance(members,list) or not members or any(not isinstance(v,str) for v in members) or len(set(members))!=len(members):raise ValueError('Укажите неповторяющийся список выходов')
        if identifier in members or native.get('default',members[0]) not in members:raise ValueError('Проверьте начальный выход очереди')
    return native
