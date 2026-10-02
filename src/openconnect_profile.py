"""Validated OpenConnect settings shared by web editing and file import.

No executable paths, systemd arguments, shell commands or network operations
come from an imported connection. Existing service bindings remain separate.
"""
import copy
import ipaddress
import re
import shlex
import ssl
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

MAX_BYTES=128*1024
PROTOCOLS=('anyconnect','nc','pulse','gp','f5','fortinet','array')
TEXT={'server':4096,'username':512,'authgroup':512,'usergroup':512,
      'useragent':512,'os':32,'local_hostname':253,'servercert':256}
NUMBERS={'mtu':(576,9000),'base_mtu':(576,9000),'reconnect_timeout':(1,604800),
         'force_dpd':(1,3600),'dtls_local_port':(1,65535),'tcp_keepalive':(1,3600)}
FLAGS=('no_dtls','disable_ipv6','no_http_keepalive','no_system_trust','pfs')
SECRETS=('password','cookie','private_key','key_password')
MATERIALS=('ca','certificate')
DEFAULT={'protocol':'anyconnect','auth_mode':'password',**{k:'' for k in TEXT},
         **{k:None for k in NUMBERS},**{k:False for k in FLAGS},
         **{k:'' for k in (*SECRETS,*MATERIALS)},'compression':'stateless'}
LABELS={'server':'Адрес VPN','username':'Логин','authgroup':'Группа входа',
        'usergroup':'Путь группы','useragent':'User-Agent','os':'Тип устройства',
        'local_hostname':'Имя устройства','servercert':'Отпечаток сервера',
        'mtu':'MTU туннеля','base_mtu':'MTU внешнего пути','reconnect_timeout':'Повторное подключение',
        'force_dpd':'Проверка живости','dtls_local_port':'Локальный порт DTLS','tcp_keepalive':'TCP keepalive',
        'password':'Пароль','cookie':'Cookie сессии','private_key':'Закрытый ключ','key_password':'Пароль ключа',
        'ca':'Сертификаты CA','certificate':'Клиентский сертификат'}


def scalar(value,key,limit):
    if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError(LABELS.get(key,key)+': недопустимые символы или слишком длинное значение')
    return value


def server_url(value):
    scalar(value,'server',4096)
    if not value or any(c.isspace() for c in value):raise ValueError('Адрес VPN: укажите HTTPS-адрес без пробелов')
    try:
        url=urlsplit(value)
        if url.scheme!='https' or not url.hostname or url.username is not None or url.password is not None or url.fragment:
            raise ValueError()
        if url.port is not None and not 1<=url.port<=65535:raise ValueError()
        try:ipaddress.ip_address(url.hostname)
        except ValueError:
            from policy import normalized_domain
            normalized_domain(url.hostname)
    except ValueError:raise ValueError('Адрес VPN: нужен HTTPS URL без встроенного логина, пароля и фрагмента #') from None
    # Unlike the built-in client, the existing native OpenConnect accepts query.
    return value


def validate(model,*,ready=False):
    if not isinstance(model,dict) or set(model)!=set(DEFAULT):raise ValueError('Неполный набор настроек OpenConnect')
    model=copy.deepcopy(model)
    if model['protocol'] not in PROTOCOLS:raise ValueError('Выберите поддерживаемый протокол OpenConnect')
    if model['auth_mode'] not in ('password','cookie','certificate'):raise ValueError('Выберите способ входа')
    for key,limit in TEXT.items():scalar(model[key],key,limit)
    server_url(model['server'])
    if model['os'] not in ('','linux','linux-64','win','mac-intel','android','apple-ios'):
        raise ValueError('Тип устройства: выберите значение из списка')
    pin=model['servercert']
    if pin and not (re.fullmatch(r'(?:sha1:)?[0-9a-fA-F]{40}',pin) or re.fullmatch(r'sha256:[0-9a-fA-F]{64}',pin) or re.fullmatch(r'pin-sha256:[A-Za-z0-9+/]{43}=',pin)):
        raise ValueError('Отпечаток сервера: нужен SHA-1, sha256:HEX или pin-sha256:BASE64 целиком')
    if model['compression'] not in ('stateless','none','all'):raise ValueError('Неизвестный режим сжатия')
    for key,(low,high) in NUMBERS.items():
        value=model[key]
        if value is not None and (type(value) is not int or not low<=value<=high):
            raise ValueError(f'{LABELS[key]}: от {low} до {high}, либо пустое поле')
    for key in FLAGS:
        if type(model[key]) is not bool:raise ValueError('Некорректный переключатель OpenConnect')
    for key in ('password','cookie','key_password'):scalar(model[key],key,16384)
    for key in (*MATERIALS,'private_key'):
        value=model[key]
        if not isinstance(value,str) or len(value)>32768 or '\x00' in value or '\r' in value:
            raise ValueError(LABELS[key]+': нужен PEM до 32 КиБ с обычными переводами строк')
        if not value:continue
        if key=='private_key':
            if not re.fullmatch(r'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\n[\s\S]+\n-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\n?',value):
                raise ValueError('Закрытый ключ: нужен файл PEM')
        else:
            if 'PRIVATE KEY' in value:raise ValueError(LABELS[key]+': закрытый ключ задаётся отдельно')
            try:ssl.create_default_context(cadata=value)
            except (ValueError,ssl.SSLError):raise ValueError(LABELS[key]+': не удалось прочитать сертификат PEM') from None
    if model['no_system_trust'] and not model['ca'] and not pin:
        raise ValueError('При отключении системных CA задайте CA или отпечаток сервера')
    if bool(model['certificate'])!=bool(model['private_key']):raise ValueError('Клиентский сертификат и закрытый ключ нужны вместе')
    if model['key_password'] and not model['private_key']:raise ValueError('Пароль ключа задан без закрытого ключа')
    if model['certificate']:
        # Parse and match certificate/key locally; never prompt for a password.
        with tempfile.TemporaryDirectory(prefix='okopy-oc-') as temporary:
            cert=Path(temporary)/'client.pem';key=Path(temporary)/'key.pem'
            cert.write_text(model['certificate']);key.write_text(model['private_key']);cert.chmod(0o600);key.chmod(0o600)
            try:
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_cert_chain(str(cert),str(key),password=lambda:model['key_password'])
            except (ValueError,ssl.SSLError):raise ValueError('Клиентский сертификат и ключ не совпадают, повреждены или неверен пароль ключа') from None
    if ready:
        if model['auth_mode']=='password' and (not model['username'] or not model['password']):raise ValueError('Для входа по паролю нужны логин и пароль')
        if model['auth_mode']=='cookie' and not model['cookie']:raise ValueError('Для входа по cookie нужна действующая cookie сессии')
        if model['auth_mode']=='certificate' and not model['certificate']:raise ValueError('Для входа по сертификату нужны сертификат и ключ')
    return model


def public(model):
    result={k:v for k,v in validate(model).items() if k not in SECRETS}
    result['saved_secrets']={k:bool(model[k]) for k in SECRETS}
    return result


def update(model,values):
    if not isinstance(values,dict) or set(values)!=set(DEFAULT)|{k+'_action' for k in SECRETS}:
        raise ValueError('Форма OpenConnect неполна; обновите страницу')
    result=copy.deepcopy(model)
    for key in DEFAULT:
        value=values[key]
        if key in SECRETS:
            action=values[key+'_action']
            if action not in ('keep','replace','clear'):raise ValueError('Выберите действие с секретом')
            if action=='replace':
                if not value:raise ValueError(LABELS[key]+': новое значение не заполнено')
                result[key]=value
            elif action=='clear':result[key]=''
            elif value:raise ValueError(LABELS[key]+': выберите «Заменить» для введённого значения')
        else:result[key]=value
    return validate(result)


OPTION_MAP={'user':'username','local-hostname':'local_hostname','force-dpd':'force_dpd',
            **{k.replace('_','-'):k for k in TEXT if k not in ('username','local_hostname')},
            **{k.replace('_','-'):k for k in NUMBERS},**{k.replace('_','-'):k for k in FLAGS},
            'protocol':'protocol','compression':'compression','cookie':'cookie','key-password':'key_password'}


def parse_options(pairs,model):
    result=copy.deepcopy(model);seen=set()
    for option,value in pairs:
        if option not in OPTION_MAP:raise ValueError('Файл содержит неподдерживаемый параметр: '+option[:60])
        key=OPTION_MAP[option]
        if key in seen:raise ValueError('Параметр указан повторно: '+option)
        seen.add(key)
        if key in FLAGS:
            if value not in ('',None):raise ValueError('Переключатель '+option+' не принимает значение')
            value=True
        elif key in NUMBERS:
            if not isinstance(value,str) or not value.isascii() or not value.isdigit():raise ValueError(LABELS[key]+': нужно целое число')
            value=int(value)
        elif value is None:raise ValueError('Не задан параметр: '+option)
        result[key]=value
    if 'cookie' in seen:result['auth_mode']='cookie'
    return validate(result)


def import_config(text,model,format):
    if format=='native-bundle':
        from openconnect_export import import_bundle
        return import_bundle(text)
    if not isinstance(text,str) or len(text.encode())>MAX_BYTES or '\x00' in text:raise ValueError('Файл подключения превышает 128 КиБ или повреждён')
    if format=='openconnect':
        pairs=[]
        for raw in text.splitlines():
            line=raw.strip()
            if not line or line.startswith('#'):continue
            # Native OpenConnect treats the remainder as the value, not shell.
            match=re.fullmatch(r'([a-z][a-z0-9-]*)(?:\s*=\s*|\s+)?(.*)',line)
            if not match:raise ValueError('Нужен конфиг OpenConnect с длинными именами параметров без --')
            key,value=match.groups();pairs.append((key,value))
        if not pairs:raise ValueError('Файл OpenConnect пуст')
        return parse_options(pairs,model)
    if format!='anyconnect':raise ValueError('Выберите формат файла подключения')
    if '<!' in text:raise ValueError('XML с DTD или сущностями не поддерживается')
    try:root=ElementTree.fromstring(text)
    except ElementTree.ParseError:raise ValueError('Не удалось прочитать XML AnyConnect') from None
    for node in root.iter():node.tag=node.tag.rsplit('}',1)[-1]
    if root.tag!='AnyConnectProfile':raise ValueError('Нужен профиль Cisco AnyConnectProfile')
    allowed={'AnyConnectProfile','ServerList','HostEntry','HostName','HostAddress','UserGroup'}
    for node in root.iter():
        if node.tag not in allowed:raise ValueError('XML содержит неподдерживаемую настройку: '+node.tag[:60])
    entries=root.findall('./ServerList/HostEntry')
    if len(entries)!=1:raise ValueError('Импортируйте профиль с одним сервером; выбор из нескольких серверов ещё не поддерживается')
    entry=entries[0]
    if len(entry.findall('HostAddress'))!=1 or len(entry.findall('UserGroup'))>1:raise ValueError('Неоднозначный адрес или группа в XML')
    server=(entry.findtext('HostAddress') or '').strip()
    if '://' not in server:server='https://'+server
    pairs=[('protocol','anyconnect'),('server',server),('usergroup',(entry.findtext('UserGroup') or '').strip())]
    return parse_options(pairs,model)


def from_legacy_unit(unit_text,password,binding):
    """Import only the known plain ExecStart syntax, refusing hidden expansion."""
    section=None;commands=[];stdin=[]
    for raw in unit_text.splitlines():
        line=raw.strip()
        if line.startswith('['):section=line
        if section!='[Service]' or '=' not in line or line.startswith('#'):continue
        key,value=line.split('=',1)
        if key=='ExecStart':commands.append(value)
        elif key=='StandardInput':stdin.append(value)
        elif key in ('Environment','EnvironmentFile','ExecStartPre','ExecStartPost'):raise ValueError('В службе есть дополнительные команды или окружение; нужен отдельный разбор')
    if len(commands)!=1 or stdin!=['file:'+binding['password_file']]:raise ValueError('Структура службы OpenConnect отличается от сохранённой привязки')
    if any(c in commands[0] for c in ('\n','\r','\\','$','%')):raise ValueError('Расширения команды systemd требуют отдельного разбора')
    try:args=shlex.split(commands[0])
    except ValueError:raise ValueError('Не удалось прочитать команду OpenConnect') from None
    if not args or args.pop(0)!=binding['binary']:raise ValueError('Исполняемый файл службы OpenConnect изменён')
    expected={'--interface='+binding['interface'],'--script='+binding['script'],'--non-inter','--passwd-on-stdin'}
    if not expected.issubset(args) or any(args.count(v)!=1 for v in expected):raise ValueError('Сетевые параметры службы OpenConnect изменены')
    pairs=[]
    for arg in args:
        if arg in expected:continue
        if arg.startswith('https://'):pairs.append(('server',arg))
        elif arg.startswith('--'):
            key,sep,value=arg[2:].partition('=');pairs.append((key,value if sep else None))
        else:raise ValueError('Неподдерживаемый аргумент службы OpenConnect')
    model=copy.deepcopy(DEFAULT);model['password']=password.rstrip('\n')
    return parse_options(pairs,model)


def values_from_form(form):
    required=set(DEFAULT)-set(FLAGS)
    required|={key+'_action' for key in SECRETS}
    if not required.issubset(form):raise ValueError('Форма OpenConnect неполна; обновите страницу')
    result={key:form[key] for key in required}
    for key in NUMBERS:
        value=result[key].strip()
        if value and (not value.isascii() or not value.isdigit()):raise ValueError(LABELS[key]+': нужно целое число')
        result[key]=int(value) if value else None
    for key in FLAGS:result[key]=form.get(key)=='on'
    for key in (*MATERIALS,'private_key'):result[key]=result[key].replace('\r\n','\n')
    return result
