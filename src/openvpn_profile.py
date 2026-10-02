"""Typed OpenVPN 1.14.1 endpoint model; only inline material, no host hooks."""
import copy
import ipaddress
import re
import ssl
import shlex
import tempfile
from pathlib import Path
from policy import normalized_domain

MAX_BYTES=128*1024
# path, label, kind, constraints; used by both validation and the protocol form.
GROUPS=[('Соединение',[
 ('mode','Режим','choice',['tls','static_key']),('network','Транспорт','choice',['udp','udp4','udp6','tcp','tcp4','tcp6']),
 ('servers','Серверы: адрес порт транспорт, по одному в строке','servers',None),('remote_random','Случайный порядок серверов','bool',None),
 ('username','Логин','text',512),('password','Пароль','secret',16384),('auth_retry','При ошибке входа','choice',['none','nointeract']),
 ('mtu','MTU внутри туннеля','int',(576,9000)),
 ]),('Проверка сервера и сертификаты',[
 ('tls.server_name','Ожидаемое имя сертификата','text',1024),('tls.server_name_type','Сравнение имени','choice',['subject','name','name-prefix']),
 ('tls.certificate','Доверенный CA · PEM','pem',32768),('tls.client_certificate','Клиентский сертификат · PEM','pem',32768),('tls.client_key','Закрытый ключ клиента · PEM','private_pem',32768),
 ('tls.peer_fingerprint','SHA-256 сертификата сервера, по одному в строке','fingerprints',None),
 ('tls.remote_certificate_tls','Назначение сертификата сервера','choice',['server','client','none']),
 ('tls.remote_certificate_eku','Расширенное назначение сертификата EKU','text',1024),('tls.remote_certificate_ku','Маски назначения KU, по одной в строке','hexes',None),
 ('tls.certificate_profile','Совместимость сертификатов','choice',['legacy','preferred','insecure','suiteb']),
 ('tls.ns_certificate_type','Старое Netscape-назначение','choice',['server','client']),
 ('tls.version_min','Минимальная TLS','choice',['1.0','1.1','1.2','1.3']),('tls.version_max','Максимальная TLS','choice',['1.0','1.1','1.2','1.3']),
 ('tls.cipher','Наборы шифров TLS через :','text',2048),('tls.groups','Группы обмена TLS через :','text',1024),
 ]),('Ключи канала управления',[
 ('tls.control_wrap.type','Защита управляющего канала','choice',['tls_auth','tls_crypt','tls_crypt_v2']),
 ('tls.control_wrap.key','Ключ TLS-auth / TLS-crypt','key',32768),('tls.control_wrap.direction','Направление TLS-auth','choice',['server','client']),
 ('static_key','Статический ключ для режима static_key','key',32768),('key_direction','Направление статического ключа','choice',['server','client']),
 ]),('Шифрование и совместимость',[
 ('data_ciphers','Допустимые шифры данных, по одному в строке','tokens',None),('data_ciphers_fallback','Резервный шифр старого сервера','token',128),
 ('cipher','Шифр старого сервера / static_key','token',128),('auth','Алгоритм HMAC','token',128),
 ('compression','Сжатие','choice',['lz4','lz4-v2','stub','stub-v2']),
 ('compression_lzo','Совместимость LZO','choice',['no','yes','adaptive']),
 ('allow_compression','Разрешать сжатие','choice',['no','asym','yes']),
 ]),('Адреса и маршруты внутри VPN',[
 ('address','Адреса клиента с префиксом, по одному в строке','addresses',None),('peer_address','IPv4 шлюза VPN','ipv4',None),('peer_address_ipv6','IPv6 шлюза VPN','ipv6',None),
 ('topology','Топология','choice',['net30','p2p','subnet']),('route_no_pull','Не принимать маршруты сервера','bool',None),
 ('pull_filters','Фильтры PUSH: accept/ignore/reject и текст, по одному в строке','filters',None),
 ('routes','Маршруты внутри VPN, по одному префиксу в строке','networks',None),('route_gateway','Шлюз маршрутов VPN','ip',None),('route_metric','Метрика маршрутов','int',(0,65535)),
 ('redirect_gateway','Принимать маршрут по умолчанию внутри VPN','bool',None),('redirect_private','Режим redirect-private внутри VPN','bool',None),
 ('redirect_gateway_flags','Флаги redirect-gateway/private, по одному в строке','redirect_flags',None),('block_ipv6','Блокировать IPv6 внутри этого VPN','bool',None),
 ]),('Пакеты и повторное соединение',[
 ('mss_fix','Размер MSS-fix','int',(1,65535)),('mss_fix_disabled','Отключить MSS-fix','bool',None),('mss_fix_mode','Расчёт MSS','choice',['mtu','fixed']),('fragment','Фрагментация UDP','int',(1,65535)),
 ('replay_window','Окно защиты от повторов, пакеты','int',(1,65535)),('replay_window_time','Окно защиты от повторов, секунды','duration',None),
 ('ping_interval','Интервал keepalive, секунды','duration',None),('ping_restart','Перезапуск после потери связи, секунды','duration',None),('ping_restart_disabled','Отключить ping-restart','bool',None),
 ('renegotiate_interval','Повторное согласование ключей, секунды','duration',None),('renegotiate_disabled','Отключить согласование по таймеру','bool',None),
 ('renegotiate_bytes','Пересогласование после байт','int',(1,2**53-1)),('renegotiate_packets','Пересогласование после пакетов','int',(1,2**53-1)),
 ('tls_timeout','Повтор управляющего пакета, секунды','duration',None),('handshake_window','Срок TLS-рукопожатия, секунды','duration',None),('explicit_exit_notify','Уведомления при выходе из UDP','int',(1,100)),
 ])]
SPECS={row[0]:row for _,rows in GROUPS for row in rows}
SECRET_KINDS={'secret','private_pem','key'}
LIST_KINDS={'fingerprints','hexes','tokens','addresses','networks','redirect_flags','servers','filters'}
DEFAULT={'type':'openvpn-client','mode':'tls','network':'udp','system':False,'tls':{'remote_certificate_tls':'server'},'auth_retry':'none'}


def get(model,path,default=None):
 for part in path.split('.'):
  if not isinstance(model,dict):return default
  model=model.get(part,default)
 return model


def put(model,path,value):
 parts=path.split('.');target=model
 for part in parts[:-1]:target=target.setdefault(part,{})
 if value is None:
  target.pop(parts[-1],None)
 else:target[parts[-1]]=value


def text(value,limit,label,*,multiline=False):
 if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 and not (multiline and c=='\n') or ord(c)==127 for c in value):raise ValueError(label+': некорректное значение')
 return value


def host(value):
 text(value,253,'Сервер')
 if not value or '%' in value:raise ValueError('Нужен IP или имя сервера без зоны интерфейса')
 try:return str(ipaddress.ip_address(value))
 except ValueError:return normalized_domain(value)


def leaves(value,prefix=''):
 if not isinstance(value,dict):raise ValueError('Некорректная структура OpenVPN')
 for key,item in value.items():
  if not isinstance(key,str):raise ValueError('Некорректное поле OpenVPN')
  path=prefix+key
  if isinstance(item,dict):yield from leaves(item,path+'.')
  else:yield path,item


def validate(model,*,ready=False):
 if not isinstance(model,dict) or model.get('type')!='openvpn-client':raise ValueError('Нужен клиент OpenVPN')
 model=copy.deepcopy(model)
 model.setdefault('mode','tls');model.setdefault('network','udp');model.setdefault('system',False)
 if model['mode']=='tls':
  model.setdefault('auth_retry','none')
  tls=model.setdefault('tls',{})
  if isinstance(tls,dict) and not tls.get('remote_certificate_eku'):tls.setdefault('remote_certificate_tls','server')
  if isinstance(tls,dict) and tls.get('server_name'):tls.setdefault('server_name_type','name')
 if model.get('system',False) is not False or model.get('name'):raise ValueError('OpenVPN использует внутренний стек; системный интерфейс не создаётся')
 allowed=set(SPECS)|{'type','tag','system','domain_resolver'}
 if set(model)-{path.split('.')[0] for path in allowed}:raise ValueError('Неизвестное поле OpenVPN')
 for prefix in ('tls','tls.control_wrap'):
  container=get(model,prefix)
  if container is not None and (not isinstance(container,dict) or set(container)-{path[len(prefix)+1:].split('.')[0] for path in allowed if path.startswith(prefix+'.')}):raise ValueError('Неизвестные поля TLS OpenVPN')
 for field in ('tag','domain_resolver'):
  if field in model and (not isinstance(model[field],str) or not model[field] or len(model[field])>128 or any(ord(c)<32 for c in model[field])):raise ValueError('Некорректный идентификатор '+field)
 if any(path not in allowed for path,_ in leaves(model)):raise ValueError('OpenVPN содержит неизвестное поле, путь к файлу или неподдержанную интерактивную авторизацию')
 for path,label,kind,limits in SPECS.values():
  value=get(model,path)
  if value is None:continue
  if kind=='bool':
   if type(value) is not bool:raise ValueError(label+': нужен переключатель')
   if not value:put(model,path,None)
  elif kind=='int':
   if type(value) is not int or not limits[0]<=value<=limits[1]:raise ValueError(label+': значение вне диапазона')
  elif kind=='choice':
   if value not in limits:raise ValueError(label+': неизвестный вариант')
  elif kind=='duration':
   if not isinstance(value,str) or not re.fullmatch(r'[1-9][0-9]{0,6}s',value) or int(value[:-1])>6048000:raise ValueError(label+': от 1 до 6048000 секунд')
  elif kind in ('ip','ipv4','ipv6'):
   try:address=ipaddress.ip_address(value)
   except (ValueError,TypeError):raise ValueError(label+': нужен IP') from None
   if '%' in value or kind!='ip' and address.version!=int(kind[-1]):raise ValueError(label+': неверная версия IP')
  elif kind in LIST_KINDS:
   if not isinstance(value,list) or len(value)>64:raise ValueError(label+': до 64 строк')
   if kind=='servers':
    for server in value:
     if not isinstance(server,dict) or set(server)-{'server','server_port','network'} or not {'server','server_port'}<=set(server):raise ValueError('Сервер: нужны адрес, порт и необязательный транспорт')
     host(server['server'])
     if type(server['server_port']) is not int or not 1<=server['server_port']<=65535:raise ValueError('Порт сервера: от 1 до 65535')
     if server.get('network','udp') not in SPECS['network'][3]:raise ValueError('Неизвестный транспорт сервера')
   elif kind=='filters':
    for entry in value:
     if not isinstance(entry,dict) or set(entry)!={'action','text'} or entry['action'] not in ('accept','ignore','reject'):raise ValueError('Фильтр PUSH: accept, ignore или reject и текст')
     if not text(entry['text'],1024,label):raise ValueError('Фильтр PUSH не должен быть пустым')
   else:
    if len(set(map(str,value)))!=len(value):raise ValueError(label+': строки не должны повторяться')
    for entry in value:
     text(entry,2048,label)
     if kind=='fingerprints' and not re.fullmatch('[a-f0-9]{64}',entry):raise ValueError('Fingerprint: SHA-256, 64 строчные HEX-цифры без разделителей')
     if kind=='hexes' and not re.fullmatch('[a-fA-F0-9]{1,4}',entry):raise ValueError('KU: нужна HEX-маска')
     if kind=='tokens' and not re.fullmatch('[A-Za-z0-9_-]{1,128}',entry):raise ValueError(label+': недопустимое имя')
     if kind=='redirect_flags' and entry not in ('local','autolocal','def1','bypass-dhcp','bypass-dns','block-local','ipv6','!ipv4'):raise ValueError('Неизвестный флаг redirect-gateway')
     if kind in ('addresses','networks'):
      try:(ipaddress.ip_interface if kind=='addresses' else ipaddress.ip_network)(entry)
      except ValueError:raise ValueError(label+': нужен адрес с корректным префиксом') from None
  else:
   text(value,limits or 32768,label,multiline=kind in ('pem','private_pem','key'))
   if kind=='token' and not re.fullmatch('[A-Za-z0-9_-]{1,128}',value):raise ValueError(label+': недопустимое имя')
   if kind=='pem':
    if 'PRIVATE KEY' in value:raise ValueError(label+': закрытый ключ задаётся отдельно')
    try:ssl.create_default_context(cadata=value)
    except (ValueError,ssl.SSLError):raise ValueError(label+': не удалось прочитать PEM') from None
   if kind=='private_pem':
    if 'ENCRYPTED' in value or not re.fullmatch(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+\n-----END (?:RSA |EC )?PRIVATE KEY-----\s*',value):raise ValueError('Нужен незашифрованный PEM ключ; пароль зашифрованного ключа этим клиентом не поддержан')
   if kind=='key':
    wrap=get(model,'tls.control_wrap.type') if path.startswith('tls.') else 'static'
    if wrap=='tls_crypt_v2':
     if not re.fullmatch(r'-----BEGIN OpenVPN tls-crypt-v2 client key-----\n[A-Za-z0-9+/=\n]+\n-----END OpenVPN tls-crypt-v2 client key-----\s*',value):raise ValueError('Нужен клиентский ключ tls-crypt-v2')
    else:
     body=re.sub(r'^#.*\n?','',value,flags=re.M).strip()
     match=re.fullmatch(r'-----BEGIN OpenVPN Static key V1-----\n([a-fA-F0-9\n]+)\n-----END OpenVPN Static key V1-----',body)
     if not match or len(match[1].replace('\n',''))!=512:raise ValueError('Нужен ключ OpenVPN Static key V1: 256 байт HEX')
 mode=model.get('mode','tls')
 if ready and not model.get('servers'):raise ValueError('Укажите хотя бы один сервер')
 if mode=='tls':
  tls=model.get('tls',{})
  if ready and not (tls.get('certificate') or tls.get('peer_fingerprint')):raise ValueError('Укажите CA или SHA-256 сертификата сервера')
  if bool(tls.get('client_certificate'))!=bool(tls.get('client_key')):raise ValueError('Клиентские сертификат и ключ задаются вместе')
  if tls.get('client_certificate'):
   # Python/OpenSSL checks PEM syntax and certificate/key correspondence without
   # executing the VPN or exposing material outside a private temporary folder.
   try:
    with tempfile.TemporaryDirectory(prefix='okopy-ovpn-key-') as folder:
     cert=Path(folder)/'cert.pem';key=Path(folder)/'key.pem'
     cert.write_text(tls['client_certificate']);key.write_text(tls['client_key']);cert.chmod(0o600);key.chmod(0o600)
     context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.load_cert_chain(cert,key)
   except (ValueError,ssl.SSLError):raise ValueError('Клиентский сертификат и ключ не читаются или не соответствуют друг другу') from None
  if bool(model.get('username'))!=bool(model.get('password')):raise ValueError('Логин и пароль задаются вместе')
  if model.get('static_key') or model.get('key_direction'):raise ValueError('Статический ключ относится к режиму static_key')
  if tls.get('remote_certificate_eku') and tls.get('remote_certificate_tls'):raise ValueError('Выберите EKU или remote-cert-tls, не оба одновременно')
  if float(tls.get('version_min','1.2'))>float(tls.get('version_max','1.3')):raise ValueError('Минимальная TLS выше максимальной')
  wrap=tls.get('control_wrap',{})
  if bool(wrap.get('type'))!=bool(wrap.get('key')) or wrap.get('direction') and wrap.get('type')!='tls_auth':raise ValueError('Защита канала требует тип и ключ; направление доступно только TLS-auth')
 else:
  if model.get('tls') or model.get('username') or model.get('password') or model.get('auth_retry') or model.get('remote_random'):raise ValueError('Статический режим не использует TLS/логин/пароль/очередь случайных серверов')
  if ready and (not model.get('static_key') or not model.get('address')):raise ValueError('В static_key нужны ключ и адрес клиента')
  for address in model.get('address',[]):
   if not model.get('peer_address' if ipaddress.ip_interface(address).version==4 else 'peer_address_ipv6'):raise ValueError('Укажите адрес шлюза для каждой семьи IP статического туннеля')
 for enabled,value in [('mss_fix_disabled','mss_fix'),('ping_restart_disabled','ping_restart'),('renegotiate_disabled','renegotiate_interval')]:
  if model.get(enabled) and model.get(value):raise ValueError('Нельзя одновременно отключить параметр и задать его значение')
 if model.get('mss_fix'):model.setdefault('mss_fix_mode','fixed')
 elif model.get('mss_fix_mode'):raise ValueError('Режим MSS требует явного размера MSS')
 for path in ('tls.control_wrap','tls'):
  if get(model,path)=={}:put(model,path,None)
 return model


def form_view(model):
 rows=[]
 for title,fields in GROUPS:
  group=[]
  for path,label,kind,options in fields:
   value=get(model,path,'');saved=bool(value)
   if kind in SECRET_KINDS:value=''
   elif kind=='servers':value='\n'.join(v['server']+' '+str(v['server_port'])+' '+v.get('network',model.get('network','udp')) for v in value)
   elif kind=='filters':value='\n'.join(v['action']+' '+shlex.quote(v['text']) for v in value)
   elif kind in LIST_KINDS:value='\n'.join(value)
   elif kind=='duration':value=value[:-1] if value else ''
   group.append({'path':path,'label':label,'kind':kind,'options':options,'value':value,'saved':saved})
  rows.append((title,group))
 return rows


def from_form(form,previous):
 model=copy.deepcopy(previous or DEFAULT)
 for path,label,kind,limits in SPECS.values():
  key='ov_'+path;value=form.get(key,'')
  if kind in SECRET_KINDS:
   if form.get('clear_'+key)=='on':put(model,path,None)
   elif value:put(model,path,value.replace('\r\n','\n').strip() if kind!='secret' else value)
   continue
  if kind=='bool':value=form.get(key)=='on'
  else:
   value=value.replace('\r\n','\n').strip()
   if not value:put(model,path,None);continue
   if kind=='int':
    if not value.isascii() or not value.isdigit():raise ValueError(label+': нужно целое число')
    value=int(value)
   elif kind=='duration':value+='s'
   elif kind in LIST_KINDS:
    lines=[s.strip() for s in value.splitlines() if s.strip()]
    if kind=='servers':
     value=[]
     for line in lines:
      parts=line.split()
      if len(parts) not in (2,3) or not parts[1].isascii() or not parts[1].isdigit():raise ValueError('Сервер: адрес порт и необязательный транспорт')
      value.append({'server':host(parts[0]),'server_port':int(parts[1]),**({'network':parts[2]} if len(parts)==3 else {})})
    elif kind=='filters':
     value=[]
     for line in lines:
      try:parts=shlex.split(line)
      except ValueError:raise ValueError('Фильтр PUSH: проверьте кавычки текста') from None
      if len(parts)!=2:raise ValueError('Фильтр PUSH: действие и текст')
      value.append({'action':parts[0],'text':parts[1]})
    else:value=lines
  put(model,path,value)
 # Remove only empty structural containers; never erase fields when changing mode.
 for path in ('tls.control_wrap','tls'):
  if get(model,path)=={}:put(model,path,None)
 model.update(type='openvpn-client',system=False)
 return validate(model,ready=True)
