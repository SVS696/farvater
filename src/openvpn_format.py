"""Native .ovpn import/export, with explicit unsupported options and no file IO."""
import copy
import ipaddress
import re
import shlex
from pathlib import PurePosixPath
from openvpn_profile import MAX_BYTES,get,put,validate,host

# Options controlled by the standalone process are retained for export; the
# embedded client has its own process lifecycle, logging and credential store.
COMPAT={'nobind':(0,'bool'),'persist-key':(0,'bool'),'persist-tun':(0,'bool'),
        'auth-nocache':(0,'bool'),'resolv-retry':(1,'retry'),'verb':(1,'verbosity')}
SCALAR={
 'proto':'network','topology':'topology','cipher':'cipher','auth':'auth','auth-retry':'auth_retry',
 'data-ciphers-fallback':'data_ciphers_fallback','allow-compression':'allow_compression',
 'tls-version-min':'tls.version_min','tls-version-max':'tls.version_max','tls-cipher':'tls.cipher','tls-groups':'tls.groups',
 'tls-cert-profile':'tls.certificate_profile','remote-cert-tls':'tls.remote_certificate_tls',
 'remote-cert-eku':'tls.remote_certificate_eku','ns-cert-type':'tls.ns_certificate_type',
 'route-gateway':'route_gateway',
 }
NUMERIC={'tun-mtu':'mtu','fragment':'fragment','route-metric':'route_metric','reneg-bytes':'renegotiate_bytes','reneg-pkts':'renegotiate_packets'}
DURATION={'ping':'ping_interval','ping-restart':'ping_restart','reneg-sec':'renegotiate_interval','tls-timeout':'tls_timeout','hand-window':'handshake_window'}
ZERO={'ping-restart':'ping_restart_disabled','reneg-sec':'renegotiate_disabled'}
BOOL={'remote-random':'remote_random','route-nopull':'route_no_pull','block-ipv6':'block_ipv6'}
INLINE={'ca':'tls.certificate','cert':'tls.client_certificate','key':'tls.client_key','secret':'static_key','tls-auth':'tls.control_wrap.key','tls-crypt':'tls.control_wrap.key','tls-crypt-v2':'tls.control_wrap.key'}
PROTOS={'tcp-client':'tcp','tcp4-client':'tcp4','tcp6-client':'tcp6','tcp':'tcp','tcp4':'tcp4','tcp6':'tcp6','udp':'udp','udp4':'udp4','udp6':'udp6'}
WRAPS={'tls-auth':'tls_auth','tls-crypt':'tls_crypt','tls-crypt-v2':'tls_crypt_v2'}


def lines(raw):
 if not isinstance(raw,str) or len(raw.encode())>MAX_BYTES or '\x00' in raw:raise ValueError('Нужен текстовый .ovpn до 128 КиБ')
 raw=raw.replace('\r\n','\n')
 if '\r' in raw:raise ValueError('В .ovpn обнаружены отдельные символы CR')
 content=raw.splitlines();result=[];index=0
 while index<len(content):
  number=index+1;line=content[index].strip();index+=1
  if not line or line.startswith(('#',';')):continue
  if line.startswith('<'):
   match=re.fullmatch(r'<([a-z0-9-]+)>',line)
   if not match or match[1] not in {*INLINE,'auth-user-pass','peer-fingerprint'}:raise ValueError(f'Строка {number}: неподдержанный inline-блок OpenVPN')
   kind=match[1];body=[]
   while index<len(content) and content[index].strip()!='</'+kind+'>':body.append(content[index]);index+=1
   if index==len(content):raise ValueError(f'Строка {number}: inline-блок не закрыт')
   index+=1;result.append((number,kind,[], '\n'.join(body).strip() if kind!='auth-user-pass' else '\n'.join(body)));continue
  try:
   lexer=shlex.shlex(line,posix=True);lexer.whitespace_split=True;lexer.commenters='#;';parts=list(lexer)
  except ValueError:raise ValueError(f'Строка {number}: ошибка кавычек') from None
  if not parts:continue
  name=parts[0].removeprefix('--')
  if not re.fullmatch('[a-z][a-z0-9-]{0,63}',name):raise ValueError(f'Строка {number}: неизвестная директива OpenVPN')
  result.append((number,name,parts[1:],None))
 return result


def number(value):
 if not isinstance(value,str) or not value.isascii() or not value.isdigit():raise ValueError('Нужно неотрицательное целое число')
 return int(value)


def direction(value):
 if value not in ('0','1'):raise ValueError('key-direction: нужен 0 или 1')
 return 'server' if value=='0' else 'client'


def compat_options(value):
 if not isinstance(value,dict) or set(value)-set(COMPAT):raise ValueError('Неизвестные параметры обычного OpenVPN-клиента')
 for key,item in value.items():
  kind=COMPAT[key][1]
  if kind=='bool' and item is not True:raise ValueError('Некорректный флаг обычного клиента')
  if kind=='retry' and (not isinstance(item,str) or item!='infinite' and not re.fullmatch('[1-9][0-9]{0,6}',item)):raise ValueError('resolv-retry: infinite или секунды')
  if kind=='verbosity' and (type(item) is not int or not 0<=item<=11):raise ValueError('verb: уровень от 0 до 11')
 return copy.deepcopy(value)


def parse(raw,*,files=None,username='',password=''):
 files=files or {}
 if not isinstance(files,dict) or len(files)>16 or any(not isinstance(k,str) or not isinstance(v,str) or len(v.encode())>MAX_BYTES for k,v in files.items()):raise ValueError('Допустимо до 16 текстовых файлов профиля')
 model={'type':'openvpn-client','system':False,'mode':'tls','network':'udp','tls':{'remote_certificate_tls':'none'}}
 compatibility={};seen=set();remotes=[];routes=[];key_direction=None;require_auth=False;tls_client=False;pull=False;inline_slots=set()
 def set_once(path,value):
  if path in seen:raise ValueError('Параметр повторяется или конфликтует с другим параметром')
  seen.add(path);put(model,path,value)
 def file_content(path):
  # File names match uploaded parts only; never read the server filesystem.
  if not isinstance(path,str) or '\\' in path or '/' in path or path in ('.','..') or path not in files:raise ValueError('Загрузите указанный сопутствующий файл по его имени; пути сервера не читаются')
  return files[path].replace('\r\n','\n')
 records=lines(raw);blocks={name for _,name,_,body in records if body is not None};references=set()
 for row,name,args,inline in records:
  try:
   if inline is None and args and args[0]=='[inline]' and name in {*INLINE,'auth-user-pass','peer-fingerprint'}:
    if name not in blocks or name in references:raise ValueError('Отсутствует inline-блок или повторяется его объявление')
    references.add(name)
    if name in ('tls-auth','secret') and len(args)==2:
     if key_direction is not None:raise ValueError('Направление ключа повторяется')
     key_direction=direction(args[1])
    elif len(args)!=1:raise ValueError('Некорректное объявление inline-блока')
    continue
   if name in INLINE:
    if inline is not None:
     if name in inline_slots:raise ValueError('Inline-файл повторяется')
     inline_slots.add(name);value=inline
    else:
     if name=='secret' or name=='tls-auth':
      if len(args) not in (1,2):raise ValueError('Нужен файл и необязательное направление')
      if len(args)==2:
       if key_direction is not None:raise ValueError('Направление ключа повторяется')
       key_direction=direction(args[1])
     elif len(args)!=1:raise ValueError('Нужно имя файла')
     value=file_content(args[0]).strip()
    set_once(INLINE[name],value)
    if name=='secret':model['mode']='static_key'
    if name in WRAPS:set_once('tls.control_wrap.type',WRAPS[name])
   elif name=='auth-user-pass':
    if len(args)>1:raise ValueError('auth-user-pass: один файл')
    if require_auth:raise ValueError('auth-user-pass повторяется')
    require_auth=True
    if inline is not None or args and not (username and password):
     if len(args)>1:raise ValueError('auth-user-pass: один файл')
     body=inline if inline is not None else file_content(args[0]);pair=body.splitlines()
     if len(pair)!=2 or not all(pair):raise ValueError('Файл авторизации должен содержать две непустые строки: логин и пароль')
     if username or password:raise ValueError('Реквизиты уже есть в профиле; не задавайте вторую пару при импорте')
     username,password=pair
   elif name=='peer-fingerprint':
    fingerprints=inline.splitlines() if inline is not None else args
    if not fingerprints:raise ValueError('Нужен SHA-256 сертификата')
    set_once('tls.peer_fingerprint',[value.strip().replace(':','').lower() for value in fingerprints])
   elif inline is not None:raise ValueError('Неподдержанный inline-файл')
   elif name in COMPAT:
    arity,kind=COMPAT[name]
    if len(args)!=arity or name in compatibility:raise ValueError('Неверные или повторяющиеся параметры обычного клиента')
    compatibility[name]=True if kind=='bool' else number(args[0]) if kind=='verbosity' else args[0]
   elif name in ('client','tls-client','pull'):
    if args or name in seen:raise ValueError('Флаг повторяется или содержит аргумент')
    seen.add(name)
    tls_client|=name in ('client','tls-client');pull|=name in ('client','pull')
   elif name=='dev':
    if args!=['tun'] or name in seen:raise ValueError('Поддерживается dev tun без системного имени; TAP пока не поддержан')
    seen.add(name)
   elif name=='remote':
    if not 1<=len(args)<=3:raise ValueError('remote: адрес, необязательные порт и транспорт')
    entry={'server':host(args[0]),'server_port':number(args[1]) if len(args)>1 else 1194}
    if len(args)==3:
     if args[2] not in PROTOS:raise ValueError('Неизвестный транспорт remote')
     entry['network']=PROTOS[args[2]]
    remotes.append(entry)
   elif name in SCALAR:
    if len(args)!=1:raise ValueError('Ожидается одно значение')
    value=args[0]
    if name=='proto':
     if value not in PROTOS:raise ValueError('Нужен UDP или TCP в клиентском режиме')
     value=PROTOS[value]
    if name=='remote-cert-eku':model['tls'].pop('remote_certificate_tls',None)
    set_once(SCALAR[name],value)
   elif name in NUMERIC:
    if len(args)!=1:raise ValueError('Ожидается одно число')
    set_once(NUMERIC[name],number(args[0]))
   elif name in DURATION:
    if len(args)!=1:raise ValueError('Ожидается число секунд')
    value=number(args[0]);path=DURATION[name]
    if value==0 and name in ZERO:set_once(ZERO[name],True)
    else:set_once(path,str(value)+'s')
   elif name in BOOL:
    if args:raise ValueError('Флаг не имеет аргументов')
    set_once(BOOL[name],True)
   elif name=='data-ciphers':
    if len(args)!=1:raise ValueError('Нужен список шифров через :')
    set_once('data_ciphers',args[0].split(':'))
   elif name=='remote-cert-ku':
    if not args:raise ValueError('Нужны HEX-маски KU')
    set_once('tls.remote_certificate_ku',args)
   elif name=='verify-x509-name':
    if len(args) not in (1,2):raise ValueError('Нужно имя и необязательный вид сравнения')
    set_once('tls.server_name',args[0]);set_once('tls.server_name_type',args[1] if len(args)==2 else 'subject')
   elif name=='key-direction':
    if len(args)!=1 or key_direction is not None:raise ValueError('Нужно одно направление ключа')
    key_direction=direction(args[0])
   elif name in ('compress','comp-lzo'):
    if len(args)>1:raise ValueError('Нужно не более одного значения')
    set_once('compression' if name=='compress' else 'compression_lzo',args[0] if args else ('stub' if name=='compress' else 'adaptive'))
   elif name=='mssfix':
    if len(args) not in (1,2) or len(args)==2 and args[1]!='mtu':raise ValueError('mssfix: число и необязательное mtu')
    value=number(args[0])
    if value==0:
     if len(args)!=1:raise ValueError('mssfix 0 не имеет режима')
     set_once('mss_fix_disabled',True)
    else:set_once('mss_fix',value);set_once('mss_fix_mode','mtu' if len(args)==2 else 'fixed')
   elif name=='replay-window':
    if not 1<=len(args)<=2:raise ValueError('replay-window: пакеты и необязательные секунды')
    set_once('replay_window',number(args[0]))
    if len(args)==2:set_once('replay_window_time',str(number(args[1]))+'s')
   elif name=='explicit-exit-notify':
    if len(args)>1:raise ValueError('Ожидается не более одного числа')
    set_once('explicit_exit_notify',number(args[0]) if args else 1)
   elif name=='keepalive':
    if len(args)!=2:raise ValueError('keepalive: интервал и срок перезапуска')
    set_once('ping_interval',str(number(args[0]))+'s');set_once('ping_restart',str(number(args[1]))+'s')
   elif name=='pull-filter':
    if len(args)!=2:raise ValueError('pull-filter: действие и текст в кавычках')
    model.setdefault('pull_filters',[]).append({'action':args[0],'text':args[1]})
   elif name in ('redirect-gateway','redirect-private'):
    set_once(name.replace('-','_'),True)
    if args:set_once('redirect_gateway_flags',args)
   elif name=='ifconfig':
    if len(args)!=2 or 'ifconfig' in seen:raise ValueError('ifconfig: адрес и маска/шлюз')
    seen.add('ifconfig');model['_ifconfig']=args
   elif name=='ifconfig-ipv6':
    if len(args)!=2:raise ValueError('ifconfig-ipv6: адрес/префикс и шлюз')
    if ipaddress.ip_interface(args[0]).version!=6 or ipaddress.ip_address(args[1]).version!=6:raise ValueError('Нужны адреса IPv6')
    set_once('peer_address_ipv6',args[1]);model.setdefault('address',[]).append(args[0])
   elif name=='route':
    if len(args) not in (1,2):raise ValueError('Маршруты с отдельными шлюзами/метриками пока не поддержаны; задайте общие route-gateway и route-metric')
    routes.append(str(ipaddress.IPv4Network(args[0]+'/'+(args[1] if len(args)==2 else '255.255.255.255'),strict=True)))
   elif name=='route-ipv6':
    if len(args)!=1 or ipaddress.ip_network(args[0]).version!=6:raise ValueError('route-ipv6: нужен один IPv6-префикс')
    routes.append(str(ipaddress.ip_network(args[0])))
   else:raise ValueError('Директива '+name+' не поддержана; она не будет молча отброшена')
  except (ValueError,TypeError,KeyError) as error:
   message=str(error) if isinstance(error,ValueError) and type(error) is ValueError else 'Некорректные параметры директивы'
   raise ValueError(f'Строка {row}: '+message) from None
 if 'dev' not in seen:raise ValueError('В профиле нужен dev tun')
 if model['mode']=='static_key':
  if tls_client or pull or require_auth or any(path.startswith('tls.') for path in seen):raise ValueError('secret несовместим с TLS, pull и авторизацией')
  model.pop('tls',None)
 else:
  if not tls_client or not pull:raise ValueError('Для встроенного TLS-клиента нужен client либо tls-client вместе с pull')
 if key_direction:
  if model['mode']=='static_key':model['key_direction']=key_direction
  elif get(model,'tls.control_wrap.type')=='tls_auth':put(model,'tls.control_wrap.direction',key_direction)
  else:raise ValueError('key-direction требует secret или tls-auth')
 if '_ifconfig' in model:
  address,peer=model.pop('_ifconfig')
  if model.get('topology')=='subnet':prefix=ipaddress.IPv4Interface(address+'/'+peer)
  else:
   prefix=ipaddress.IPv4Interface(address+'/32');model['peer_address']=str(ipaddress.IPv4Address(peer))
  model.setdefault('address',[]).insert(0,str(prefix))
 if routes:model['routes']=routes
 if require_auth:
  if not username or not password:raise ValueError('Профиль требует логин и пароль. Введите их в поля импорта или загрузите указанный файл авторизации')
  model.update(username=username,password=password)
 elif username or password:raise ValueError('В профиле нет auth-user-pass; реквизиты входа не будут молча добавлены')
 model['servers']=remotes
 return {'native':validate(model,ready=True),'openvpn_export_options':compat_options(compatibility)}


def quote(value):
 value=str(value)
 return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'


def render(outbound):
 model=validate(outbound['native'],ready=True);compat=compat_options(outbound.get('openvpn_export_options',{}));result=[]
 def emit(name,*values):result.append(name+(' '+' '.join(quote(v) for v in values) if values else ''))
 def inline(name,value):result.extend(['<'+name+'>',value.rstrip('\n'),'</'+name+'>'])
 emit('client') if model['mode']=='tls' else None
 emit('dev','tun');emit('proto',{'tcp':'tcp-client','tcp4':'tcp4-client','tcp6':'tcp6-client'}.get(model['network'],model['network']))
 for remote in model['servers']:
  args=[remote['server'],remote['server_port']]
  if 'network' in remote:args.append({'tcp':'tcp-client','tcp4':'tcp4-client','tcp6':'tcp6-client'}.get(remote['network'],remote['network']))
  emit('remote',*args)
 for cli,path in SCALAR.items():
  if cli=='proto':continue
  value=get(model,path)
  if value is None or cli=='remote-cert-tls' and value=='none':continue
  emit(cli,value)
 for cli,path in NUMERIC.items():
  if get(model,path) is not None:emit(cli,get(model,path))
 for cli,path in DURATION.items():
  if get(model,path):emit(cli,get(model,path)[:-1])
  elif cli in ZERO and model.get(ZERO[cli]):emit(cli,0)
 for cli,path in BOOL.items():
  if model.get(path):emit(cli)
 for cli,(arity,kind) in COMPAT.items():
  if cli in compat:emit(cli,*([compat[cli]] if arity else []))
 for cli,path in [('data-ciphers','data_ciphers')]:
  if model.get(path):emit(cli,':'.join(model[path]))
 for cli,path in [('ca','tls.certificate'),('cert','tls.client_certificate'),('key','tls.client_key'),('secret','static_key')]:
  if get(model,path):inline(cli,get(model,path))
 wrap=get(model,'tls.control_wrap',{})
 if wrap.get('type'):
  inline({v:k for k,v in WRAPS.items()}[wrap['type']],wrap['key'])
  if wrap.get('direction'):emit('key-direction','0' if wrap['direction']=='server' else '1')
 if model.get('key_direction'):emit('key-direction','0' if model['key_direction']=='server' else '1')
 if model.get('username'):inline('auth-user-pass',model['username']+'\n'+model['password'])
 if get(model,'tls.peer_fingerprint'):inline('peer-fingerprint','\n'.join(':'.join(v[i:i+2] for i in range(0,64,2)) for v in get(model,'tls.peer_fingerprint')))
 if get(model,'tls.server_name'):emit('verify-x509-name',get(model,'tls.server_name'),get(model,'tls.server_name_type','name'))
 if get(model,'tls.remote_certificate_ku'):emit('remote-cert-ku',*get(model,'tls.remote_certificate_ku'))
 if model.get('compression'):emit('compress',model['compression'])
 if model.get('compression_lzo'):emit('comp-lzo',model['compression_lzo'])
 if model.get('mss_fix_disabled'):emit('mssfix',0)
 elif model.get('mss_fix'):emit('mssfix',model['mss_fix'],*(['mtu'] if model.get('mss_fix_mode')=='mtu' else []))
 if model.get('replay_window'):emit('replay-window',model['replay_window'],*([model['replay_window_time'][:-1]] if model.get('replay_window_time') else []))
 elif model.get('replay_window_time'):raise ValueError('Для экспорта replay-window нужны и пакеты, и секунды')
 if model.get('explicit_exit_notify'):emit('explicit-exit-notify',model['explicit_exit_notify'])
 for item in model.get('pull_filters',[]):emit('pull-filter',item['action'],item['text'])
 if model.get('redirect_gateway') and model.get('redirect_private'):raise ValueError('Для экспорта выберите redirect-gateway либо redirect-private')
 for field in ('redirect_gateway','redirect_private'):
  if model.get(field):emit(field.replace('_','-'),*model.get('redirect_gateway_flags',[]))
 if model.get('redirect_gateway_flags') and not (model.get('redirect_gateway') or model.get('redirect_private')):raise ValueError('Флаги redirect требуют включённого режима')
 for value in model.get('address',[]):
  address=ipaddress.ip_interface(value)
  if address.version==4:
   peer=str(address.netmask) if model.get('topology')=='subnet' else model.get('peer_address')
   if not peer:raise ValueError('Для экспорта IPv4 ifconfig нужен шлюз VPN или топология subnet')
   emit('ifconfig',str(address.ip),peer)
  else:
   if not model.get('peer_address_ipv6'):raise ValueError('Для экспорта IPv6 ifconfig нужен шлюз VPN')
   emit('ifconfig-ipv6',str(address),model['peer_address_ipv6'])
 for value in model.get('routes',[]):
  net=ipaddress.ip_network(value)
  emit('route',str(net.network_address),str(net.netmask)) if net.version==4 else emit('route-ipv6',str(net))
 text='\n'.join(result)+'\n'
 imported=parse(text)
 expected={k:v for k,v in model.items() if k not in ('tag','domain_resolver')}
 if imported['native']!=expected or imported['openvpn_export_options']!=compat:raise ValueError('Профиль не переносится в .ovpn без потери параметров; экспорт остановлен')
 return text
