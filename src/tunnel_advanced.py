"""Typed TLS and V2Ray fields for the pinned sing-box 1.14.1 client."""
import base64,copy,ipaddress,json,re,ssl
from urllib.parse import urlsplit
from policy import normalized_domain

FINGERPRINTS=['','chrome','firefox','edge','safari','360','qq','ios','android','random','randomized']
TRANSPORTS={'':'Обычный TCP','ws':'WebSocket','http':'HTTP','grpc':'gRPC','httpupgrade':'HTTPUpgrade','quic':'QUIC'}
VERSIONS=['','1.0','1.1','1.2','1.3']
TOKEN=re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")

def text(form,key,limit=2048):
 value=form.get(key,'')
 if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 and c not in '\n\r' for c in value):raise ValueError('Некорректное текстовое поле подключения')
 return value.strip()

def single(form,key,limit=2048):
 value=text(form,key,limit)
 if '\n' in value or '\r' in value:raise ValueError('Поле подключения должно занимать одну строку')
 return value

def set_optional(target,key,value):
 if value not in ('',[],None):target[key]=value
 else:target.pop(key,None)

def authority(value):
 try:
  u=urlsplit('//'+value);port=u.port
  if not u.hostname or u.username is not None or u.password is not None or u.path or u.query or u.fragment or any(c.isspace() for c in value):raise ValueError()
  try:
   ip=ipaddress.ip_address(u.hostname);host='['+str(ip)+']' if ip.version==6 else str(ip)
  except ValueError:host=normalized_domain(u.hostname)
  if port is not None and not 1<=port<=65535:raise ValueError()
  return host+(':'+str(port) if port is not None else '')
 except ValueError:raise ValueError('Некорректный Host транспорта: нужно имя или IP с необязательным портом') from None

def parse_tls(form,native):
 if not native.get('tls',{}).get('enabled'):return
 tls=native['tls']
 low=single(form,'tls_min_version',10);high=single(form,'tls_max_version',10)
 if low not in VERSIONS or high not in VERSIONS or float(low or '1.2')>float(high or '1.3'):raise ValueError('Некорректный диапазон версий TLS')
 set_optional(tls,'min_version',low);set_optional(tls,'max_version',high)
 alpn=[v.strip() for v in text(form,'tls_alpn',4096).splitlines() if v.strip()]
 if len(alpn)>16 or len(set(alpn))!=len(alpn) or any(not 1<=len(v.encode())<=255 or any(ord(c)<33 or ord(c)>126 for c in v) for v in alpn):raise ValueError('ALPN: до 16 неповторяющихся протоколов, по одному в строке')
 set_optional(tls,'alpn',alpn)
 fingerprint=single(form,'tls_fingerprint',40)
 if fingerprint not in FINGERPRINTS:raise ValueError('Неизвестный отпечаток uTLS')
 if fingerprint:tls['utls']={'enabled':True,'fingerprint':fingerprint}
 else:tls.pop('utls',None)
 if form.get('tls_insecure')=='on':tls['insecure']=True
 else:tls.pop('insecure',None)
 certificate=text(form,'tls_certificate',32768)
 if form.get('clear_tls_certificate')=='on':
  tls.pop('certificate',None);tls.pop('certificate_path',None)
 elif certificate:
  try:ssl.create_default_context(cadata=certificate)
  except (ssl.SSLError,ValueError):raise ValueError('Не удалось прочитать сертификат CA в PEM') from None
  if 'PRIVATE KEY' in certificate:raise ValueError('В поле CA нужен публичный сертификат, не закрытый ключ')
  tls['certificate']=certificate;tls.pop('certificate_path',None)
 if native['type']=='vless' and form.get('tls_reality')=='on':
  if not fingerprint:raise ValueError('Reality в sing-box требует отпечаток uTLS')
  if tls.get('insecure'):raise ValueError('Reality использует свой открытый ключ; отключение проверки сертификата здесь не требуется')
  key=single(form,'reality_public_key',100)
  try:
   if not re.fullmatch('[A-Za-z0-9_-]{43}',key):raise ValueError()
   decoded=base64.urlsafe_b64decode(key+'=')
   if len(decoded)!=32 or base64.urlsafe_b64encode(decoded).decode().rstrip('=')!=key:raise ValueError()
  except ValueError:raise ValueError('Открытый ключ Reality: нужны 32 байта в base64url без padding') from None
  reality=copy.deepcopy(tls.get('reality',{}))
  short_id=single(form,'reality_short_id',32) or reality.get('short_id','')
  if form.get('clear_reality_short_id')=='on':short_id=''
  if not isinstance(short_id,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}',short_id):raise ValueError('Reality short ID: от 0 до 8 байт, чётное число hex-символов')
  if tls.get('spoof') or tls.get('spoof_method'):raise ValueError('Reality несовместим с импортированным TLS spoof')
  reality.update(enabled=True,public_key=key,short_id=short_id.lower());tls['reality']=reality
 elif native['type']=='vless':tls.pop('reality',None)

def headers(form,previous):
 if form.get('clear_transport_headers')=='on':return {}
 raw=text(form,'transport_headers',16384)
 if not raw:return copy.deepcopy(previous)
 try:value=json.loads(raw)
 except ValueError:raise ValueError('Заголовки транспорта должны быть JSON-объектом') from None
 if not isinstance(value,dict) or len(value)>32:raise ValueError('Допустимо до 32 заголовков транспорта')
 seen=set()
 for key,values in value.items():
  if not TOKEN.fullmatch(key) or key.lower() in seen:raise ValueError('Некорректное или повторяющееся имя заголовка')
  if key.lower()=='host':raise ValueError('Host задаётся отдельным полем транспорта')
  seen.add(key.lower());items=[values] if isinstance(values,str) else values
  if not isinstance(items,list) or not 1<=len(items)<=16 or any(not isinstance(v,str) or len(v)>4096 or any(ord(c)<32 or ord(c)==127 for c in v) for v in items):raise ValueError('Некорректное значение заголовка')
 return value

def parse_transport(form,native):
 kind=single(form,'transport_type',20)
 if kind not in TRANSPORTS:raise ValueError('Неизвестный транспорт VLESS')
 if not kind:native.pop('transport',None)
 else:
  old=native.get('transport',{})
  transport=copy.deepcopy(old) if old.get('type')==kind else {'type':kind}
  if kind in ('http','ws','httpupgrade'):
   path=single(form,'transport_path')
   if path and (not path.startswith('/') or '#' in path or any(c.isspace() for c in path)):raise ValueError('Путь транспорта должен начинаться с / и не содержать пробелов или #')
   set_optional(transport,'path',path)
   host_values=[authority(v.strip()) for v in text(form,'transport_hosts').splitlines() if v.strip()]
   if len(host_values)>16 or len(set(host_values))!=len(host_values) or (kind!='http' and len(host_values)>1):raise ValueError('Для этого транспорта нужен один Host; HTTP допускает до 16')
   extra=headers(form,old.get('headers',{}) if old.get('type')==kind else {})
   for key in list(extra):
    if key.lower()=='host':extra.pop(key)
   if kind=='ws':
    if host_values:extra['Host']=host_values[0]
   else:set_optional(transport,'host',host_values if kind=='http' else (host_values[0] if host_values else ''))
   set_optional(transport,'headers',extra)
  if kind=='http':
   method=single(form,'transport_method',32)
   if method and not TOKEN.fullmatch(method):raise ValueError('Некорректный HTTP-метод транспорта')
   set_optional(transport,'method',method)
  if kind=='ws':
   early=single(form,'transport_early_data',10) or '0'
   if not early.isascii() or not early.isdigit() or not 0<=int(early)<=65535:raise ValueError('WebSocket early data: от 0 до 65535 байт')
   header=single(form,'transport_early_header',128)
   if header and not TOKEN.fullmatch(header):raise ValueError('Некорректный заголовок early data')
   set_optional(transport,'max_early_data',int(early) or None);set_optional(transport,'early_data_header_name',header)
  if kind=='grpc':
   service=single(form,'transport_service_name',255)
   if any(c.isspace() for c in service):raise ValueError('Имя gRPC-сервиса не должно содержать пробелы')
   set_optional(transport,'service_name',service)
  native['transport']=transport
 if kind=='quic' and (not native.get('tls',{}).get('enabled') or native['tls'].get('reality',{}).get('enabled') or native['tls'].get('utls',{}).get('enabled')):raise ValueError('QUIC требует обычный TLS без Reality и uTLS')
 if native.get('flow')=='xtls-rprx-vision' and (kind or not native.get('tls',{}).get('enabled')):raise ValueError('XTLS Vision требует TLS и обычный TCP без дополнительного транспорта')
 encoding=single(form,'packet_encoding',30)
 if encoding not in ('default','none','packetaddr','xudp'):raise ValueError('Неизвестное кодирование UDP VLESS')
 if encoding=='default':native.pop('packet_encoding',None)
 else:native['packet_encoding']='' if encoding=='none' else encoding

def parse_advanced(form,native):
 if form.get('advanced_fields')!='v1':return
 if native['type'] in ('http','vless'):parse_tls(form,native)
 if native['type']=='vless':parse_transport(form,native)

def transport_hosts(native):
 transport=native.get('transport',{})
 value=transport.get('host',[])
 if transport.get('type')=='ws':value=next((v for k,v in transport.get('headers',{}).items() if k.lower()=='host'),[])
 return '\n'.join(value if isinstance(value,list) else [value])
