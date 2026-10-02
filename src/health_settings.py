"""Typed host probes; no caller-supplied command or executable path."""
import copy
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

COMMON=[('name','Название','text','',120),('scope','Группа','text','',120),
        ('action','Что проверить при отказе','text','',1000)]
PERIOD=[('interval_seconds','Период проверки, секунд (не чаще завершения предыдущей)','int',5,(5,300))]
CUSTOM_KINDS={'dns':'DNS','https':'HTTP(S)','https_slow':'HTTP(S), медленная сеть','tcp':'TCP-порт','icmp':'ICMP','udp_stun':'UDP STUN','service':'Служба systemd'}
FIELDS={
 'service':[('unit','Служба systemd','unit','',0)],
 'dns':[('server','IP DNS','ip','127.0.0.1',0),('port','Порт DNS','int',53,(1,65535)),
        ('domain','Проверочное имя','domain','',0),('tcp','DNS по TCP','bool',False,0),
        ('timeout_seconds','Ожидание DNS, секунд','int',2,(1,5))],
 'https':[('url','URL проверки','url','',0),('proxy','SOCKS5 — IP:порт; пусто для прямого запроса','proxy','',0),
          ('codes','Допустимые HTTP-коды через запятую','codes',['200','204'],0),
          ('observe_ip','Проверять внешний IPv4 в теле ответа','bool',False,0),
          ('connect_timeout_seconds','Ожидание соединения, секунд','int',2,(1,6)),
          ('timeout_seconds','Общее ожидание HTTP, секунд','int',6,(1,6))],
 'udp_stun':[('host','Имя STUN-сервера','domain','stun.cloudflare.com',0),('port','Порт STUN UDP','int',3478,(1,65535)),
             ('proxy','SOCKS5 — IP:порт, без прямого обхода','proxy','127.0.0.1:2081',0),
             ('timeout_seconds','Общее ожидание UDP, секунд','int',3,(1,5))],
 'tcp':[('host','IP узла','ip','',0),('port','Порт','int',443,(1,65535)),('timeout_seconds','Ожидание соединения, секунд','int',2,(1,5))],
 'icmp':[('host','IP узла','ip','',0),('timeout_seconds','Ожидание ответа, секунд','int',2,(1,5))],
 'router_lan':[('server','LAN IPv4 кандидата','ip','10.0.0.1',0),('dns_port','Порт DNS','int',15454,(1,65535)),
               ('proxy_port','Порт SOCKS5','int',15458,(1,65535)),('domain','Проверочное имя DNS','domain','example.com',0),
               ('url','HTTPS URL проверки','url','https://api.ipify.org',0)],
 'resources':[('disk_warning_gib','Предупреждать при свободном диске меньше, GiB','int',5,(1,100000)),
              ('memory_warning_mib','Предупреждать при доступной памяти меньше, MiB; 0 — без порога','int',0,(0,1048576))],
 'runtime':[], 'candidate_adguard':[], 'candidate_lan':[], 'candidate_vpn':[],
 'dns_filter':[('blocked_domain','Имя, которое должно блокироваться','domain','',0),
               ('allowed_domain','Имя, которое должно проходить','domain','',0),
               ('filtered.server','IP фильтрующего DNS','ip','',0),('filtered.port','Порт фильтрующего DNS','int',53,(1,65535)),
               ('unfiltered.server','IP исходного DNS','ip','',0),('unfiltered.port','Порт исходного DNS','int',5300,(1,65535))]
}
FIELDS['https_slow']=[(key,label,kind,30 if key in ('connect_timeout_seconds','timeout_seconds') else default,
                      (1,30) if key=='connect_timeout_seconds' else (10,30) if key=='timeout_seconds' else bounds)
                     for key,label,kind,default,bounds in FIELDS['https']]
FIELDS['vpn_gate']=[
 ('client','IPv4 роутера внутри WireGuard','ip','',0),
 ('host','IPv4 сервера для проверки роутером','ip','',0),
 ('port','TCP-порт готовности для роутера','int',18081,(1024,65535)),
 ('dns_server','IP DNS нового ядра','ip','127.0.0.1',0),
 ('dns_port','Порт DNS нового ядра','int',5301,(1,65535)),
 ('proxy','SOCKS5 нового ядра — IP:порт','proxy','127.0.0.1:2081',0),
 ('url','Контрольный HTTPS URL; его имя проверяется по UDP и TCP','url','https://example.com/',0),
 ('codes','Допустимые HTTP-коды через запятую','codes',['200'],0),
 ('dns_timeout_seconds','Ожидание DNS, секунд','int',2,(1,5)),
 ('timeout_seconds','Ожидание HTTPS, секунд','int',5,(1,10)),
 ('rise','Успешных проверок до возврата на VPN','int',2,(1,10)),
 ('fall','Неуспешных проверок до выхода через провайдера','int',1,(1,3)),
 ('max_age_seconds','Максимальный возраст успешной проверки, секунд','int',20,(5,600))]

def definitions(check):
 if check.get('kind') not in FIELDS:raise ValueError('Этот тип датчика не поддерживает редактирование')
 period=[('interval_seconds','Период проверки, секунд (не чаще завершения предыдущей)','int',60,(60,300))] if check['kind']=='https_slow' else PERIOD
 return COMMON+([] if check['kind']=='router_lan' else period)+FIELDS[check['kind']]

def removable(check):
 return check.get('custom') is True and bool(re.fullmatch(r'custom:[a-f0-9]{32}',check.get('id',''))) and check.get('kind') in CUSTOM_KINDS

def new_check(kind,identifier):
 if kind not in CUSTOM_KINDS:raise ValueError('Этот тип нельзя добавить как собственную проверку')
 return {'id':identifier,'kind':kind,'custom':True,'name':CUSTOM_KINDS[kind],
         'scope':'Собственные проверки','action':'Проверьте параметры и доступность ресурса'}

def get_value(check,key,default):
 if key=='codes' and check.get('observe_ip'):default=['200']
 value=check
 for part in key.split('.'):
  if not isinstance(value,dict) or part not in value:return default
  value=value[part]
 return value

def form_fields(check):
 return [{'key':key,'label':label,'type':kind,'value':(','.join(get_value(check,key,default)) if kind=='codes' else get_value(check,key,default)),
          'minimum':bounds[0] if kind=='int' else None,'maximum':bounds[1] if kind=='int' else None}
         for key,label,kind,default,bounds in definitions(check)]

def edit_check(check,values):
 defs=definitions(check)
 if not isinstance(values,dict) or set(values)!={d[0] for d in defs}:raise ValueError('Неполный набор параметров датчика')
 result=copy.deepcopy(check)
 for key,label,kind,default,bounds in defs:
  v=values[key]
  if kind=='bool':
   if type(v) is not bool:raise ValueError(label+': ожидается переключатель')
  else:
   if not isinstance(v,str) or len(v)>2000 or any(ord(c)<32 for c in v):raise ValueError(label+': некорректное значение')
   v=v.strip()
   if kind=='text':
    if not v or len(v)>bounds:raise ValueError(label+': пустое или слишком длинное значение')
   elif kind=='int':
    if not v.isascii() or not v.isdigit() or not bounds[0]<=int(v)<=bounds[1]:raise ValueError(label+': значение вне допустимого диапазона')
    v=int(v)
   elif kind=='ip':
    try:v=str(ipaddress.ip_address(v))
    except ValueError:raise ValueError(label+': нужен IP-адрес') from None
   elif kind=='unit':
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,150}',v):raise ValueError('Некорректное имя службы')
   elif kind=='domain':
    if len(v)>253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',v) or any(not p or len(p)>63 or p.startswith('-') or p.endswith('-') for p in v.split('.')):
     raise ValueError(label+': нужно полное имя латиницей, без маски')
   elif kind=='url':
    try:
     u=urlsplit(v);port=u.port
     if u.scheme not in ('http','https') or not u.hostname or u.username is not None or u.password is not None or u.fragment or u.query or '{' in v or '}' in v or '\\' in v or ' ' in v:raise ValueError()
     if len(v)>1000:raise ValueError()
    except ValueError:raise ValueError('URL: разрешены HTTP(S) без логина, пароля, параметров запроса и фрагмента') from None
   elif kind=='proxy':
    if v:
     try:
      host,port=v.rsplit(':',1)
      if host.startswith('[') and host.endswith(']'):ipaddress.IPv6Address(host[1:-1])
      else:ipaddress.IPv4Address(host)
      if not port.isdigit() or not 1<=int(port)<=65535:raise ValueError()
     except ValueError:raise ValueError('SOCKS5: нужен IP:порт или [IPv6]:порт без реквизитов') from None
   elif kind=='codes':
    v=[x.strip() for x in v.split(',')]
    if not 1<=len(v)<=10 or len(set(v))!=len(v) or any(not re.fullmatch('[1-5][0-9]{2}',c) for c in v):raise ValueError('Укажите от 1 до 10 различных HTTP-кодов')
  if key=='interval_seconds' and key not in check and v==5:continue
  parts=key.split('.');target=result
  for part in parts[:-1]:target=target.setdefault(part,{})
  target[parts[-1]]=v
 if result['kind']=='udp_stun' and not result['proxy']:raise ValueError('Для UDP-проверки нужен SOCKS5; прямой обход не выполняется')
 if result['kind']=='vpn_gate':
  for key in ('client','host','dns_server'):
   address=ipaddress.ip_address(result[key])
   if address.version!=4 or not address.is_private or address.is_unspecified or address.is_multicast:
    raise ValueError('Для проверки роутера нужны конкретные частные IPv4-адреса')
  if not result['proxy'] or urlsplit(result['url']).scheme!='https':raise ValueError('Проверка пути требует HTTPS и SOCKS5 без прямого обхода')
  if result['max_age_seconds']<=result.get('interval_seconds',5)+2*(result['dns_timeout_seconds']+1)+result['timeout_seconds']+2:
   raise ValueError('Возраст результата должен превышать период плюс полное время DNS и HTTPS')
 if result['kind'] in ('https','https_slow'):
  if result['connect_timeout_seconds']>result['timeout_seconds']:raise ValueError('Ожидание соединения не может превышать общее ожидание')
  if result['observe_ip'] and result['codes']!=['200']:raise ValueError('Измерение внешнего IPv4 требует единственный HTTP-код 200')
  if result['observe_ip'] and urlsplit(result['url']).scheme!='https':raise ValueError('Измерение внешнего IPv4 требует HTTPS')
 return result

def fingerprint(check):
 return hashlib.sha256(json.dumps(check,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

def pending_row(check,now):
 return {**{k:check[k] for k in ('id','name','scope','action')},'status':'unknown',
         'detail':'Ожидается первое измерение с текущими параметрами','observed_at':now,
         'duration_ms':0,'definition_sha256':fingerprint(check),'interval_seconds':check.get('interval_seconds',5)}

def read_settings(root):
 raw=(root/'checks.json').read_bytes()
 if len(raw)>128*1024:raise ValueError('Слишком большой список датчиков')
 value=json.loads(raw)
 if not isinstance(value,dict) or set(value)!={'checks'} or not isinstance(value['checks'],list) or not 1<=len(value['checks'])<=64:raise ValueError('Некорректный список датчиков')
 ids=[]
 for c in value['checks']:
  if not isinstance(c,dict):raise ValueError('Некорректный датчик')
  definitions(c)
  if c['kind']=='https_slow' and (type(c.get('interval_seconds')) is not int or not 60<=c['interval_seconds']<=300):
   raise ValueError('Период медленного датчика должен быть от 60 до 300 секунд')
  if 'custom' in c and not removable(c):raise ValueError('Некорректная собственная проверка')
  if 'interval_seconds' in c and (type(c['interval_seconds']) is not int or not 5<=c['interval_seconds']<=300):raise ValueError('Некорректный период датчика')
  if not isinstance(c.get('id'),str) or not re.fullmatch('[A-Za-z0-9:_.@-]{1,100}',c['id']):raise ValueError('Некорректный идентификатор датчика')
  ids.append(c['id'])
  fields=form_fields(c)
  edit_check(c,{f['key']:(f['value'] if f['type']=='bool' else str(f['value'])) for f in fields})
 if len(ids)!=len(set(ids)):raise ValueError('Повторяющийся датчик')
 if sum(c['kind']=='https_slow' for c in value['checks'])>4:raise ValueError('Допустимо до четырёх медленных HTTP-проверок')
 return value,hashlib.sha256(raw).hexdigest()
