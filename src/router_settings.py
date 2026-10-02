"""Typed router measurement settings; no user-supplied commands or paths."""
import hashlib,ipaddress,json,shlex,re
from urllib.parse import urlsplit
from health_settings import edit_check,form_fields,fingerprint

DEFAULT={'id':'router:default','kind':'router_lan','name':'Проверка сервера с роутера','scope':'Роутер · собственные измерения',
         'action':'Сверьте контрольные имена LAN-входа, DNS/прокси кандидата и время измерения.',
         'server':'10.0.0.1','dns_port':15454,'proxy_port':15458,'domain':'example.com','url':'https://api.ipify.org'}
KEYS=set(DEFAULT)

def validate(check):
    if not isinstance(check,dict) or set(check)!=KEYS or not re.fullmatch(r'router:[A-Za-z0-9_-]{1,40}',str(check.get('id',''))) or check.get('kind')!='router_lan':raise ValueError('Некорректные настройки измерителя роутера')
    fields=form_fields(check)
    normalized=edit_check(check,{f['key']:str(f['value']) for f in fields})
    address=ipaddress.ip_address(normalized['server'])
    if address.version!=4 or not any(address in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):raise ValueError('Измерителю роутера нужен частный IPv4-адрес кандидата в LAN')
    url=urlsplit(normalized['url'])
    if url.scheme!='https' or (url.port is not None and url.port!=443):raise ValueError('Контроль роутера использует HTTPS на порту 443')
    if '*' in normalized['url'] or '[' in normalized['url'] or ']' in normalized['url']:raise ValueError('Для контроля нужен один точный HTTPS URL')
    try:ipaddress.ip_address(url.hostname)
    except ValueError:pass
    else:raise ValueError('В HTTPS URL нужно имя, допущенное для контрольных запросов роутера')
    if normalized!=check:raise ValueError('Настройки измерителя требуют нормализации')
    return normalized

def compile_settings(check):
    validate(check)
    value=json.dumps(check,sort_keys=True,ensure_ascii=False,separators=(',',':'))
    fields={'REVISION':fingerprint(check),'SETTINGS_JSON':value,'SERVER':check['server'],'DNS_PORT':str(check['dns_port']),
            'PROXY_PORT':str(check['proxy_port']),'DOMAIN':check['domain'],'URL':check['url']}
    content=('\n'.join(k+'='+shlex.quote(v) for k,v in fields.items())+'\n').encode()
    if len(content)>16000:raise ValueError('Слишком большие настройки измерителя')
    return content

def status_view(value):
    if not isinstance(value,dict) or set(value)!={'check','revision','persistent_matches'} or type(value['persistent_matches']) is not bool:raise ValueError('Неполный ответ настроек роутера')
    check=validate(value['check'])
    if fingerprint(check)!=value['revision']:raise ValueError('Ревизия роутера не соответствует параметрам')
    return {'revision':value['revision'],'persistent_matches':value['persistent_matches'],'checks':[{'id':check['id'],'name':check['name'],'scope':check['scope']}],
            'selected':{'id':check['id'],'kind':check['kind'],'fields':form_fields(check)},'check':check}
