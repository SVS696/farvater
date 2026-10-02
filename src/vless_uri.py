"""VLESS share links, mapped through the same typed form as manual setup.

Reference: https://github.com/XTLS/Xray-core/discussions/716
Unsupported extensions fail explicitly instead of silently changing a connection.
"""
import copy
import ipaddress
from urllib.parse import quote, urlsplit, urlencode
from shadowsocks_uri import decoded, string, LIMIT
from tunnel_form import parse_outbound

COMMON={'encryption','type','security','flow'}
TLS={'sni','fp','alpn'}
REALITY={'pbk','sid'}
TRANSPORT={'tcp':set(),'ws':{'host','path'},'http':{'host','path'},
           'httpupgrade':{'host','path'},'grpc':{'serviceName','mode'}}


def parse(raw):
    if not isinstance(raw,str) or len(raw.encode())>LIMIT:raise ValueError('Ссылка VLESS превышает 64 КиБ')
    raw=raw.strip()
    if not raw.startswith('vless://') or any(c.isspace() or ord(c)<32 or ord(c)==127 for c in raw):
        raise ValueError('Нужна одна ссылка vless://; пробелы в параметрах кодируются через %')
    decoded(raw)  # Validate percent escapes before URL parsing can normalize anything.
    try:
        u=urlsplit(raw)
        if u.scheme!='vless' or not u.hostname or u.port is None or not u.username or u.password is not None or u.path not in ('','/') or u.netloc.count('@')!=1:raise ValueError()
        host=u.hostname;port=u.port
    except ValueError:raise ValueError('Нужны UUID, сервер и порт; IPv6 задаётся в квадратных скобках') from None
    params={}
    for pair in u.query.split('&') if u.query else []:
        if '=' not in pair:raise ValueError('У параметра ссылки нет значения')
        key,value=pair.split('=',1);key=decoded(key);value=decoded(value)
        if key in params:raise ValueError('В ссылке повторяется параметр')
        params[key]=value
    kind=params.get('type','tcp');security=params.get('security','none')
    if kind not in TRANSPORT:raise ValueError('Этот транспорт VLESS пока не поддержан: используйте TCP, WebSocket, HTTP, HTTPUpgrade или gRPC')
    if security not in ('none','tls','reality'):raise ValueError('Поддержаны TLS, Reality или соединение без TLS')
    allowed=COMMON|TRANSPORT[kind]|(TLS if security!='none' else set())|(REALITY if security=='reality' else set())
    if set(params)-allowed:raise ValueError('Ссылка содержит неподдержанные параметры; импорт не выполнен, чтобы не потерять настройки')
    if params.get('encryption','none')!='none':raise ValueError('Установленное ядро поддерживает VLESS encryption=none')
    if kind=='grpc' and params.get('mode','gun')!='gun':raise ValueError('Поддержан обычный режим gRPC gun')
    for key in ('path','fp','sni','alpn','serviceName'):
        if key in params and not params[key]:raise ValueError('Параметр '+key+' не может быть пустым')
    if security=='reality' and (not params.get('pbk') or not params.get('fp')):raise ValueError('Reality требует открытый ключ pbk и отпечаток fp')
    name=decoded(u.fragment) if u.fragment else host
    string(name,120,'Название')
    form={'name':name,'scope':'public','type':'vless','server':host,'server_port':str(port),
          'uuid':decoded(u.username),'flow':params.get('flow',''),'advanced_fields':'v1',
          'transport_type':'' if kind=='tcp' else kind,'packet_encoding':'default'}
    if security!='none':
        form.update(tls_enabled='on',server_name=params.get('sni',''),tls_fingerprint=params.get('fp','chrome'),tls_alpn=params.get('alpn','').replace(',','\n'))
    if security=='reality':form.update(tls_reality='on',reality_public_key=params['pbk'],reality_short_id=params.get('sid',''))
    if kind in ('ws','http','httpupgrade'):
        form.update(transport_path=params.get('path','/'),transport_hosts=params.get('host','').replace(',','\n') if kind=='http' else params.get('host',''))
    if kind=='grpc':form['transport_service_name']=params.get('serviceName','')
    result=parse_outbound(form,{},'imported-vless',{'exits':{},'dns':{}})
    result['native'].pop('tag',None)
    return result


def only(value,fields,label):
    if not isinstance(value,dict) or set(value)-fields:raise ValueError('Ссылка vless:// не передаёт дополнительные настройки '+label+'. Экспорт остановлен, чтобы не потерять их')


def render(outbound):
    n=copy.deepcopy(outbound.get('native',{}));n.pop('tag',None)
    only(n,{'type','server','server_port','uuid','flow','tls','transport'},'этого выхода')
    if n.get('type')!='vless':raise ValueError('Нужен выход VLESS')
    name=string(outbound.get('name'),120,'Название')
    q={'encryption':'none','type':'tcp','security':'none'}
    if n.get('flow'):q['flow']=n['flow']
    tls=n.get('tls')
    if tls:
        only(tls,{'enabled','server_name','alpn','utls','reality'},'TLS')
        if tls.get('enabled') is not True:raise ValueError('Отключённые параметры TLS нельзя передать ссылкой')
        utls=tls.get('utls',{})
        only(utls,{'enabled','fingerprint'},'uTLS')
        if utls.get('enabled') is not True or not utls.get('fingerprint'):
            raise ValueError('Для стандартной ссылки выберите отпечаток TLS в настройках: при отсутствии fp клиенты включают Chrome, что изменило бы текущее подключение')
        q.update(security='tls',fp=utls['fingerprint'])
        if tls.get('server_name'):q['sni']=tls['server_name']
        if tls.get('alpn'):q['alpn']=','.join(tls['alpn'])
        reality=tls.get('reality')
        if reality:
            only(reality,{'enabled','public_key','short_id'},'Reality')
            if reality.get('enabled') is not True:raise ValueError('Отключённые параметры Reality нельзя передать ссылкой')
            q.update(security='reality',pbk=reality.get('public_key',''),sid=reality.get('short_id',''))
    transport=n.get('transport')
    if transport:
        kind=transport.get('type');q['type']=kind
        allowed={'type','service_name'} if kind=='grpc' else {'type','path','host','headers'}
        only(transport,allowed,'транспорта')
        if kind not in TRANSPORT or kind=='tcp':raise ValueError('Этот транспорт не поддержан форматом обмена')
        if kind=='grpc':
            if transport.get('service_name'):q['serviceName']=transport['service_name']
        else:
            headers=transport.get('headers',{})
            only(headers,{'Host'},'заголовков транспорта')
            if headers and kind!='ws':raise ValueError('Дополнительные заголовки не передаются ссылкой')
            host=headers.get('Host','') if kind=='ws' else transport.get('host','')
            if isinstance(host,list):host=','.join(host)
            if host:q['host']=host
            q['path']=transport.get('path','/')
            transport.setdefault('path','/')
    host=string(n.get('server'),253,'Сервер')
    try:
        if ipaddress.ip_address(host).version==6:host='['+host+']'
    except ValueError:pass
    result='vless://'+quote(str(n.get('uuid','')),safe='')+'@'+host+':'+str(n.get('server_port',''))+'?'+urlencode(q,quote_via=quote)+'#'+quote(name,safe='')
    if parse(result)['native']!=n:raise ValueError('Параметры не передаются ссылкой без изменений; проверьте настройки подключения')
    return result+'\n'
