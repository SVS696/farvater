"""AmneziaWG server/client material; reuse the native .conf codec.

No processes, kernel interfaces or host routes are changed here. Private client
keys are optional for imported peers and never appear in a server .conf export.
"""
import base64
import copy
import ipaddress
import secrets
from amnezia_profile import FIELDS, parse, render
from wireguard_profile import key, endpoint

TYPE='amneziawg'
SERVER_FIELDS={'type','listen_port','interface','users','client_dns','client_routes','keepalive'}
USER_FIELDS={'name','public_key','private_key','preshared_key','allowed_ips','addresses'}


def private_key():
    return base64.b64encode(secrets.token_bytes(32)).decode()


def public_key(private):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    return base64.b64encode(X25519PrivateKey.from_private_bytes(base64.b64decode(key(private,'Закрытый ключ'))).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()


def server_model(native,disabled=()):
    interface={**copy.deepcopy(native['interface']),'ListenPort':native['listen_port']}
    peers=[]
    for u in native['users']:
        if u['name'] in disabled:continue
        peer={'PublicKey':u['public_key'],'AllowedIPs':list(u['allowed_ips'])}
        if u.get('preshared_key'):peer['PresharedKey']=u['preshared_key']
        peers.append(peer)
    return {'interface':interface,'peers':peers}


def validate(native):
    from incoming_connections import text
    if not isinstance(native,dict) or set(native)!=SERVER_FIELDS or native.get('type')!=TYPE:
        raise ValueError('AmneziaWG: неверная структура сервера')
    if type(native['listen_port']) is not int or not 1<=native['listen_port']<=65535:raise ValueError('AmneziaWG: порт от 1 до 65535')
    interface=native['interface']
    if not isinstance(interface,dict) or set(interface)-({'PrivateKey','Address','MTU'}|set(FIELDS)-{'DNS'}):
        raise ValueError('AmneziaWG: неизвестные поля сервера; DNS задаётся отдельно для клиентов')
    users=native['users']
    if not isinstance(users,list) or len(users)>64:raise ValueError('AmneziaWG: до 64 клиентов на сервер')
    names=set();publics=set();networks=[]
    server_public=public_key(interface.get('PrivateKey'))
    try:
        values=interface.get('Address',[])
        if not isinstance(values,list) or any(not isinstance(v,str) or '%' in v for v in values):raise ValueError()
        addresses=[ipaddress.ip_interface(v) for v in values]
        if not addresses or len(addresses)>2 or len({a.version for a in addresses})!=len(addresses):raise ValueError()
        if any(a.network.prefixlen==0 or a.ip.is_multicast or a.ip.is_loopback or a.ip.is_unspecified for a in addresses):raise ValueError()
    except (ValueError,TypeError):raise ValueError('AmneziaWG: укажите серверный адрес и пул IPv4 и/или IPv6') from None
    for u in users:
        if not isinstance(u,dict) or set(u)-USER_FIELDS or not {'name','public_key','allowed_ips','addresses'}.issubset(u):raise ValueError('AmneziaWG: неверные поля клиента')
        text(u['name'],'Имя клиента',128);key(u['public_key'],'PublicKey')
        if u['name'] in names or u['public_key'] in publics or u['public_key']==server_public:raise ValueError('AmneziaWG: имя и ключ клиента должны быть уникальны')
        names.add(u['name']);publics.add(u['public_key'])
        if u.get('private_key') and public_key(u['private_key'])!=u['public_key']:raise ValueError('AmneziaWG: закрытый ключ клиента не соответствует открытому')
        if u.get('preshared_key'):key(u['preshared_key'],'PresharedKey')
        if not isinstance(u['allowed_ips'],list) or not u['allowed_ips'] or len(u['allowed_ips'])>64:raise ValueError('AmneziaWG: укажите адреса и сети клиента')
        own=[]
        for value in u['allowed_ips']:
            if not isinstance(value,str):raise ValueError('AmneziaWG: некорректная сеть клиента')
            try:n=ipaddress.ip_network(value,strict=True)
            except ValueError:raise ValueError('AmneziaWG: сеть клиента должна иметь корректный префикс') from None
            if n.prefixlen==0 or n.is_multicast or n.is_loopback or any(a.version==n.version and a.ip in n for a in addresses):raise ValueError('AmneziaWG: сеть клиента не должна включать сервер или весь интернет')
            if any(n.version==old.version and n.overlaps(old) for old in networks):raise ValueError('AmneziaWG: сети разных клиентов пересекаются')
            own.append(n)
        networks.extend(own)
        if not isinstance(u['addresses'],list) or len(u['addresses'])>2:raise ValueError('AmneziaWG: до двух адресов клиента')
        families=set()
        for value in u['addresses']:
            if not isinstance(value,str) or '%' in value:raise ValueError('AmneziaWG: некорректный адрес клиента')
            a=ipaddress.ip_interface(value)
            if a.version in families or a.ip.is_unspecified or a.ip.is_multicast or a.ip.is_loopback:raise ValueError('AmneziaWG: укажите один адрес клиента для каждой семьи IP')
            families.add(a.version)
            if not any(a.version==n.version and a.ip in n for n in own):raise ValueError('AmneziaWG: адрес клиента отсутствует в его разрешённых сетях')
    if not isinstance(native['client_dns'],list) or len(native['client_dns'])>16:raise ValueError('AmneziaWG: некорректные DNS клиентов')
    for value in native['client_dns']:
        if not isinstance(value,str) or '%' in value:raise ValueError('AmneziaWG: DNS должен быть IP-адресом')
        ipaddress.ip_address(value)
    if not isinstance(native['client_routes'],list) or not 1<=len(native['client_routes'])<=64:raise ValueError('AmneziaWG: укажите маршруты клиентов')
    for value in native['client_routes']:
        if not isinstance(value,str) or '%' in value:raise ValueError('AmneziaWG: некорректный маршрут клиента')
        ipaddress.ip_network(value,strict=True)
    if type(native['keepalive']) is not int or not 0<=native['keepalive']<=65535:raise ValueError('AmneziaWG: keepalive от 0 до 65535 секунд')
    parse(render(server_model(native)))
    return native


def allocate(native):
    """Smallest free host in each declared pool, without enumerating IPv6 pools."""
    occupied=[ipaddress.ip_network(v) for u in native['users'] for v in u['allowed_ips']]
    result=[]
    for value in native['interface']['Address']:
        address=ipaddress.ip_interface(value);network=address.network
        candidate=int(network.network_address)+(1 if network.num_addresses>2 else 0)
        limit=int(network.broadcast_address)-(1 if address.version==4 and network.num_addresses>2 else 0)
        ranges=sorted([(int(n.network_address),int(n.broadcast_address)) for n in occupied if n.version==address.version]+[(int(address.ip),int(address.ip))])
        for start,end in ranges:
            if start<=candidate<=end:candidate=end+1
        if candidate>limit:raise ValueError('AmneziaWG: в пуле закончились свободные адреса')
        ip=(ipaddress.IPv4Address if address.version==4 else ipaddress.IPv6Address)(candidate)
        result.append(str(ip)+'/'+str(ip.max_prefixlen))
    return result


def client_config(entry,name,mode):
    from incoming_connections import host
    n=validate(entry['native'])
    if not entry['enabled'] or name in entry.get('disabled_clients',[]):raise ValueError('Подключение или клиент отключён')
    if mode not in ('local','external'):raise ValueError('Выберите локальное или внешнее подключение')
    u=next((u for u in n['users'] if u['name']==name),None)
    if not u:raise ValueError('Клиент AmneziaWG не найден')
    if not u.get('private_key') or not u['addresses']:raise ValueError('Для этого пира нет клиентского ключа или адреса; импортируйте его клиентский .conf')
    interface={k:copy.deepcopy(v) for k,v in n['interface'].items() if k not in ('PrivateKey','Address')}
    interface.update(PrivateKey=u['private_key'],Address=list(u['addresses']))
    if n['client_dns']:interface['DNS']=list(n['client_dns'])
    hostname=host(entry[mode+'_host'])
    endpoint_value=('['+hostname+']' if ':' in hostname else hostname)+':'+str(n['listen_port'])
    peer={'PublicKey':public_key(n['interface']['PrivateKey']),'Endpoint':endpoint(endpoint_value),
          'AllowedIPs':list(n['client_routes']),'PersistentKeepalive':str(n['keepalive'])}
    if u.get('preshared_key'):peer['PresharedKey']=u['preshared_key']
    return {'interface':interface,'peers':[peer]}


def import_server(text,previous):
    """Server .conf cannot contain client private keys; preserve verified matches."""
    model=parse(text)
    if model['interface'].get('Table','off')!='off':raise ValueError('Серверный импорт не должен задавать чужую таблицу маршрутов')
    native=copy.deepcopy(previous);interface=model['interface'];interface.pop('Table',None)
    native['listen_port']=interface.pop('ListenPort',0)
    if 'DNS' in interface:native['client_dns']=interface.pop('DNS')
    native['interface']=interface
    old={u['public_key']:u for u in previous['users']};users=[]
    reserved={u['name'] for u in previous['users']}
    for index,p in enumerate(model['peers'],1):
        if p.get('Endpoint'):raise ValueError('Это клиентский профиль; для сервера импортируйте .conf без Endpoint у пиров')
        generated='Пир '+str(index)
        while generated in reserved:index+=1;generated='Пир '+str(index)
        u=copy.deepcopy(old.get(p['PublicKey'],{'name':generated,'public_key':p['PublicKey'],'addresses':[]}))
        reserved.add(u['name'])
        u['allowed_ips']=p['AllowedIPs'];u.pop('preshared_key',None)
        if p.get('PresharedKey'):u['preshared_key']=p['PresharedKey']
        u['addresses']=[a for a in u['addresses'] if any(ipaddress.ip_interface(a).ip in ipaddress.ip_network(n) for n in u['allowed_ips'] if ipaddress.ip_interface(a).version==ipaddress.ip_network(n).version)]
        users.append(u)
    native['users']=users
    return validate(native)


def parse_form(form,previous=None):
    import uuid
    from amnezia_profile import validate_extra
    from incoming_connections import validate as validate_entries
    previous=previous or {};old=previous.get('native',{})
    def lines(field):return [v.strip() for v in form.get(field,'').splitlines() if v.strip()]
    def number(field,default=None):
        try:return int(form.get(field,'') or default)
        except (ValueError,TypeError):raise ValueError('Укажите целое число: '+field) from None
    interface={'PrivateKey':form.get('server_private') or old.get('interface',{}).get('PrivateKey') or private_key(), 'Address':lines('address')}
    if form.get('mtu'):interface['MTU']=number('mtu')
    defaults={'Jc':3,'Jmin':40,'Jmax':70,'S1':16,'S2':32,'S3':16,'S4':16}
    for field in ('H1','H2','H3','H4'):defaults[field]=str(secrets.randbelow(4294967291)+4)
    for field in FIELDS:
        if field=='DNS':continue
        value=form.get('awg_'+field,'').strip()
        if field=='HeaderProtectionKey' and not value:value=old.get('interface',{}).get(field,'')
        if not previous and not value:value=defaults.get(field,'')
        if value!='':interface[field]=validate_extra(field,value)
    n={'type':TYPE,'listen_port':number('listen_port'),'interface':interface,'users':[], 'client_dns':lines('client_dns'), 'client_routes':lines('client_routes'),'keepalive':number('keepalive',25)}
    keys=('original','name','secret','public','psk','address','networks')
    columns={key:form.getlist('client_'+key) for key in keys}
    if len({len(v) for v in columns.values()})!=1 or len(columns['name'])>64:raise ValueError('Некорректный список клиентов')
    old_users={u['name']:u for u in old.get('users',[])}
    originals=[v for v in columns['original'] if v]
    if len(set(originals))!=len(originals) or any(v not in old_users for v in originals):raise ValueError('Исходный клиент изменился')
    # Reserve retained addresses before allocating new rows, regardless of their UI order.
    reserved=[copy.deepcopy(old_users[v]) for v in originals]
    users=[]
    for values in zip(*(columns[k] for k in keys)):
        fields=dict(zip(keys,values));before=old_users.get(fields['original'],{})
        private=fields['secret'].strip() or before.get('private_key')
        supplied_public=fields['public'].strip()
        public=supplied_public or before.get('public_key')
        if not public and not private:private=private_key()
        if private:
            calculated=public_key(private)
            if supplied_public and supplied_public!=calculated:raise ValueError('Открытый и закрытый ключи клиента не совпадают')
            public=calculated
        addresses=[v.strip() for v in fields['address'].splitlines() if v.strip()]
        if not addresses and not before:
            addresses=allocate({**n,'users':reserved+users})
        elif not addresses:addresses=list(before.get('addresses',[]))
        networks=[v.strip() for v in fields['networks'].splitlines() if v.strip()]
        networks=networks or [str(ipaddress.ip_network(a,strict=False)) for a in addresses]
        u={'name':fields['name'].strip(),'public_key':public,'addresses':addresses,'allowed_ips':networks}
        if private:u['private_key']=private
        psk=fields['psk'].strip() or before.get('preshared_key')
        if not psk and not before:psk=private_key()
        if psk:u['preshared_key']=psk
        users.append(u)
    n['users']=users
    disabled=form.getlist('disabled_client')
    if any(v not in old_users for v in disabled):raise ValueError('Отключаемый клиент не найден')
    result={'id':previous.get('id') or uuid.uuid4().hex,'name':form.get('name','').strip(),'enabled':form.get('enabled')=='on',
      'local_host':form.get('local_host','').strip(),'external_host':form.get('external_host','').strip(),'native':n,
      'disabled_clients':[u['name'] for original,u in zip(columns['original'],users) if original in disabled]}
    validate_entries([result]);return result


def import_client(raw,previous,name):
    """Recover client private material from a standard profile for this server."""
    n=copy.deepcopy(validate(previous));model=parse(raw)
    if len(model['peers'])!=1 or model['peers'][0]['PublicKey']!=public_key(n['interface']['PrivateKey']):raise ValueError('Клиентский конфиг должен подключаться к этому серверу')
    peer=model['peers'][0];interface=model['interface']
    for field in FIELDS:
        expected=n['client_dns'] if field=='DNS' else n['interface'].get(field)
        actual=interface.get(field,[] if field=='DNS' else None)
        if actual!=expected:raise ValueError('Клиентский конфиг отличается от настроек сервера: '+field)
    if peer['AllowedIPs']!=n['client_routes']:raise ValueError('Маршруты импортируемого клиента отличаются от выдаваемых сервером')
    if 'ListenPort' in interface or interface.get('Table','off')!='off':raise ValueError('Сначала уберите из клиентского файла собственный ListenPort/Table')
    if interface.get('MTU',1280)!=n['interface'].get('MTU',1280):raise ValueError('MTU клиента отличается от настроек выдачи сервера')
    public=public_key(interface['PrivateKey']);old=next((u for u in n['users'] if u['public_key']==public),None)
    u={'name':name.strip() or (old['name'] if old else ''),'public_key':public,'private_key':interface['PrivateKey'],
       'addresses':interface['Address'],'allowed_ips':old['allowed_ips'] if old else [str(ipaddress.ip_network(str(ipaddress.ip_interface(a).ip)+'/'+str(ipaddress.ip_interface(a).max_prefixlen))) for a in interface['Address']]}
    if peer.get('PresharedKey'):u['preshared_key']=peer['PresharedKey']
    n['users']=[u if v['public_key']==public else v for v in n['users']] if old else [*n['users'],u]
    return validate(n)
