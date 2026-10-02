"""OpenVPN server endpoint using the shared core and native client exports."""
import copy
import hashlib
import ipaddress
import re
import secrets
import ssl
import tempfile
from pathlib import Path

FIELDS = {'type','tag','listen','listen_port','system','mode','network','address','users','tls',
          'mtu','max_clients','duplicate_cn','topology','data_ciphers','auth','push',
          'ping_interval','ping_restart','handshake_window','renegotiate_interval'}
TLS_FIELDS = {'certificate','key','verify_client_certificate','version_min','version_max','control_wrap'}
PUSH_FIELDS = {'routes','dns','search_domains','redirect_gateway','block_outside_dns'}


def control_key():
    value=secrets.token_hex(256)
    return ['-----BEGIN OpenVPN Static key V1-----',*[value[i:i+32] for i in range(0,len(value),32)],'-----END OpenVPN Static key V1-----']


def validate_control_wrap(value):
    if not isinstance(value,dict) or set(value)-{'type','key','direction'} or value.get('type') not in ('tls_auth','tls_crypt'):
        raise ValueError('OpenVPN: поддерживаются tls-auth и tls-crypt со встроенным ключом')
    key=value.get('key')
    if not isinstance(key,list) or any(not isinstance(v,str) for v in key):raise ValueError('OpenVPN: вставьте общий ключ в формате OpenVPN Static key V1')
    lines=[v.strip() for v in key if v.strip() and not v.strip().startswith('#')]
    if len(lines)<3 or lines[0]!='-----BEGIN OpenVPN Static key V1-----' or lines[-1]!='-----END OpenVPN Static key V1-----' or not re.fullmatch(r'[0-9a-fA-F]{512}',''.join(lines[1:-1])):
        raise ValueError('OpenVPN: общий ключ должен содержать 256 байт в формате OpenVPN Static key V1')
    if 'direction' in value and (value['type']!='tls_auth' or value['direction'] not in ('server','client')):
        raise ValueError('OpenVPN: направление ключа задаётся только для tls-auth')
    return {**value,'key':lines}


def pem(value, marker):
    if not isinstance(value,list) or not value or any(not isinstance(v,str) for v in value):
        raise ValueError('OpenVPN: нужен встроенный PEM ' + marker)
    result='\n'.join(value)
    if len(result)>65536 or marker not in result:raise ValueError('OpenVPN: некорректный PEM ' + marker)
    return result


def validate(native):
    from incoming_connections import text
    if not isinstance(native,dict) or set(native)-FIELDS or native.get('type')!='openvpn-server':
        raise ValueError('Неизвестные параметры сервера OpenVPN')
    if native.get('system',False) is not False or native.get('mode','tls')!='tls':
        raise ValueError('Входящий OpenVPN использует TLS и внутренний сетевой стек')
    if native.get('network','udp') not in ('tcp','udp') or native.get('topology','subnet')!='subnet':
        raise ValueError('OpenVPN: выберите TCP/UDP и топологию subnet')
    address=native.get('address',[])
    if not isinstance(address,list) or not 1<=len(address)<=2:raise ValueError('Укажите пул IPv4 и/или IPv6 для клиентов OpenVPN')
    families=set()
    for value in address:
        if not isinstance(value,str):raise ValueError('Некорректный адрес OpenVPN')
        try:a=ipaddress.ip_interface(value)
        except ValueError:raise ValueError('OpenVPN: адрес сервера и префикс, например 10.20.0.1/24') from None
        if a.version in families or a.network.num_addresses<8 or a.ip==a.network.network_address or a.version==4 and a.ip==a.network.broadcast_address:
            raise ValueError('OpenVPN: нужен один непустой пул каждого семейства и адрес сервера внутри него')
        families.add(a.version)
    for field,low,high in [('mtu',576,9000),('max_clients',1,65535)]:
        if field in native and (type(native[field]) is not int or not low<=native[field]<=high):raise ValueError('OpenVPN: неверное значение '+field)
    if 'duplicate_cn' in native and type(native['duplicate_cn']) is not bool:raise ValueError('OpenVPN: неверный признак повторного подключения')
    tls=native.get('tls')
    if not isinstance(tls,dict) or set(tls)-TLS_FIELDS or tls.get('verify_client_certificate')!='none':
        raise ValueError('OpenVPN: здесь используется TLS сервера и индивидуальный логин/пароль каждого клиента')
    cert=pem(tls.get('certificate'),'CERTIFICATE');key=pem(tls.get('key'),'PRIVATE KEY')
    if 'control_wrap' in tls:tls['control_wrap']=validate_control_wrap(tls['control_wrap'])
    for field in ('version_min','version_max'):
        if field in tls and tls[field] not in ('1.2','1.3'):raise ValueError('OpenVPN: TLS 1.2 или 1.3')
    if tls.get('version_min','1.2')>tls.get('version_max','1.3'):raise ValueError('Минимальная версия TLS выше максимальной')
    try:
        with tempfile.TemporaryDirectory() as directory:
            c=Path(directory)/'cert';k=Path(directory)/'key';c.write_text(cert);k.write_text(key);c.chmod(0o600);k.chmod(0o600)
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(c,k)
    except (ValueError,ssl.SSLError):raise ValueError('OpenVPN: сертификат и закрытый ключ PEM не подходят друг к другу') from None
    ciphers=native.get('data_ciphers',[])
    if not isinstance(ciphers,list) or any(v not in ('AES-128-GCM','AES-256-GCM','CHACHA20-POLY1305') for v in ciphers):raise ValueError('OpenVPN: выберите AEAD-шифры данных')
    if native.get('auth','SHA256') not in ('SHA256','SHA384','SHA512'):raise ValueError('OpenVPN: неподдержанный алгоритм HMAC')
    for field in ('ping_interval','ping_restart','handshake_window','renegotiate_interval'):
        if field in native and (not isinstance(native[field],str) or not re.fullmatch(r'[1-9][0-9]{0,5}s',native[field])):raise ValueError('OpenVPN: интервал задаётся в секундах')
    push=native.get('push',{})
    if not isinstance(push,dict) or set(push)-PUSH_FIELDS:raise ValueError('OpenVPN: неизвестный параметр клиентских маршрутов/DNS')
    for field in ('redirect_gateway','block_outside_dns'):
        if field in push and type(push[field]) is not bool:raise ValueError('OpenVPN: неверный переключатель '+field)
    for field in ('routes','dns','search_domains'):
        values=push.get(field,[])
        if not isinstance(values,list) or len(values)>128:raise ValueError('OpenVPN: некорректный список '+field)
        for value in values:
            text(value,field,253)
            if field=='routes':ipaddress.ip_network(value,strict=True)
            elif field=='dns':ipaddress.ip_address(value)
            else:
                from policy import normalized_domain
                normalized_domain(value)
    return native


def client(native,user,hostname):
    certificate=pem(native['tls']['certificate'],'CERTIFICATE')
    first=certificate[:certificate.index('-----END CERTIFICATE-----')+len('-----END CERTIFICATE-----')]
    fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(first)).hexdigest()
    out={'type':'openvpn-client','system':False,'mode':'tls','network':native.get('network','udp'),
         'servers':[{'server':hostname,'server_port':native['listen_port']}],
         'username':user['username'],'password':user['password'],'auth_retry':'none',
         'tls':{'peer_fingerprint':[fingerprint],'remote_certificate_tls':'server'}}
    for field in ('mtu','data_ciphers','auth','ping_interval','ping_restart','handshake_window','renegotiate_interval'):
        if field in native:out[field]=copy.deepcopy(native[field])
    for field in ('version_min','version_max'):
        if field in native['tls']:out['tls'][field]=native['tls'][field]
    if 'control_wrap' in native['tls']:
        wrap=copy.deepcopy(validate_control_wrap(native['tls']['control_wrap']))
        wrap['key']='\n'.join(wrap['key'])
        if wrap.get('direction'):wrap['direction']='client' if wrap['direction']=='server' else 'server'
        out['tls']['control_wrap']=wrap
    from openvpn_profile import validate as check_client
    return check_client(out,ready=True)
