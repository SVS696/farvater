"""Native outbound fields used by the draft panel; no service side effects."""
import copy
import ipaddress
import re
import uuid
from policy import normalized_domain

OUTBOUND_TYPES={'direct':'Прямой выход / сетевой интерфейс','socks':'SOCKS','http':'HTTP CONNECT',
                'shadowsocks':'Shadowsocks','vless':'VLESS','openconnect':'OpenConnect (встроенный клиент)',
                'selector':'Очередь выходов (ручной выбор)'}
SS_METHODS=['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305',
            'aes-128-gcm','aes-192-gcm','aes-256-gcm','chacha20-ietf-poly1305','xchacha20-ietf-poly1305',
            'none','aes-128-ctr','aes-192-ctr','aes-256-ctr','aes-128-cfb','aes-192-cfb','aes-256-cfb','rc4-md5','chacha20-ietf','xchacha20']


def external_connection(outbound):
    """A transport into an existing VPN is not that VPN's settings form."""
    protocol = outbound.get('protocol', '')
    native = outbound.get('native', {})
    expected = {'OpenConnect': 'openconnect', 'WireGuard': 'wireguard',
                'TrustTunnel': 'trusttunnel'}
    return protocol in expected and native.get('type') != expected[protocol]


def parse_outbound(form,previous,identifier,policy):
    kind=form.get('type','');scope=form.get('scope','');name=form.get('name','').strip()
    if kind not in OUTBOUND_TYPES:raise ValueError('Неизвестный тип выхода')
    if scope not in ('public','work','special'):raise ValueError('Неизвестное назначение выхода')
    if not name or len(name)>120:raise ValueError('Название должно содержать от 1 до 120 символов')
    old=previous.get('native',{})
    native=copy.deepcopy(old) if old.get('type')==kind else {}
    native.update(type=kind,tag=identifier)
    if kind=='openconnect':
        from openconnect_form import parse_openconnect
        parse_openconnect(form,native,policy)
    elif kind=='selector':
        members=[value.strip() for value in form.get('outbounds','').splitlines() if value.strip()]
        if not members or len(set(members))!=len(members):raise ValueError('Укажите неповторяющийся список выходов')
        if identifier in members or any(tag not in policy['exits'] for tag in members):raise ValueError('Очередь ссылается на себя или неизвестный выход')
        default=form.get('default','')
        if default not in members:raise ValueError('Начальный выход должен входить в очередь')
        native.update(outbounds=members,default=default,interrupt_exist_connections=form.get('interrupt')=='on')
    else:
        interface=form.get('bind_interface','').strip()
        if interface and not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',interface):raise ValueError('Некорректное имя сетевого интерфейса')
        if interface:native['bind_interface']=interface
        else:native.pop('bind_interface',None)
        if kind=='direct' and scope in ('work','special') and not interface:
            raise ValueError('Защищённый прямой выход должен быть привязан к интерфейсу VPN')
        if kind!='direct':
            server=form.get('server','').strip()
            try:server=str(ipaddress.ip_address(server))
            except ValueError:server=normalized_domain(server)
            try:port=int(form.get('server_port',''))
            except ValueError:raise ValueError('Укажите числовой порт сервера')
            if not 1<=port<=65535:raise ValueError('Порт сервера должен быть от 1 до 65535')
            native.update(server=server,server_port=port)
            if kind!='http':
                network=form.get('network','')
                if network not in ('','tcp','udp'):raise ValueError('Неизвестный транспорт сети')
                if network:native['network']=network
                else:native.pop('network',None)
            if kind in ('socks','http'):
                username=form.get('username','').strip()
                if username:native['username']=username
                else:native.pop('username',None)
            if kind in ('socks','http','shadowsocks'):
                if form.get('clear_password')=='on':native.pop('password',None)
                elif form.get('password'):native['password']=form['password']
                if kind=='shadowsocks' and not native.get('password'):raise ValueError('Укажите пароль Shadowsocks')
            if kind=='socks':
                version=form.get('version','5')
                if version not in ('4','4a','5'):raise ValueError('Неизвестная версия SOCKS')
                native['version']=version
            if kind=='shadowsocks':
                method=form.get('method','')
                if method not in SS_METHODS:raise ValueError('Неизвестный метод Shadowsocks')
                native['method']=method
            if kind=='vless':
                user_id=form.get('uuid','').strip() or native.get('uuid','')
                try:native['uuid']=str(uuid.UUID(user_id))
                except ValueError:raise ValueError('Укажите корректный UUID VLESS')
                flow=form.get('flow','')
                if flow not in ('','xtls-rprx-vision'):raise ValueError('Неизвестный VLESS flow')
                if flow:native['flow']=flow
                else:native.pop('flow',None)
            if kind in ('http','vless'):
                if form.get('tls_enabled')=='on':
                    tls=native.setdefault('tls',{});tls['enabled']=True
                    sni=form.get('server_name','').strip()
                    if sni:tls['server_name']=normalized_domain(sni)
                    else:tls.pop('server_name',None)
                else:native.pop('tls',None)
    from tunnel_advanced import parse_advanced
    parse_advanced(form,native)
    # External service labels such as TrustTunnel describe the existing backend,
    # not a new native sing-box protocol. Keep that label for unmodified types.
    protocol=previous.get('protocol',kind) if old.get('type')==kind else kind
    return {**previous,'name':name,'scope':scope,'protocol':protocol,'native':native}
