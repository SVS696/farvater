"""Protocol-specific incoming forms; credentials are generated or preserved server-side."""
import base64
import copy
import secrets
import uuid
from incoming_connections import TYPES, validate


def password(method=''):
    if method.startswith('2022-'):
        return base64.b64encode(secrets.token_bytes(16 if method=='2022-blake3-aes-128-gcm' else 32)).decode()
    return secrets.token_urlsafe(24)


def parse(form, previous=None):
    previous=previous or {};old=previous.get('native',{})
    kind=form.get('type')
    if kind not in TYPES or previous and old.get('type')!=kind:
        raise ValueError('Для другого протокола создайте отдельное подключение')
    if kind=='openconnect-server':
        from ocserv_incoming import parse_form
        return parse_form(form,previous)
    if kind=='amneziawg':
        from amnezia_incoming import parse_form
        return parse_form(form,previous)
    try:port=int(form.get('listen_port',''))
    except ValueError:raise ValueError('Укажите числовой порт') from None
    n={'type':kind,'listen':form.get('listen','').strip(),'listen_port':port}
    result={'id':previous.get('id') or uuid.uuid4().hex,'name':form.get('name','').strip(),
            'enabled':form.get('enabled')=='on','local_host':form.get('local_host','').strip(),
            'external_host':form.get('external_host','').strip(),'native':n}
    if kind=='shadowsocks':
        n['method']=form.get('method','')
        same=old.get('method')==n['method']
        n['password']=form.get('server_password') or (old.get('password') if same else None) or password(n['method'])
        if form.get('network'):n['network']=form['network']
    originals=form.getlist('client_original');names=form.getlist('client_name');credentials=form.getlist('client_secret');flows=form.getlist('client_flow')
    if not len(originals)==len(names)==len(credentials)==len(flows) or len(names)>64:
        raise ValueError('Некорректный список клиентов')
    user_field='username' if kind in ('socks','http','openvpn-server') else 'name'
    old_users={u[user_field]:u for u in old.get('users',[])};users=[];seen=set()
    for original,name,secret,flow in zip(originals,names,credentials,flows):
        if original and (original not in old_users or original in seen):raise ValueError('Исходный клиент изменился')
        seen.add(original)
        before=old_users.get(original,{})
        field='uuid' if kind=='vless' else 'password'
        value=secret or before.get(field) or (str(uuid.uuid4()) if kind=='vless' else password(n.get('method','')))
        user={user_field:name.strip(),field:value}
        if kind=='vless' and flow:user['flow']=flow
        users.append(user)
    if users or kind!='shadowsocks':n['users']=users
    disabled=form.getlist('disabled_client')
    if any(v not in old_users for v in disabled):raise ValueError('Отключаемый клиент не найден')
    result['disabled_clients']=[name.strip() for original,name in zip(originals,names) if original in disabled]
    if kind in ('http','vless') and form.get('tls_enabled')=='on':
        cert=form.get('certificate','').strip();key=form.get('private_key','').strip()
        n['tls']={**copy.deepcopy(old.get('tls',{})), 'enabled':True,'certificate':cert.splitlines() if cert else copy.deepcopy(old.get('tls',{}).get('certificate',[])),
                  'key':key.splitlines() if key else copy.deepcopy(old.get('tls',{}).get('key',[]))}
        n['tls'].pop('server_name',None);n['tls'].pop('alpn',None)
        if form.get('server_name'):n['tls']['server_name']=form['server_name'].strip()
        if form.get('alpn'):n['tls']['alpn']=[v.strip() for v in form['alpn'].splitlines() if v.strip()]
    if kind=='vless' and form.get('transport'):
        transport=form['transport'];previous_transport=old.get('transport',{})
        n['transport']=copy.deepcopy(previous_transport) if previous_transport.get('type')==transport else {'type':transport}
        if transport=='grpc':n['transport']['service_name']=form.get('service_name','')
        else:
            n['transport']['path']=form.get('transport_path','/')
            hostname=form.get('transport_host','').strip()
            if transport in ('http','httpupgrade'):n['transport'].pop('host',None)
            elif 'headers' in n['transport']:n['transport']['headers'].pop('Host',None)
            if hostname:
                if transport=='http':n['transport']['host']=[v.strip() for v in hostname.splitlines() if v.strip()]
                elif transport=='httpupgrade':n['transport']['host']=hostname
                else:n['transport'].setdefault('headers',{})['Host']=hostname
    if kind=='openvpn-server':
        cert=form.get('certificate','').strip();key=form.get('private_key','').strip()
        n.update(system=False,mode='tls',topology='subnet',network=form.get('network','udp'),
                 address=[v.strip() for v in form.get('address','').splitlines() if v.strip()],
                 duplicate_cn=form.get('duplicate_cn')=='on')
        n['tls']={**copy.deepcopy(old.get('tls',{})),
                  'certificate':cert.splitlines() if cert else copy.deepcopy(old.get('tls',{}).get('certificate',[])),
                  'key':key.splitlines() if key else copy.deepcopy(old.get('tls',{}).get('key',[])),
                  'verify_client_certificate':'none'}
        if 'control_wrap' in form:
            from openvpn_incoming import control_key
            mode=form.get('control_wrap','')
            previous_wrap=old.get('tls',{}).get('control_wrap',{})
            n['tls'].pop('control_wrap',None)
            if mode:
                supplied=form.get('control_key','').strip()
                n['tls']['control_wrap']={'type':mode,'key':supplied.splitlines() if supplied else copy.deepcopy(previous_wrap.get('key')) or control_key()}
                if mode=='tls_auth' and form.get('control_direction','server'):
                    n['tls']['control_wrap']['direction']=form.get('control_direction','server')
        for field in ('mtu','max_clients'):
            if form.get(field):
                try:n[field]=int(form[field])
                except ValueError:raise ValueError('Укажите целое число: '+field) from None
        for field in ('ping_interval','ping_restart','handshake_window','renegotiate_interval'):
            if form.get(field):n[field]=form[field].strip()+'s'
        if form.get('auth'):n['auth']=form['auth']
        if form.get('data_ciphers'):n['data_ciphers']=[v.strip() for v in form['data_ciphers'].splitlines() if v.strip()]
        n['push']={field:form.get(field)=='on' for field in ('redirect_gateway','block_outside_dns')}
        for field in ('routes','dns','search_domains'):
            if form.get(field):n['push'][field]=[v.strip() for v in form[field].splitlines() if v.strip()]
    if n.get('tls'):
        for field in ('version_min','version_max') if kind=='openvpn-server' else ('min_version','max_version'):
            if field in form:
                n['tls'].pop(field,None)
                if form[field]:n['tls'][field]=form[field]
    validate([result]);return result
