"""Typed OpenConnect draft fields; saving never authenticates or starts a VPN."""
import re
import ssl
from native_endpoints import openconnect_host, validate_endpoint
from tunnel_advanced import single, text, set_optional


def parse_openconnect(form, native, policy):
    server = single(form, 'oc_server')
    openconnect_host(server)
    native.update(server=server, system=False)
    native.pop('name', None)
    native['flavor'] = single(form, 'oc_flavor', 20) or 'anyconnect'
    for key in ('username', 'auth_group', 'user_agent', 'reported_os', 'local_hostname'):
        set_optional(native, key, single(form, 'oc_' + key, 512))
    for key in ('password', 'cookie'):
        value = form.get('oc_' + key, '')
        if not isinstance(value, str) or len(value) > 16384 or any(ord(c) < 32 for c in value):
            raise ValueError('Некорректное секретное поле OpenConnect')
        if form.get('clear_oc_' + key) == 'on':
            native.pop(key, None)
        elif value:
            native[key] = value
    for key in ('no_udp', 'ipv6_disabled', 'compression_disabled', 'tcp_keep_alive_enabled'):
        native[key] = form.get('oc_' + key) == 'on'
    for key, low, high in (('mtu', 576, 9000), ('base_mtu', 576, 9000), ('dtls_local_port', 1, 65535)):
        value = single(form, 'oc_' + key, 10)
        if value and (not value.isascii() or not value.isdigit() or not low <= int(value) <= high):
            raise ValueError(f'OpenConnect {key}: допустимо от {low} до {high}, либо пустое поле')
        set_optional(native, key, int(value) if value else None)
    for key in ('dpd_interval', 'reconnect_timeout'):
        value = single(form, 'oc_' + key, 12)
        if value and (not re.fullmatch(r'[1-9][0-9]{0,5}s', value) or int(value[:-1]) > 604800):
            raise ValueError('Интервал OpenConnect: от 1s до 604800s')
        set_optional(native, key, value)
    tls = native.setdefault('tls', {})
    from policy import normalized_domain
    sni = single(form, 'oc_server_name', 253)
    set_optional(tls, 'server_name', normalized_domain(sni) if sni else '')
    tls['insecure'] = form.get('oc_tls_insecure') == 'on'
    certificate = text(form, 'oc_ca', 32768)
    if form.get('clear_oc_ca') == 'on':
        tls.pop('certificate_authority', None)
        tls.pop('certificate_authority_path', None)
    elif certificate:
        if 'PRIVATE KEY' in certificate:
            raise ValueError('В поле CA нужен публичный сертификат')
        try:
            ssl.create_default_context(cadata=certificate)
        except (ssl.SSLError, ValueError):
            raise ValueError('Не удалось прочитать CA OpenConnect в PEM') from None
        tls['certificate_authority'] = certificate
        tls.pop('certificate_authority_path', None)
    resolver = single(form, 'oc_domain_resolver', 120)
    if resolver not in policy.get('dns', {}) or policy['dns'][resolver].get('native', {}).get('type') == 'fakeip':
        raise ValueError('Выберите обычный DNS для подключения к серверу OpenConnect')
    native['domain_resolver'] = resolver
    validate_endpoint(native)
