"""Endpoint placement and host-route guard for the pinned sing-box runtime."""
from urllib.parse import urlsplit
import ipaddress


ENDPOINT_TYPES = {'openconnect', 'openvpn-client'}


def openconnect_host(server):
    if not isinstance(server, str) or not server or len(server) > 2048:
        raise ValueError('Укажите HTTPS-адрес сервера OpenConnect')
    try:
        url = urlsplit(server if '://' in server else 'https://' + server)
        port = url.port
        if (url.scheme != 'https' or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment
                or '?' in server or '#' in server or '\\' in server
                or any(c.isspace() or ord(c) < 32 for c in server)
                or port is not None and not 1 <= port <= 65535):
            raise ValueError()
        try:
            return str(ipaddress.ip_address(url.hostname))
        except ValueError:
            from policy import normalized_domain
            return normalized_domain(url.hostname)
    except ValueError:
        raise ValueError('OpenConnect: нужен HTTPS-адрес без логина, query (?...) и фрагмента (#...)') from None


def validate_endpoint(native):
    if native.get('type') not in ENDPOINT_TYPES:
        return
    if native.get('type') == 'openvpn-client':
        from openvpn_profile import validate
        validate(native, ready=True)
        return
    openconnect_host(native.get('server'))
    if native.get('system', False) is not False or native.get('name'):
        raise ValueError('OpenConnect в общем ядре использует внутренний сетевой стек без системного интерфейса')
    if native.get('flavor', 'anyconnect') not in ('anyconnect', 'gp', 'fortinet', 'f5', 'pulse', 'nc'):
        raise ValueError('Неизвестный протокол OpenConnect')
    # Imported profiles must not turn a network editor into a root command runner.
    for key in ('csd', 'hip', 'tncc'):
        value = native.get(key, {})
        if not isinstance(value, dict) or value.get('wrapper_path'):
            raise ValueError('Внешние исполняемые обработчики OpenConnect не поддерживаются панелью')


def split_endpoints(entries):
    for native in entries:
        validate_endpoint(native)
    return ([entry for entry in entries if entry['type'] not in ENDPOINT_TYPES],
            [entry for entry in entries if entry['type'] in ENDPOINT_TYPES])


def validate_bootstrap(policy):
    """A VPN cannot obtain its own server address through the same VPN."""
    dns = policy.get('dns', {})
    exits = policy.get('exits', {})
    for tag, entry in exits.items():
        native = entry.get('native', {})
        if native.get('type') not in ENDPOINT_TYPES:
            continue
        resolver = native.get('domain_resolver')
        if isinstance(resolver, dict):
            resolver = resolver.get('server')
        pending = [('dns', resolver)] if resolver else []
        seen = set()
        while pending:
            kind, name = pending.pop()
            if kind == 'exit' and name == tag:
                raise ValueError('DNS адреса VPN зависит от этого же VPN: ' + tag)
            if (kind, name) in seen:
                continue
            seen.add((kind, name))
            item = (dns if kind == 'dns' else exits).get(name, {}).get('native', {})
            if kind == 'dns' and item.get('type') == 'fakeip':
                raise ValueError('FakeIP нельзя использовать для адреса VPN')
            boot = item.get('domain_resolver')
            if isinstance(boot, dict):
                boot = boot.get('server')
            if boot:
                pending.append(('dns', boot))
            if item.get('detour'):
                pending.append(('exit', item['detour']))
            if kind == 'dns' and item.get('type') in ('openvpn', 'openconnect') and item.get('endpoint'):
                pending.append(('exit', item['endpoint']))
            pending.extend(('exit', child) for child in item.get('outbounds', []))
