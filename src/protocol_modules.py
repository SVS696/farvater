"""Protocol modules share one catalog for incoming and outgoing connections.

An engine is an implementation dependency, not a separate management product.
Only the selected module may require its optional engine at installation time.
"""
MODULES = {
    'wireguard': {'name': 'WireGuard', 'engine': 'wireguard', 'incoming': True, 'outgoing': True},
    'amnezia': {'name': 'AmneziaWG', 'engine': 'amneziawg', 'incoming': True, 'outgoing': True},
    'openvpn': {'name': 'OpenVPN', 'engine': 'sing-box', 'incoming': True, 'outgoing': True},
    'openconnect': {'name': 'OpenConnect / Cisco', 'engine': 'ocserv', 'outgoing_engine': 'sing-box', 'incoming': True, 'outgoing': True},
    'trusttunnel': {'name': 'TrustTunnel', 'engine': 'trusttunnel', 'incoming': True, 'outgoing': True},
    'vless': {'name': 'VLESS', 'engine': 'sing-box', 'incoming': True, 'outgoing': True},
    'shadowsocks': {'name': 'Shadowsocks', 'engine': 'sing-box', 'incoming': True, 'outgoing': True},
    'socks': {'name': 'SOCKS', 'engine': 'sing-box', 'incoming': True, 'outgoing': True},
    'http': {'name': 'HTTP CONNECT', 'engine': 'sing-box', 'incoming': True, 'outgoing': True},
}


def choices(direction):
    if direction not in ('incoming', 'outgoing'):
        raise ValueError('Неизвестное направление подключения')
    return [(key, value['name']) for key, value in MODULES.items() if value[direction]]


def engines(selected, direction):
    """Resolve only explicitly selected modules, without installing anything."""
    if direction not in ('incoming', 'outgoing') or not isinstance(selected, list):
        raise ValueError('Укажите список модулей и направление')
    result = set()
    for key in selected:
        if key not in MODULES or not MODULES[key][direction]:
            raise ValueError('Неизвестный модуль протокола')
        module = MODULES[key]
        result.add(module.get(direction + '_engine', module['engine']))
    return sorted(result)
