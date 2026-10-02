"""Fixed public section digests for draft-versus-applied policy display."""

import hashlib
import json


SECTION_FIELDS = {
    'rules': ('profiles',),
    'routes': ('default_exit', 'default_dns', 'failover', 'health_probes'),
    'connections': ('exits',),
    'dns': ('dns',),
    'filtering': ('filtering',),
    'lan': ('lan_ingress',),
    'wireguard_ingress': ('vpn_ingress',),
    'incoming': ('incoming_connections',),
}
SECTION_LABELS = {
    'rules': 'Правила',
    'routes': 'Основной маршрут и резервы',
    'connections': 'Подключения',
    'dns': 'DNS-профили',
    'filtering': 'Фильтрация',
    'lan': 'LAN-вход',
    'wireguard_ingress': 'Вход из WireGuard',
    'incoming': 'Входящие VPN',
    'other': 'Другие настройки',
}


def section_hashes(policy):
    """Return only digests; never expose policy values to a status caller."""
    known = {field for fields in SECTION_FIELDS.values() for field in fields}
    sections = {name: {field: policy[field] for field in fields if field in policy}
                for name, fields in SECTION_FIELDS.items()}
    sections['other'] = {key: value for key, value in policy.items() if key not in known}
    return {name: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                         ensure_ascii=False).encode()).hexdigest()
            for name, value in sections.items()}


def changed_section_labels(draft_hashes, applied_hashes):
    if not isinstance(applied_hashes, dict) or set(applied_hashes) != set(SECTION_LABELS):
        return None
    if any(not isinstance(value, str) or len(value) != 64 or
           any(char not in '0123456789abcdef' for char in value)
           for value in applied_hashes.values()):
        return None
    return [label for name, label in SECTION_LABELS.items()
            if draft_hashes[name] != applied_hashes[name]]
