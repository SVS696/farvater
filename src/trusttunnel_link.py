"""Bounded adapter around TrustTunnel's pinned v1.0.33 native link codec.

Vendored encode/decode modules are unchanged upstream scripts; see THIRD_PARTY.md.
The upstream TOML string writer is deliberately not used: json quoting preserves
quotes and backslashes in credentials safely in TOML basic strings.
"""
import base64
import json
import re
from trusttunnel_deeplink_decode import parse_tlv, decode_varint, decode_config
from trusttunnel_deeplink_encode import config_to_deeplink


def endpoint_values(values):
    from trusttunnel_profile import ENDPOINT, text
    if not isinstance(values, dict) or not values or set(values) - set(ENDPOINT) - {'name', 'client_random_prefix'}:
        raise ValueError('Endpoint содержит неизвестные поля; параметры не были отброшены')
    values = dict(values)
    if 'name' in values:
        # Endpoint display name is presentation metadata. The panel has an
        # explicit connection-name field, explained alongside both import forms.
        text(values.pop('name'), 512, 'Название в файле')
    if 'client_random_prefix' in values:
        prefix = values.pop('client_random_prefix')
        if 'client_random' in values and values['client_random'] != prefix:
            raise ValueError('В файле заданы разные client_random и client_random_prefix')
        values['client_random'] = prefix
    return values


def decode(uri):
    from trusttunnel_profile import MAX_BYTES
    if not isinstance(uri, str) or len(uri.encode()) > MAX_BYTES:
        raise ValueError('Ссылка TrustTunnel превышает 128 КиБ')
    uri = uri.strip()
    match = re.fullmatch(r'tt://\??([A-Za-z0-9_-]+={0,2})', uri)
    if not match:
        raise ValueError('Нужна стандартная ссылка tt://? без постороннего текста')
    try:
        encoded = match[1]
        data = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        entries = parse_tlv(data); seen = set()
        for tag, value in entries:
            if tag not in range(14) or tag in seen and tag != 2:
                raise ValueError('unknown or duplicate field')
            seen.add(tag)
            if tag == 0:
                version, end = decode_varint(value, 0)
                if version != 1 or end != len(value): raise ValueError('version')
            if tag in (4, 7, 10) and value not in (b'\x00', b'\x01'): raise ValueError('boolean')
            if tag == 9 and value not in (b'\x01', b'\x02'): raise ValueError('protocol')
        if not {0, 1, 2, 5, 6} <= seen: raise ValueError('missing fields')
        return endpoint_values(decode_config(data))
    except (ValueError, UnicodeError, IndexError, KeyError):
        raise ValueError('Некорректная или неподдерживаемая ссылка TrustTunnel; параметры не изменены') from None


def native_values(model):
    from trusttunnel_profile import validate, ENDPOINT
    checked = validate(model, ready=True)
    result = {k: checked[k] for k in ENDPOINT}
    result['client_random_prefix'] = result.pop('client_random')
    return result


def export(model, kind):
    values = native_values(model)
    if kind == 'deeplink': return config_to_deeplink(values) + '\n'
    if kind == 'endpoint': return '\n'.join(k + ' = ' + json.dumps(v, ensure_ascii=False) for k, v in values.items()) + '\n'
    raise ValueError('Выберите endpoint TOML или ссылку TrustTunnel')
