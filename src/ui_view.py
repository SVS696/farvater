"""Display labels only: never rewrite stored names, addresses, or configuration."""
from datetime import datetime, timezone
import re
SCOPE_LABELS={'public':'Обычный интернет','work':'Рабочие ресурсы','special':'Специальные ресурсы'}
PROTOCOL_LABELS={'direct':'Прямое подключение','selector':'Группа подключений','socks':'SOCKS','http':'HTTP CONNECT','shadowsocks':'Shadowsocks','vless':'VLESS','openconnect':'OpenConnect / Cisco','openvpn-client':'OpenVPN','wireguard':'WireGuard','trusttunnel':'TrustTunnel','amneziawg':'AmneziaWG'}

def protocol_label(value):
    key=value.get('protocol') or value.get('native',{}).get('type','direct')
    return PROTOCOL_LABELS.get(key,key)

def dns_summary(value):
    native=value.get('native',{});kind=native.get('type','')
    if kind=='dhcp':return 'Автоматически по DHCP'
    if kind=='local':return 'DNS операционной системы'
    if kind=='hosts':return 'Локальные записи'
    if kind=='fakeip':return 'Виртуальные IP-адреса'
    if kind=='openvpn':return 'DNS от подключения OpenVPN'
    host=native.get('server')
    if host:
        port=native.get('server_port');host='['+host+']' if ':' in host and not host.startswith('[') else host
        return host+(':'+str(port) if port else '')
    return value.get('address','Адрес не задан')


def accepted_drill(value):
    """Only a complete isolated acceptance record may appear as a passed drill."""
    if not isinstance(value,dict) or value.get('status')!='passed':return False
    if value.get('platform')!='linux-amd64' or value.get('scope')!='isolated-full-systemd':return False
    digest=value.get('evidence_sha256')
    if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):return False
    timestamp=value.get('at')
    if type(timestamp) not in (int,float) or timestamp<=0:return False
    try:datetime.fromtimestamp(timestamp,timezone.utc)
    except (OSError,OverflowError,ValueError):return False
    return True
