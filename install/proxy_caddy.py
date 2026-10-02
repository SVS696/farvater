"""Build the existing HTTPS ingress with an independent recovery access gate.

The production transform preserves the existing listener and network restrictions.
It rejects an unfamiliar configuration instead of guessing its routing structure.
"""
import argparse
import ipaddress
from pathlib import Path
import re

TLS_ROOT = '/var/lib/okopy-recovery-ui/tls'
MAIN = 'reverse_proxy unix//var/www/certbot/.okopy-panel/panel.sock'
RECOVERY_ROUTE = '''route {
            handle /recovery/* {
                reverse_proxy unix//var/www/certbot/.farvater-recovery/recovery.sock
            }
            handle {
                forward_auth unix//var/www/certbot/.farvater-recovery/recovery.sock {
                    uri /recovery/access-check
                }
                reverse_proxy unix//var/www/certbot/.okopy-panel/panel.sock
            }
        }'''


def protect_existing(text):
    if text.count(MAIN) != 1 or 'forward_auth' in text or '/recovery/' in text:
        raise ValueError('The expected single main upstream was not found')
    tls = re.findall(r'^\s*tls (/etc/letsencrypt/live/[^\s]+/fullchain.pem) (/etc/letsencrypt/live/[^\s]+/privkey.pem)$', text, re.M)
    if len(tls) != 1 or Path(tls[0][0]).parent != Path(tls[0][1]).parent:
        raise ValueError('The expected certbot certificate pair was not found')
    # This operation changes two exact directives; CIDRs, binds, legacy redirect,
    # protocols and the admin socket keep their original bytes.
    return text.replace(MAIN, RECOVERY_ROUTE).replace(
        f'tls {tls[0][0]} {tls[0][1]}',
        f'tls {TLS_ROOT}/current/chain.pem {TLS_ROOT}/current/key.pem'), tls[0]


def render(host, port, networks):
    if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
        raise ValueError('Use a plain HTTPS hostname')
    if isinstance(port, bool) or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid existing HTTPS port')
    if not networks:
        raise ValueError('At least one owner network is required')
    cidrs = ' '.join(str(ipaddress.ip_network(n, strict=False)) for n in networks)
    return f'''{{
    auto_https off
    admin off
}}

https://{host}:{int(port)} {{
    tls {TLS_ROOT}/current/chain.pem {TLS_ROOT}/current/key.pem
    @owner_network remote_ip {cidrs}
    handle @owner_network {{
        {RECOVERY_ROUTE}
    }}
    handle {{
        respond "Access requires home LAN or an authorized VPN." 403
    }}
}}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--owner-network', action='append', required=True)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    with args.destination.open('x') as stream:
        stream.write(render(args.host, args.port, args.owner_network))


if __name__ == '__main__':
    main()
