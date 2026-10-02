#!/usr/bin/python3
"""Experimental administrative IPv4 macOS VPN gateway; stdlib, Python 3.9+."""
import argparse
import base64
import binascii
import fcntl
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path('/Library/Application Support/Farvater/Gateway')
PLIST = Path('/Library/LaunchDaemons/app.farvater.gateway-watchdog.plist')
LABEL = 'app.farvater.gateway-watchdog'
CORE_LABEL = 'app.farvater.gateway-core'
ANCHOR = 'com.apple/farvater'
VERSION = '1.14.1'
ARCHIVES = {
    'arm64': 'b9024642ef7b4848252df5469b7f60ef3c18bb5e217a16a0934f0174f8ad11b4',
    'x86_64': 'b34381b047106fe84895df14f7aaae06f3182130b728006944deb0d59d8590c3',
}
PRIVATE = [ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]


class GatewayError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def protected(path, directory=False):
    """Reject symlinks and writable/non-root ancestors, including final path."""
    path = Path(path).absolute()
    for item in list(reversed(path.parents)) + [path]:
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise GatewayError('Protected path or ancestor is not root-owned and immutable to users')
    if directory and not path.is_dir():
        raise GatewayError('Protected directory required')
    if not directory and not path.is_file():
        raise GatewayError('Protected regular file required')
    return path


def read_json(path, trusted=False):
    if trusted:
        protected(path)
    if Path(path).is_symlink() or Path(path).stat().st_size > 65536:
        raise GatewayError('Invalid input file')
    try:
        return json.loads(Path(path).read_text())
    except (ValueError, UnicodeError):
        raise GatewayError('Invalid JSON') from None


def atomic(path, data, mode=0o600):
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(str(temporary), str(path))
        fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def save(path, value):
    atomic(path, (json.dumps(value, sort_keys=True) + '\n').encode())


def network(value):
    try:
        return ipaddress.IPv4Network(value, strict=True)
    except (ValueError, TypeError):
        raise GatewayError('Canonical IPv4 CIDR required') from None


def settings(value):
    keys = {'lan_interface', 'upstream_interface', 'lan_cidr', 'lan_address',
            'management_cidrs', 'upstream', 'dns_server', 'tun_interface', 'tun_address', 'system_dns_service'}
    if not isinstance(value, dict) or set(value) != keys:
        raise GatewayError('Gateway settings contain missing or unknown fields')
    for name in ('lan_interface', 'upstream_interface'):
        if not isinstance(value[name], str) or not re.fullmatch(r'en[0-9]{1,3}', value[name]):
            raise GatewayError('Physical enN interface required')
    if value['lan_interface'] == value['upstream_interface']:
        raise GatewayError('Separate LAN and upstream interfaces required')
    if not isinstance(value['system_dns_service'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}', value['system_dns_service']):
        raise GatewayError('Explicit native upstream network service required')
    lan = network(value['lan_cidr'])
    if not any(lan.subnet_of(n) for n in PRIVATE) or lan.prefixlen > 29:
        raise GatewayError('Dedicated RFC1918 client LAN /29 or larger required')
    address = ipaddress.IPv4Address(value['lan_address'])
    if address not in lan or address in (lan.network_address, lan.broadcast_address):
        raise GatewayError('LAN gateway address must be in the client LAN')
    if not isinstance(value['management_cidrs'], list) or not 1 <= len(value['management_cidrs']) <= 8:
        raise GatewayError('Explicit management exclusions required')
    for cidr in value['management_cidrs']:
        n = network(cidr)
        if (not any(n.subnet_of(private) for private in PRIVATE) and n.prefixlen != 32) or n.overlaps(network('198.18.0.0/15')):
            raise GatewayError('Management exclusion too broad or overlaps TUN space')
    if not re.fullmatch(r'utun[0-9]{1,3}', str(value['tun_interface'])):
        raise GatewayError('Explicit free utun interface required')
    tun = ipaddress.IPv4Interface(value['tun_address'])
    if tun.network.prefixlen != 30 or not tun.network.subnet_of(network('198.18.0.0/15')):
        raise GatewayError('TUN requires an unused benchmark /30')
    if tun.ip != tun.network.network_address + 1:
        raise GatewayError('TUN address must be the first host')
    upstream = value['upstream']
    if not isinstance(upstream, dict) or set(upstream) != {'type', 'method', 'server', 'server_port', 'password'}:
        raise GatewayError('Only bounded encrypted Shadowsocks upstream fields accepted')
    server = ipaddress.IPv4Address(upstream['server'])
    if server in lan or server.is_loopback or server.is_link_local or server.is_multicast or server.is_unspecified or server in network('198.18.0.0/15'):
        raise GatewayError('Upstream must be numeric unicast IPv4 outside the client LAN')
    if type(upstream['server_port']) is not int or not 1 <= upstream['server_port'] <= 65535:
        raise GatewayError('Invalid upstream port')
    if upstream['type'] != 'shadowsocks' or upstream['method'] != '2022-blake3-aes-128-gcm':
        raise GatewayError('Pinned full gateway requires Shadowsocks 2022 AES-128')
    try:
        if len(base64.b64decode(upstream['password'], validate=True)) != 16:
            raise ValueError()
    except (ValueError, TypeError, binascii.Error):
        raise GatewayError('Shadowsocks 2022 needs one base64 16-byte secret') from None
    dns = ipaddress.IPv4Address(value['dns_server'])
    if not dns.is_global:
        raise GatewayError('Numeric global DNS IPv4 required')
    return value


def exclusions(value):
    return list(ipaddress.collapse_addresses([network(x) for x in value['management_cidrs']] +
        [network(value['lan_cidr']), network(value['upstream']['server'] + '/32'),
         network('127.0.0.0/8'), network('0.0.0.0/8'), network('224.0.0.0/3'), network('198.18.0.0/15')]))


def route_ranges(value):
    """Compute exact owned destinations; no default or pre-existing route replacement."""
    ranges = [network('0.0.0.0/0')]
    for exclude in exclusions(value):
        updated = []
        for item in ranges:
            if item.subnet_of(exclude):
                continue
            updated.extend(item.address_exclude(exclude) if exclude.subnet_of(item) else [item])
        ranges = updated
    return sorted(ranges, key=lambda n: (int(n.network_address), n.prefixlen))


def config(value):
    settings(value)
    upstream = dict(value['upstream'])
    upstream.update(tag='upstream', bind_interface=value['upstream_interface'])
    return {'log': {'level': 'warn'},
        'inbounds': [
            {'type': 'tun', 'tag': 'gateway', 'interface_name': value['tun_interface'],
             'address': [value['tun_address']], 'auto_route': False, 'stack': 'gvisor',
             'route_exclude_address': [str(n) for n in exclusions(value)]},
            {'type': 'direct', 'tag': 'lan-dns', 'listen': value['lan_address'], 'listen_port': 53},
            {'type': 'direct', 'tag': 'host-dns', 'listen': '127.0.0.1', 'listen_port': 53}],
        'outbounds': [upstream],
        'dns': {'servers': [{'type': 'tcp', 'tag': 'resolver', 'server': value['dns_server'],
                             'detour': 'upstream'}], 'final': 'resolver', 'strategy': 'ipv4_only'},
        'route': {'rules': [{'inbound': ['lan-dns', 'host-dns'], 'action': 'hijack-dns'},
                            {'port': 53, 'action': 'hijack-dns'}],
                  'final': 'upstream', 'default_interface': value['upstream_interface']}}


def pf_rules(value):
    lan, wan = value['lan_interface'], value['upstream_interface']
    # Fail closed before forwarding; core uses a local WAN source outside the client LAN.
    lines = ['block drop in quick on %s inet6 all' % lan,
             'block drop out quick inet6 all',
             'block drop out quick on %s inet from %s to any' % (wan, value['lan_cidr'])]
    lines.append('pass out quick on %s inet proto { tcp udp } to %s port %s keep state' %
                 (wan, value['upstream']['server'], value['upstream']['server_port']))
    for cidr in value['management_cidrs']:
        lines.append('pass out quick on %s inet to %s keep state' % (wan, cidr))
    lines.append('pass out quick on %s inet to %s keep state' % (lan, value['lan_cidr']))
    lines.append('pass out quick on %s inet all keep state' % value['tun_interface'])
    lines.append('pass out quick on lo0 all')
    lines.append('block drop out quick all')
    return ('\n'.join(lines) + '\n').encode()


class System:
    def run(self, args, check=True):
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}, timeout=15)
        if check and result.returncode:
            # Command diagnostics may contain secrets from config: never echo them.
            raise GatewayError('System operation failed: ' + Path(args[0]).name)
        return result.stdout.decode(errors='replace')

    def boot(self):
        return self.run(['/usr/sbin/sysctl', '-n', 'kern.boottime']).strip()

    def routes(self):
        output = self.run(['/usr/sbin/netstat', '-rn', '-f', 'inet'])
        rows = []
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 4 and re.match(r'^(default|[0-9])', fields[0]):
                destination = fields[0]
                if destination == 'default':
                    destination = '0.0.0.0/0'
                else:
                    parts = destination.split('/')
                    octets = parts[0].split('.')
                    destination = '.'.join(octets + ['0'] * (4 - len(octets))) + '/' + (parts[1] if len(parts) == 2 else str(8 * len(octets)))
                rows.append({'destination': str(network(destination)), 'gateway': fields[1],
                             'interface': fields[3], 'flags': fields[2]})
        if not any(r['destination'] == '0.0.0.0/0' for r in rows):
            raise GatewayError('Could not parse the current route table')
        return rows

    def identity(self, pid):
        if type(pid) is not int or pid <= 1:
            return None
        # lsof supplies the actual executable vnode path; ps supplies owner and birth identity.
        ps = self.run(['/bin/ps', '-p', str(pid), '-o', 'uid=', '-o', 'lstart='], check=False).strip()
        exe = self.run(['/usr/sbin/lsof', '-a', '-p', str(pid), '-d', 'txt', '-Fn'], check=False)
        paths = [line[1:] for line in exe.splitlines() if line.startswith('n')]
        if not ps or not paths:
            return None
        executable = str(ROOT / 'sing-box') if str(ROOT / 'sing-box') in paths else paths[0]
        return {'pid': pid, 'birth': ps, 'executable': executable}

    def core_pid(self):
        output = self.run(['/bin/launchctl', 'print', 'system/' + CORE_LABEL], check=False)
        match = re.search(r'^\s*pid = ([0-9]+)$', output, re.MULTILINE)
        return int(match.group(1)) if match else None

    def start(self):
        self.run(['/bin/launchctl', 'bootstrap', 'system', str(ROOT / 'core.plist')])
        for _ in range(30):
            identity = self.identity(self.core_pid())
            if identity and identity['executable'] == str(ROOT / 'sing-box') and identity['birth'].startswith('0 '):
                return identity
            time.sleep(0.1)
        raise GatewayError('Core startup identity unavailable')

    def stop(self):
        # The fixed root-owned job is an independent launchd ownership boundary.
        verify_core_job()
        self.run(['/bin/launchctl', 'bootout', 'system/' + CORE_LABEL])

    def enable_pf(self):
        # Kernel enable output is journaled directly, recoverable after caller death.
        fd = os.open(str(ROOT / 'pf-enable.log'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as output:
                result = subprocess.run(['/sbin/pfctl', '-E'], stdin=subprocess.DEVNULL,
                    stdout=output, stderr=output, timeout=15,
                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
                output.flush()
                os.fsync(output.fileno())
                if result.returncode:
                    raise GatewayError('PF enable failed')
        finally:
            pass
        return (ROOT / 'pf-enable.log').read_text()


def preflight(value, system):
    settings(value)
    lan = system.run(['/sbin/ifconfig', value['lan_interface']])
    wan = system.run(['/sbin/ifconfig', value['upstream_interface']])
    for text in (lan, wan):
        if 'status: active' not in text or 'UP' not in text:
            raise GatewayError('Both physical interfaces must be up and active')
    if 'inet6 ' in lan:
        raise GatewayError('Disable IPv6 on the dedicated client LAN before apply')
    if not re.search(r'\binet ' + re.escape(value['lan_address']) + r'\b', lan):
        raise GatewayError('Selected LAN address is not assigned to the LAN interface')
    expected_mask = '0x%08x' % int(network(value['lan_cidr']).netmask)
    if not re.search(r'\binet ' + re.escape(value['lan_address']) + r'\s+netmask ' + expected_mask + r'\b', lan):
        raise GatewayError('LAN interface netmask must match the explicit client CIDR')
    wan_addresses = re.findall(r'\binet ([0-9.]+)', wan)
    if not wan_addresses:
        raise GatewayError('Upstream IPv4 address required')
    for found in wan_addresses:
        if ipaddress.IPv4Address(found) in network(value['lan_cidr']):
            raise GatewayError('Upstream source overlaps client LAN')
    existing = system.run(['/sbin/ifconfig', '-l']).split()
    if value['tun_interface'] in existing:
        raise GatewayError('Selected TUN interface already exists')
    routes = system.routes()
    if not any(r['destination'] == '0.0.0.0/0' and r['interface'] == value['upstream_interface'] for r in routes):
        raise GatewayError('Default upstream does not match the selected physical interface')
    planned = route_ranges(value)
    tun = ipaddress.IPv4Interface(value['tun_address']).network
    for row in routes:
        n = network(row['destination'])
        if any(n.subnet_of(prefix) for prefix in planned) or (n.prefixlen > 0 and n.overlaps(tun)):
            raise GatewayError('TUN route collision; existing routes are never replaced')
    rules = system.run(['/sbin/pfctl', '-sr'])
    active_rules = [line.strip() for line in rules.splitlines() if line.startswith(('pass ', 'block ', 'anchor '))]
    if not active_rules or not re.match(r'anchor "com.apple/\*"(?: all)?$', active_rules[0]):
        raise GatewayError('First active main PF rule must reference com.apple/* anchor')
    anchor = system.run(['/sbin/pfctl', '-a', ANCHOR, '-sr']).strip()
    if any(line.startswith(('pass ', 'block ', 'anchor ')) for line in anchor.splitlines()):
        raise GatewayError('Gateway PF anchor is already in use')
    siblings = system.run(['/sbin/pfctl', '-a', 'com.apple', '-s', 'Anchors']).splitlines()
    for sibling in siblings:
        name = sibling.strip()
        if name and name not in ('farvater', ANCHOR):
            if not re.fullmatch(r'[A-Za-z0-9._/-]+', name):
                raise GatewayError('Unrecognized PF child anchor')
            child = name if name.startswith('com.apple/') else 'com.apple/' + name
            if system.run(['/sbin/pfctl', '-a', child, '-sr']).strip():
                raise GatewayError('Other Apple PF anchors prevent verified fail-closed activation')
    states = system.run(['/sbin/pfctl', '-ss']).strip()
    if states:
        raise GatewayError('Existing PF states prevent verified fail-closed activation; use an isolated gateway')
    forwarding = system.run(['/usr/sbin/sysctl', '-n', 'net.inet.ip.forwarding']).strip()
    if forwarding != '0':
        raise GatewayError('Existing forwarding service must not be replaced')
    order = system.run(['/usr/sbin/networksetup', '-listnetworkserviceorder'])
    service = re.escape(value['system_dns_service'])
    if not re.search(r'\([0-9]+\) ' + service + r'\n\([^\n]*Device: ' + re.escape(value['upstream_interface']) + r'\)', order):
        raise GatewayError('Selected system DNS service must use the selected upstream interface')
    dns_text = system.run(['/usr/sbin/networksetup', '-getdnsservers', value['system_dns_service']]).strip()
    if dns_text.startswith("There aren't any DNS Servers set"):
        dns_servers = []
    else:
        dns_servers = dns_text.splitlines()
        if not dns_servers or len(dns_servers) > 16:
            raise GatewayError('Cannot snapshot native DNS')
        for address in dns_servers:
            ipaddress.ip_address(address)
    return {'routes': routes, 'forwarding': forwarding, 'anchor': anchor, 'system_dns': dns_servers,
            'main_rules': rules, 'pf_info': system.run(['/sbin/pfctl', '-s', 'info']), 'boot': system.boot()}


def receipt():
    value = read_json(ROOT / 'receipt.json', trusted=True)
    required = {'version', 'phase', 'boot', 'deadline', 'settings', 'original', 'core_sha256',
                'process', 'pf_token', 'routes_added', 'route_intent', 'forwarding_intent', 'pf_intent', 'core_intent', 'dns_intent'}
    if (not isinstance(value, dict) or set(value) != required or value['version'] != 1 or
            value['phase'] not in ('prepared', 'pending', 'confirmed', 'rolling-back', 'rolled-back')):
        raise GatewayError('Corrupt receipt; no network mutation permitted')
    settings(value['settings'])
    if (type(value['deadline']) not in (int, float) or not isinstance(value['boot'], str) or
        not re.fullmatch('[0-9a-f]{64}', str(value['core_sha256'])) or
        value['pf_token'] is not None and not re.fullmatch('[0-9]+', str(value['pf_token']))):
        raise GatewayError('Corrupt receipt')
    planned = {str(n) for n in route_ranges(value['settings'])}
    if not isinstance(value['routes_added'], list) or not set(value['routes_added']).issubset(planned):
        raise GatewayError('Corrupt route ownership receipt')
    if value['route_intent'] is not None and value['route_intent'] not in planned:
        raise GatewayError('Corrupt route intent')
    for key in ('forwarding_intent', 'pf_intent', 'core_intent', 'dns_intent'):
        if type(value[key]) is not bool:
            raise GatewayError('Corrupt mutation intent')
    original = value['original']
    if not isinstance(original, dict) or original.get('forwarding') != '0' or not isinstance(original.get('routes'), list):
        raise GatewayError('Corrupt original state')
    if not isinstance(original.get('system_dns'), list) or len(original['system_dns']) > 16:
        raise GatewayError('Corrupt original DNS state')
    for address in original['system_dns']:
        ipaddress.ip_address(address)
    process = value['process']
    if process is not None and (not isinstance(process, dict) or set(process) != {'pid', 'birth', 'executable'} or
            type(process['pid']) is not int or process['pid'] <= 1 or process['executable'] != str(ROOT / 'sing-box') or
            not isinstance(process['birth'], str)):
        raise GatewayError('Corrupt process ownership receipt')
    return value


def write_receipt(value):
    save(ROOT / 'receipt.json', value)


def verify_runtime():
    protected(ROOT, True)
    if ROOT.stat().st_mode & 0o077:
        raise GatewayError('Gateway runtime must be private root0700')
    for name in ('mac_gateway.py', 'sing-box', 'manifest.json'):
        protected(ROOT / name)
    manifest = read_json(ROOT / 'manifest.json', trusted=True)
    if manifest.get('version') != VERSION or manifest.get('archive_sha256') != ARCHIVES.get(platform.machine()) or manifest.get('core_sha256') != digest((ROOT / 'sing-box').read_bytes()):
        raise GatewayError('Protected core provenance changed')


def core_job():
    return {'Label': CORE_LABEL,
            'ProgramArguments': [str(ROOT / 'sing-box'), 'run', '-c', str(ROOT / 'config.json')],
            'RunAtLoad': True, 'UserName': 'root',
            'StandardErrorPath': str(ROOT / 'core.log'), 'StandardOutPath': str(ROOT / 'core.log'),
            'WorkingDirectory': str(ROOT)}


def verify_core_job():
    protected(ROOT / 'core.plist')
    if plistlib.loads((ROOT / 'core.plist').read_bytes()) != core_job():
        raise GatewayError('Protected core job changed')


def register_watchdog(system):
    protected(PLIST)
    if plistlib.loads(PLIST.read_bytes()) != watchdog_job():
        raise GatewayError('Watchdog job changed')
    system.run(['/bin/launchctl', 'print', 'system/' + LABEL])


def apply(value, seconds, system):
    verify_runtime()
    if not 30 <= seconds <= 300:
        raise GatewayError('Confirmation window must be 30..300 seconds')
    if (ROOT / 'receipt.json').exists() and receipt()['phase'] != 'rolled-back':
        raise GatewayError('Rollback the previous lease before activation')
    original = preflight(value, system)
    if system.core_pid() is not None:
        raise GatewayError('Protected core job already active')
    atomic(ROOT / 'config.json', (json.dumps(config(value)) + '\n').encode())
    atomic(ROOT / 'anchor.pf', pf_rules(value))
    atomic(ROOT / 'core.plist', plistlib.dumps(core_job()))
    atomic(ROOT / 'pf-enable.log', b'')
    # Dry parse and independent daemon registration precede protected networking mutations.
    system.run([str(ROOT / 'sing-box'), 'check', '-c', str(ROOT / 'config.json')])
    system.run(['/sbin/pfctl', '-n', '-a', ANCHOR, '-f', str(ROOT / 'anchor.pf')])
    register_watchdog(system)
    record = {'version': 1, 'phase': 'prepared', 'boot': original['boot'],
        'deadline': time.time() + seconds, 'settings': value, 'original': original,
        'core_sha256': digest((ROOT / 'sing-box').read_bytes()), 'process': None,
        'pf_token': None, 'routes_added': [], 'route_intent': None, 'forwarding_intent': False, 'pf_intent': False, 'core_intent': False, 'dns_intent': False}
    write_receipt(record)
    try:
        record['pf_intent'] = True
        write_receipt(record)
        system.run(['/sbin/pfctl', '-a', ANCHOR, '-f', str(ROOT / 'anchor.pf')])
        token = system.enable_pf()
        match = re.search(r'Token\s*:\s*([0-9]+)', token)
        if not match:
            raise GatewayError('PF enable reference unavailable; retain receipt for administrative recovery')
        record['pf_token'] = match.group(1)
        write_receipt(record)
        record['core_intent'] = True
        write_receipt(record)
        record['process'] = system.start()
        record['phase'] = 'pending'
        write_receipt(record)
        for _ in range(30):
            if value['tun_interface'] in system.run(['/sbin/ifconfig', '-l']).split():
                break
            time.sleep(0.1)
        else:
            raise GatewayError('TUN did not become ready')
        # Recheck after core creation; auto_route=False avoids the native replacement path.
        planned = route_ranges(value)
        if any(network(row['destination']).subnet_of(prefix)
               for row in system.routes() for prefix in planned):
            raise GatewayError('Route collision appeared during startup')
        for n in route_ranges(value):
            if time.time() >= record['deadline']:
                raise GatewayError('Lease expired during route installation')
            record['route_intent'] = str(n)
            write_receipt(record)
            system.run(['/sbin/route', '-n', 'add', '-net', str(n), '-interface', value['tun_interface']])
            record['routes_added'].append(str(n))
            record['route_intent'] = None
            write_receipt(record)
        if time.time() >= record['deadline']:
            raise GatewayError('Lease expired before forwarding activation')
        record['dns_intent'] = True
        write_receipt(record)
        system.run(['/usr/sbin/networksetup', '-setdnsservers', value['system_dns_service'], '127.0.0.1'])
        if time.time() >= record['deadline']:
            raise GatewayError('Lease expired during native DNS selection')
        record['forwarding_intent'] = True
        write_receipt(record)
        system.run(['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1'])
        if time.time() >= record['deadline']:
            raise GatewayError('Lease expired during forwarding activation')
    except Exception:
        rollback(record, system)
        raise
    return {'phase': 'pending', 'deadline': record['deadline']}


def rollback(record, system):
    if record['phase'] == 'rolled-back':
        return
    record['phase'] = 'rolling-back'
    write_receipt(record)
    same_boot = record['boot'] == system.boot()
    # Stop forwarding before removing the fail-closed filter or the tunnel.
    if record['forwarding_intent']:
        system.run(['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=' + record['original']['forwarding']])
    process = record['process']
    if same_boot and record['core_intent']:
        pid = system.core_pid()
        current = system.identity(pid)
        if current is not None:
            if (process is not None and current != process or
                    current['executable'] != str(ROOT / 'sing-box') or not current['birth'].startswith('0 ')):
                raise GatewayError('Foreign PID identity; filter retained for administrative recovery')
            if digest((ROOT / 'sing-box').read_bytes()) != record['core_sha256']:
                raise GatewayError('Core provenance mismatch; filter retained')
            system.stop()
            for _ in range(50):
                if system.identity(pid) != current:
                    break
                time.sleep(0.1)
            else:
                raise GatewayError('Owned core did not stop; filter retained')
        else:
            # A bootstrap without a process may still own a job; unload only its fixed plist.
            verify_core_job()
            system.run(['/bin/launchctl', 'bootout', 'system/' + CORE_LABEL], check=False)
    destinations = record['routes_added'] + ([record['route_intent']] if record['route_intent'] else [])
    for row in system.routes():
        if row['destination'] in destinations:
            if not same_boot or row['interface'] != record['settings']['tun_interface']:
                raise GatewayError('Owned route was replaced or survived reboot unexpectedly; do not delete foreign route')
            system.run(['/sbin/route', '-n', 'delete', '-net', row['destination'], '-interface', row['interface']])
    if record['dns_intent']:
        system.run(['/usr/sbin/networksetup', '-setdnsservers', record['settings']['system_dns_service']] +
                   (record['original']['system_dns'] or ['Empty']))
    if record['pf_intent']:
        # Empty only this anchor; never flush the global ruleset or PF states.
        atomic(ROOT / 'empty.pf', b'')
        system.run(['/sbin/pfctl', '-a', ANCHOR, '-f', str(ROOT / 'empty.pf')])
    if same_boot:
        token = record['pf_token']
        if not token and (ROOT / 'pf-enable.log').exists():
            protected(ROOT / 'pf-enable.log')
            match = re.search(r'Token\s*:\s*([0-9]+)', (ROOT / 'pf-enable.log').read_text())
            token = match.group(1) if match else None
        if token:
            system.run(['/sbin/pfctl', '-X', token])
    record['phase'] = 'rolled-back'
    write_receipt(record)


def watchdog(system):
    if not (ROOT / 'receipt.json').exists():
        return
    record = receipt()
    if record['phase'] == 'rolled-back':
        return
    same_boot = record['boot'] == system.boot()
    process = record['process']
    alive = same_boot and process and system.identity(process['pid']) == process
    if not same_boot or record['phase'] in ('prepared', 'rolling-back') or not alive or (
            record['phase'] == 'pending' and time.time() >= record['deadline']):
        rollback(record, system)


def watchdog_job():
    return {'Label': LABEL, 'ProgramArguments': ['/usr/bin/python3', '-I', str(ROOT / 'mac_gateway.py'), 'watchdog'],
            'RunAtLoad': True, 'StartInterval': 5, 'UserName': 'root',
            'StandardErrorPath': str(ROOT / 'watchdog.log'), 'StandardOutPath': str(ROOT / 'watchdog.log')}


def setup(archive, system):
    expected = ARCHIVES.get(platform.machine())
    if Path(archive).stat().st_size > 150 * 1024 * 1024:
        raise GatewayError('Core archive exceeds size limit')
    archive_data = Path(archive).read_bytes()
    if expected is None or digest(archive_data) != expected:
        raise GatewayError('Official pinned Darwin archive digest mismatch')
    if ROOT.exists():
        raise GatewayError('Protected installation already exists; use it or review upgrade explicitly')
    protected(ROOT.parent.parent, True)
    ROOT.parent.mkdir(mode=0o700, exist_ok=True)
    protected(ROOT.parent, True)
    ROOT.mkdir(mode=0o700)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode='r:gz') as package:
            architecture = 'arm64' if platform.machine() == 'arm64' else 'amd64'
            member = package.getmember('sing-box-%s-darwin-%s/sing-box' % (VERSION, architecture))
            if not member.isfile() or member.size > 150 * 1024 * 1024:
                raise GatewayError('Invalid core archive member')
            core = package.extractfile(member).read()
        atomic(ROOT / 'sing-box', core, 0o700)
        atomic(ROOT / 'mac_gateway.py', Path(__file__).read_bytes(), 0o600)
        save(ROOT / 'manifest.json', {'version': VERSION, 'archive_sha256': expected,
                                     'core_sha256': digest(core)})
        job = watchdog_job()
        if PLIST.exists() or PLIST.is_symlink():
            raise GatewayError('Watchdog launchd path already exists')
        protected(PLIST.parent, True)
        atomic(PLIST, plistlib.dumps(job), 0o600)
        system.run(['/bin/launchctl', 'bootstrap', 'system', str(PLIST)])
        register_watchdog(system)
    except Exception:
        # Preserve install evidence for review, never start a gateway after partial setup.
        raise GatewayError('Setup incomplete; no network configuration was applied') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['setup', 'check', 'apply', 'confirm', 'rollback', 'status', 'watchdog'])
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--settings', type=Path)
    parser.add_argument('--seconds', type=int, default=120)
    args = parser.parse_args()
    if platform.system() != 'Darwin' or os.geteuid() != 0:
        raise GatewayError('Administrative helper requires root on macOS')
    system = System()
    if args.action == 'setup':
        if not args.archive:
            parser.error('setup requires --archive')
        setup(args.archive, system)
        print('Protected gateway helper installed; networking unchanged')
        return
    if Path(__file__).resolve() != ROOT / 'mac_gateway.py':
        raise GatewayError('Use the installed protected helper')
    verify_runtime()
    lock = os.open(str(ROOT / 'lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action in ('check', 'apply'):
            if not args.settings:
                parser.error('check/apply requires --settings')
            info = args.settings.lstat()
            if info.st_mode & 0o077 or info.st_uid not in (0, int(os.environ.get('SUDO_UID', '0'))):
                raise GatewayError('Settings with secrets require private0600 root/admin ownership')
            value = settings(read_json(args.settings))
            if args.action == 'check':
                preflight(value, system)
                print('Topology preflight passed; kernel/LAN acceptance remains unverified')
            else:
                print(json.dumps(apply(value, args.seconds, system)))
        elif args.action == 'watchdog':
            watchdog(system)
        else:
            record = receipt()
            if args.action == 'rollback':
                rollback(record, system)
                print('Owned gateway lease rolled back')
            elif args.action == 'confirm':
                if (record['phase'] != 'pending' or record['boot'] != system.boot() or
                    time.time() >= record['deadline'] or not record['process'] or
                    system.identity(record['process']['pid']) != record['process']):
                    raise GatewayError('Lease cannot be confirmed; run rollback')
                record['phase'] = 'confirmed'
                write_receipt(record)
                print('Lease confirmed; watchdog continues monitoring core ownership')
            else:
                print(json.dumps({'phase': record['phase'], 'deadline': record['deadline'],
                                  'experimental': True, 'kernel_lan_acceptance': 'unverified'}))
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except (GatewayError, OSError, ValueError, subprocess.SubprocessError):
        # Credentials can be present in input/config: fixed public failure text only.
        print('Gateway operation refused or incomplete. Review private receipt and documented recovery.', file=sys.stderr)
        sys.exit(1)
