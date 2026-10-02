"""Router fallback gate driven by an editable monitor definition."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time

ROOT = Path('/var/lib/okopy-candidate')
SETTINGS = Path('/var/lib/okopy-monitor')


def settings(identifier, root=None):
    from health_settings import read_settings, fingerprint
    root = SETTINGS if root is None else root
    value, _ = read_settings(root)
    check = next(c for c in value['checks'] if c['id'] == identifier)
    if check['kind'] != 'vpn_gate':
        raise ValueError('Expected a router gate definition')
    return check, fingerprint(check)


def runtime_revision(check):
    from vpn_runtime import verify_runtime
    # Keep writers blocked only while checking the local runtime and its revision.
    # Network probes can be slow; the same revision must still be live afterwards.
    with (ROOT/'apply.lock').open('r') as lock, (ROOT/'vpn.lock').open('r') as network:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(network, fcntl.LOCK_SH | fcntl.LOCK_NB)
        if not verify_runtime(ROOT).get('enabled'):
            return None
        files = {name: (ROOT/name).read_bytes() for name in
                 ('applied-policy.json', 'config.json', 'transaction.json')}
        policy = json.loads(files['applied-policy.json'])
        if not any(ipaddress.ip_address(check['client']) in ipaddress.ip_network(n)
                   for n in policy['vpn_ingress']['clients']):
            return None
        return tuple(hashlib.sha256(data).digest() for data in files.values())


def probe(check):
    revision = runtime_revision(check)
    if revision is None:
        return False
    from urllib.parse import urlsplit
    url = urlsplit(check['url'])
    host, port = url.hostname, url.port or 443
    addresses = []
    for tcp in (False, True):
        args = ['dig', '@'+check['dns_server'], '-p', str(check['dns_port']), host, 'A',
                '+time='+str(check['dns_timeout_seconds']), '+tries=1', '+noall', '+comments', '+answer']
        if tcp:
            args.append('+tcp')
        result = subprocess.run(args, capture_output=True, text=True, timeout=check['dns_timeout_seconds']+1)
        if result.returncode or 'status: NOERROR' not in result.stdout:
            return False
        answers = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[-2] == 'A':
                address = ipaddress.IPv4Address(fields[-1])
                if address.is_global or address in ipaddress.ip_network('198.18.0.0/15'):
                    answers.append(str(address))
        if not answers:
            return False
        addresses.extend(answers)
    # Give all unique addresses one shared HTTPS budget. TLS still verifies the
    # configured hostname through the selected SOCKS path; there is no direct fallback.
    deadline = time.monotonic()+check['timeout_seconds']
    for address in dict.fromkeys(addresses):
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            break
        result = subprocess.run(['curl', '--noproxy', '', '--socks5', check['proxy'],
            '--resolve', host+':'+str(port)+':'+address, '--silent',
            '--connect-timeout', str(remaining), '--max-time', str(remaining), '--output', '/dev/null',
            '--write-out', '%{http_code}', check['url']],
            capture_output=True, text=True, timeout=remaining)
        if result.returncode == 0 and result.stdout.strip() in check['codes']:
            return runtime_revision(check) == revision
    return False


def notify(message):
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
            channel.connect('\0'+address[1:] if address.startswith('@') else address)
            channel.sendall(message.encode())


def serve(identifier):
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    listener = None
    child = None
    streak = failures = 0
    revision = None
    check = None
    last_good = 0
    next_probe = 0
    notify('READY=1')
    try:
        while not stopping:
            now = time.monotonic()
            notify('WATCHDOG=1')
            try:
                current, current_revision = settings(identifier)
            except (OSError, ValueError, TypeError, KeyError, StopIteration):
                current, current_revision = None, None
            if current_revision != revision or current is None:
                if child is not None:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait(timeout=2)
                    child = None
                if listener is not None:
                    listener.close()
                    listener = None
                streak = failures = 0
                last_good = next_probe = 0
                revision, check = current_revision, current
            if check is None:
                time.sleep(1)
                continue
            if child is None and now >= next_probe:
                child = subprocess.Popen(['/usr/bin/python3', '-E', '-s', '-B', __file__, '--probe', '--check-id', identifier, '--revision', revision, '--settings', str(SETTINGS)],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         start_new_session=True)
                started = now
            if child is not None:
                result = child.poll()
                if result is None and now-started > 2*(check['dns_timeout_seconds']+1)+check['timeout_seconds']+3:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=2)
                    result = 1
                if result is not None:
                    # Terminate any descendant left by a failed bounded probe.
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child = None
                    next_probe = now+check.get('interval_seconds', 5)
                    if result == 0:
                        streak = min(check['rise'], streak+1)
                        failures = 0
                        last_good = now
                    else:
                        failures += 1
                        if listener is None or failures >= check['fall']:
                            streak = 0
            healthy = streak >= check['rise'] and now-last_good < check['max_age_seconds']
            if healthy and listener is None:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((check['host'], check['port']))
                listener.listen(16)
                listener.setblocking(False)
            elif not healthy and listener is not None:
                listener.close()
                listener = None
            if listener is not None:
                readable, _, _ = select.select([listener], [], [], 1)
                if readable:
                    connection, _ = listener.accept()
                    connection.close()
            else:
                time.sleep(1)
    finally:
        if listener is not None:
            listener.close()
        if child is not None:
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--check-id', required=True)
    parser.add_argument('--revision')
    parser.add_argument('--settings', type=Path, default=SETTINGS)
    args = parser.parse_args()
    SETTINGS = args.settings
    if args.probe:
        try:
            check, revision = settings(args.check_id)
            success = (args.revision is None or args.revision == revision) and probe(check)
            success = success and settings(args.check_id)[1] == revision
        except Exception:
            success = False
        raise SystemExit(0 if success else 1)
    serve(args.check_id)
