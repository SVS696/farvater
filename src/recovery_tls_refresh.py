"""Refresh protected HTTPS material after certbot renewal while no restore runs.

Installed as root-owned tls_refresh.py alongside the frozen access.py. No
certificate or credential contents enter output. The deploy hook uses only this
fixed action; it does not run snapshot-managed application code.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

CAPSULE = Path('/var/lib/okopy-recovery')
ACCESS = Path('/opt/okopy-recovery-ui/access.py')
BARRIER = Path('/var/lib/okopy-recovery-ui/barrier.json')


def read_owned(path, maximum):
    path = Path(path)
    if path.resolve() != path:
        raise ValueError('Protected refresh path changed')
    for parent in path.parents:
        meta = parent.stat()
        if meta.st_uid != 0 or not stat.S_ISDIR(meta.st_mode) or meta.st_mode & 0o022:
            raise ValueError('Protected refresh parent is writable')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if meta.st_uid != 0 or not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o022 or meta.st_size > maximum:
            raise ValueError('Protected refresh file changed')
        return stream.read(maximum + 1)


def refresh(*, reload_caddy=False):
    if os.geteuid() != 0:
        raise ValueError('HTTPS refresh requires root')
    # Same installer-owned lock as prepare/start, outside snapshot paths.
    read_owned(CAPSULE / 'settings.json', 16384)
    fd = os.open(CAPSULE / 'control.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        meta = os.fstat(lock.fileno())
        if meta.st_uid != 0 or not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077:
            raise ValueError('HTTPS refresh lock changed')
        fcntl.flock(lock, fcntl.LOCK_EX)
        barrier = json.loads(read_owned(BARRIER, 512))
        if barrier != {'version': 1, 'status': 'inactive', 'job_id': None}:
            raise ValueError('HTTPS renewal waits until recovery is complete')
        settings = json.loads(read_owned(CAPSULE / 'settings.json', 16384))
        chain = settings['tls_chain_source']
        key = settings['tls_key_source']
        for source in (chain, key):
            if not isinstance(source, str) or not source.startswith('/etc/letsencrypt/live/'):
                raise ValueError('Unknown HTTPS certificate source')
        read_owned(ACCESS, 128 * 1024)
        spec = importlib.util.spec_from_file_location('frozen_recovery_access', ACCESS)
        access = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(access)
        access.stage_tls(chain, key)
        if reload_caddy:
            subprocess.run(['docker', 'exec', 'okopy-panel-https', 'caddy', 'reload',
                            '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile',
                            '--address', 'unix//config/admin.sock'],
                           capture_output=True, check=True, timeout=30)
    return {'status': 'refreshed', 'proxy_reloaded': reload_caddy}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reload-caddy', action='store_true')
    args = parser.parse_args()
    print(json.dumps(refresh(reload_caddy=args.reload_caddy)))


if __name__ == '__main__':
    main()
