"""Safe apply pilot for the isolated candidate only; not a production installer.

The rollback is a separate systemd timer and does not depend on a web process.
All paths and the target service are deliberately fixed until the pilot passes.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import urllib.request


ROOT = Path('/var/lib/okopy-candidate')
UNIT = 'okopy-candidate.service'
MANAGED_FILES = ('applied-policy.json', 'policy-manifest.json', 'config.json')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def remove_created_file(path: Path) -> None:
    path.unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)


class Backend:
    def __init__(self, root: Path):
        self.root = root

    def boot_id(self) -> str:
        return str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))

    def validate_bundle(self, files) -> None:
        try:
            from candidate_bundle import validate_bundle
            manifest=validate_bundle(files)
            self.validated_endpoints=json.loads(files['config.json']).get('endpoints', [])
            from incoming_connections import compile_inbounds
            self.validated_incoming=compile_inbounds(json.loads(files['applied-policy.json']).get('incoming_connections', []))
            from incoming_runtime import entries as incoming_entries
            incoming_policy=json.loads(files['applied-policy.json'])
            if incoming_entries(incoming_policy):
                from incoming_runtime import check_service as check_incoming,preflight as incoming_preflight
                check_incoming(self.root);incoming_preflight(incoming_policy)
            from lan_ingress import settings as lan_settings
            self.validated_lan = lan_settings(json.loads(files['applied-policy.json']))
            from vpn_ingress import settings as vpn_settings
            self.validated_vpn = vpn_settings(json.loads(files['applied-policy.json']))
            if manifest['build_options'].get('lan_adapter'):
                from lan_runtime import check_service as check_lan, preflight
                from lan_ingress import settings
                check_lan(self.root); preflight(settings(json.loads(files['applied-policy.json'])))
            if manifest['build_options'].get('adguard_adapter'):
                from adguard_runtime import check_service,validate
                check_service(self.root);validate(self.root,files)
            if manifest['build_options'].get('vpn_adapter'):
                from vpn_runtime import check_service,preflight
                check_service(self.root,self.validated_vpn);preflight(self.validated_vpn)
        except Exception as error:
            atomic_write(self.root/'last-bundle-error.log',str(error).encode())
            raise ValueError('Bundle validation failed; private diagnostic saved') from None

    def validate(self, path: Path) -> None:
        # Keep the pilot's listeners, state files and lifecycle fixed. This is
        # not a sandbox for arbitrary untrusted sing-box configurations.
        config = json.loads(path.read_text())
        allowed = {'log','dns','inbounds','outbounds','endpoints','route','experimental'}
        if not isinstance(config, dict) or set(config)-allowed:
            raise ValueError('Unsupported top-level field in candidate pilot')
        expected = {'direct': 5301, 'mixed': 2081}
        inbounds = config.get('inbounds', [])
        from incoming_connections import PREFIX as INCOMING_PREFIX
        incoming = [i for i in inbounds if i.get('tag','').startswith(INCOMING_PREFIX)]
        if incoming:
            if incoming != getattr(self, 'validated_incoming', None):
                raise ValueError('Incoming listeners require a validated complete bundle')
            inbounds = [i for i in inbounds if not i.get('tag','').startswith(INCOMING_PREFIX)]
        from lan_ingress import PREFIX as LAN_PREFIX, validate_config
        from vpn_ingress import PREFIX as VPN_PREFIX, validate_config as validate_vpn
        vpn_entries = [i for i in inbounds if i.get('tag','').startswith(VPN_PREFIX)]
        if vpn_entries:
            if not getattr(self, 'validated_vpn', None):
                raise ValueError('VPN requires a validated complete bundle')
            validate_vpn(config,self.validated_vpn,self.validated_lan)
        lan_entries = [i for i in inbounds if i.get('tag','').startswith(LAN_PREFIX)]
        if lan_entries:
            # Only the reproduced complete bundle may open managed LAN ports.
            if not getattr(self, 'validated_lan', None):
                raise ValueError('LAN requires a validated complete bundle')
            validate_config(config, self.validated_lan)
            inbounds = inbounds[:-len(lan_entries)]
        if vpn_entries:inbounds = inbounds[:-len(vpn_entries)]
        if len(inbounds) < 2:
            raise ValueError('Candidate requires its two main loopback inbounds')
        if len(inbounds)>2:
            from pair_probes import validate_probe_inbounds
            from adguard_adapter import PREFIX,validate_inbounds
            from fakeip_adapter import PREFIX as UNMAP_PREFIX,validate_inbounds as validate_unmapping
            end=next((i for i in range(2,len(inbounds)) if inbounds[i].get('tag','').startswith(UNMAP_PREFIX)),len(inbounds))
            validate_unmapping(inbounds[end:])
            inbounds=inbounds[:end]
            split=next((i for i in range(2,len(inbounds)) if inbounds[i].get('tag','').startswith(PREFIX)),len(inbounds))
            validate_probe_inbounds(inbounds[2:split]);validate_inbounds(inbounds[split:])
        seen = set()
        for inbound in inbounds[:2]:
            kind = inbound.get('type')
            if kind not in expected or kind in seen or inbound.get('listen') != '127.0.0.1' or inbound.get('listen_port') != expected[kind]:
                raise ValueError('Candidate inbound must remain isolated')
            seen.add(kind)
        endpoints = config.get('endpoints', [])
        if endpoints:
            from native_endpoints import ENDPOINT_TYPES, validate_endpoint
            if endpoints != getattr(self, 'validated_endpoints', None):
                raise ValueError('Endpoints require a validated complete bundle')
            for endpoint in endpoints:
                if endpoint.get('type') == 'openvpn-server':
                    from incoming_connections import validate_native
                    validate_native(endpoint)
                    continue
                if endpoint.get('type') not in ENDPOINT_TYPES:
                    raise ValueError('Unsupported endpoint type')
                validate_endpoint(endpoint)
        experimental = config.get('experimental', {})
        if set(experimental)-{'clash_api','cache_file'}:
            raise ValueError('Additional experimental services are forbidden')
        api = experimental.get('clash_api', {})
        if set(api)-{'external_controller','secret','default_mode'}:
            raise ValueError('Unsupported candidate API field')
        if api.get('external_controller') != '127.0.0.1:9091' or not api.get('secret'):
            raise ValueError('Candidate API must remain authenticated on loopback')
        cache = experimental.get('cache_file', {})
        if set(cache)-{'enabled','path','cache_id','store_fakeip'} or cache.get('path') != str(self.root/'cache.db'):
            raise ValueError('Candidate cache must stay in its fixed private file')
        if 'output' in config.get('log', {}):
            raise ValueError('Candidate logs must go to its journal, not arbitrary files')
        result = subprocess.run([str(self.root/'sing-box'), 'check', '-c', str(path)],
                                capture_output=True, timeout=15)
        if result.returncode:
            # Full core diagnostics can contain secrets: preserve locally only.
            atomic_write(self.root/'last-check-error.log', result.stderr)
            raise ValueError('sing-box check failed; private diagnostic saved')

    def verify_runtime(self, *, adguard_verified: bool = False) -> None:
        from candidate_bundle import read_bundle, validate_bundle
        manifest = validate_bundle(read_bundle(self.root))
        from incoming_runtime import verify as verify_incoming
        verify_incoming(self.root)
        if manifest['build_options'].get('adguard_adapter') and not adguard_verified:
            from adguard_runtime import verify_runtime as verify_adguard
            verify_adguard(self.root)
        if manifest['build_options'].get('lan_adapter'):
            from lan_runtime import verify_runtime as verify_lan
            # The caller already owns apply.lock; only take the adapter lock.
            with (self.root/'lan.lock').open('r') as lock:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                verify_lan(self.root)
        if manifest['build_options'].get('vpn_adapter'):
            from vpn_runtime import verify_runtime
            # Apply/confirm already owns apply.lock; never reacquire it.
            with (self.root/'vpn.lock').open('r') as lock:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                verify_runtime(self.root)

    def restart(self) -> None:
        from adguard_runtime import configured,UNIT as ADGUARD_UNIT,wait_ready
        adguard_running = configured(self.root)
        if adguard_running:
            # Slots may be reassigned in the new policy. Drain both old engines
            # before starting either against a different mapping.
            subprocess.run(['systemctl','stop',UNIT,ADGUARD_UNIT],check=True,capture_output=True,timeout=15)
            subprocess.run(['systemctl','start',ADGUARD_UNIT],check=True,capture_output=True,timeout=15)
            wait_ready(self.root)
            subprocess.run(['systemctl','start',UNIT],check=True,capture_output=True,timeout=15)
        else:
            subprocess.run(['systemctl', 'restart', UNIT], check=True, capture_output=True, timeout=15)
        # Type=simple may report active before sing-box finishes initialization.
        # Wait for its authenticated control endpoint, not only the PID.
        secret = json.loads((self.root/'config.json').read_text())['experimental']['clash_api']['secret']
        request = urllib.request.Request('http://127.0.0.1:9091/version', headers={'Authorization':'Bearer '+secret})
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(request, timeout=0.5) as response:
                    json.loads(response.read())
                break
            except (OSError, ValueError):
                time.sleep(0.1)
        else:
            raise RuntimeError('Candidate control endpoint did not become ready')
        self.verify_runtime(adguard_verified=adguard_running)

    def arm(self, transaction: str, seconds: int) -> str:
        self.check_boot_guard()
        timer = 'okopy-candidate-rollback-' + transaction
        script = str(self.root/'safe_apply.py')
        subprocess.run(['systemd-run', '--quiet', '--unit='+timer,
                        '--on-active='+str(seconds)+'s', '--timer-property=AccuracySec=1s',
                        '--property=UMask=0077', '--property=Restart=on-failure',
                        '--property=RestartSec=5s', '--property=StartLimitIntervalSec=1h',
                        '--property=StartLimitBurst=3', '/usr/bin/python3', script,
                        'rollback', transaction], check=True, capture_output=True, timeout=10)
        subprocess.run(['systemctl', 'is-active', '--quiet', timer+'.timer'], check=True, timeout=5)
        return timer

    def check_boot_guard(self) -> None:
        result = subprocess.run(['systemctl','show',UNIT,
            '--property=ExecStartPre,User,DynamicUser,ProtectSystem,ReadWritePaths,ProcSubset,RootDirectory,RootImage,FragmentPath,Transient,DropInPaths,NeedDaemonReload'],
            check=True,capture_output=True,text=True,timeout=5)
        fields={}
        for line in result.stdout.splitlines():
            if '=' in line:
                key,value=line.split('=',1);fields[key]=(fields[key]+' ' if key in fields else '')+value
        expected='argv[]=/usr/bin/python3 -E -s -B '+str(self.root/'safe_apply.py')+' recover-before-start ; ignore_errors=no'
        if expected not in fields.get('ExecStartPre',''):
            raise ValueError('Required boot recovery hook is not active in the service definition')
        persistent_hook='/etc/systemd/system/'+UNIT+'.d/10-boot-recovery.conf'
        if (fields.get('NeedDaemonReload')!='no' or fields.get('Transient')!='no' or fields.get('FragmentPath')!='/etc/systemd/system/'+UNIT
                or persistent_hook not in fields.get('DropInPaths','').split()):
            raise ValueError('Boot recovery must be installed in the persistent service definition')
        if (fields.get('User','') not in ('','root') or fields.get('DynamicUser')=='yes'
                or fields.get('ProcSubset','') not in ('','all')
                or fields.get('RootDirectory') or fields.get('RootImage')
                or (fields.get('ProtectSystem')=='strict'
                    and str(self.root) not in fields.get('ReadWritePaths','').split())):
            raise ValueError('Service sandbox is incompatible with boot recovery; configuration unchanged')

    def cancel(self, timer: str) -> None:
        subprocess.run(['systemctl', 'stop', timer+'.timer'], check=True, capture_output=True, timeout=10)


class Coordinator:
    def __init__(self, root: Path, backend):
        self.root = root
        self.backend = backend
        self.config = root/'config.json'
        self.state_path = root/'transaction.json'

    def state(self) -> dict:
        return json.loads(self.state_path.read_text()) if self.state_path.exists() else {}

    def save(self, state: dict) -> None:
        atomic_write(self.state_path, json.dumps(state, indent=2).encode())

    def apply_bundle(self, files: dict, seconds: int) -> dict:
        return self.apply(files['config.json'],seconds,bundle=files)

    def apply(self, candidate: bytes, seconds: int, *, bundle=None) -> dict:
        if not 20 <= seconds <= 600:
            raise ValueError('Rollback deadline must be 20..600 seconds')
        previous = self.state()
        if previous.get('status') in ('prepared', 'pending', 'rollback_failed'):
            raise ValueError('Another unconfirmed transaction exists')
        files={'config.json':candidate} if bundle is None else dict(bundle)
        if bundle is not None:
            self.backend.validate_bundle(files)
            if files['config.json']!=candidate:raise ValueError('Candidate differs from bundle')
        if bundle is None and (self.root/'policy-manifest.json').exists():
            if json.loads((self.root/'policy-manifest.json').read_text()).get('bundle_version')==1:
                raise ValueError('This candidate uses a complete bundle; use apply-bundle')
        path = self.root/'next.json'
        atomic_write(path, candidate)
        self.backend.validate(path)
        transaction = uuid.uuid4().hex
        revisions = self.root/'revisions'
        revisions.mkdir(mode=0o700, exist_ok=True)
        old = self.config.read_bytes()
        backup = revisions/(transaction+'.json')
        atomic_write(backup, old)
        previous_files={};next_files={}
        for name,data in files.items():
            if name not in MANAGED_FILES:raise ValueError('Unsupported bundle file')
            existing=old if name=='config.json' else ((self.root/name).read_bytes() if (self.root/name).exists() else None)
            previous_files[name]=None if existing is None else digest(existing)
            next_files[name]=digest(data)
            if name!='config.json' and existing is not None:
                atomic_write(revisions/(transaction+'.'+name),existing)
        state = {'id': transaction, 'status': 'prepared', 'previous_sha256': digest(old),
                 'next_sha256': digest(candidate), 'created_at': time.time(),
                 'deadline': time.time()+seconds, 'boot_id': self.backend.boot_id(),
                 'previous_files':previous_files,'next_files':next_files,'runtime_ready':False}
        self.save(state)
        try:
            state['timer'] = self.backend.arm(transaction, seconds)
        except Exception:
            state['status'] = 'schedule_failed'
            self.save(state)
            raise
        # The timer was verified before the first modification of live config.
        state['status'] = 'pending'
        self.save(state)
        try:
            for name in MANAGED_FILES:
                if name in files:atomic_write(self.root/name,files[name])
            self.backend.restart()
            state['runtime_ready']=True
            self.save(state)
        except Exception as error:
            state['apply_error'] = type(error).__name__
            self.save(state)
            self.rollback(transaction)
            raise
        return state

    def previous_files(self, state):
        hashes=state.get('previous_files',{'config.json':state['previous_sha256']})
        if (not isinstance(hashes,dict) or 'config.json' not in hashes
                or set(hashes)-set(MANAGED_FILES) or hashes['config.json']!=state['previous_sha256']):
            raise ValueError('Invalid revision manifest')
        return hashes

    def old_files_are_durable(self, state):
        for name,expected in self.previous_files(state).items():
            path=self.root/name
            if expected is None:
                if path.exists() or path.is_symlink():return False
            else:
                try:actual=digest(path.read_bytes())
                except OSError:return False
                if actual!=expected:return False
        return True

    def rollback(self, transaction: str, *, start_service: bool = True) -> dict:
        state = self.state()
        if state.get('id') != transaction or state.get('status') not in ('prepared', 'pending', 'rollback_failed'):
            return {'status': 'ignored', 'reason': 'transaction is no longer pending'}
        try:
            if len(transaction)!=32 or any(c not in '0123456789abcdef' for c in transaction):
                raise ValueError('Invalid revision identifier')
            saved={}
            for name,expected in self.previous_files(state).items():
                if expected is None:saved[name]=None;continue
                suffix='.json' if name=='config.json' else '.'+name
                saved[name]=(self.root/'revisions'/(transaction+suffix)).read_bytes()
                if digest(saved[name])!=expected:raise ValueError('Backup checksum mismatch')
            # Validate every saved file before changing the first live file.
            for name in MANAGED_FILES:
                if name not in saved:continue
                if saved[name] is None:remove_created_file(self.root/name)
                else:atomic_write(self.root/name,saved[name])
            # The old file is already durable. A startup guard invoked by our
            # restart may skip locking, so it cannot deadlock behind this writer.
            state['restore_boot_id'] = self.backend.boot_id()
            self.save(state)
            if start_service:
                self.backend.restart()
        except Exception:
            state['status'] = 'rollback_failed'
            self.save(state)
            raise
        state['status'] = 'rolled_back'
        state['finished_at'] = time.time()
        self.save(state)
        return state

    def recover_before_start(self) -> dict:
        """Restore an unconfirmed previous-boot file before sing-box can bind.

        Called by ExecStartPre. The initial read deliberately precedes locking:
        a normal same-boot apply holds the writer lock while restarting the unit.
        Only a different boot needs recovery. Recheck after acquiring the lock.
        """
        pending = ('prepared', 'pending', 'rollback_failed')
        boot = self.backend.boot_id()
        def needed(state):
            if state.get('status') == 'rollback_failed':
                # A failed restore may still leave the unconfirmed file live.
                # Only skip a parent's restart if its old file is already durable.
                old_file_is_durable = self.old_files_are_durable(state)
                return not (state.get('restore_boot_id') == boot and old_file_is_durable)
            return state.get('status') in pending and boot not in (
                state.get('boot_id'), state.get('restore_boot_id'))
        if not needed(self.state()):
            return {'status':'ignored','reason':'no unconfirmed previous-boot change'}
        with (self.root/'apply.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self.state()
            if not needed(state):
                return {'status':'ignored','reason':'recovery already handled'}
            result = self.rollback(state['id'], start_service=False)
            result['recovery_reason'] = 'unconfirmed change from previous boot'
            self.save(result)
            return result

    def confirm(self, transaction: str) -> dict:
        state = self.state()
        if state.get('id') != transaction or state.get('status') != 'pending' or state.get('runtime_ready') is not True:
            raise ValueError('Transaction is not pending or its restart was not verified')
        if state.get('boot_id') != self.backend.boot_id():
            raise ValueError('Host restarted; recover the unconfirmed change before applying again')
        if time.time() >= state['deadline']:
            raise ValueError('Deadline expired; allow rollback')
        expected=state.get('next_files',{'config.json':state['next_sha256']})
        if not isinstance(expected,dict) or 'config.json' not in expected or set(expected)-set(MANAGED_FILES):
            raise ValueError('Invalid confirmation manifest')
        for name,value in expected.items():
            if digest((self.root/name).read_bytes())!=value:
                raise ValueError('Configuration or policy drift; confirmation refused')
        self.backend.verify_runtime()
        if time.time() >= state['deadline']:
            raise ValueError('Deadline expired during runtime verification; allow rollback')
        # Persist confirmation before stopping the timer: if this process dies,
        # an already-dispatched callback sees confirmed and cannot revert it.
        state['status'] = 'confirmed'
        state['finished_at'] = time.time()
        self.save(state)
        try:
            self.backend.cancel(state['timer'])
        except Exception as error:
            # The callback is already inert because confirmed is durable.
            # Do not report a successful commit as a failed transaction.
            state['warning'] = 'confirmed; timer cleanup failed: ' + type(error).__name__
            self.save(state)
        return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['apply', 'apply-bundle', 'confirm', 'rollback', 'status', 'recover-before-start'])
    parser.add_argument('value', nargs='?')
    parser.add_argument('--seconds', type=int, default=60)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo on the candidate host')
    os.umask(0o077)
    if not ROOT.is_dir():
        raise SystemExit('Candidate not prepared')
    coordinator = Coordinator(ROOT, Backend(ROOT))
    if args.action == 'recover-before-start':
        print(json.dumps(coordinator.recover_before_start()))
        return
    with (ROOT/'apply.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'apply':
            if not args.value:
                parser.error('apply requires a config file')
            result = coordinator.apply(Path(args.value).read_bytes(), args.seconds)
        elif args.action == 'apply-bundle':
            if not args.value:parser.error('apply-bundle requires a private bundle directory')
            from candidate_bundle import read_bundle
            result = coordinator.apply_bundle(read_bundle(args.value),args.seconds)
        elif args.action == 'confirm':
            result = coordinator.confirm(args.value)
        elif args.action == 'rollback':
            result = coordinator.rollback(args.value)
        else:
            result = coordinator.state()
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'error': type(error).__name__, 'message': str(error)}), file=sys.stderr)
        raise SystemExit(1)
