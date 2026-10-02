"""Read sanitized server snapshots over existing SSH; never run remote probes.

The server timer works independently of this UI transport. Only this transport
stops when the local panel process stops. Credentials are not read or copied.
"""
import json
import subprocess
import threading
import time
from health_model import MAX_BYTES, validate_snapshot, read_snapshot
from safe_apply import atomic_write


PULL_LOCK=threading.Lock()


def pull_once(directory,source='ssh'):
    with PULL_LOCK:return _pull_once(directory,source)


def invalidate_local_check(directory,identifier,observed_at,*,removed=False):
    # Wait for any fetch that began before the edit, then invalidate its result.
    # Subsequent fetches see the server-side invalidation or a new measurement.
    with PULL_LOCK:
        try:snapshot=read_snapshot(directory/'health.json')
        except (OSError,ValueError,TypeError):return
        for row in snapshot['checks']:
            if row['id']==identifier:
                row.update(status='unknown',detail='Параметры датчика изменены; ожидается новое измерение',
                           observed_at=observed_at,duration_ms=0)
                row.pop('retained_observation',None);row.pop('in_progress',None)
                row.pop('scheduled',None);row.pop('next_check_at',None)
        if removed:snapshot['checks']=[r for r in snapshot['checks'] if r['id']!=identifier]
        atomic_write(directory/'health.json',json.dumps(snapshot,ensure_ascii=False).encode())


def _pull_once(directory,source='ssh'):
    if source not in ('ssh','local'):raise ValueError('Unknown health transport')
    if source=='local':
        commands=[['/usr/bin/sudo','-n','/usr/bin/head','-c','524289','/var/lib/okopy-monitor/health.json']]
    else:
        from server_connection import read,ssh
        try:commands=[ssh(t,3)+['head -c 524289 /var/lib/okopy-monitor/health.json'] for t in read()['targets']]
        except (OSError,ValueError,KeyError):commands=[]
    for command in commands:
        try:
            response=subprocess.run(command,capture_output=True,timeout=6)
            if response.returncode or len(response.stdout)>MAX_BYTES:continue
            snapshot=validate_snapshot(json.loads(response.stdout))
            atomic_write(directory/'health.json',json.dumps(snapshot,ensure_ascii=False).encode())
            atomic_write(directory/'health-transport.json',json.dumps({'at':time.time(),'ok':True}).encode())
            return True
        except (OSError,ValueError,TypeError,subprocess.SubprocessError):continue
    atomic_write(directory/'health-transport.json',json.dumps({'at':time.time(),'ok':False}).encode())
    return False


def start_pull(directory,source='ssh'):
    def loop():
        while True:
            try:pull_once(directory,source)
            except Exception:
                try:atomic_write(directory/'health-transport.json',json.dumps({'at':time.time(),'ok':False}).encode())
                except OSError:pass
            time.sleep(30)
    thread=threading.Thread(target=loop,name='health-snapshot-reader',daemon=True)
    thread.start()
    return thread
