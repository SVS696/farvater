"""Root-only lifecycle for the candidate AdGuard, derived from the same bundle."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import uuid

from adguard_adapter import compile_adapter,runtime_config,HTTP_PORT

UNIT='okopy-adguard-candidate.service'
BINARY='/opt/AdGuardHome/AdGuardHome'


def configured(root):return (root/'adguard-base.json').is_file()


def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def configuration(root,files):
    from candidate_bundle import validate_bundle
    manifest=validate_bundle(files)
    policy=json.loads(files['applied-policy.json'])
    if manifest['build_options'].get('adguard_adapter'):
        adapter=compile_adapter(policy)
        if manifest.get('adguard')!=adapter['records']:raise ValueError('AdGuard mapping mismatch')
    else:
        adapter={'records':[],'settings':{'default_enabled':False,'blocklists':[],'allowlists':[],'rules':[]}}
    return runtime_config(json.loads((root/'adguard-base.json').read_text()),adapter)


def validate(root,files):
    from safe_apply import atomic_write
    path=root/('.adguard-check-'+uuid.uuid4().hex+'.yaml')
    try:
        value=configuration(root,files)
        prepare_filters(root,value)
        atomic_write(path,json.dumps(value,ensure_ascii=False).encode())
        response=subprocess.run([BINARY,'--check-config','--config',str(path),'--work-dir',str(root/'adguard')],
                                capture_output=True,timeout=12)
        if response.returncode:
            atomic_write(root/'last-adguard-check-error.log',response.stderr)
            raise ValueError('AdGuard configuration rejected; diagnostic saved privately')
    finally:path.unlink(missing_ok=True)


def prepare_filters(root,config):
    """Fetch new list URLs before touching running engines; existing IDs survive.

    The native engine remains the only filter parser. URL-derived IDs prevent a
    changed source from borrowing another list's previously downloaded cache.
    """
    directory=root/'adguard/data/filters';directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    deadline=time.monotonic()+25
    for item in [*config['filters'],*config['whitelist_filters']]:
        if not item['enabled']:continue
        destination=directory/(str(item['id'])+'.txt')
        if destination.is_file() and 0<destination.stat().st_size<=64*1024*1024:continue
        remaining=deadline-time.monotonic()
        if remaining<1:raise ValueError('Filter preparation deadline exceeded; running policy unchanged')
        temporary=directory/('.download-'+uuid.uuid4().hex)
        try:
            response=subprocess.run(['curl','--config','-','--fail','--silent','--show-error',
                '--location','--max-redirs','3','--proto','=http,https','--proto-redir','=http,https',
                '--max-time',str(min(15,remaining)),'--max-filesize',str(64*1024*1024),
                '--output',str(temporary)],input=('url = '+json.dumps(item['url'])+'\n').encode(),
                capture_output=True,timeout=min(15,remaining)+2)
            if response.returncode or not temporary.is_file() or not 0<temporary.stat().st_size<=64*1024*1024:
                raise ValueError('Filter download failed; running policy unchanged')
            temporary.chmod(0o600)
            with temporary.open('rb') as stream:os.fsync(stream.fileno())
            os.replace(temporary,destination)
        finally:temporary.unlink(missing_ok=True)


def prepare(root):
    from candidate_bundle import read_bundle
    from safe_apply import atomic_write
    files=read_bundle(root);state=json.loads((root/'transaction.json').read_text())
    def matches(hashes):
        return set(hashes)==set(files) and all(hashlib.sha256(data).hexdigest()==hashes[name] for name,data in files.items())
    restoring=state.get('restore_boot_id')==boot_id() and matches(state.get('previous_files',{}))
    expected=state.get('next_files' if state.get('status') in ('confirmed','pending') else 'previous_files',{})
    if restoring:expected=state['previous_files']
    if not matches(expected):
        raise ValueError('AdGuard refuses an inconsistent candidate bundle')
    if state.get('status') in ('prepared','pending','rollback_failed') and (restoring or not state.get('runtime_ready')):
        response=subprocess.run(['systemctl','show','okopy-candidate.service','--property=ActiveState','--value'],
                                capture_output=True,text=True,check=True,timeout=3)
        if response.stdout.strip() not in ('inactive','failed'):
            raise ValueError('The previous candidate must stop before AdGuard loads a changed mapping')
    value=configuration(root,files)
    # Cold startup must not silently start with missing requested lists or rely
    # on a DNS path that is itself still starting. Downloads happen before apply.
    for item in [*value['filters'],*value['whitelist_filters']]:
        cache=root/'adguard/data/filters'/(str(item['id'])+'.txt')
        if item['enabled'] and (not cache.is_file() or cache.stat().st_size==0):
            raise ValueError('An enabled AdGuard list is missing from the local cache')
    directory=root/'adguard';directory.mkdir(mode=0o700,exist_ok=True)
    atomic_write(directory/'AdGuardHome.yaml',json.dumps(value,ensure_ascii=False).encode())
    atomic_write(root/'adguard-source.json',json.dumps({'transaction_id':state['id'],
        'policy_sha256':hashlib.sha256(files['applied-policy.json']).hexdigest(),
        'config_sha256':hashlib.sha256(files['config.json']).hexdigest()}).encode())


def wait_ready(root):
    if not configured(root):return
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        try:
            verify_runtime(root)
            return
        except (OSError,ValueError,KeyError):pass
        time.sleep(.1)
    raise RuntimeError('Candidate AdGuard did not load the expected filtering settings')


def api(root,path):
    access=json.loads((root/'adguard-access.json').read_text())
    authorization=base64.b64encode((access['username']+':'+access['password']).encode()).decode()
    request=urllib.request.Request('http://127.0.0.1:'+str(HTTP_PORT)+'/control/'+path,
        headers={'Authorization':'Basic '+authorization})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):raise ValueError('Unexpected local AdGuard redirect')
    with urllib.request.build_opener(NoRedirect).open(request,timeout=.6) as response:raw=response.read(1024*1024+1)
    if len(raw)>1024*1024:raise ValueError('Oversized AdGuard response')
    return json.loads(raw)


def verify_runtime(root):
    from candidate_bundle import read_bundle
    desired=configuration(root,read_bundle(root))
    status=api(root,'status');filtering=api(root,'filtering/status')
    if status.get('protection_enabled') is not True or filtering.get('enabled') is not True:
        raise ValueError('AdGuard protection or filtering is disabled')
    for key in ('filters','whitelist_filters'):
        actual=filtering.get(key) or []
        if {item['id'] for item in actual}!={item['id'] for item in desired[key]}:raise ValueError('AdGuard list IDs differ')
        for expected in desired[key]:
            item=next(row for row in actual if row['id']==expected['id'])
            if any(item.get(k)!=expected[k] for k in ('url','enabled')):
                raise ValueError('AdGuard list configuration differs')
            if expected['enabled'] and item.get('rules_count',0)<=0:
                raise ValueError('An enabled AdGuard list contains no loaded rules')
    if (filtering.get('user_rules') or [])!=desired['user_rules']:raise ValueError('AdGuard custom rules differ')
    dns=api(root,'dns_info')
    for key in ('upstream_dns','fallback_dns','cache_enabled','cache_size','cache_optimistic'):
        if dns.get(key)!=desired['dns'][key]:raise ValueError('AdGuard DNS isolation settings differ')
    actual=api(root,'clients').get('clients',[])
    expected=desired['clients']['persistent']
    if len(actual)!=len(expected) or {c['name'] for c in actual}!={c['name'] for c in expected}:
        raise ValueError('AdGuard resolver identities differ')
    for client in expected:
        loaded=next(c for c in actual if c['name']==client['name'])
        for key in ('ids','upstreams','upstreams_cache_enabled','use_global_settings'):
            if loaded.get(key)!=client[key]:raise ValueError('AdGuard resolver mapping or cache differs')
    return {'blocklists':len(desired['filters']),'allowlists':len(desired['whitelist_filters']),
            'custom_rules':len(desired['user_rules']),'resolvers':len(expected)}


def health(root):
    """Read-only, revision-bound inspection; no network or settings mutation."""
    from candidate_bundle import read_bundle,validate_bundle
    try:
        with (root/'apply.lock').open('r') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
            except BlockingIOError:return {'status':'unknown','detail':'Применяется политика; ожидается новая проверка AdGuard'}
            state=json.loads((root/'transaction.json').read_text())
            if state.get('status') not in ('confirmed','rolled_back','pending') or (
                    state['status']=='pending' and state.get('runtime_ready') is not True):
                return {'status':'unknown','detail':'Применение политики не завершено; проверьте откат'}
            files=read_bundle(root);manifest=validate_bundle(files)
            if not manifest['build_options'].get('adguard_adapter'):
                return {'status':'unknown','detail':'Адаптер AdGuard ещё не подключён к этой политике'}
            expected=state.get('previous_files' if state['status']=='rolled_back' else 'next_files',{})
            if set(expected)!=set(files) or any(hashlib.sha256(b).hexdigest()!=expected[n] for n,b in files.items()):
                return {'status':'unknown','detail':'Файлы политики не совпадают с принятой ревизией'}
            source=json.loads((root/'adguard-source.json').read_text())
            if any(source.get(key)!=hashlib.sha256(files[name]).hexdigest() for key,name in
                   [('policy_sha256','applied-policy.json'),('config_sha256','config.json')]):
                return {'status':'unknown','detail':'AdGuard загружен из другой ревизии политики'}
            counts=verify_runtime(root)
            return {'status':'up','detail':f"Фильтры, исключения, {counts['resolvers']} DNS и отключение общего кэша соответствуют политике. Прохождение DNS проверяется отдельно"}
    except urllib.error.URLError:
        return {'status':'down','detail':'API кандидата AdGuard недоступен; проверьте службу и журнал'}
    except ValueError:
        return {'status':'down','detail':'Настройки AdGuard не соответствуют политике или списки не загружены; проверьте применение и журнал'}
    except (OSError,KeyError,TypeError):
        return {'status':'unknown','detail':'Не удалось достоверно сверить AdGuard; проверьте службу и источник настроек'}


def check_service(root):
    response=subprocess.run(['systemctl','show',UNIT,
        '--property=ExecStartPre,ExecStart,User,DynamicUser,ProtectSystem,ReadWritePaths,ProcSubset,RootDirectory,RootImage,FragmentPath,Transient,NeedDaemonReload'],
        capture_output=True,text=True,check=True,timeout=5)
    fields={}
    for line in response.stdout.splitlines():
        if '=' in line:
            key,value=line.split('=',1);fields[key]=(fields[key]+' ' if key in fields else '')+value
    for command in [str(root/'safe_apply.py')+' recover-before-start',str(root/'adguard_runtime.py')+' prepare']:
        if 'argv[]=/usr/bin/python3 -E -s -B '+command+' ; ignore_errors=no' not in fields.get('ExecStartPre',''):
            raise ValueError('Candidate AdGuard startup recovery hook is missing')
    expected='argv[]='+BINARY+' --config '+str(root/'adguard/AdGuardHome.yaml')+' --work-dir '+str(root/'adguard')+' --no-check-update ;'
    if expected not in fields.get('ExecStart',''):raise ValueError('Unexpected candidate AdGuard command')
    if (fields.get('NeedDaemonReload')!='no' or fields.get('Transient')!='no'
            or fields.get('FragmentPath')!='/etc/systemd/system/'+UNIT
            or fields.get('User','') not in ('','root') or fields.get('DynamicUser')=='yes'
            or fields.get('ProcSubset','') not in ('','all') or fields.get('RootDirectory') or fields.get('RootImage')
            or (fields.get('ProtectSystem')=='strict' and str(root) not in fields.get('ReadWritePaths','').split())):
        raise ValueError('Candidate AdGuard service cannot safely recover its bundle')


def main():
    from safe_apply import ROOT
    if os.geteuid()!=0:raise PermissionError('Root is required')
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['prepare','wait-ready','health'])
    action=parser.parse_args().action
    if action=='prepare':prepare(ROOT)
    elif action=='wait-ready':wait_ready(ROOT)
    else:print(json.dumps(health(ROOT),ensure_ascii=False))


if __name__=='__main__':main()
