"""One durable active-model change with an independent timer and boot recovery."""
import fcntl
import json
import math
import os
from pathlib import Path
import re
import sys
import time
import uuid

from safe_apply import atomic_write,digest
from wireguard_control import read_private
from openconnect_profile import validate
from openconnect_runtime import LinuxBackend,probe_values

ROOT=Path('/var/lib/okopy-openconnect')
NETWORK=Path('/var/lib/okopy-candidate')
PENDING=('prepared','pending','rollback_failed','recovery_required')


def state(root=ROOT):
    if not (root/'transaction.json').exists():return {}
    value=json.loads(read_private(root/'transaction.json'))
    if not isinstance(value,dict) or not re.fullmatch('[0-9a-f]{32}',value.get('id','')):raise ValueError('Журнал подключения VPN повреждён; изменения запрещены')
    from openconnect_control import identifier
    identifier(value.get('connection'))
    try:
        required={'id','connection','status','created_at','deadline','previous_sha256','next_sha256','boot_id','snapshot','target_active','probe','runtime_ready','mutation_started','kind','draft_revision'}
        optional={'finished_at','last_probe','recovering','recovery_reason'}
        if not required.issubset(value) or set(value)-required-optional:raise ValueError()
        if value['status'] not in (*PENDING,'confirmed','rolled_back','recovered','schedule_failed'):raise ValueError()
        if value['kind'] not in ('configuration','runtime'):raise ValueError()
        for key in ('created_at','deadline','finished_at'):
            if key in value and (type(value[key]) not in (int,float) or not math.isfinite(value[key]) or not 0<=value[key]<=253402300799):raise ValueError()
        for key in ('previous_sha256','next_sha256'):
            if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{64}',value[key]):raise ValueError()
        if not isinstance(value['draft_revision'],str) or value['draft_revision'] and not re.fullmatch('[0-9a-f]{64}',value['draft_revision']):raise ValueError()
        if not isinstance(value['boot_id'],str) or not re.fullmatch('[A-Za-z0-9-]{1,64}',value['boot_id']):raise ValueError()
        for key in ('target_active','runtime_ready','mutation_started','recovering'):
            if key in value and type(value[key]) is not bool:raise ValueError()
        snap=value['snapshot']
        if not isinstance(snap,dict) or set(snap) not in ({'active','boot','unit_sha256','script_sha256'},{'active','boot','unit_sha256','script_sha256','companions'}) or type(snap['active']) is not bool or snap['boot'] not in ('enabled','disabled'):raise ValueError()
        for key in ('unit_sha256','script_sha256'):
            if not isinstance(snap[key],str) or not re.fullmatch('[0-9a-f]{64}',snap[key]):raise ValueError()
        companions=snap.get('companions',{})
        if not isinstance(companions,dict) or len(companions)>8:raise ValueError()
        for unit,entry in companions.items():
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,100}\.service',unit):raise ValueError()
            if not isinstance(entry,dict) or set(entry)!={'active','boot','unit_sha256'} or type(entry['active']) is not bool or entry['boot'] not in ('enabled','disabled'):raise ValueError()
            if not isinstance(entry['unit_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',entry['unit_sha256']):raise ValueError()
        if value['probe'] is not None:probe_values(value['probe'])
        elif value['target_active'] or value['kind']=='configuration' and snap['active']:raise ValueError()
    except (ValueError,TypeError,KeyError):raise ValueError('Журнал подключения VPN неполон или повреждён; автоматическое изменение запрещено') from None
    return value


def public(value):return {k:value[k] for k in ('id','connection','status','created_at','deadline','finished_at','runtime_ready','target_active','probe','last_probe','kind','recovery_reason') if k in value}


def runtime_signature(snapshot):
    result={k:snapshot[k] for k in ('active','boot')}
    if 'companions' in snapshot:
        result['companions']={u:{k:v[k] for k in ('active','boot')} for u,v in snapshot['companions'].items()}
    return result


class Transaction:
    def __init__(self,root,binding,name,backend=None,network=NETWORK,model_validator=validate):
        self.root=Path(root);self.name=name;self.binding=binding;self.backend=backend or LinuxBackend(root,binding,name);self.network=network;self.model_validator=model_validator
    def active_path(self):return self.root/(self.name+'.active.json')
    def save(self,s):atomic_write(self.root/'transaction.json',json.dumps(s).encode())
    def data(self,s,kind):
        content=read_private(self.root/'revisions'/s['id']/(kind+'.json'))
        if digest(content)!=s[kind+'_sha256']:raise ValueError('Резервная версия VPN повреждена')
        self.model_validator(json.loads(content),ready=True);return content
    def claim(self,s,original):
        # Publish the durable exclusion while holding the shared network writer lock.
        # Network probes/reconnect run after releasing it, so router health reads continue.
        if self.network is None:
            self.save(s);return
        with (self.network/'apply.lock').open('a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('Сеть сейчас изменяется; VPN не переключался') from None
            general=json.loads(read_private(self.network/'transaction.json'))
            if general.get('status') not in ('confirmed','rolled_back','schedule_failed'):raise ValueError('Сначала завершите применение сетевой политики')
            from wireguard_apply import Transaction as WGTransaction,PENDING as WG_PENDING
            if any(WGTransaction(root).state().get('status') in WG_PENDING for root in (Path('/var/lib/okopy-wireguard'),Path('/var/lib/okopy-amnezia'))):raise ValueError('Сначала завершите изменение WireGuard')
            for other in (ROOT,Path('/var/lib/okopy-trusttunnel')):
                if other!=self.root and state(other).get('status') in PENDING:raise ValueError('Сначала завершите изменение другого VPN')
            if read_private(self.active_path())!=original or self.backend.capture()!=s['snapshot']:raise ValueError('Подключение изменилось во время проверки')
            self.save(s)
    def apply(self,original,proposed,probe,*,target_active=None,draft_revision='',expected_state=None):
        if state(self.root).get('status') in PENDING:raise ValueError('Сначала завершите предыдущую операцию VPN')
        model=self.model_validator(json.loads(proposed),ready=True);self.backend.validate(model)
        snapshot=self.backend.capture();target=snapshot['active'] if target_active is None else target_active
        if type(target) is not bool:raise ValueError('Некорректное целевое состояние службы')
        if target_active is not None:
            if expected_state!=runtime_signature(snapshot):raise ValueError('Состояние службы изменилось; обновите страницу')
            if snapshot['active']==target and all(v['active']==target for v in snapshot.get('companions',{}).values()):raise ValueError('Служба уже находится в выбранном состоянии')
        probe=probe_values(probe) if target or target_active is None and snapshot['active'] else None
        if snapshot['active'] and probe is not None:self.backend.probe(probe)
        if read_private(self.active_path())!=original or self.backend.capture()!=snapshot:raise ValueError('Подключение изменилось во время проверки')
        identifier=uuid.uuid4().hex;directory=self.root/'revisions'/identifier;directory.mkdir(mode=0o700,parents=True)
        for parent in (self.root,self.root/'revisions'):
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        atomic_write(directory/'previous.json',original);atomic_write(directory/'next.json',proposed)
        s={'id':identifier,'connection':self.name,'status':'prepared','created_at':time.time(),'deadline':time.time()+180,
           'previous_sha256':digest(original),'next_sha256':digest(proposed),'boot_id':self.backend.boot_id(),
           'snapshot':snapshot,'target_active':target,'probe':probe,'runtime_ready':False,'mutation_started':False,
           'kind':'configuration' if target_active is None else 'runtime','draft_revision':draft_revision}
        self.claim(s,original)
        try:self.backend.arm(identifier)
        except Exception:
            s['status']='schedule_failed';self.save(s);self.backend.cancel(identifier);raise
        try:
            s.update(status='pending',mutation_started=True);self.save(s)
            self.backend.stop()
            atomic_write(self.active_path(),proposed)
            if target:
                self.backend.start();self.backend.wait_ready(s['next_sha256']);s['last_probe']=self.backend.probe(probe)
            if self.backend.active()!=target or not self.backend.environment_matches(snapshot):raise ValueError('Состояние службы после изменения не подтверждено')
            s['runtime_ready']=True;self.save(s)
        except Exception:
            try:self.rollback(identifier)
            except Exception:pass
            raise
        return public(s)
    def restore_file(self,s):
        original=self.data(s,'previous');current=read_private(self.active_path())
        if digest(current) not in (s['previous_sha256'],s['next_sha256']):
            s.update(status='recovery_required',recovery_reason='active_file_changed');self.save(s)
            raise ValueError('Настройки изменились вне операции; автоматический возврат не перезаписывает новую версию')
        atomic_write(self.active_path(),original)
    def rollback(self,identifier,*,before_start=False):
        s=state(self.root)
        if s.get('id')!=identifier:return {'status':'stale','changed':False}
        if s.get('status') not in PENDING:return public(s)
        if s['connection']!=self.name:raise ValueError('Операция относится к другому подключению')
        # Never stop a service or touch files until backup and ownership are checked.
        try:self.data(s,'previous')
        except (ValueError,OSError):
            s.update(status='recovery_required',recovery_reason='backup_unavailable');self.save(s)
            raise ValueError('Резервная версия недоступна; восстановите её перед возвратом') from None
        if digest(read_private(self.active_path())) not in (s['previous_sha256'],s['next_sha256']):
            s.update(status='recovery_required',recovery_reason='active_file_changed');self.save(s);raise ValueError('Активный файл изменён вне панели; требуется согласование восстановления')
        if not self.backend.environment_matches(s['snapshot']):
            s.update(status='recovery_required',recovery_reason='service_changed');self.save(s);raise ValueError('Служба или сетевой обработчик изменены вне панели; автоматический возврат остановлен')
        try:
            if before_start or s['boot_id']!=self.backend.boot_id():
                self.restore_file(s);s.update(status='recovered',finished_at=time.time(),runtime_ready=False);self.save(s)
                return public(s)
            if s['mutation_started']:
                self.backend.stop();self.restore_file(s)
                # Save a recovery state before start so the launcher admits the old version.
                s['recovering']=True;self.save(s)
                if s['snapshot']['active']:
                    self.backend.start();self.backend.wait_ready(s['previous_sha256'])
                    if s['probe'] is not None:s['last_probe']=self.backend.probe(s['probe'])
                if self.backend.active()!=s['snapshot']['active']:raise ValueError('Прежнее состояние VPN не восстановлено')
            s.update(status='rolled_back',finished_at=time.time(),runtime_ready=False);s.pop('recovering',None);self.save(s)
        except Exception:
            if s.get('status')!='recovery_required':s.update(status='rollback_failed');self.save(s)
            raise
        self.backend.cancel(identifier);return public(s)
    def confirm(self,identifier):
        s=state(self.root)
        if s.get('id')!=identifier or s.get('connection')!=self.name or s.get('status')!='pending' or not s.get('runtime_ready'):
            raise ValueError('Нет готового изменения VPN для подтверждения')
        if self.backend.boot_id()!=s['boot_id'] or time.time()>=s['deadline']-10:raise ValueError('Срок подтверждения истёк или сервер перезапущен')
        if digest(read_private(self.active_path()))!=s['next_sha256'] or not self.backend.environment_matches(s['snapshot']) or self.backend.active()!=s['target_active']:
            raise ValueError('Состояние VPN изменилось; подтверждение запрещено')
        if s['target_active']:self.backend.wait_ready(s['next_sha256']);s['last_probe']=self.backend.probe(s['probe'])
        # The final readiness probe can consume the remaining confirmation time.
        # Do not commit a late result while the timer waits for this lock.
        if time.time()>=s['deadline'] or self.backend.boot_id()!=s['boot_id']:
            raise ValueError('Срок подтверждения истёк во время проверки; действует автоматический возврат')
        if digest(read_private(self.active_path()))!=s['next_sha256'] or not self.backend.environment_matches(s['snapshot']) or self.backend.active()!=s['target_active']:
            raise ValueError('Состояние VPN изменилось во время проверки; подтверждение запрещено')
        s.update(status='confirmed',finished_at=time.time());self.save(s);self.backend.cancel(identifier)
        draft=self.root/(self.name+'.draft.json')
        if draft.exists() and digest(read_private(draft))==s['draft_revision']:
            from safe_apply import remove_created_file
            remove_created_file(draft)
        return public(s)


def rollback_command(identifier):
    from openconnect_control import binding_for
    with (ROOT/'control.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        s=state(ROOT)
        if s.get('id')!=identifier or s.get('status') not in PENDING:return
        name=s['connection'];Transaction(ROOT,binding_for(ROOT,name),name).rollback(identifier)


if __name__=='__main__':
    os.umask(0o077)
    if len(sys.argv)!=3 or sys.argv[1]!='rollback' or not re.fullmatch('[0-9a-f]{32}',sys.argv[2]):raise SystemExit(64)
    rollback_command(sys.argv[2])
