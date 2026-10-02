"""Durable WG file/runtime transaction. Callers hold the shared editor lock."""
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

from safe_apply import atomic_write,digest
from wireguard_profile import parse
from wireguard_runtime import LinuxBackend,probe_values

ROOT=Path('/var/lib/okopy-wireguard')
PROFILES=Path('/etc/wireguard')
PENDING=('prepared','pending','rollback_failed','recovery_required')


class Transaction:
    def __init__(self,root=ROOT,profiles=PROFILES,backend=None,*,parser=parse):
        self.root=root;self.profiles=profiles;self.backend=backend or LinuxBackend(profiles);self.parse=parser
    def state(self):
        path=self.root/'transaction.json'
        if not path.exists():return {}
        from wireguard_control import read_private
        value=json.loads(read_private(path))
        if not isinstance(value,dict) or not re.fullmatch('[0-9a-f]{32}',value.get('id','')):raise ValueError('Журнал WG повреждён; применение запрещено')
        from wireguard_control import profile_name
        profile_name(value.get('profile'))
        return value
    def save(self,s):atomic_write(self.root/'transaction.json',json.dumps(s).encode())
    def file(self,s):return self.profiles/(s['profile']+'.conf')
    def revision(self,s,which):return self.root/'revisions'/s['id']/(which+'.conf')
    def data(self,s,which):
        from wireguard_control import read_private
        content=read_private(self.revision(s,which))
        if digest(content)!=s[which+'_sha256']:raise ValueError('Контрольная сумма резервной версии WireGuard не совпала')
        self.parse(content.decode());return content
    def public(self,s=None):
        s=self.state() if s is None else s
        result={k:s[k] for k in ('id','profile','kind','status','created_at','deadline','finished_at','runtime_ready','active','probe','last_probe','previous_sha256','next_sha256','recovered_before_start','recovery_attempts','recovery_reason') if k in s}
        if s.get('kind')=='runtime':result['boot_changed']=s['boot_id']!=self.backend.boot_id()
        return result
    def apply(self,name,original,proposed,probe,*,draft_revision="",runtime_active=None,expected_state=None):
        old=self.state()
        if old.get('status') in PENDING:raise ValueError('Предыдущая операция WireGuard ещё не подтверждена или не восстановлена')
        model=self.parse(proposed.decode());snapshot=self.backend.capture(name,original)
        runtime=runtime_active is not None
        if runtime:
            if type(runtime_active) is not bool or original!=proposed:raise ValueError('Переключение состояния не должно менять файл WireGuard')
            if expected_state!={k:snapshot[k] for k in ('active','enabled')}:raise ValueError('Состояние службы изменилось. Обновите страницу')
            if runtime_active==snapshot['active']:raise ValueError('Профиль уже находится в выбранном состоянии')
        target={**snapshot,'active':runtime_active} if runtime else snapshot
        self.backend.validate(name,model,activation=target['active'] or (not runtime and snapshot['enabled']=='enabled'))
        if runtime:probe=None
        if target['active'] and not runtime:
            probe=probe_values(probe)
            if snapshot['active']:self.backend.probe(name,probe,self.parse(original.decode()))
            # The same target must remain within the proposed peer routes.
            import ipaddress
            address=ipaddress.ip_address(probe['address'])
            if address in {ipaddress.ip_interface(a).ip for a in model['interface']['Address']}:
                raise ValueError('Контрольный адрес должен находиться за пиром, а не на самом сервере')
            if not any(address.version==n.version and address in n for p in model['peers'] for n in map(ipaddress.ip_network,p['AllowedIPs'])):
                raise ValueError('Контрольный адрес исключён из нового профиля; выберите общий проверяемый адрес')
        elif probe is not None:raise ValueError('Для выключенного состояния проверка трафика неприменима')
        from wireguard_control import read_private
        if read_private(self.profiles/(name+'.conf'))!=original:raise ValueError('Рабочий файл изменился во время проверки')
        identifier=uuid.uuid4().hex;directory=self.root/'revisions'/identifier
        directory.mkdir(mode=0o700,parents=True)
        for parent in (self.root,self.root/'revisions'):
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        atomic_write(directory/'previous.conf',original);atomic_write(directory/'next.conf',proposed)
        s={'id':identifier,'profile':name,'status':'prepared','created_at':time.time(),'deadline':time.time()+180,
           'boot_id':self.backend.boot_id(),'previous_sha256':digest(original),'next_sha256':digest(proposed),
           'kind':'runtime' if runtime else 'file','draft_revision':draft_revision,'snapshot':snapshot,'target':target,'active':target['active'],'runtime_ready':False,'mutation_started':False,'runtime_owner':'previous','probe':probe}
        atomic_write(directory/'metadata.json',json.dumps(s).encode());self.save(s)
        try:self.backend.arm(identifier)
        except Exception:
            s['status']='schedule_failed';self.save(s);self.backend.cancel(identifier);raise
        try:
            s['mutation_started']=True;s['status']='pending';self.save(s)
            if snapshot['active']:self.backend.stop(name)
            s['runtime_owner']='next';self.save(s)
            if not runtime:atomic_write(self.file(s),proposed)
            if s['active']:self.backend.start(name)
            if not self.backend.matches(name,proposed,target):raise ValueError('Новое состояние WireGuard не соответствует файлу')
            s['runtime_ready']=True;self.save(s)
        except Exception:
            try:self.rollback(identifier)
            except Exception:pass
            raise
        return self.public(s)
    def original(self,s):
        # A live file matching the recorded checksum is an equally valid copy.
        # A lost backup must not prevent booting an already restored config.
        from wireguard_control import read_private
        try:
            current=read_private(self.file(s))
            if digest(current)==s['previous_sha256']:
                self.parse(current.decode());return current
        except ValueError:pass
        return self.data(s,'previous')
    def preserve_unexpected(self,s):
        from wireguard_control import read_private
        if not os.path.lexists(self.file(s)):return
        current=read_private(self.file(s))
        if digest(current) not in (s['previous_sha256'],s['next_sha256']):
            atomic_write(self.revision(s,'unexpected-'+uuid.uuid4().hex),current)
    def require_recovery(self,s,reason):
        s['status']='recovery_required';s['recovery_reason']=reason;self.save(s)
        self.backend.cancel(s['id'])
    def rollback(self,identifier,*,manual=False):
        s=self.state()
        if s.get('id')!=identifier:
            self.backend.cancel(identifier);return {'status':'stale','changed':False}
        if s.get('status') not in PENDING:
            self.backend.cancel(identifier);return self.public(s)
        if s.get('kind')=='runtime':return self.rollback_runtime(s,manual=manual)
        if manual:s['recovery_attempts']=0;s.pop('recovery_reason',None)
        elif s['status']=='recovery_required' or s.get('recovery_attempts',0)>=3:
            self.require_recovery(s,s.get('recovery_reason','attempt_limit'));return self.public(s)
        # Verify backup data before touching runtime. An unreadable copy needs
        # repair, not an unlimited timer or another network restart.
        try:original=self.original(s)
        except (ValueError,OSError):
            self.require_recovery(s,'backup_unavailable');raise ValueError('Резервная версия недоступна. Автоматический возврат остановлен; восстановите копию и повторите возврат') from None
        if s['boot_id']!=self.backend.boot_id():
            # A reboot discards transient runtime. Do not turn an originally
            # active but disabled profile back on through a stale callback.
            self.preserve_unexpected(s)
            atomic_write(self.file(s),original);self.file(s).chmod(s['snapshot']['mode'])
            s.update(status='recovered',finished_at=time.time(),runtime_ready=False)
            self.save(s);self.backend.cancel(identifier);return self.public(s)
        if not s['mutation_started']:
            s['status']='rolled_back';s['finished_at']=time.time();self.save(s);self.backend.cancel(identifier);return self.public(s)
        s['recovery_attempts']=s.get('recovery_attempts',0)+1;self.save(s)
        try:
            from wireguard_control import read_private
            try:restored=read_private(self.file(s))==original and self.file(s).stat().st_mode&0o777==s['snapshot']['mode'] and self.backend.matches(s['profile'],original,s['snapshot'],environment=False)
            except ValueError:restored=False
            if not restored:
                running=(original if s.get('runtime_owner','previous')=='previous' else self.data(s,'next')) if s['active'] else None
                self.preserve_unexpected(s)
                if s['active']:
                    atomic_write(self.file(s),running)
                    self.backend.stop(s['profile'])
                atomic_write(self.file(s),original);self.file(s).chmod(s['snapshot']['mode'])
                s['runtime_owner']='previous';s['restore_boot_id']=self.backend.boot_id();self.save(s)
                if s['active']:self.backend.start(s['profile'])
                if not self.backend.matches(s['profile'],original,s['snapshot'],environment=False):raise ValueError('Возврат исходного WireGuard ещё не подтверждён')
            if not self.backend.matches(s['profile'],original,s['snapshot']):
                self.require_recovery(s,'service_changed')
                raise ValueError('Файл и интерфейс возвращены, но настройки systemd изменились извне. Автоматические перезапуски остановлены; согласуйте службу и повторите возврат')
            s['status']='rolled_back';s['finished_at']=time.time();self.save(s)
        except Exception:
            if s.get('status')!='recovery_required':
                if s['recovery_attempts']>=3:self.require_recovery(s,'attempt_limit')
                else:s['status']='rollback_failed';self.save(s)
            raise
        self.backend.cancel(identifier);return self.public(s)
    def confirm(self,identifier):
        s=self.state()
        if s.get('id')!=identifier or s.get('status')!='pending' or not s.get('runtime_ready'):raise ValueError('Нет готовой неподтверждённой операции WireGuard')
        if s['boot_id']!=self.backend.boot_id() or time.time()>=s['deadline']-10:raise ValueError('Срок подтверждения истёк или сервер перезагружен')
        proposed=self.data(s,'next')
        from wireguard_control import read_private
        if read_private(self.file(s))!=proposed or not self.backend.matches(s['profile'],proposed,s.get('target',s['snapshot'])):raise ValueError('Рабочий файл или состояние WireGuard изменились')
        if s['active'] and s.get('kind')!='runtime':s['last_probe']=self.backend.probe(s['profile'],s['probe'],self.parse(proposed.decode()))
        if time.time()>=s['deadline']:raise ValueError('Срок подтверждения истёк во время проверки')
        s['status']='confirmed';s['finished_at']=time.time();self.save(s)
        try:self.backend.cancel(identifier)
        except Exception:pass  # durable confirmation makes every callback inert
        return self.public(s)
    def reconcile_runtime_boot(self):
        """Called under the exclusive editor lock. Never changes network state."""
        s=self.state()
        if s.get('kind')!='runtime' or s.get('status') not in PENDING or s['boot_id']==self.backend.boot_id():return s
        from wireguard_control import read_private
        expected={**s['snapshot'],'active':s['snapshot']['enabled']=='enabled'}
        try:
            content=read_private(self.file(s))
            restored=digest(content)==s['previous_sha256'] and self.backend.matches(s['profile'],content,expected)
        except ValueError:restored=False
        if restored:
            s.update(status='rolled_back',finished_at=time.time(),runtime_ready=False,recovery_reason='boot_policy_restored')
            self.save(s);self.backend.cancel(s['id'])
        return s
    def abandon_runtime(self,identifier):
        s=self.state()
        if s.get('id')!=identifier or s.get('kind')!='runtime' or s.get('status') not in PENDING:
            raise ValueError('Нет незавершённой проверки состояния WireGuard')
        if s['status']!='recovery_required' and s['boot_id']==self.backend.boot_id():
            raise ValueError('До завершения автоматического возврата проверку закрыть нельзя')
        s.update(status='closed_unrestored',finished_at=time.time(),runtime_ready=False,recovery_reason='operator_closed')
        self.save(s);self.backend.cancel(identifier)
        return self.public(s)
    def rollback_runtime(self,s,*,manual=False):
        """Restore same-boot runtime; reboot follows unchanged native boot policy."""
        if s['boot_id']!=self.backend.boot_id():
            result=self.reconcile_runtime_boot()
            if result['status'] in PENDING:
                self.require_recovery(result,'boot_state_mismatch')
                raise ValueError('После перезагрузки состояние не совпало с автозапуском. Проверьте службу; автоматическое переключение остановлено')
            return self.public(result)
        if manual:s['recovery_attempts']=0;s.pop('recovery_reason',None)
        elif s['status']=='recovery_required' or s.get('recovery_attempts',0)>=3:
            self.require_recovery(s,s.get('recovery_reason','attempt_limit'));return self.public(s)
        from wireguard_control import read_private
        try:
            content=read_private(self.file(s))
            if digest(content)!=s['previous_sha256']:raise ValueError()
        except ValueError:
            self.require_recovery(s,'runtime_profile_changed')
            raise ValueError('Файл WireGuard изменён вне панели; автоматическое переключение остановлено') from None
        if not self.backend.environment_matches(s['profile'],s['snapshot']):
            self.require_recovery(s,'service_changed')
            raise ValueError('Настройки systemd изменены вне панели; автоматическое переключение остановлено')
        s['recovery_attempts']=s.get('recovery_attempts',0)+1;self.save(s)
        try:
            if not self.backend.matches(s['profile'],content,s['snapshot'],environment=False):
                s['restore_boot_id']=self.backend.boot_id();self.save(s)
                self.backend.stop(s['profile'])
                if s['snapshot']['active']:self.backend.start(s['profile'])
            if not self.backend.matches(s['profile'],content,s['snapshot'],environment=False):raise ValueError('Прежнее состояние WireGuard ещё не восстановлено')
            if not self.backend.matches(s['profile'],content,s['snapshot']):
                self.require_recovery(s,'service_changed');raise ValueError('Состояние восстановлено, но настройки systemd изменились извне')
            s.update(status='rolled_back',finished_at=time.time(),runtime_ready=False);self.save(s)
        except Exception:
            if s.get('status')!='recovery_required':
                if s['recovery_attempts']>=3:self.require_recovery(s,'attempt_limit')
                else:s['status']='rollback_failed';self.save(s)
            raise
        self.backend.cancel(s['id']);return self.public(s)
    def recover_before_start(self,name):
        # Normal same-boot apply/rollback holds this lock while systemd starts us.
        # Never acquire it in the verified skip path or the parent would deadlock.
        boot=self.backend.boot_id()
        def needed(s):
            if s.get('profile')!=name or s.get('status') not in PENDING:return False
            # Runtime trials never alter the file or native boot policy. Let
            # systemd start normally; only a later observation can prove boot.
            if s.get('kind')=='runtime':return False
            if s.get('restore_boot_id')==boot:
                try:
                    from wireguard_control import read_private
                    return digest(read_private(self.file(s)))!=s['previous_sha256']
                except ValueError:return True
            return s.get('boot_id')!=boot or s.get('status') in ('rollback_failed','recovery_required')
        if not needed(self.state()):return {'status':'unchanged'}
        with (self.root/'control.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            s=self.state()
            if not needed(s):return {'status':'unchanged'}
            try:
                original=self.original(s)
                self.preserve_unexpected(s)
            except (ValueError,OSError):
                self.require_recovery(s,'backup_or_live_file_unavailable');raise
            atomic_write(self.file(s),original);self.file(s).chmod(s['snapshot']['mode'])
            s.update(status='recovered',finished_at=time.time(),recovered_before_start=True,runtime_ready=False)
            self.save(s);self.backend.cancel(s['id']);return self.public(s)


def main(tx=None):
    if os.geteuid()!=0:raise ValueError('Требуются права root')
    action,value=sys.argv[1:]
    tx=tx or Transaction()
    if action=='recover-before-start':
        from wireguard_control import profile_name
        return tx.recover_before_start(profile_name(value))
    if action!='rollback' or not re.fullmatch('[0-9a-f]{32}',value):raise ValueError('Некорректная операция восстановления')
    with (tx.root/'control.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:tx.state()
        except (ValueError,OSError):
            tx.backend.cancel(value)
            raise
        return tx.rollback(value)

if __name__=='__main__':
    try:print(json.dumps({'ok':True,'result':main()}))
    except Exception as error:
        print(json.dumps({'ok':False,'message':str(error) if isinstance(error,ValueError) else 'Восстановление WireGuard не завершено; требуется повторная проверка'}));sys.exit(1)
