"""Durable file restoration journal, tested only against private alternate roots.

No live / application is exposed until the service/boot recovery coordinator
exists. This module uses stdlib only so a frozen copy can undo replacement of
the panel itself. The caller must exclusively own the target tree throughout
prepare/apply/confirm (including service writers), not only this journal lock.
"""
import argparse
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
import urllib.parse


LIVE_ROOT=Path('/')
CAPSULE_ROOT=Path('/var/lib/okopy-recovery')
BACKUP_JOBS_ROOT=Path('/var/lib/okopy-backup/jobs')
BARRIER_ROOT=Path('/var/lib/okopy-recovery-ui')
BARRIER=BARRIER_ROOT/'barrier.json'
BARRIER_LOCK=BARRIER_ROOT/'barrier.lock'
BARRIER_OWNER=0


def sync_directory(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)


def boot_id():
 return str(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()))


def save(path,value):
 temporary=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
 try:
  with temporary.open('xb') as stream:
   os.chmod(temporary,0o600)
   stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode());stream.flush();os.fsync(stream.fileno())
  os.replace(temporary,path);sync_directory(path.parent)
 finally:temporary.unlink(missing_ok=True)


def barrier_update(status,journal):
 """Publish only the HTTP/writer lease, outside every restorable snapshot."""
 if status not in ('inactive','active','verifying_writers','rollback_writers'):
  raise ValueError('Неизвестная фаза независимого барьера')
 if os.geteuid()!=0:raise ValueError('Барьер меняется только root coordinator')
 journal=Path(journal)
 if journal.parent!=CAPSULE_ROOT or not re.fullmatch('[a-f0-9]{32}',journal.name):
  raise ValueError('Барьер привязан к фиксированному журналу')
 group=grp.getgrnam('okopy-recovery').gr_gid
 if BARRIER_ROOT.resolve()!=BARRIER_ROOT or BARRIER_ROOT.is_symlink():raise ValueError('Каталог барьера изменён')
 owner=BARRIER_ROOT.stat()
 if not stat.S_ISDIR(owner.st_mode) or owner.st_uid!=BARRIER_OWNER or owner.st_gid!=group or stat.S_IMODE(owner.st_mode)!=0o750:
  raise ValueError('Каталог барьера должен быть root:okopy-panel 0750')
 if BARRIER.is_symlink():raise ValueError('Файл барьера изменён')
 lock_fd=os.open(BARRIER_LOCK,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
 with os.fdopen(lock_fd,'wb') as lock:
  s=os.fstat(lock.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=BARRIER_OWNER or stat.S_IMODE(s.st_mode)!=0o600:
   raise ValueError('Блокировка барьера изменена')
  fcntl.flock(lock,fcntl.LOCK_EX)
  current=barrier_status()
  if current['job_id'] not in (None,journal.name):
   raise ValueError('Другая операция удерживает независимый барьер')
  if status=='inactive' and current['status']=='inactive':return
  value={'version':1,'status':status,'job_id':journal.name if status!='inactive' else None}
  temporary=BARRIER_ROOT/('.barrier-'+uuid.uuid4().hex)
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(fd,'wb') as out:
    os.fchown(out.fileno(),BARRIER_OWNER,group);os.fchmod(out.fileno(),0o640)
    out.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
    out.flush();os.fsync(out.fileno())
   os.replace(temporary,BARRIER);sync_directory(BARRIER_ROOT)
  finally:temporary.unlink(missing_ok=True)


def barrier_status():
 if BARRIER.is_symlink():raise ValueError('Файл барьера изменён')
 raw=BARRIER.read_bytes();owner=BARRIER.stat()
 if (not stat.S_ISREG(owner.st_mode) or owner.st_uid!=BARRIER_OWNER or
     owner.st_gid!=grp.getgrnam('okopy-recovery').gr_gid or stat.S_IMODE(owner.st_mode)!=0o640
     or len(raw)>512):raise ValueError('Небезопасный файл барьера')
 value=json.loads(raw)
 if (not isinstance(value,dict) or set(value)!={'version','status','job_id'} or value['version']!=1
     or value['status'] not in ('inactive','active','verifying_writers','rollback_writers')
     or (value['status']=='inactive' and value['job_id'] is not None)
     or (value['status']!='inactive' and (not isinstance(value['job_id'],str) or
         not re.fullmatch('[a-f0-9]{32}',value['job_id'])))):
  raise ValueError('Файл барьера повреждён')
 return value


def private_directory(path):
 path=Path(path)
 if not path.is_absolute() or path.resolve()!=path or path==Path('/'):
  raise ValueError('Требуется отдельный абсолютный каталог без ссылок; живой корень запрещён')
 s=path.stat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)&0o077:
  raise ValueError('Каталог должен принадлежать исполнителю и иметь права 0700')
 return path


def authorize_live(root,source,journal,*,check_source=True):
 """Permit only the installer-owned capsule and one checked backup job."""
 root=Path(root);source=Path(source);journal=Path(journal)
 if root!=LIVE_ROOT or root.resolve()!=root or (LIVE_ROOT==Path('/') and os.geteuid()!=0):
  raise ValueError('Живой корень доступен только фиксированному root-координатору')
 if (journal.parent!=CAPSULE_ROOT or not re.fullmatch('[a-f0-9]{32}',journal.name)
     or source.name!='materialized' or source.parent.name!=journal.name
     or source.parent.parent!=BACKUP_JOBS_ROOT):
  raise ValueError('Источник и журнал восстановления должны принадлежать одной фиксированной операции')
 private_directory(CAPSULE_ROOT);private_directory(BACKUP_JOBS_ROOT)
 if check_source:
  private_directory(source.parent);private_directory(source)
 return root


def protected_live_path(name):
 name=relative(name)
 fixed=('var/lib/okopy-recovery','var/lib/okopy-recovery-ui','var/lib/okopy-backup/jobs',
        'var/lib/okopy-backup/control.lock',
        'opt/okopy-recovery-ui','opt/okopy-panel/proxy/Caddyfile',
        'var/www/certbot/.okopy-panel','var/www/certbot/.farvater-recovery',
        'etc/sudoers.d/farvater-recovery-ui',
        'etc/farvater/recovery-ui.env',
        'etc/systemd/system/infrastructure-recovery-ui.service',
        'usr/local/lib/systemd/system/infrastructure-recovery-ui.service')
 if any(name==base or name.startswith(base+'/') for base in fixed):
  return True
 if name.startswith(('usr/local/sbin/farvater-recovery-','etc/cron.d/farvater-recovery-')):return True
 if name=='etc/letsencrypt/renewal-hooks/deploy/infrastructure-recovery-tls.sh':return True
 if name.startswith('usr/local/lib/systemd/system/'):
  part=name.removeprefix('usr/local/lib/systemd/system/')
  return (part.startswith('infrastructure-recovery-') or '/90-infrastructure-recovery-' in part
          or part in ('okopy-panel.service.d/80-infrastructure-recovery-access.conf',
                      'okopy-routing.service.d/80-infrastructure-recovery-access.conf'))
 return False


def relative(name):
 if (not isinstance(name,str) or not name or len(name)>1024 or '\\' in name
     or any(ord(c)<32 for c in name) or PurePosixPath(name).is_absolute()
     or str(PurePosixPath(name))!=name or any(p in ('.','..') for p in name.split('/'))):
  raise ValueError('Некорректный относительный путь восстановления')
 if any(p.startswith('.okopy-restore-') for p in name.split('/')):
  raise ValueError('Путь занят пространством временных файлов восстановления')
 return name


def path_at(root,name):
 """Never follow a link in a managed ancestor, including during rollback."""
 relative(name)
 p=root
 for part in Path(name).parts[:-1]:
  p=p/part
  try:s=p.lstat()
  except FileNotFoundError:continue
  if not stat.S_ISDIR(s.st_mode):raise ValueError('Родитель пути не является обычным каталогом')
 return root/name


def inspect(path,objects=None):
 if not hasattr(os,'listxattr'):raise ValueError('Журнал восстановления требует Linux с проверкой xattr')
 try:s=path.lstat()
 except FileNotFoundError:return {'kind':'absent'}
 if os.listxattr(path,follow_symlinks=False):raise ValueError('Файловые ACL/xattr пока не поддержаны восстановлением')
 r={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}
 if stat.S_ISDIR(s.st_mode):return {**r,'kind':'directory'}
 if stat.S_ISLNK(s.st_mode):return {**r,'kind':'symlink','target':os.readlink(path)}
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise ValueError('Специальные файлы и hardlink требуют отдельного восстановления')
 if s.st_size>256*1024*1024:raise ValueError('Файл слишком велик для журнала')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 temporary=None
 try:
  with os.fdopen(fd,'rb') as source:
   start=os.fstat(source.fileno())
   if (start.st_dev,start.st_ino,start.st_ctime_ns)!=(s.st_dev,s.st_ino,s.st_ctime_ns):raise ValueError('Файл изменился во время подготовки')
   digest=hashlib.sha256();size=0
   if objects is not None:
    handle,temporary=tempfile.mkstemp(prefix='.object-',dir=objects);destination=os.fdopen(handle,'wb')
   else:destination=None
   try:
    while data:=source.read(1024*1024):
     size+=len(data)
     if size>s.st_size:raise ValueError('Файл вырос во время подготовки')
     digest.update(data)
     if destination:destination.write(data)
    end=os.fstat(source.fileno())
    if size!=s.st_size or (end.st_mtime_ns,end.st_ctime_ns,end.st_size)!=(start.st_mtime_ns,start.st_ctime_ns,start.st_size):raise ValueError('Файл изменился во время подготовки')
    if destination:destination.flush();os.fsync(destination.fileno())
   finally:
    if destination:destination.close()
   if objects is not None:
    os.replace(temporary,objects/digest.hexdigest());temporary=None
   return {**r,'kind':'file','size':size,'sha256':digest.hexdigest()}
 finally:
  if temporary:Path(temporary).unlink(missing_ok=True)


def prepare(root,source,current_paths,desired_paths,journal,*,live=False):
 """Snapshot BOTH directions before making any target mutation.

 current_paths is the explicitly managed current scope, never an inferred rm -r.
 Unknown contents in removed directories block preparation.
 """
 journal=Path(journal)
 if live:root=authorize_live(root,source,journal)
 else:root=private_directory(root);source=private_directory(source);private_directory(journal.parent)
 source=Path(source)
 if journal.exists() or journal.is_symlink():raise ValueError('Журнал уже существует')
 pairs=((journal,source),) if live else ((root,source),(journal,root),(journal,source))
 if any(a==b or a.is_relative_to(b) or b.is_relative_to(a) for a,b in pairs):
  raise ValueError('Каталоги источника, назначения и журнала должны быть независимыми')
 current={relative(n) for n in current_paths};desired={relative(n) for n in desired_paths}
 if live and any(protected_live_path(name) for name in current|desired):
  raise ValueError('Снимок затрагивает независимую область восстановления')
 if not current|desired or len(current|desired)>20000:raise ValueError('Некорректный объём восстановления')
 names=set(current|desired)
 for name in tuple(names):names.update(str(p) for p in Path(name).parents if str(p)!='.')
 # The final capsule name is published only after plan, objects, runtime and
 # state are durable. A SIGKILL during preparation leaves an unpublished sibling
 # that no status/start/boot path can mistake for an executable journal.
 working=journal.with_name('.preparing-'+journal.name+'-'+uuid.uuid4().hex)
 working.mkdir(mode=0o700);objects=working/'objects';objects.mkdir(mode=0o700)
 try:
  (working/'lock').touch(mode=0o600)
  entries={}
  for name in sorted(names):
   old=inspect(path_at(root,name),objects)
   new=inspect(path_at(source,name),objects) if name in desired else {'kind':'absent'}
   if name not in current|desired:new=old
   if name in desired and new['kind']=='absent':raise ValueError('В подготовленном дереве отсутствует выбранный путь')
   if name not in desired and any(n.startswith(name+'/') for n in desired):
    new=old if old['kind']=='directory' else inspect(path_at(source,name),objects)
    if new['kind']!='directory':raise ValueError('Отсутствует родительский каталог')
   if old['kind']!='absent' and new['kind']!='absent' and (old['kind']=='directory')!=(new['kind']=='directory'):
    raise ValueError('Замена каталога файлом или ссылкой требует отдельного плана')
   entries[name]={'before':old,'after':new}
  for name,entry in entries.items():
   if entry['before']['kind']=='directory' and entry['after']['kind']=='absent':
    for child in path_at(root,name).iterdir():
     key=str(child.relative_to(root))
     if key not in entries or entries[key]['after']['kind']!='absent':raise ValueError('Удаляемый каталог содержит данные вне выбранного состава')
   for p in Path(name).parents:
    if str(p)!='.' and entries[str(p)]['after']['kind'] not in ('directory','absent'):
     raise ValueError('Путь назначения проходит через файл или ссылку')
  # Reserve all new files plus the largest rollback replacement. Looking only
  # at one file can exhaust the disk halfway and also prevent rollback writes.
  sizes=[e[side].get('size',0) for e in entries.values() for side in ('before','after')]
  if sum(sizes)>2*1024**3:raise ValueError('Набор слишком велик для журнала')
  required=sum(e['after'].get('size',0) for e in entries.values())+max((e['before'].get('size',0) for e in entries.values()),default=0)+64*1024**2
  if shutil.disk_usage(root).free<required:raise ValueError('Недостаточно места для замены и возврата файлов')
  sync_directory(objects)
  # Freeze the stdlib-only recovery runtime before touching any destination.
  # A later panel/release replacement cannot change how this journal is undone.
  with (working/'rollback.py').open('xb') as runtime:
   os.chmod(working/'rollback.py',0o400);runtime.write(Path(__file__).read_bytes());runtime.flush();os.fsync(runtime.fileno())
  save(working/'plan.json',{'version':1,'root':str(root),'source':str(source) if live else None,'live_root':live,'boot_id':boot_id(),'entries':entries})
  save(working/'state.json',{'status':'prepared'})
  sync_directory(working)
  if journal.exists() or journal.is_symlink():raise ValueError('Журнал появился во время подготовки')
  os.rename(working,journal);sync_directory(journal.parent)
 except BaseException:
  if working.exists():shutil.rmtree(working)
  raise
 return {'entries':len(entries),'status':'prepared','live_root_supported':live}


@contextmanager
def locked(journal):
 journal=private_directory(journal)
 with (journal/'lock').open('r') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  plan=json.loads((journal/'plan.json').read_text());state=json.loads((journal/'state.json').read_text())
  if plan.get('version')!=1:raise ValueError('Неизвестный журнал')
  root=authorize_live(plan['root'],plan.get('source'),journal,check_source=False) if plan.get('live_root') else private_directory(plan['root'])
  yield journal,plan,root,state


def status(journal):
 with locked(journal) as (journal,plan,root,state):
  if plan.get('live_root') and state.get('status') in ('confirmed','rolled_back'):
   if barrier_status()['job_id'] in (None,journal.name):barrier_update('inactive',journal)
  result={'status':state.get('status','unknown'),'id':journal.name,'live_root':bool(plan.get('live_root'))}
  if (journal/'guard.json').exists():
   guard=guard_info(journal);result['timer']=guard['timer']
   if plan.get('live_root') and state.get('status')=='prepared':
    try:armed=subprocess.run(['systemctl','is-active','--quiet',guard['timer']+'.timer'],
                             capture_output=True,timeout=5).returncode==0
    except (OSError,subprocess.SubprocessError):armed=False
    if not armed:
     result['status']='recovery_required';result['guard_registration']='missing'
    else:
     result['status']='start_scheduled';result['guard_registration']='active'
     result['seconds_left']=max(0,round(guard['deadline']-time.monotonic()))
   else:result['seconds_left']=max(0,round(guard['deadline']-time.monotonic()))
  if (journal/'boot-guard.json').exists():result['boot_guard']=json.loads((journal/'boot-guard.json').read_text()).get('status')
 if result['live_root'] and result['status'] in ('confirmed','rolled_back') and 'timer' in result:
  try:disarm_guard_timer(journal)
  except (ValueError,OSError,subprocess.SubprocessError):result['timer_cleanup_pending']=True
 return result


def verify_objects(journal,entries,side):
 for r in (entry[side] for entry in entries.values()):
  if r['kind']=='file':
   data=inspect(journal/'objects'/r['sha256'])
   if data['kind']!='file' or (data['size'],data['sha256'])!=(r['size'],r['sha256']):raise ValueError('Повреждён сохранённый образ файла')


def service_name(name):
 if not isinstance(name,str) or len(name)>255 or not re.fullmatch(r'[A-Za-z0-9_:][A-Za-z0-9_.:@\\-]*\.(service|timer|socket|path)',name):
  raise ValueError('Некорректное имя управляемой службы восстановления')
 return name


def service_capture(names):
 names=sorted({service_name(n) for n in names})
 if not names:return {}
 p=subprocess.run(['systemctl','show',*names,'-p','Id,LoadState,ActiveState,SubState,UnitFileState,Type,TriggeredBy'],
                  capture_output=True,text=True,check=True,timeout=10)
 units={}
 for block in p.stdout.strip().split('\n\n'):
  values=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
  name=service_name(values.get('Id'));units[name]=values
 if set(units)!=set(names):raise ValueError('Состав служб изменился или содержит несогласованный alias')
 return units


def service_targets(registry):
 """Normalize observed states; timer-triggered oneshots are not manual jobs."""
 if not isinstance(registry,dict) or len(registry)>200:raise ValueError('Некорректный реестр восстановления служб')
 result={}
 for name,u in registry.items():
  service_name(name)
  if u.get('Id')!=name:raise ValueError('Идентификатор службы не совпал')
  state=u.get('ActiveState');load=u.get('LoadState');boot=u.get('UnitFileState','')
  triggers=u.get('TriggeredBy','').split()
  if any(service_name(n) not in registry for n in triggers):raise ValueError('Службу активирует механизм вне состава восстановления')
  if load not in ('loaded','masked','not-found'):raise ValueError('Описание службы повреждено или не загружено')
  if boot not in ('enabled','disabled','static','indirect','masked','enabled-runtime','masked-runtime','linked','linked-runtime','alias',''):
   raise ValueError('Не поддержан режим автозапуска службы')
  triggered=u.get('Type')=='oneshot' and bool(triggers)
  if state not in ('active','inactive','failed') and not (triggered and state in ('activating','deactivating')):
   raise ValueError('Дождитесь устойчивого состояния службы')
  mode='triggered' if triggered else 'start' if state=='active' else 'stop'
  if mode=='start' and load!='loaded':raise ValueError('Нельзя восстановить запущенную, но скрытую или отсутствующую службу')
  result[name]={'mode':mode,'boot':boot,'load':load,'triggers':triggers}
 return result


def health_checks(values):
 if not isinstance(values,list) or not 1<=len(values)<=20:raise ValueError('Нужны контрольные HTTP/HTTPS-проверки восстановления')
 result=[]
 for value in values:
  if not isinstance(value,dict) or set(value)!={'url','codes','timeout'}:raise ValueError('Некорректная проверка восстановления')
  url=value['url'];codes=value['codes'];timeout=value['timeout']
  if not isinstance(url,str) or len(url)>2048 or any(c.isspace() or ord(c)<32 for c in url):raise ValueError('Некорректный URL проверки')
  parsed=urllib.parse.urlsplit(url)
  if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query:
   raise ValueError('Проверка не принимает реквизиты, query и fragment в URL')
  if parsed.port is not None and not 1<=parsed.port<=65535:raise ValueError('Некорректный порт проверки')
  if not isinstance(codes,list) or not 1<=len(codes)<=8 or any(type(c) is not int or not 200<=c<=499 for c in codes):raise ValueError('Некорректные ожидаемые HTTP-коды')
  if type(timeout) is not int or not 1<=timeout<=10:raise ValueError('Время одной проверки должно быть от 1 до 10 секунд')
  result.append({'url':url,'codes':sorted(set(codes)),'timeout':timeout})
 if sum(c['timeout'] for c in result)>60:raise ValueError('Общий срок HTTP-проверок превышает минуту')
 return result


def attach_services(journal,desired,*,allowed_units,before_checks,after_checks,mutable_paths=(),deferred_writers=()):
 """Bind the approved service scope to a PREPARED file journal, before arming.

 allowed_units comes from the trusted current and signed snapshot scope, not a
 browser field. Source files remain isolated; this is not live-root enablement.
 """
 allowed={service_name(n) for n in allowed_units};desired=service_targets(desired)
 deferred={service_name(n) for n in deferred_writers}
 if not deferred<=set(desired) or any(desired[n]['mode']!='start' for n in deferred):
  raise ValueError('Отложенные службы записи должны запускаться в целевом состоянии')
 if not desired or not set(desired)<=allowed:raise ValueError('Службы вышли за согласованный состав восстановления')
 with locked(journal) as (journal,plan,root,state):
  if state['status']!='prepared' or (journal/'guard.json').exists() or 'services' in plan:raise ValueError('Состав уже зафиксирован или операция началась')
  if (journal/'rollback.py').read_bytes()!=Path(__file__).read_bytes():raise ValueError('Версия координатора изменилась; пересоздайте подготовку')
  current=service_targets(service_capture(allowed))
  paths=sorted({relative(n) for n in mutable_paths})
  if any(n not in plan['entries'] for n in paths):raise ValueError('Рабочий файл вне состава восстановления')
  if any(plan['entries'][n]['after']['kind']!='file' for n in paths):raise ValueError('Изменяемыми могут быть только явно сохранённые обычные файлы')
  plan['services']={'before':current,'after':desired,'before_checks':health_checks(before_checks),'after_checks':health_checks(after_checks),'mutable_paths':paths,
                    'deferred_writers':sorted(deferred)}
  save(journal/'plan.json',plan)
 return {'services':len(allowed),'status':'prepared'}


def stop_services(services):
 names=set(services['before'])|set(services['after'])
 actual=service_capture(names)
 # First disable sources of automatic activation, then their workers.
 triggers=sorted(n for n in names if n.endswith(('.timer','.socket','.path')) and actual[n]['LoadState']!='not-found')
 others=sorted(n for n in names if n not in triggers and actual[n]['LoadState']!='not-found')
 for group in (triggers,others):
  if group:subprocess.run(['systemctl','stop',*group],capture_output=True,check=True,timeout=60)
 if any(u['ActiveState'] not in ('inactive','failed') for u in service_capture(names).values()):raise ValueError('Не все службы остановлены перед заменой файлов')


def service_matches(services,side,*,pending=False):
 target=services[side];names=set(services['before'])|set(services['after']);actual=service_capture(names)
 for name,u in actual.items():
  expected=target.get(name,{'mode':'stop','boot':None})
  if pending and side=='after' and name in services.get('deferred_writers',()):expected={**expected,'mode':'stop'}
  if expected['boot'] is not None and u.get('UnitFileState','')!=expected['boot']:return False
  if expected['mode']=='start' and u['ActiveState']!='active':return False
  if expected['mode']=='stop' and u['ActiveState'] not in ('inactive','failed'):return False
  if expected['mode']=='triggered' and u['ActiveState'] not in ('inactive','active','activating','deactivating'):return False
 return True


def start_services(services,side,*,pending=False):
 subprocess.run(['systemctl','daemon-reload'],capture_output=True,check=True,timeout=15)
 if services.get('boot_gate'):verify_boot_gate(services,services['boot_gate'],before_start=False,side=side)
 target=services[side];actual=service_capture(target)
 if any(actual[n].get('UnitFileState','')!=u['boot'] for n,u in target.items()):
  raise ValueError('Автозапуск или маски не совпали с восстановленными файлами')
 # systemd owns dependency ordering. Do not hand-sort VPN names or protocols.
 names=sorted(n for n,u in target.items() if u['mode']=='start' and not (pending and side=='after' and n in services.get('deferred_writers',())))
 if names:subprocess.run(['systemctl','start',*names],capture_output=True,check=True,timeout=60)
 if not service_matches(services,side,pending=pending):raise ValueError('Не восстановлено ожидаемое состояние служб')


def start_deferred_services(services):
 names=services.get('deferred_writers',())
 if names:subprocess.run(['systemctl','start',*names],capture_output=True,check=True,timeout=60)
 if not service_matches(services,'after'):raise ValueError('Службы панели не подтвердили запуск перед восстановлением')


def verify_boot_gate(services,gate,*,before_start=True,side='before'):
 """The caller must install an independent Requires+After barrier on EVERY unit.

 Checking an active oneshot barrier prevents this API from queueing starts in a
 running service group, or from recursively waiting for its own startup job.
 """
 service_name(gate)
 names=set(services['before'])|set(services['after'])
 if gate in names:raise ValueError('Загрузочный guard не может входить в заменяемый состав')
 state=service_capture([gate])[gate]
 if state['ActiveState']!=('activating' if before_start else 'active') or state['Type']!='oneshot':raise ValueError('Загрузочный guard не удерживает запуск служб')
 p=subprocess.run(['systemctl','show',*sorted(names),'-p','Id,Requires,After,ActiveState,LoadState'],capture_output=True,text=True,check=True,timeout=10)
 found={}
 for block in p.stdout.strip().split('\n\n'):
  u=dict(line.split('=',1) for line in block.splitlines() if '=' in line);found[u.get('Id')]=u
 if set(found)!=names:raise ValueError('Не подтверждён полный состав загрузочной защиты')
 for name,u in found.items():
  if before_start and u.get('ActiveState') not in ('inactive','failed'):raise ValueError('Служба уже запущена до завершения загрузочного возврата')
  # Returning to an originally absent/masked unit removes its dependencies
  # along with its executable definition. It cannot start and needs no gate.
  old=services[side].get(name,{'mode':'stop','load':'not-found'})
  if u.get('LoadState') in ('not-found','masked') and old.get('load')==u['LoadState'] and old.get('mode')=='stop':continue
  if u.get('LoadState')!='loaded' or gate not in u.get('Requires','').split() or gate not in u.get('After','').split():raise ValueError('Служба не защищена загрузочным guard')


def check_persistent_guard(journal,plan,side='before'):
 path=journal/'boot-guard.json'
 if not path.exists():
  if plan.get('live_root'):raise ValueError('Для живого корня не установлена загрузочная защита')
  return
 info=json.loads(path.read_text())
 gate=plan.get('services',{}).get('boot_gate')
 if info.get('status')!='installed' or not gate or gate!=info.get('gate'):raise ValueError('Постоянная защита ещё не установлена или уже удаляется')
 verify_boot_gate(plan['services'],gate,before_start=False,side=side)


def queue_boot_services(services,gate):
 """Reload restored definitions and reconcile QUEUED jobs without waiting.

 Queued jobs may reflect the interrupted snapshot's autostart links. Explicitly
 cancel unwanted jobs and queue previously running units. Their verified gate
 remains activating until this caller exits successfully. This is not health
 acceptance; actual readiness must be verified after boot.
 """
 subprocess.run(['systemctl','daemon-reload'],capture_output=True,check=True,timeout=15)
 verify_boot_gate(services,gate)
 target=services['before'];names=set(target)|set(services['after']);actual=service_capture(names)
 if any(actual[n].get('UnitFileState','')!=u['boot'] for n,u in target.items()):raise ValueError('Автозапуск не восстановлен перед загрузкой')
 # daemon-reload cancels starts of units removed by the restored snapshot.
 # systemctl stop on a now-absent unit returns exit 5; do not misreport a
 # successful removal as a failed recovery. Reject any surviving queued job.
 for n,u in actual.items():
  if u['LoadState']=='not-found':
   job=subprocess.run(['systemctl','show',n,'--property=Job','--value'],capture_output=True,text=True,check=True,timeout=5).stdout.strip()
   if job:raise ValueError('У удалённой службы осталась незавершённая загрузочная операция')
 stopped=sorted(n for n in names if target.get(n,{}).get('mode')!='start' and actual[n]['LoadState']!='not-found')
 started=sorted(n for n,u in target.items() if u['mode']=='start')
 if stopped:subprocess.run(['systemctl','stop','--no-block',*stopped],capture_output=True,check=True,timeout=10)
 if started:subprocess.run(['systemctl','start','--no-block',*started],capture_output=True,check=True,timeout=10)


def run_checks(checks):
 # curl's deadline also bounds resolution; a Python getaddrinfo call may not.
 # No rc file, proxy environment, or redirects. Response content is discarded.
 results=[]
 for check in checks:
  deadline=time.monotonic()+check['timeout'];code=None
  while time.monotonic()<deadline:
   try:
    remaining=max(.1,deadline-time.monotonic())
    p=subprocess.run(['/usr/bin/curl','--disable','--noproxy','*','--silent','--max-time',str(remaining),
                      '--connect-timeout',str(min(3,remaining)),'--output','/dev/null','--write-out','%{http_code}',
                      '--proto','=http,https','--url',check['url']],capture_output=True,text=True,timeout=remaining+.5)
    code=int(p.stdout) if p.returncode==0 and p.stdout.isdigit() else None
   except (OSError,ValueError,subprocess.TimeoutExpired):code=None
   if code in check['codes']:break
   time.sleep(min(.2,max(0,deadline-time.monotonic())))
  else:raise ValueError('Контрольный HTTP/HTTPS-доступ не восстановлен')
  results.append({'http_code':code})
 return results


def check_window(journal,plan):
 if plan['boot_id']!=boot_id():raise ValueError('Операция начата до перезагрузки')
 if (journal/'cancel.json').exists():raise ValueError('Независимый guard уже начал возврат')
 if (journal/'guard.json').exists() and time.monotonic()>=guard_info(journal)['deadline']:
  raise ValueError('Срок подтверждения истёк; возврат нельзя отменить')


def replace_entry(root,name,record,journal):
 path=path_at(root,name);kind=record['kind']
 if kind=='absent':
  try:s=path.lstat()
  except FileNotFoundError:return
  if stat.S_ISDIR(s.st_mode):path.rmdir()
  else:path.unlink()
 elif kind=='directory':
  if not path.exists():path.mkdir(mode=0o700)
  if not stat.S_ISDIR(path.lstat().st_mode):raise ValueError('Ожидался обычный каталог')
  os.chown(path,record['uid'],record['gid']);os.chmod(path,record['mode'])
 else:
  # Fixed private sibling is removed by the next attempt after interruption.
  # Its name is reserved during prepare; never remove an arbitrary user file.
  temporary=path.with_name('.okopy-restore-'+hashlib.sha256(name.encode()).hexdigest())
  temporary.unlink(missing_ok=True)
  try:
   if kind=='symlink':
    temporary.symlink_to(record['target']);os.lchown(temporary,record['uid'],record['gid'])
   elif kind=='file':
    fd=os.open(journal/'objects'/record['sha256'],os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as src,temporary.open('xb') as dst:
     os.chmod(temporary,0o600);shutil.copyfileobj(src,dst,1024*1024)
     dst.flush();os.fchown(dst.fileno(),record['uid'],record['gid']);os.fchmod(dst.fileno(),record['mode']);os.fsync(dst.fileno())
   else:raise ValueError('Неизвестный тип записи')
   os.replace(temporary,path)
  finally:temporary.unlink(missing_ok=True)
 sync_directory(path.parent)


def install(journal,root,entries,side,step,force=()):
 # Parents first; links/files second; removals last. Modes finalized bottom-up.
 # Identical files are already verified before apply. Do not rewrite all of a
 # venv or chmod shared ancestors (e.g. etc) merely because they are in a backup.
 entries={name:e for name,e in entries.items() if e['before']!=e['after'] or name in force}
 ordered=sorted(entries,key=lambda n:(len(Path(n).parts),n))
 # A process may have died after creating an atomic sibling but before rename.
 # apply reserved these names while still in the prepared state.
 for name in ordered:
  temporary=path_at(root,name).with_name('.okopy-restore-'+hashlib.sha256(name.encode()).hexdigest())
  try:temporary.unlink()
  except FileNotFoundError:pass
  else:sync_directory(temporary.parent)
 for name in ordered:
  r=entries[name][side]
  if r['kind']=='directory':
   path=path_at(root,name)
   try:current=path.lstat()
   except FileNotFoundError:
    path.mkdir(mode=0o700);sync_directory(path.parent);step(name)
   else:
    if not stat.S_ISDIR(current.st_mode):raise ValueError('Ожидался обычный каталог')
 for name in ordered:
  r=entries[name][side]
  if r['kind'] in ('file','symlink'):replace_entry(root,name,r,journal);step(name)
 for name in reversed(ordered):
  r=entries[name][side]
  if r['kind']=='absent':replace_entry(root,name,r,journal);step(name)
  elif r['kind']=='directory':replace_entry(root,name,r,journal);step(name)


def apply(journal,step=lambda name:None):
 with locked(journal) as (journal,plan,root,state):
  if plan.get('live_root'):
   barrier=barrier_status()
   if barrier['status']!='active' or barrier['job_id']!=journal.name:
    raise ValueError('Основной HTTPS доступ не закрыт независимым барьером')
  check_window(journal,plan)
  check_persistent_guard(journal,plan)
  if state['status']!='prepared':raise ValueError('Этот журнал уже применялся; сначала выполните возврат')
  for name,entry in plan['entries'].items():
   if inspect(path_at(root,name))!=entry['before']:raise ValueError('Назначение изменилось после подготовки')
   temporary=path_at(root,name).with_name('.okopy-restore-'+hashlib.sha256(name.encode()).hexdigest())
   if temporary.exists() or temporary.is_symlink():raise ValueError('Служебное имя занято чужим файлом')
  verify_objects(journal,plan['entries'],'before');verify_objects(journal,plan['entries'],'after')
  services=plan.get('services')
  if services:
   if not service_matches(services,'before'):raise ValueError('Службы изменились после подготовки')
   run_checks(services['before_checks'])
  check_window(journal,plan)
  save(journal/'state.json',{'status':'applying'})
  if services:stop_services(services)
  install(journal,root,plan['entries'],'after',step)
  if services:
   # Establish file correctness before services may legitimately update caches.
   if any(inspect(path_at(root,n))!=e['after'] for n,e in plan['entries'].items()):raise ValueError('Файлы снимка не прошли проверку перед запуском')
   save(journal/'state.json',{'status':'starting_services'})
   start_services(services,'after',pending=bool(services.get('deferred_writers')));run_checks(services['after_checks'])
  check_window(journal,plan)
  save(journal/'state.json',{'status':'awaiting_confirmation'})
 return {'status':'awaiting_confirmation'}


def rollback(journal,step=lambda name:None,*,before_start=False,boot_gate=None):
 with locked(journal) as (journal,plan,root,state):
  if state['status'] in ('confirmed','rolled_back'):
   result=state
  elif state['status']=='prepared':
   if (journal/'guard.json').exists():save(journal/'cancel.json',{'cancelled':True})
   save(journal/'state.json',{'status':'rolled_back'})
   if plan.get('live_root'):barrier_update('inactive',journal)
   result={'status':'rolled_back'}
  else:
   if state['status'] not in ('applying','starting_services','awaiting_confirmation','rolling_back'):raise ValueError('Неизвестное состояние возврата')
   verify_objects(journal,plan['entries'],'before')
   services=plan.get('services')
   if services and before_start:verify_boot_gate(services,boot_gate)
   save(journal/'state.json',{'status':'rolling_back'})
   if services and not before_start:stop_services(services)
   install(journal,root,plan['entries'],'before',step,services['mutable_paths'] if services else ())
   if plan.get('live_root'):barrier_update('rollback_writers',journal)
   if services and not before_start:
    start_services(services,'before');run_checks(services['before_checks'])
   elif services:queue_boot_services(services,boot_gate)
   save(journal/'state.json',{'status':'rolled_back'})
   if plan.get('live_root'):barrier_update('inactive',journal)
   result={'status':'rolled_back'}
  disarm=bool(plan.get('live_root') and (journal/'guard.json').exists())
 if disarm:
  try:disarm_guard_timer(journal)
  except (ValueError,OSError,subprocess.SubprocessError):result={**result,'timer_cleanup_pending':True}
 return result


def confirm(journal):
 started_deferred=False
 try:
  with locked(journal) as (journal,plan,root,state):
   check_window(journal,plan)
   check_persistent_guard(journal,plan,'after')
   if state['status']!='awaiting_confirmation':raise ValueError('Нет ожидающего подтверждения восстановления')
   services=plan.get('services');mutable=set(services['mutable_paths']) if services else set()
   if any(inspect(path_at(root,n))!=e['after'] for n,e in plan['entries'].items() if n not in mutable):raise ValueError('Файлы не соответствуют восстановленному снимку')
   if services:
    pending=bool(services.get('deferred_writers'))
    if not service_matches(services,'after',pending=pending):raise ValueError('Состояние служб не соответствует снимку')
    run_checks(services['after_checks'])
    if pending:
     if plan.get('live_root'):barrier_update('verifying_writers',journal)
     started_deferred=True
     start_deferred_services(services)
    if not service_matches(services,'after'):raise ValueError('Службы изменились во время контрольной проверки')
    if any(inspect(path_at(root,n))!=e['after'] for n,e in plan['entries'].items() if n not in mutable):raise ValueError('Настройки изменились во время контрольной проверки')
   check_window(journal,plan)
   save(journal/'state.json',{'status':'confirmed'})
 except Exception:
  if started_deferred:
   try:rollback(journal)
   except Exception:pass  # Independent timer remains armed if immediate return fails.
  raise
 # Commit first. A concurrently firing guard then sees confirmed and cannot undo.
 if (Path(journal)/'guard.json').exists():
  info=guard_info(journal)
  subprocess.run(['systemctl','stop',info['timer']+'.timer'],check=True,capture_output=True,timeout=10)
 with locked(journal) as (journal,plan,root,state):
  if plan.get('live_root') and state['status']=='confirmed':barrier_update('inactive',journal)
 return {'status':'confirmed'}


def guard_info(journal):
 info=json.loads((Path(journal)/'guard.json').read_text())
 token=info.get('token','')
 if len(token)!=32 or any(c not in '0123456789abcdef' for c in token):raise ValueError('Некорректный идентификатор guard')
 if info.get('timer')!='okopy-restore-undo-'+token or info.get('worker')!='okopy-restore-worker-'+token:
  raise ValueError('Службы guard не соответствуют журналу')
 if type(info.get('deadline')) not in (float,int) or not math.isfinite(info['deadline']) or info['deadline']<0:
  raise ValueError('Некорректный срок guard')
 return info


def disarm_guard_timer(journal):
 """Terminal-only timer cleanup, outside the journal lock and safe after reboot."""
 info=guard_info(journal);unit=info['timer']+'.timer'
 loaded=subprocess.run(['systemctl','show',unit,'--property=LoadState','--value'],
                       check=True,capture_output=True,text=True,timeout=5).stdout.strip()
 if loaded=='loaded':
  subprocess.run(['systemctl','stop',unit],check=True,capture_output=True,timeout=10)
 elif loaded!='not-found':raise ValueError('Состояние таймера возврата не подтверждено')


def arm_guard(journal,seconds):
 """Arm first, while still prepared. An early timer safely cancels the job."""
 if os.geteuid()!=0:raise ValueError('Для отдельного systemd guard нужны права root')
 if type(seconds) is not int or not 10<=seconds<=600:raise ValueError('Срок возврата должен быть от 10 до 600 секунд')
 with locked(journal) as (journal,plan,root,state):
  if state['status']!='prepared' or (journal/'guard.json').exists():raise ValueError('Guard уже создан или операция началась')
  check_persistent_guard(journal,plan)
  if (journal/'rollback.py').read_bytes()!=Path(__file__).read_bytes():raise ValueError('Версия координатора изменилась; пересоздайте подготовку')
  token=uuid.uuid4().hex
  info={'token':token,'timer':'okopy-restore-undo-'+token,'worker':'okopy-restore-worker-'+token,'seconds':seconds,'deadline':time.monotonic()+seconds}
  save(journal/'guard.json',info)
  subprocess.run(['systemd-run','--quiet','--unit='+info['timer'],'--on-active='+str(seconds)+'s',
                  '--timer-property=AccuracySec=1s','--property=UMask=0077','--property=Restart=on-failure',
                  '--property=TimeoutStartSec=300s',
                  '--property=RestartSec=3s','--property=StartLimitIntervalSec=1h','--property=StartLimitBurst=5',
                  '/usr/bin/python3','-I',str(journal/'rollback.py'),'recover-guarded',str(journal)],
                  check=True,capture_output=True,timeout=10)
  subprocess.run(['systemctl','is-active','--quiet',info['timer']+'.timer'],check=True,capture_output=True,timeout=5)
 return info


def start_guarded(journal,seconds):
 with locked(journal) as (journal,plan,root,state):
  if plan.get('live_root'):
   if state['status']!='prepared':raise ValueError('Восстановление уже начато')
   barrier_update('active',journal)
 info=arm_guard(journal,seconds)
 subprocess.run(['systemd-run','--quiet','--unit='+info['worker'],'--property=UMask=0077',
                 '--property=TimeoutStopSec=3s','--property=KillMode=control-group',
                 '/usr/bin/python3','-I',str(Path(journal)/'rollback.py'),'apply-guarded',str(journal)],
                 check=True,capture_output=True,timeout=10)
 return {'status':'started','timeout':seconds}


def apply_guarded(journal):
 private_directory(journal);info=guard_info(journal)
 subprocess.run(['systemctl','is-active','--quiet',info['timer']+'.timer'],check=True,capture_output=True,timeout=5)
 try:return apply(journal)
 except Exception:
  # Routine failure can return immediately; the independent timer still covers
  # process death, hangs, and an unsuccessful return attempt.
  try:rollback(journal)
  except Exception:pass
  raise


def recover_guarded(journal):
 private_directory(journal);info=guard_info(journal)
 # Fence a worker that has not yet been registered by systemd. Once this is
 # durable, a late worker cannot begin writes even if stop saw no unit yet.
 save(Path(journal)/'cancel.json',{'cancelled':True})
 # Stop a stuck writer BEFORE obtaining its file lock. systemd kills the whole
 # dedicated cgroup after TimeoutStopSec, including subprocesses holding the lock.
 loaded=subprocess.run(['systemctl','show',info['worker']+'.service','--property=LoadState','--value'],
                       check=True,capture_output=True,text=True,timeout=5).stdout.strip()
 if loaded!='not-found':subprocess.run(['systemctl','stop',info['worker']+'.service'],check=True,capture_output=True,timeout=10)
 return rollback(journal)


def recover_before_start(journal,boot_gate=None):
 """Boot hook; only queues jobs behind a verified, still-activating boot barrier.

 The coordinator must install and verify ordering BEFORE live-root support. A
 unit test with another boot id does not prove that systemd wiring exists.
 """
 with locked(journal) as (journal,plan,root,state):
  needed=plan['boot_id']!=boot_id() and state['status'] not in ('confirmed','rolled_back')
 if not needed:return {'status':'not_needed'}
 return rollback(journal,before_start=True,boot_gate=boot_gate)


def main():
 p=argparse.ArgumentParser(description='Возврат подготовленного файлового журнала, включая фиксированный защищённый live-root')
 p.add_argument('action',choices=['status','start-guarded','confirm','rollback','apply-guarded','recover-guarded','recover-before-start']);p.add_argument('journal');p.add_argument('--boot-gate')
 args=p.parse_args();actions={'status':status,'start-guarded':lambda journal:start_guarded(journal,300),'confirm':confirm,'rollback':rollback,'apply-guarded':apply_guarded,'recover-guarded':recover_guarded,'recover-before-start':recover_before_start}
 if args.boot_gate and args.action!='recover-before-start':p.error('--boot-gate допускается только для загрузочного возврата')
 print(json.dumps(recover_before_start(args.journal,args.boot_gate) if args.action=='recover-before-start' else actions[args.action](args.journal)))


if __name__=='__main__':main()
