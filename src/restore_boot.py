"""Install a persistent per-journal boot barrier outside snapshot-managed paths.

No daemon and no new rollback implementation: systemd executes the journal's
frozen restore_files runtime. Live-root restoration is still not enabled.
"""
import json
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
import restore_files as files

CAPSULE_ROOT=Path('/var/lib/okopy-recovery')
UNIT_ROOT=Path('/usr/local/lib/systemd/system')
PROTECTED=(Path('/var/lib/okopy-recovery-ui'),Path('/opt/okopy-recovery-ui'),
           Path('/var/www/certbot/.okopy-panel'),Path('/opt/okopy-panel/proxy/Caddyfile'),
           Path('/var/www/certbot/.farvater-recovery'),
           Path('/etc/sudoers.d/farvater-recovery-ui'),
           Path('/etc/farvater/recovery-ui.env'),
           Path('/etc/letsencrypt/renewal-hooks/deploy/infrastructure-recovery-tls.sh'),
           Path('/etc/systemd/system/infrastructure-recovery-ui.service'))


def secure_directory(path,*,create=False):
 path=Path(path)
 if not path.is_absolute() or path.resolve()!=path:raise ValueError('Каталог защиты не должен проходить через ссылку')
 for item in [*reversed(path.parents),path]:
  if not item.exists():
   if not create:raise ValueError('Отсутствует каталог загрузочной защиты')
   item.mkdir(mode=0o755);files.sync_directory(item.parent)
  s=item.stat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or (s.st_mode&0o022 and not s.st_mode&stat.S_ISVTX):raise ValueError('Каталог загрузочной защиты доступен для чужой записи')
 return path


def capsule(journal):
 if os.geteuid()!=0:raise ValueError('Установка загрузочной защиты требует root')
 journal=files.private_directory(journal)
 if journal.parent!=CAPSULE_ROOT or not re.fullmatch('[a-f0-9]{32}',journal.name):raise ValueError('Журнал должен находиться в постоянном каталоге восстановления')
 secure_directory(CAPSULE_ROOT)
 if not re.fullmatch(r'[A-Za-z0-9/_.-]+',str(journal)):raise ValueError('Путь журнала не подходит для команды systemd')
 return journal


def definitions(journal,plan,info):
 gate=info['gate'];names=sorted(set(plan['services']['before'])|set(plan['services']['after']))
 # UUID is generated locally, not supplied by a browser or snapshot.
 if gate!='infrastructure-recovery-'+info['token']+'.service' or not re.fullmatch('[a-f0-9]{32}',info['token']):raise ValueError('Повреждено описание загрузочной защиты')
 body=('[Unit]\nDescription=Recover interrupted infrastructure restore\n'
       '[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\n'
       'TimeoutStartSec=300s\nExecStart=/usr/bin/python3 -I '+str(journal/'rollback.py')+
       ' recover-before-start '+str(journal)+' --boot-gate '+gate+'\n')
 result={UNIT_ROOT/gate:body}
 for name in names:
  files.service_name(name)
  result[UNIT_ROOT/(name+'.d')/info['dropin']]='[Unit]\nRequires='+gate+'\nAfter='+gate+'\n'
 return result


def load_info(journal,plan):
 info=json.loads((journal/'boot-guard.json').read_text())
 if info.get('version')!=1 or info.get('unit_root')!=str(UNIT_ROOT) or info.get('dropin')!='90-infrastructure-recovery-'+info.get('token','')+'.conf':raise ValueError('Неизвестная загрузочная защита')
 definitions(journal,plan,info)
 return info


@contextmanager
def installation_lock(journal):
 with (journal/'boot-install.lock').open('a') as lock:
  os.chmod(journal/'boot-install.lock',0o600)
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  yield


def write_owned(path,content):
 """Resume our exact durable intent; never overwrite a pre-existing unit."""
 secure_directory(path.parent,create=True)
 if path.is_symlink():raise ValueError('Путь загрузочной защиты занят ссылкой')
 if path.exists():
  if path.read_text()!=content or path.stat().st_uid!=0 or path.stat().st_mode&0o022:raise ValueError('Путь загрузочной защиты занят другим файлом')
  return
 # Complete the file before publishing its final unit/drop-in name. A process
 # death may leave an ignored temporary file, never a partial systemd directive.
 temporary=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
 try:
  with temporary.open('x') as stream:
   os.chmod(temporary,0o644);stream.write(content);stream.flush();os.fsync(stream.fileno())
  os.link(temporary,path);files.sync_directory(path.parent)
 finally:temporary.unlink(missing_ok=True)


def verify(journal,plan,info):
 for path,body in definitions(journal,plan,info).items():
  if path.is_symlink() or not path.is_file() or path.read_text()!=body or path.stat().st_uid!=0 or path.stat().st_mode&0o022:raise ValueError('Загрузочная защита изменилась после установки')
 gate=files.service_capture([info['gate']])[info['gate']]
 if gate['LoadState']!='loaded' or gate['ActiveState']!='active' or gate['Type']!='oneshot':raise ValueError('Загрузочная защита не запущена')
 names=sorted(set(plan['services']['before'])|set(plan['services']['after']))
 p=subprocess.run(['systemctl','show',*names,'-p','Id,LoadState,Requires,After,DropInPaths'],capture_output=True,text=True,check=True,timeout=10)
 found={}
 for block in p.stdout.strip().split('\n\n'):
  u=dict(line.split('=',1) for line in block.splitlines() if '=' in line);found[u.get('Id')]=u
 if set(found)!=set(names):raise ValueError('Не подтверждён полный состав загрузочной защиты')
 for name,u in found.items():
  if u['LoadState'] in ('not-found','masked'):continue
  if u['LoadState']!='loaded' or info['gate'] not in u.get('Requires','').split() or info['gate'] not in u.get('After','').split():raise ValueError('Служба не получила обязательную загрузочную защиту')
  if str(UNIT_ROOT/(name+'.d')/info['dropin']) not in u.get('DropInPaths','').split():raise ValueError('Загрузочная защита перекрыта другим drop-in')


def install(journal):
 journal=capsule(journal)
 with installation_lock(journal):return install_locked(journal)


def install_locked(journal):
 paths=subprocess.run(['systemd-analyze','unit-paths'],capture_output=True,text=True,check=True,timeout=10).stdout.splitlines()
 if str(UNIT_ROOT) not in paths:raise ValueError('Этот systemd не загружает каталог независимой защиты')
 with files.locked(journal) as (_,plan,root,state):
  if state['status']!='prepared' or (journal/'guard.json').exists():raise ValueError('Защита устанавливается до начала операции')
  if not plan.get('services'):raise ValueError('Не задан состав восстанавливаемых служб')
  if (journal/'rollback.py').read_bytes()!=Path(files.__file__).read_bytes():raise ValueError('Код журнала изменился; пересоздайте подготовку')
  for name,entry in plan['entries'].items():
   p=root/name
   if entry['before']==entry['after']:continue
   for protected in (CAPSULE_ROOT,UNIT_ROOT,*PROTECTED):
    if p==protected or p.is_relative_to(protected) or protected.is_relative_to(p):raise ValueError('Снимок затрагивает собственную защиту восстановления')
  if (journal/'boot-guard.json').exists():
   info=load_info(journal,plan)
   if info['status']=='removed':raise ValueError('Эта загрузочная защита уже удалена')
  else:
   token=uuid.uuid4().hex
   info={'version':1,'token':token,'gate':'infrastructure-recovery-'+token+'.service',
         'dropin':'90-infrastructure-recovery-'+token+'.conf','unit_root':str(UNIT_ROOT),'status':'installing'}
   for path in definitions(journal,plan,info):
    if path.exists() or path.is_symlink():raise ValueError('Имя загрузочной защиты уже занято')
   files.save(journal/'boot-guard.json',info)
 # Do not hold the journal lock while starting its guard: the frozen runtime
 # acquires that same lock even for the no-op check in the current boot.
 wanted=definitions(journal,plan,info);gatepath=UNIT_ROOT/info['gate']
 write_owned(gatepath,wanted[gatepath])
 subprocess.run(['systemctl','daemon-reload'],capture_output=True,check=True,timeout=15)
 subprocess.run(['systemctl','start',info['gate']],capture_output=True,check=True,timeout=20)
 for path,body in wanted.items():
  if path!=gatepath:write_owned(path,body)
 subprocess.run(['systemctl','daemon-reload'],capture_output=True,check=True,timeout=15)
 verify(journal,plan,info)
 with files.locked(journal) as (_,latest,root,state):
  if latest!=plan or state['status']!='prepared':raise ValueError('Журнал изменился во время установки защиты')
  plan['services']['boot_gate']=info['gate'];files.save(journal/'plan.json',plan)
  files.save(journal/'boot-guard.json',{**info,'status':'installed'})
 return {'gate':info['gate'],'services':len(wanted)-1,'status':'installed'}


def remove(journal):
 """Terminal/prepared journals only; keep recovery data until every link is gone."""
 journal=capsule(journal)
 with installation_lock(journal):return remove_locked(journal)


def remove_locked(journal):
 with files.locked(journal) as (_,plan,root,state):
  if state['status'] not in ('prepared','confirmed','rolled_back'):raise ValueError('Сначала завершите восстановление или возврат')
  info=load_info(journal,plan);wanted=definitions(journal,plan,info)
  # Check all existing files before the first unlink. Never remove foreign data.
  for path,body in wanted.items():
   if path.is_symlink() or (path.exists() and (path.read_text()!=body or path.stat().st_uid!=0)):raise ValueError('Защита изменена извне; автоматическое удаление запрещено')
  files.save(journal/'boot-guard.json',{**info,'status':'removing'})
 gatepath=UNIT_ROOT/info['gate']
 for path in wanted:
  if path==gatepath:continue
  path.unlink(missing_ok=True)
  if path.parent.exists():
   files.sync_directory(path.parent)
   try:path.parent.rmdir();files.sync_directory(path.parent.parent)
   except OSError:pass  # Preserve a shared directory with other drop-ins.
 # Detach dependencies before stopping the gate, so systemd cannot propagate
 # its stop into the otherwise healthy restored services.
 subprocess.run(['systemctl','daemon-reload'],capture_output=True,check=True,timeout=15)
 loaded=subprocess.run(['systemctl','show',info['gate'],'--property=LoadState','--value'],capture_output=True,text=True,check=True,timeout=5).stdout.strip()
 if loaded!='not-found':subprocess.run(['systemctl','stop',info['gate']],capture_output=True,check=True,timeout=15)
 gatepath.unlink(missing_ok=True)
 if UNIT_ROOT.exists():files.sync_directory(UNIT_ROOT)
 subprocess.run(['systemctl','daemon-reload'],capture_output=True,check=True,timeout=15)
 with files.locked(journal):files.save(journal/'boot-guard.json',{**info,'status':'removed'})
 return {'status':'removed'}
