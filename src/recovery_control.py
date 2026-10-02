"""Fixed-root bridge from checked backups to the one restore_files journal.

The request selects a checked job, never paths, units, health URLs or keys.
All writes stay in the installer-owned recovery capsule until a guarded start.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import math

import backup_restore_tree
import backup_services
import recovery_access
import restore_boot
import restore_files
import system_backup


ROOT=Path('/var/lib/okopy-recovery')
BACKUP=system_backup.ROOT
HOST=Path('/')
FROZEN_PYTHON='/usr/bin/python3'
TERMINAL={'confirmed','rolled_back'}
RESCUE_UNIT='infrastructure-recovery-ui.service'
REQUIRED_DEFERRED_WRITERS={'okopy-panel.service','okopy-routing.service','okopy-routing.timer'}
RESCUE_FILES=(Path('/opt/okopy-recovery-ui/rescue.py'),
              Path('/opt/okopy-recovery-ui/server.py'),
              Path('/opt/okopy-recovery-ui/writer_guard.py'),
              Path('/opt/okopy-recovery-ui/access.py'),
              Path('/opt/okopy-recovery-ui/tls_refresh.py'),
              Path('/opt/okopy-recovery-ui/boot_cleanup.py'),
              Path('/opt/okopy-recovery-ui/restore_files.py'),
              Path('/opt/okopy-recovery-ui/restore_boot.py'),
              Path('/opt/okopy-recovery-ui/venv/bin/python'),
              Path('/etc/systemd/system/infrastructure-recovery-ui.service'),
              Path('/usr/local/lib/systemd/system/okopy-panel.service.d/80-infrastructure-recovery-access.conf'),
              Path('/etc/sudoers.d/farvater-recovery-ui'),
              Path('/etc/farvater/recovery-ui.env'),
              Path('/var/lib/okopy-recovery-ui/barrier.json'))


def job_id(value):
 if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value):raise ValueError('Некорректная операция восстановления')
 return value


def private_root(root):
 root=Path(root)
 if not root.is_absolute() or root.resolve()!=root or root.is_symlink():raise ValueError('Каталог восстановления изменён')
 s=root.stat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077:raise ValueError('Каталог восстановления должен быть закрытым')
 return root


def last_drill(root=ROOT):
 """Expose only a validated record written after an actual isolated drill."""
 path=Path(root)/'last-drill.json'
 if not path.exists():return None
 private_root(root)
 if path.is_symlink():raise ValueError('Запись проверки восстановления изменена')
 s=path.stat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077 or s.st_size>2048:
  raise ValueError('Небезопасная запись проверки восстановления')
 value=json.loads(path.read_text())
 if (not isinstance(value,dict) or set(value)!={'status','at','platform','scope','evidence_sha256'}
     or value['status'] not in ('passed','failed') or type(value['at']) not in (int,float)
     or not math.isfinite(value['at']) or value['at']<0 or value['platform']!='linux-amd64'
     or value['scope']!='isolated-full-systemd' or not isinstance(value['evidence_sha256'],str)
     or not re.fullmatch('[a-f0-9]{64}',value['evidence_sha256'])):
  raise ValueError('Неподтверждённый формат результата проверки восстановления')
 return value


def settings(root):
 value=json.loads((private_root(root)/'settings.json').read_text())
 if (not isinstance(value,dict) or set(value)!={'version','before_checks','after_checks','deferred_writers','tls_chain_source','tls_key_source'}
     or value['version']!=1 or not isinstance(value['deferred_writers'],list)
     or not value['deferred_writers'] or len(value['deferred_writers'])>16):
  raise ValueError('Параметры восстановления не установлены')
 value['before_checks']=restore_files.health_checks(value['before_checks'])
 value['after_checks']=restore_files.health_checks(value['after_checks'])
 value['deferred_writers']=[restore_files.service_name(n) for n in value['deferred_writers']]
 if len(set(value['deferred_writers']))!=len(value['deferred_writers']):raise ValueError('Повторяются отложенные службы')
 if set(value['deferred_writers'])!=REQUIRED_DEFERRED_WRITERS:
  raise ValueError('Панель и автоматический routing должны оставаться остановленными до подтверждения')
 for field in ('tls_chain_source','tls_key_source'):
  if not isinstance(value[field],str) or not value[field].startswith('/etc/letsencrypt/live/') or len(value[field])>512:
   raise ValueError('Не настроен защищённый TLS источник восстановления')
 return value


def available(root=ROOT):
 """Only advertise application when the independent installed boundary exists.

The socket/auth copy is refreshed during prepare, so it is not a prerequisite
for displaying that action. A settings file alone is never readiness evidence.
"""
 try:
  settings(root)
  restore_files.barrier_status()
  venv_python=Path('/opt/okopy-recovery-ui/venv/bin/python')
  for path in RESCUE_FILES:
   if not path.is_file():return False
   if path.is_symlink() and path!=venv_python:return False
   if path==venv_python and not (path.resolve().is_relative_to(venv_python.parent) or
                                 path.resolve().is_relative_to(Path('/usr/bin'))):return False
   s=path.stat()
   if s.st_uid!=0 or s.st_mode&0o022:return False
  return True
 except (ValueError,OSError,KeyError,TypeError):return False


def journal_for(root,value):return private_root(root)/job_id(value)


def job_active(value,*,root=ROOT):
 """Deletion interlock; invalid/partial journals fail closed."""
 value=job_id(value);root=Path(root)
 if not root.exists():return False
 private_root(root);journal=root/value
 if not journal.exists():return False
 try:return restore_files.status(journal)['status'] not in TERMINAL
 except (ValueError,OSError,KeyError,TypeError):return True


def any_active(root):
 for path in private_root(root).iterdir():
  if path.is_dir() and re.fullmatch('[a-f0-9]{32}',path.name) and job_active(path.name,root=root):return True
 return False


def checked_job(value,expected_manifest,*,backup_root=BACKUP,host=HOST):
 """Re-read immutable facts; a checked summary alone is not authorization."""
 job=Path(backup_root)/'jobs'/job_id(value)
 state=system_backup.load(job/'state.json')
 if (state.get('kind')!='import' or state.get('status')!='checked' or
     not isinstance(expected_manifest,str) or not re.fullmatch('[a-f0-9]{64}',expected_manifest) or
     state.get('manifest_sha256')!=expected_manifest or state.get('summary',{}).get('unsupported')!=0):
  raise ValueError('Проверенный состав копии изменился; загрузите и проверьте архив заново')
 if not state.get('summary',{}).get('accounts',{}).get('ready'):
  raise ValueError('Владельцы файлов не подготовлены для восстановления')
 if system_backup.sha(job/'uploaded.age')!=state.get('sha256'):
  raise ValueError('Зашифрованный архив изменился после проверки')
 identity=system_backup.verification_identity(backup_root,state.get('anchor_id'))
 if identity['digest']!=state.get('anchor_digest'):
  raise ValueError('Доверенная идентичность изменилась после проверки')
 staged=job/'staged';manifest=backup_restore_tree.signed_manifest(staged,identity['public_key'])
 if system_backup.sha(staged/'manifest.json')!=expected_manifest:
  raise ValueError('Подписанный manifest изменился после проверки')
 metadata=manifest['metadata'];config=system_backup.settings(backup_root)
 if metadata.get('host_id')!=identity['host_id'] or metadata.get('scope')!=identity['scope'] or identity['scope']!=config['scope']:
  raise ValueError('Копия принадлежит другой установке или области')
 platform=metadata.get('platform')
 if not isinstance(platform,dict) or platform.get('architecture')!=os.uname().machine:
  raise ValueError('Архитектура копии несовместима с целевым хостом')
 os_release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
 if any(platform.get('os_release',{}).get(key)!=os_release.get(key) for key in ('ID','VERSION_ID')):
  raise ValueError('Версия системы копии несовместима с целевым хостом')
 desired=[r['path'] for r in manifest['files']]
 if any(not system_backup.covered(name,config) or restore_files.protected_live_path(name) for name in desired):
  raise ValueError('Копия затрагивает путь вне разрешённого состава или recovery capsule')
 registry=metadata.get('service_registry')
 if not isinstance(registry,dict) or registry.get('version')!=1 or not isinstance(registry.get('units'),list) or not registry['units']:
  raise ValueError('В копии нет полного реестра служб')
 return job,state,manifest,config


def attach_and_guard(journal,manifest,config,options,current):
 registry=manifest['metadata']['service_registry']
 desired_units={row['Id']:row for row in registry['units']}
 deferred=deferred_for_registry(desired_units,options)
 current_registry=backup_services.capture(current,config.get('units',[]))
 current_units={row['Id'] for row in current_registry['units']}
 allowed=current_units|set(desired_units)
 restore_files.attach_services(journal,desired_units,allowed_units=allowed,
   before_checks=options['before_checks'],after_checks=options['after_checks'],
   deferred_writers=deferred)


def deferred_for_registry(desired_units,options):
 """Stop fixed writers that this snapshot would otherwise start."""
 targets=restore_files.service_targets(desired_units)
 if targets.get('okopy-panel.service',{}).get('mode')!='start':
  raise ValueError('В снимке нет запускаемой службы панели')
 return sorted(name for name in options['deferred_writers']
               if targets.get(name,{}).get('mode')=='start')


def resume_prepared(journal,source,manifest,config,options,host):
 """Resume only before the first guarded start; never create another journal."""
 restore_files.private_directory(source)
 with restore_files.locked(journal) as (_,plan,root,state):
  if not plan.get('live_root') or plan.get('source')!=str(source) or root!=Path(host):
   raise ValueError('Подготовленный журнал относится к другому корню или источнику')
  if state['status']!='prepared' or (journal/'guard.json').exists():
   raise ValueError('Восстановление уже запускалось; перечитайте независимый статус')
  attached=bool(plan.get('services'))
  if attached:
   bound=plan['services']
   desired_units={row['Id']:row for row in manifest['metadata']['service_registry']['units']}
   expected_deferred=deferred_for_registry(desired_units,options)
   if (set(bound.get('deferred_writers',()))!=set(expected_deferred) or
       bound.get('before_checks')!=options['before_checks'] or
       bound.get('after_checks')!=options['after_checks']):
    raise ValueError('Контрольные условия подготовленного журнала изменились')
 if not attached:
  current=system_backup.selected_paths(config,host,require=False)
  if any(restore_files.protected_live_path(name) for name in current):
   raise ValueError('Текущий состав затрагивает recovery или backup область')
  attach_and_guard(journal,manifest,config,options,current)
 restore_boot.install(journal)  # Resumes an exact partial installing intent or verifies installed files.
 result=restore_files.status(journal)
 if result.get('status')!='prepared' or result.get('boot_guard')!='installed':
  raise ValueError('Постоянная загрузочная защита не подтверждена')
 return result


def prepare(value,expected_manifest,*,root=ROOT,backup_root=BACKUP,host=HOST):
 value=job_id(value);root=private_root(root)
 with (root/'control.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  with (Path(backup_root)/'control.lock').open('a') as backup_lock:
   fcntl.flock(backup_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   journal=root/value
   if journal.exists() or journal.is_symlink():
    if system_backup.load(Path(backup_root)/'jobs'/value/'state.json').get('manifest_sha256')!=expected_manifest:
     raise ValueError('Операция относится к другой версии копии')
    existing=restore_files.status(journal)
    if existing['status']!='prepared':return existing
    job,state,manifest,config=checked_job(value,expected_manifest,backup_root=backup_root,host=host)
    return resume_prepared(journal,job/'materialized',manifest,config,settings(root),host)
   if any_active(root):raise ValueError('Другое восстановление не завершено')
   job,state,manifest,config=checked_job(value,expected_manifest,backup_root=backup_root,host=host)
   options=settings(root);source=job/'materialized'
   if source.exists() or source.is_symlink():
    # A published materialized tree with no journal cannot have been applied.
    # Drop only this fixed root-owned job copy, then rebuild from signed staged bytes.
    restore_files.private_directory(source)
    shutil.rmtree(source)
   recovery_access.stage_auth()
   recovery_access.stage_tls(options['tls_chain_source'],options['tls_key_source'])
   subprocess.run(['systemctl','restart',RESCUE_UNIT],capture_output=True,check=True,timeout=20)
   subprocess.run(['systemctl','is-active','--quiet',RESCUE_UNIT],capture_output=True,check=True,timeout=5)
   backup_restore_tree.materialize(job/'staged',source,system_backup.verification_identity(backup_root,state.get('anchor_id'))['public_key'])
   with system_backup.stable_configuration(host):
    current=system_backup.selected_paths(config,host,require=False)
    desired=[r['path'] for r in manifest['files']]
    if any(restore_files.protected_live_path(name) for name in current):raise ValueError('Текущий состав затрагивает recovery или backup область')
    restore_files.prepare(host,source,current,desired,journal,live=True)
   attach_and_guard(journal,manifest,config,options,current)
   restore_boot.install(journal)
   result=restore_files.status(journal)
   if result.get('boot_guard')!='installed':raise ValueError('Постоянная загрузочная защита не подтверждена')
   return result


def frozen(journal,action):
 if action not in ('status','confirm','rollback','recover-guarded'):raise ValueError('Неизвестное действие frozen recovery')
 journal=Path(journal)
 if not (journal/'rollback.py').is_file():raise ValueError('Нет замороженного кода восстановления')
 p=subprocess.run([FROZEN_PYTHON,'-I',str(journal/'rollback.py'),action,str(journal)],
                  capture_output=True,text=True,timeout=180)
 if p.returncode:
  raise ValueError('Независимое восстановление не подтвердило действие; перечитайте состояние')
 try:return json.loads(p.stdout)
 except ValueError:raise ValueError('Независимое восстановление вернуло неверное состояние') from None


def terminal_cleanup(journal,state):
 """Resume only post-commit timer/drop-in cleanup from the current admin path."""
 if state.get('status') not in TERMINAL:return state
 result=dict(state);pending=False
 if (journal/'guard.json').exists():
  try:
   info=restore_files.guard_info(journal)
   unit=info['timer']+'.timer'
   loaded=subprocess.run(['systemctl','show',unit,'--property=LoadState','--value'],
                         check=True,capture_output=True,text=True,timeout=5).stdout.strip()
   if loaded=='loaded':
    subprocess.run(['systemctl','stop',unit],check=True,capture_output=True,timeout=10)
   elif loaded!='not-found':raise ValueError('Состояние таймера возврата не подтверждено')
  except (ValueError,OSError,subprocess.SubprocessError):pending=True
 if state.get('boot_guard') not in (None,'removed'):
  try:restore_boot.remove(journal)
  except (ValueError,OSError,subprocess.SubprocessError):pending=True
 if pending:result['boot_guard_cleanup_pending']=True
 else:result=frozen(journal,'status')
 return result


def control(request,*,root=ROOT,backup_root=BACKUP,host=HOST):
 action=request.get('action') if isinstance(request,dict) else None
 if action not in ('restore-status','restore-prepare','restore-start','restore-confirm','restore-rollback') or request.get('version')!=1:
  raise ValueError('Неизвестное действие восстановления')
 fields={'version','action','job_id'}
 if action=='restore-prepare':fields.add('expected_manifest_sha256')
 if action in ('restore-start','restore-confirm','restore-rollback'):fields.add('transaction')
 if set(request)!=fields:raise ValueError('Некорректные поля запроса восстановления')
 value=job_id(request['job_id']);journal=journal_for(root,value)
 if action=='restore-prepare':return prepare(value,request['expected_manifest_sha256'],root=root,backup_root=backup_root,host=host)
 if action=='restore-status':return terminal_cleanup(journal,frozen(journal,'status')) if journal.exists() else {'status':'not_prepared','id':value}
 if request['transaction']!=value or not journal.exists():raise ValueError('Операция восстановления изменилась')
 state=frozen(journal,'status')
 if state.get('status') in TERMINAL:return terminal_cleanup(journal,state)
 if action=='restore-start':
  if state['status']!='prepared':return state
  if (journal/'guard.json').exists():raise ValueError('Запуск уже мог быть запланирован; перечитайте состояние')
  restore_files.start_guarded(journal,300)
  return frozen(journal,'status')
 result=frozen(journal,'confirm' if action=='restore-confirm' else
               'recover-guarded' if (journal/'guard.json').exists() else 'rollback')
 return terminal_cleanup(journal,result)
