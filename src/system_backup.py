"""Encrypted server snapshots and signed, non-applying restore inspection."""
import base64
from contextlib import ExitStack,contextmanager
import fcntl
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from safe_apply import atomic_write
import backup_archive

ROOT=Path('/var/lib/okopy-backup')
PANEL=Path('/var/lib/okopy-panel')
ANCHOR_ROOT=Path('/var/lib/okopy-recovery/anchors')
AGE='/opt/okopy-backup-tools/age'
MAX_UPLOAD=384*1024*1024
ACTIVE_TRANSACTIONS={'prepared','pending','rollback_failed','recovery_required'}
LOCKS=[('var/lib/okopy-panel/draft.lock',fcntl.LOCK_SH),('var/lib/okopy-openconnect/control.lock',fcntl.LOCK_SH),('var/lib/okopy-trusttunnel/control.lock',fcntl.LOCK_SH),('var/lib/okopy-wireguard/control.lock',fcntl.LOCK_SH),('var/lib/okopy-amnezia/control.lock',fcntl.LOCK_SH),('var/lib/okopy-candidate/apply.lock',fcntl.LOCK_SH),('var/lib/okopy-candidate/routing.lock',fcntl.LOCK_SH),('var/lib/okopy-monitor/settings.lock',fcntl.LOCK_SH)]


def identifier(value):
 if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value):raise ValueError('Некорректный номер резервной копии')
 return value


def remove_panel_file(panel,directory,value):
 fd=os.open(panel/directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  try:os.unlink(value+'.age',dir_fd=fd)
  except FileNotFoundError:pass
 finally:os.close(fd)


def load(path):return json.loads(Path(path).read_text())
def save(path,value):atomic_write(Path(path),backup_archive.canonical(value))
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as file:
  while data:=file.read(1024*1024):h.update(data)
 return h.hexdigest()


def process_token():return Path('/proc/self/stat').read_text().split()[21] if Path('/proc/self/stat').exists() else ''
def is_running(info):
 try:
  os.kill(info['pid'],0)
  return not info.get('process_token') or Path('/proc',str(info['pid']),'stat').read_text().split()[21]==info['process_token']
 except (OSError,KeyError,ValueError):return False


def settings(root):
 value=load(root/'settings.json')
 if value.get('version')!=1 or not re.fullmatch('age1[0-9a-z]{58}',value.get('recipient','')):raise ValueError('Не настроен ключ шифрования резервных копий')
 return value


def public_key(root):return Ed25519PrivateKey.from_private_bytes((root/'signing.key').read_bytes()).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)


def trust_export(root):
 """Public verifier for separately provisioned clean-host recovery."""
 config=settings(root);key=public_key(root)
 return {'version':1,'host_id':config['host_id'],'scope':config['scope'],
         'signing_public_key':base64.b64encode(key).decode(),
         'signing_fingerprint':hashlib.sha256(key).hexdigest(),'recipient':config['recipient']}


def verification_identity(root,anchor_id=None):
 """Select only a local signer or an already installed root-owned anchor."""
 if anchor_id is None:
  config=settings(root);key=public_key(root)
  value={'public_key':key,'host_id':config['host_id'],'scope':config['scope'],'anchor_id':None}
  value['digest']=hashlib.sha256(backup_archive.canonical({'key':base64.b64encode(key).decode(),'host_id':value['host_id'],'scope':value['scope']})).hexdigest()
  return value
 if not isinstance(anchor_id,str) or not re.fullmatch('[a-f0-9]{32}',anchor_id):raise ValueError('Неизвестная доверенная идентичность восстановления')
 if ANCHOR_ROOT.resolve()!=ANCHOR_ROOT or ANCHOR_ROOT.is_symlink():raise ValueError('Каталог доверенных идентичностей изменён')
 s=ANCHOR_ROOT.stat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077:raise ValueError('Небезопасный каталог доверенных идентичностей')
 try:fd=os.open(ANCHOR_ROOT/(anchor_id+'.json'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except OSError:raise ValueError('Доверенная идентичность не установлена') from None
 with os.fdopen(fd,'rb') as stream:
  s=os.fstat(stream.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077 or s.st_size>4096:raise ValueError('Небезопасная доверенная идентичность')
  raw=stream.read(4097)
 if len(raw)>4096:raise ValueError('Доверенная идентичность слишком велика')
 try:
  record=json.loads(raw)
  if (not isinstance(record,dict) or set(record)!={'version','host_id','scope','signing_public_key','signing_fingerprint'}
      or record['version']!=1 or not isinstance(record['host_id'],str) or not record['host_id']
      or not isinstance(record['scope'],str) or not record['scope']):raise ValueError()
  key=base64.b64decode(record['signing_public_key'],validate=True)
  if len(key)!=32 or hashlib.sha256(key).hexdigest()!=record['signing_fingerprint']:raise ValueError()
 except (ValueError,KeyError,TypeError):raise ValueError('Доверенная идентичность повреждена') from None
 return {'public_key':key,'host_id':record['host_id'],'scope':record['scope'],
         'anchor_id':anchor_id,'digest':hashlib.sha256(raw).hexdigest()}


def available_anchors(root):
 if not ANCHOR_ROOT.exists():return []
 if ANCHOR_ROOT.resolve()!=ANCHOR_ROOT or ANCHOR_ROOT.is_symlink():raise ValueError('Каталог доверенных идентичностей изменён')
 result=[]
 for path in sorted(ANCHOR_ROOT.glob('*.json')):
  name=path.stem
  if not re.fullmatch('[a-f0-9]{32}',name):raise ValueError('Неизвестная доверенная идентичность')
  identity=verification_identity(root,name)
  result.append({'id':name,'host_id':identity['host_id'],'scope':identity['scope'],
                 'signing_fingerprint':hashlib.sha256(identity['public_key']).hexdigest()})
 return result


def catalogue(root,panel):
 config=settings(root);items=[]
 for path in sorted((root/'jobs').glob('*/state.json'),reverse=True):
  info=load(path)
  if info.get('status') in ('creating','checking') and not is_running(info):
   info={**info,'status':'interrupted','error':'Операция прервалась. Рабочая сеть не менялась; удалите эту запись и повторите действие.'}
  items.append({key:info[key] for key in ('id','kind','status','created_at','bytes','sha256','files','total_bytes','summary','error','manifest_sha256','anchor_id') if key in info})
 try:
  from recovery_control import available as recovery_available,last_drill,ROOT as recovery_root
  restore_ready=recovery_available(recovery_root)
  drill=last_drill(recovery_root)
 except (ValueError,OSError,KeyError,TypeError):restore_ready=False;drill=None
 return {'recipient':config['recipient'],'signing_fingerprint':hashlib.sha256(public_key(root)).hexdigest(),'scope':config['scope'],'exclusions':config['exclusions'],'jobs':sorted(items,key=lambda item:item['created_at'],reverse=True),'restore_application_available':restore_ready,'last_drill':drill,'trusted_anchors':available_anchors(root)}


def recovery_path(name):
 """Recovery capsules/barriers belong to the installer, never to a snapshot.

 Keep this boundary even if an administrator expands the configured trees.
 Existing local units with other names are not excluded.
 """
 from restore_files import protected_live_path
 return (protected_live_path(name)
         or fnmatch.fnmatch(name,'usr/local/lib/systemd/system/infrastructure-recovery-*.service')
         or fnmatch.fnmatch(name,'usr/local/lib/systemd/system/*.d/90-infrastructure-recovery-*.conf'))


def selected_paths(config,host,*,require=True):
 paths=set();exclude=config.get('exclude',[])
 def include(path):
  name=str(path.relative_to(host))
  if recovery_path(name):return
  if any(fnmatch.fnmatch(name,pattern) for pattern in exclude):return
  if path.is_symlink():paths.add(name);return
  if path.is_dir():
   paths.add(name)
   for child in sorted(path.iterdir()):include(child)
  elif path.is_file():paths.add(name)
  else:raise ValueError('В составе резервной копии найден специальный файл')
 if require:
  for name in config['required']:
   path=host/backup_archive.relative(name)
   if not path.exists() and not path.is_symlink():raise ValueError('Отсутствует обязательный компонент резервной копии: '+name)
 for name in config['trees']:
  path=host/backup_archive.relative(name)
  if path.exists() or path.is_symlink():include(path)
 for pattern in config.get('globs',[]):
  if pattern.startswith('/') or '..' in pattern.split('/'):raise ValueError('Некорректный состав резервной копии')
  for path in host.glob(pattern):include(path)
 # Include the current release target explicitly, not all abandoned releases.
 for name in config.get('release_links',[]):
  path=host/backup_archive.relative(name)
  target=path.resolve(strict=True)
  if not target.is_relative_to(host) or not target.is_relative_to(path.parent/'releases'):raise ValueError('Ссылка текущего релиза вышла за каталог приложения')
  include(path);include(target)
 if not paths or not set(config['required'])<=paths:raise ValueError('Состав резервной копии не включает все обязательные компоненты')
 return sorted(paths)


@contextmanager
def stable_configuration(host):
 with ExitStack() as stack:
  for name,mode in LOCKS:
   path=host/name
   if path.parent.exists():
    file=stack.enter_context(path.open('a'))
    try:fcntl.flock(file,mode|fcntl.LOCK_NB)
    except BlockingIOError:raise ValueError('Настройки сейчас изменяются; дождитесь завершения применения') from None
  for name in ('okopy-candidate','okopy-wireguard','okopy-amnezia','okopy-openconnect','okopy-trusttunnel'):
   path=host/'var/lib'/name/'transaction.json'
   if path.exists() and load(path).get('status') in ACTIVE_TRANSACTIONS:raise ValueError('Есть неподтверждённое изменение сети. Сначала завершите его')
  yield


def stop(process):
 if process.poll() is None:process.terminate()
 try:process.wait(timeout=3)
 except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)


def package_versions():
 """Capture the native package inventory without requiring a distribution name."""
 commands=(
  ('dpkg-query',['dpkg-query','-W','-f=${Package}\t${Version}\n']),
  ('rpm',['rpm','-qa','--qf','%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\n']),
  ('pacman',['pacman','-Q']),
 )
 for manager,command in commands:
  if shutil.which(manager):
   result=subprocess.run(command,capture_output=True,text=True,timeout=10)
   if result.returncode:raise ValueError('Не удалось сохранить версии системных пакетов: '+manager)
   rows=result.stdout.splitlines()
   if manager=='pacman':rows=['\t'.join(row.split(maxsplit=1)) for row in rows]
   return rows
 raise ValueError('Для системной копии нужен dpkg-query, rpm или pacman')


def export(root,panel,host,age,config,job,info):
 with stable_configuration(host):
  paths=selected_paths(config,host)
  if shutil.disk_usage(root).free<2*sum((host/n).lstat().st_size for n in paths)+128*1024*1024:raise ValueError('Недостаточно места для проверяемой резервной копии')
  output=job/'archive.age.partial'
  metadata={'scope':config['scope'],'exclusions':config['exclusions'],'recipient':config['recipient'],'signing_fingerprint':hashlib.sha256(public_key(root)).hexdigest(),'host_id':config['host_id'],'release':os.readlink(host/'opt/okopy-panel/current') if (host/'opt/okopy-panel/current').is_symlink() else None}
  if host==Path('/'):
   from backup_accounts import capture
   metadata['accounts']=capture(paths,host)
   metadata['platform']={'architecture':os.uname().machine,'os_release':dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)}
   metadata['packages']=package_versions()
   from backup_services import capture as capture_services,legacy_states
   metadata['service_registry']=capture_services(paths,config.get('units',[]))
   metadata['services']=legacy_states(metadata['service_registry'])
  with output.open('xb') as destination:
   os.chmod(output,0o600)
   process=subprocess.Popen([age,'--encrypt','-r',config['recipient']],stdin=subprocess.PIPE,stdout=destination,stderr=subprocess.DEVNULL)
   try:
    manifest=backup_archive.write(process.stdin,paths,source_root=host,private_key=(root/'signing.key').read_bytes(),metadata=metadata)
    process.stdin.close()
    if process.wait(timeout=30):raise ValueError('Шифрование резервной копии не завершено')
    destination.flush();os.fsync(destination.fileno())
   finally:
    stop(process)
    process.stdin.close()
  if output.stat().st_size>MAX_UPLOAD:raise ValueError('Зашифрованная копия слишком велика для загрузки через панель')
  result={**info,'status':'ready','bytes':output.stat().st_size,'sha256':sha(output),'files':len(manifest['files']),'total_bytes':manifest['total_bytes']}
  target_dir=os.open(panel/'backup-downloads',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   os.chown(output,-1,os.fstat(target_dir).st_gid);os.chmod(output,0o640);os.replace(output,info['id']+'.age',dst_dir_fd=target_dir)
  finally:os.close(target_dir)
  save(job/'state.json',result);return result


def covered(name,config):
 if recovery_path(name):return False
 if any(fnmatch.fnmatch(name,pattern) for pattern in config.get('exclude',[])):return False
 if any(name==base or name.startswith(base+'/') for base in config['trees']):return True
 if any(fnmatch.fnmatch(name,pattern) for pattern in config.get('globs',[])):return True
 return any(name==link or name.startswith(str(Path(link).parent/'releases')+'/') for link in config.get('release_links',[]))


def inspect_upload(root,panel,host,age,config,job,info,recovery_key,anchor_id=None):
 if not isinstance(recovery_key,str) or not 1<=len(recovery_key.encode())<=4096 or '\x00' in recovery_key:raise ValueError('Выберите файл ключа восстановления age до 4 КиБ')
 key_lines=[line.strip() for line in recovery_key.splitlines() if line.strip() and not line.lstrip().startswith('#')]
 if len(key_lines)!=1 or not re.fullmatch('AGE-SECRET-KEY-1[0-9A-Z]{58}',key_lines[0]):raise ValueError('Нужен обычный ключ age X25519; SSH-ключи, плагины и исполняемые обработчики не используются')
 recovery_key=key_lines[0]+'\n'
 source_dir=os.open(panel/'backup-uploads',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:fd=os.open(info['id']+'.age',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=source_dir)
 finally:os.close(source_dir)
 with os.fdopen(fd,'rb') as upload:
  st=os.fstat(upload.fileno())
  if not stat.S_ISREG(st.st_mode) or not 1<=st.st_size<=MAX_UPLOAD:raise ValueError('Нужен обычный зашифрованный файл допустимого размера')
  if shutil.disk_usage(root).free<backup_archive.MAX_TOTAL+st.st_size+128*1024*1024:raise ValueError('Недостаточно свободного места для проверки распакованного комплекта')
  with (job/'uploaded.age').open('xb') as target:
   os.chmod(job/'uploaded.age',0o600);count=0
   while chunk:=upload.read(1024*1024):
    count+=len(chunk)
    if count>st.st_size:raise ValueError('Загрузка изменилась во время чтения')
    target.write(chunk)
  if (job/'uploaded.age').stat().st_size!=st.st_size:raise ValueError('Файл изменился во время загрузки')
 read_fd,write_fd=os.pipe();process=None
 try:
  key_bytes=recovery_key.encode()
  if os.write(write_fd,key_bytes)!=len(key_bytes):raise ValueError('Не удалось передать ключ расшифровки')
  os.close(write_fd);write_fd=None
  identity_fd=('/proc/self/fd/' if Path('/proc/self/fd').is_dir() else '/dev/fd/')+str(read_fd)
  process=subprocess.Popen([age,'--decrypt','-i',identity_fd,str(job/'uploaded.age')],pass_fds=(read_fd,),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
  os.close(read_fd);read_fd=None
  identity=verification_identity(root,anchor_id)
  try:manifest=backup_archive.read(process.stdout,public_key=identity['public_key'],staging=job/'staged')
  except (OSError,EOFError,ValueError,backup_archive.tarfile.TarError):raise ValueError('Архив не прошёл проверку: неверный ключ, подпись, состав или повреждённые данные') from None
  # Consume the authenticated end of the age stream even when tar ended earlier.
  tail=process.stdout.read(1024*1024+1)
  if len(tail)>1024*1024 or process.wait(timeout=20):raise ValueError('Не подтверждена целостность зашифрованного файла')
 finally:
  if process is not None:
   stop(process)
   process.stdout.close()
  if read_fd is not None:os.close(read_fd)
  if write_fd is not None:os.close(write_fd)
 if (manifest['metadata'].get('host_id')!=identity['host_id'] or manifest['metadata'].get('scope')!=identity['scope']
     or identity['scope']!=config['scope']):raise ValueError('Архив предназначен для другого узла или другого состава системы')
 changed=[];missing=[];unsupported=[]
 for entry in manifest['files']:
  name=entry['path']
  if not covered(name,config):unsupported.append(name);continue
  path=host/name
  if not path.exists() and not path.is_symlink():missing.append(name);continue
  st=path.lstat();same=stat.S_IMODE(st.st_mode)==entry['mode'] and st.st_uid==entry['uid'] and st.st_gid==entry['gid']
  if entry['kind']=='file':same=same and stat.S_ISREG(st.st_mode) and st.st_size==entry['size'] and sha(path)==entry['sha256']
  elif entry['kind']=='symlink':same=same and stat.S_ISLNK(st.st_mode) and os.readlink(path)==entry['target']
  else:same=same and stat.S_ISDIR(st.st_mode)
  if not same:changed.append(name)
 summary={'snapshot_created_at':manifest['created_at'],'same':len(manifest['files'])-len(changed)-len(missing)-len(unsupported),'changed':len(changed),'missing':len(missing),'unsupported':len(unsupported),'changed_paths':changed[:50],'missing_paths':missing[:50],'unsupported_paths':unsupported[:50],'signature_verified':True,'decryption_verified':True,'working_system_changed':False}
 if host==Path('/'):
  from backup_accounts import compare
  summary['accounts']=compare(manifest['metadata'].get('accounts'))
 result={**info,'status':'checked','bytes':(job/'uploaded.age').stat().st_size,'sha256':sha(job/'uploaded.age'),'files':len(manifest['files']),'total_bytes':manifest['total_bytes'],'summary':summary,
         'anchor_id':anchor_id,'anchor_digest':identity['digest'],'manifest_sha256':sha(job/'staged'/'manifest.json')}
 save(job/'state.json',result);return result


def control(request,*,root=ROOT,panel=PANEL,host=Path('/'),age=AGE):
 root=Path(root);panel=Path(panel);host=Path(host);action=request.get('action')
 if action=='backup-status':return catalogue(root,panel)
 if action=='backup-trust-export':
  if set(request)!={'version','action'} or request.get('version')!=1:raise ValueError('Некорректный запрос публичной идентичности')
  return trust_export(root)
 if action not in ('backup-create','backup-inspect','backup-delete'):raise ValueError('Неизвестное действие с резервной копией')
 allowed={'version','action','id'}|({'recovery_key','anchor_id'} if action=='backup-inspect' else set())
 if set(request)-allowed:raise ValueError('Неизвестные поля резервной копии')
 value=identifier(request.get('id'));job=root/'jobs'/value;config=settings(root)
 with (root/'control.lock').open('a') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise ValueError('Другая операция резервной копии ещё выполняется. Обновите список') from None
  if action=='backup-delete':
   from recovery_control import job_active
   if job_active(value):raise ValueError('Копия используется незавершённым восстановлением')
   if job.exists():shutil.rmtree(job)
   for directory in ('backup-downloads','backup-uploads'):remove_panel_file(panel,directory,value)
   return {'id':value,'deleted':True,'working_system_changed':False}
  if job.exists():return {key:val for key,val in load(job/'state.json').items() if key not in ('pid','process_token')}
  if len(list((root/'jobs').iterdir()))>=5:raise ValueError('Уже сохранено пять операций. Скачайте нужные копии и удалите лишние записи')
  job.mkdir(mode=0o700);info={'id':value,'kind':'export' if action=='backup-create' else 'import','status':'creating' if action=='backup-create' else 'checking','created_at':time.time(),'pid':os.getpid(),'process_token':process_token()};save(job/'state.json',info)
  try:
   result=export(root,panel,host,age,config,job,info) if action=='backup-create' else inspect_upload(root,panel,host,age,config,job,info,request.get('recovery_key'),request.get('anchor_id'))
   return {key:val for key,val in result.items() if key not in ('pid','process_token')}
  except Exception as error:
   message=str(error) if type(error) is ValueError else 'Операция резервной копии не завершена. Рабочая сеть не менялась'
   save(job/'state.json',{**info,'status':'failed','error':message})
   for name in ('archive.age.partial','identity.tmp'):(job/name).unlink(missing_ok=True)
   if (job/'staged').exists():shutil.rmtree(job/'staged')
   raise ValueError(message) from None
  finally:
   remove_panel_file(panel,'backup-uploads',value)
