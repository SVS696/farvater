"""Install one verified Farvater stage on an empty Linux amd64 systemd host.

`check` reads the target and refuses collisions. `apply` repeats every check,
then writes files and enables services only after validation. Dependencies and
certbot certificates must already be present; no package manager is invoked.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import shutil
import socket
import ssl
import stat
import subprocess
import sys

import proxy_caddy
import verify_current


STATE_ROOTS=(
 'opt/farvater','opt/okopy-recovery-ui','opt/okopy-panel/proxy',
 'var/lib/okopy-panel','var/lib/okopy-candidate','var/lib/okopy-backup',
 'var/lib/okopy-recovery','var/lib/okopy-recovery-ui',
 'var/www/certbot/.okopy-panel','var/www/certbot/.farvater-recovery',
)
ALLOWED_OVERLAY=('etc/farvater/','var/lib/okopy-','var/www/certbot/.farvater-recovery/')
REQUIRED_BINARIES=('/usr/bin/python3','/usr/bin/curl','/usr/bin/age',
                   '/usr/bin/sudo','/usr/bin/caddy')
SERVICES=('okopy-candidate.service','infrastructure-recovery-ui.service',
          'okopy-panel.service','infrastructure-recovery-https.service')


def run(command):
 result=subprocess.run(command,capture_output=True,text=True,timeout=300)
 if result.returncode:raise ValueError('Не выполнена системная проверка или установка: '+command[0])
 return result.stdout.strip()


def host_capabilities():
 if (sys.platform!='linux' or os.uname().machine not in ('x86_64','amd64')
     or not Path('/run/systemd/system').is_dir() or sys.version_info<(3,11)):
  raise ValueError('Нужен Linux amd64 с systemd и Python 3.11 или новее')
 for name in REQUIRED_BINARIES:
  if not Path(name).is_file():raise ValueError('Нет обязательной команды '+name)
 for name in ('systemctl','systemd-run','systemd-sysusers','systemd-tmpfiles',
              'systemd-analyze','visudo','age-keygen','nft','ip','openssl'):
  if shutil.which(name) is None:raise ValueError('Нет обязательной команды '+name)
 if not any(shutil.which(name) for name in ('dpkg-query','rpm','pacman')):
  raise ValueError('Нет поддерживаемого источника сведений о системных пакетах')
 unit_paths=run(['systemd-analyze','unit-paths']).splitlines()
 if '/usr/local/lib/systemd/system' not in unit_paths:
  raise ValueError('systemd не загружает защищённые unit из /usr/local/lib/systemd/system')
 if subprocess.run(['systemctl','is-enabled','--quiet','caddy.service']).returncode==0:
  raise ValueError('Пакетная caddy.service включена; отключите её до отдельного Farvater HTTPS unit')
 if subprocess.run(['systemctl','is-active','--quiet','caddy.service']).returncode==0:
  raise ValueError('Пакетная caddy.service запущена; не перехватываем существующий HTTPS')


def entries(tree):
 tree=Path(tree)
 if tree.is_symlink() or not tree.is_dir():raise ValueError('Нет обычного каталога комплекта')
 files={};links={};directories={}
 for path in sorted(tree.rglob('*')):
  name=path.relative_to(tree).as_posix();mode=path.lstat().st_mode
  if stat.S_ISDIR(mode):directories[name]=path
  elif stat.S_ISREG(mode):files[name]=path
  elif stat.S_ISLNK(mode):links[name]=path
  else:raise ValueError('Специальный файл в комплекте: '+name)
 return files,links,directories


def ordinary_parent(path,root):
 owner=0 if root==Path('/') else os.geteuid()
 for parent in path.parents:
  if parent==root:break
  if parent.is_symlink():raise ValueError('Родитель назначения является ссылкой: '+str(parent))
  if parent.exists():
   info=parent.stat()
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:
    raise ValueError('Родитель назначения доступен для чужой записи: '+str(parent))


def overlay_inputs(overlay,owner):
 overlay=Path(overlay)
 if overlay.is_symlink() or overlay==Path('/') or not overlay.is_dir():
  raise ValueError('Нужен отдельный приватный overlay')
 overlay=overlay.resolve()
 if overlay.stat().st_uid!=owner:raise ValueError('Приватный overlay принадлежит другому пользователю')
 if stat.S_IMODE(overlay.stat().st_mode)!=0o700:
  raise ValueError('Приватный overlay должен иметь права 0700')
 files,links,dirs=entries(overlay)
 if links:raise ValueError('Ссылки в приватном overlay запрещены')
 for name,path in files.items():
  if (not name.startswith(ALLOWED_OVERLAY) or path.stat().st_uid!=owner
      or path.stat().st_mode&0o027 or path.stat().st_mode&0o111
      or stat.S_IMODE(path.stat().st_mode)&0o7000):
   raise ValueError('Неожиданный или открытый файл приватного overlay: '+name)
 required=('var/lib/okopy-panel/auth.json','var/lib/okopy-panel/policy.json',
           'var/lib/okopy-candidate/config.json','var/lib/okopy-backup/signing.key',
           'var/lib/okopy-backup/settings.json','var/lib/okopy-recovery/settings.json',
           'var/lib/okopy-recovery-ui/auth.json','var/lib/okopy-recovery-ui/barrier.json',
           'etc/farvater/panel.env','etc/farvater/recovery-ui.env')
 if not set(required)<=set(files):raise ValueError('В приватном overlay отсутствует обязательное состояние')
 required_dirs=('var/lib/okopy-panel/backup-uploads','var/lib/okopy-panel/backup-downloads',
                'var/lib/okopy-backup/jobs','var/lib/okopy-recovery/anchors',
                'var/lib/okopy-recovery-ui/tls','var/www/certbot/.farvater-recovery')
 if not set(required_dirs)<=set(dirs):raise ValueError('В приватном overlay отсутствуют закрытые каталоги')
 modes={'var/lib/okopy-panel':0o700,'var/lib/okopy-candidate':0o700,
        'var/lib/okopy-backup':0o700,'var/lib/okopy-recovery':0o700,
        'var/lib/okopy-recovery-ui':0o750,'var/lib/okopy-recovery-ui/tls':0o700,
        'var/www/certbot/.farvater-recovery':0o770}
 for name,mode in modes.items():
  if name not in dirs or stat.S_IMODE(dirs[name].stat().st_mode)!=mode:
   raise ValueError('Небезопасные права каталога приватного overlay: '+name)
 for name in ('var/lib/okopy-recovery-ui/auth.json','var/lib/okopy-recovery-ui/barrier.json'):
  if stat.S_IMODE(files[name].stat().st_mode)!=0o640:
   raise ValueError('Небезопасные права rescue файла: '+name)
 return overlay,files,dirs


def private_settings(files,root):
 recovery=json.loads(files['var/lib/okopy-recovery/settings.json'].read_text())
 panel_env=files['etc/farvater/panel.env'].read_text().splitlines()
 rescue_env=files['etc/farvater/recovery-ui.env'].read_text().splitlines()
 if (len(panel_env)!=1 or not panel_env[0].startswith('OKOPY_TRUSTED_HOSTS=')
     or rescue_env!=['FARVATER_RECOVERY_HOSTS='+panel_env[0].split('=',1)[1]]):
  raise ValueError('HTTPS Host панели и rescue не совпадает')
 host=panel_env[0].split('=',1)[1]
 if not host or ',' in host:raise ValueError('Для первой установки нужен один HTTPS Host')
 certs=[]
 for field in ('tls_chain_source','tls_key_source'):
  value=recovery.get(field)
  if not isinstance(value,str) or not value.startswith('/etc/letsencrypt/live/') or '..' in Path(value).parts:
   raise ValueError('TLS-источник должен быть certbot live-ссылкой')
  path=root/value.lstrip('/')
  if not path.is_symlink():raise ValueError('TLS-источник не является certbot live-ссылкой')
  resolved=path.resolve(strict=True)
  if not resolved.is_relative_to(root/'etc/letsencrypt/archive') or not resolved.is_file():
   raise ValueError('TLS-источник вышел за certbot archive')
  owner=0 if root==Path('/') else os.geteuid()
  if resolved.stat().st_uid!=owner or resolved.stat().st_mode&0o022:
   raise ValueError('TLS-файл доступен для чужой записи')
  ordinary_parent(resolved,root)
  certs.append(path)
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
 try:context.load_cert_chain(str(certs[0]),str(certs[1]))
 except (ssl.SSLError,OSError):raise ValueError('TLS-сертификат и ключ не образуют пару') from None
 match=subprocess.run(['openssl','x509','-in',str(certs[0]),'-noout','-checkhost',host],
                      capture_output=True,timeout=10)
 if match.returncode or match.stdout.decode(errors='replace').strip()!=f'Hostname {host} does match certificate':
  raise ValueError('TLS-сертификат не соответствует HTTPS Host')
 return host


def plan(stage,overlay,manifest_sha256,networks,port,root=Path('/'),*,capabilities=True):
 root=Path(root).resolve();stage=Path(stage)
 if stage.is_symlink():raise ValueError('Каталог публичного комплекта не должен быть ссылкой')
 stage=stage.resolve()
 owner=0 if root==Path('/') else os.geteuid()
 if stage.stat().st_uid!=owner or stage.stat().st_mode&0o077:
  raise ValueError('Публичный stage должен принадлежать исполнителю и быть закрытым')
 if root==Path('/'):
  ordinary_parent(stage,Path('/'))
  ordinary_parent(Path(overlay).resolve(),Path('/'))
 if capabilities:host_capabilities()
 if not networks:raise ValueError('Укажите хотя бы одну административную сеть')
 verified=verify_current.verify(stage,manifest_sha256)
 manifest=json.loads((stage/'manifest.json').read_text())
 if manifest.get('platform')!='linux-amd64' or manifest.get('runtime_ready') is not False:
  raise ValueError('Это не Linux amd64 staging kit')
 if 'ocserv' in manifest.get('engines',{}):
  os_release=dict(line.split('=',1) for line in (root/'etc/os-release').read_text().splitlines() if '=' in line)
  if os_release.get('ID')!='ubuntu' or os_release.get('VERSION_ID','').strip('"')!='24.04':
   raise ValueError('Этот ocserv engine собран только для Ubuntu 24.04 amd64')
 _,private_files,private_dirs=overlay_inputs(overlay,owner)
 public_files,public_links,public_dirs=entries(stage/'rootfs')
 if set(public_files)!=set(manifest['rootfs_files']) or set(public_links)!=set(manifest['rootfs_links']):
  raise ValueError('Состав rootfs изменился после проверки')
 if set(private_files)&(set(public_files)|set(public_links)):
  raise ValueError('Публичный и приватный состав пересекаются')
 host=private_settings(private_files,root)
 caddy=proxy_caddy.render(host,port,networks)
 if capabilities:
  try:
   with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
    probe.bind(('0.0.0.0',port))
  except OSError:raise ValueError('HTTPS-порт уже занят или недоступен') from None
 for name in STATE_ROOTS:
  target=root/name
  if target.exists() or target.is_symlink():raise ValueError('Целевое состояние уже существует: /'+name)
 for name in ('var/www','var/www/certbot'):
  target=root/name
  if target.is_symlink():raise ValueError('Каталог сокетов не должен быть ссылкой: /'+name)
  if target.exists():
   info=target.stat()
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or not info.st_mode&stat.S_IXOTH:
    raise ValueError('Каталог сокетов недоступен отдельному rescue пользователю: /'+name)
 for name in list(public_files)+list(public_links)+list(private_files)+['opt/okopy-panel/proxy/Caddyfile']:
  target=root/name;ordinary_parent(target,root)
  if target.exists() or target.is_symlink():raise ValueError('Файл назначения уже существует: /'+name)
 if capabilities:
  for name in ('okopy-panel','okopy-recovery'):
   if subprocess.run(['id','-u',name],capture_output=True).returncode==0:
    raise ValueError('Системный пользователь уже существует: '+name)
 return {'stage':stage,'overlay':Path(overlay).resolve(),'root':root,'manifest':manifest,
         'public_files':public_files,'public_links':public_links,'public_dirs':public_dirs,
         'private_files':private_files,'private_dirs':private_dirs,'caddy':caddy,
         'verified':verified}


def copy_file(source,target,mode,expected=None):
 target.parent.mkdir(parents=True,exist_ok=True)
 digest=hashlib.sha256()
 created=False
 try:
  source_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(source_fd,'rb') as incoming:
   if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):raise ValueError('Источник перестал быть обычным файлом')
   fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   created=True
   with os.fdopen(fd,'wb') as output:
    while data:=incoming.read(1024*1024):digest.update(data);output.write(data)
    output.flush();os.fchmod(output.fileno(),mode);os.fsync(output.fileno())
  if expected is not None and digest.hexdigest()!=expected:
   target.unlink();raise ValueError('Хеш файла изменился при установке: '+str(target))
 except BaseException:
  if created:target.unlink(missing_ok=True)
  raise


def copy_tree(prepared):
 root=prepared['root'];manifest=prepared['manifest']
 dirs={**prepared['public_dirs'],**prepared['private_dirs']}
 for name,source in sorted(dirs.items(),key=lambda item:len(Path(item[0]).parts)):
  target=root/name
  if not target.exists():
   target.mkdir(parents=True,mode=0o711 if name in ('var/www','var/www/certbot') else 0o700)
   if name in ('var/www','var/www/certbot'):target.chmod(0o711)
  if name not in ('etc','etc/systemd','etc/systemd/system','usr','usr/local','usr/local/lib',
                  'usr/local/lib/systemd','usr/local/lib/systemd/system','var','var/lib','var/www',
                  'var/www/certbot','opt'):
   target.chmod(stat.S_IMODE(source.stat().st_mode))
 for name,source in sorted(prepared['public_files'].items()):
  record=manifest['rootfs_files'][name]
  copy_file(source,root/name,record['mode'],record['sha256'])
 for name,source in sorted(prepared['public_links'].items()):
  expected=manifest['rootfs_links'][name]
  if os.readlink(source)!=expected:raise ValueError('Ссылка комплекта изменилась')
  target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.symlink_to(expected)
 for name,source in sorted(prepared['private_files'].items()):
  copy_file(source,root/name,stat.S_IMODE(source.stat().st_mode))
 caddy=root/'opt/okopy-panel/proxy/Caddyfile'
 caddy.parent.mkdir(parents=True,exist_ok=True)
 fd=os.open(caddy,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as output:
  output.write(prepared['caddy'].encode());output.flush();os.fsync(output.fileno())


def install(stage,overlay,manifest_sha256,networks,port,root=Path('/'),*,capabilities=True):
 root=Path(root).resolve()
 if capabilities and os.geteuid()!=0:raise ValueError('Установка требует root')
 prepared=plan(stage,overlay,manifest_sha256,networks,port,root=root,capabilities=capabilities)
 copy_tree(prepared)
 for name in ('farvater-panel.conf','farvater-recovery.conf','farvater-ocserv.conf'):
  path=root/'etc/sysusers.d'/name
  if path.exists():run(['systemd-sysusers',str(path)])
 panel=pwd.getpwnam('okopy-panel');recovery=grp.getgrnam('okopy-recovery')
 panel_root=root/'var/lib/okopy-panel'
 for path in [panel_root,*panel_root.rglob('*')]:
  os.chown(path,panel.pw_uid,panel.pw_gid)
  if path.is_dir():path.chmod(0o700)
 for name in ('auth.json','barrier.json'):
  path=root/'var/lib/okopy-recovery-ui'/name
  os.chown(path,0,recovery.gr_gid);path.chmod(0o640)
 recovery_root=root/'var/lib/okopy-recovery-ui'
 os.chown(recovery_root,0,recovery.gr_gid);recovery_root.chmod(0o750)
 tls_root=recovery_root/'tls';os.chown(tls_root,0,0);tls_root.chmod(0o700)
 socket_root=root/'var/www/certbot/.farvater-recovery'
 os.chown(socket_root,0,recovery.gr_gid);socket_root.chmod(0o2770)
 panel_socket=root/'var/www/certbot/.okopy-panel'
 panel_socket.mkdir(parents=True,exist_ok=False)
 os.chown(panel_socket,0,panel.pw_gid);panel_socket.chmod(0o2770)
 for name in ('farvater-recovery.conf','farvater-amneziawg.conf','farvater-ocserv.conf'):
  path=root/'etc/tmpfiles.d'/name
  if path.exists():run(['systemd-tmpfiles','--create',str(path)])
 lock=root/'opt/farvater/app/requirements-lock.txt'
 for target in (root/'opt/farvater/venv',root/'opt/okopy-recovery-ui/venv'):
  run(['/usr/bin/python3','-m','venv',str(target)])
  run([str(target/'bin/python'),'-m','pip','install','--require-hashes','-r',str(lock)])
 run(['/usr/bin/python3','-I',str(root/'opt/okopy-recovery-ui/tls_refresh.py')])
 for name in ('okopy-panel','okopy-candidate','infrastructure-recovery-ui'):
  run(['systemd-analyze','verify',str(root/'etc/systemd/system'/(name+'.service'))])
 run(['systemd-analyze','verify',str(root/'usr/local/lib/systemd/system/infrastructure-recovery-https.service')])
 for name in ('okopy-panel','farvater-recovery-ui'):
  run(['visudo','-cf',str(root/'etc/sudoers.d'/name)])
 run([str(root/'var/lib/okopy-candidate/sing-box'),'check','-c',str(root/'var/lib/okopy-candidate/config.json')])
 run(['/usr/bin/caddy','validate','--config',str(root/'opt/okopy-panel/proxy/Caddyfile'),'--adapter','caddyfile'])
 run(['systemctl','daemon-reload'])
 for service in SERVICES:run(['systemctl','enable','--now',service])
 return {'status':'installed','services':len(SERVICES),'public_files':len(prepared['public_files'])}


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('action',choices=('check','apply'))
 parser.add_argument('--stage',required=True,type=Path)
 parser.add_argument('--overlay',required=True,type=Path)
 parser.add_argument('--manifest-sha256',required=True)
 parser.add_argument('--owner-network',action='append',required=True)
 parser.add_argument('--https-port',type=int,default=443)
 args=parser.parse_args()
 try:
  if args.action=='check':
   prepared=plan(args.stage,args.overlay,args.manifest_sha256,args.owner_network,args.https_port)
   result={'status':'ready_to_install','public_files':len(prepared['public_files']),
           'private_files':len(prepared['private_files']),'services':len(SERVICES)}
  else:result=install(args.stage,args.overlay,args.manifest_sha256,args.owner_network,args.https_port)
  print(json.dumps(result,sort_keys=True))
 except (ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
  parser.exit(1,'Установка не выполнена: '+str(error)+'\n')


if __name__=='__main__':main()
