"""Create a private first-boot overlay for one Linux amd64 systemd host.

Never accepts / as destination and never installs services. Run after building
the public rootfs; copy this private overlay only inside the intended VM/host.
"""

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from werkzeug.security import generate_password_hash

SOURCE=Path(__file__).resolve().parent.parent/'src'


def write(path,data,mode=0o600):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb') as out:out.write(data)
 path.chmod(mode)


def initial_policy(address):
 dns=ipaddress.ip_address(address)
 if dns.is_unspecified or dns.is_multicast or dns.is_loopback:
  raise ValueError('Укажите достижимый DNS стенда, а не loopback/multicast')
 return {'default_exit':'direct','default_dns':'resolver',
         'exits':{'direct':{'name':'Напрямую','scope':'public','native':{'type':'direct'}}},
         'dns':{'resolver':{'name':'Основной DNS','scope':'public',
                            'native':{'type':'udp','server':str(dns)}}},
         'profiles':[],'incoming_connections':[]}


def password_bytes(path):
 if path is None:return getpass.getpass('Пароль нового администратора: ').encode()
 path=Path(path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as source:
  s=os.fstat(source.fileno())
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077 or s.st_size>4096:
   raise ValueError('Пароль должен быть в закрытом обычном файле текущего пользователя')
  raw=source.read(4097)
 return raw.rstrip(b'\r\n')


def provision(destination,*,username,dns,host,before_url,after_url,tls_chain,tls_key,password_file=None,age_keygen='age-keygen',source=SOURCE):
 source=Path(source).resolve()
 if not (source/'candidate_bundle.py').is_file() or not (source/'restore_files.py').is_file():
  raise ValueError('Не указан полный текущий source из проверенного комплекта')
 sys.path.insert(0,str(source))
 from candidate_bundle import build_bundle,validate_bundle
 from restore_files import health_checks
 destination=Path(destination).absolute()
 if destination==Path('/') or destination.exists() or destination.is_symlink():
  raise ValueError('Для приватного overlay нужен новый отдельный каталог')
 if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}',username):raise ValueError('Некорректный логин')
 if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9.:-]{0,252}',host):raise ValueError('Некорректный HTTPS Host')
 for path in (tls_chain,tls_key):
  if not isinstance(path,str) or not path.startswith('/etc/letsencrypt/live/') or '..' in Path(path).parts:
   raise ValueError('TLS источник должен находиться в certbot live')
 checks_before=health_checks([{'url':before_url,'codes':[200],'timeout':10}])
 checks_after=health_checks([{'url':after_url,'codes':[200],'timeout':10}])
 secret=password_bytes(password_file)
 if not 12<=len(secret)<=4096 or b'\x00' in secret:raise ValueError('Пароль администратора вне допустимого диапазона')
 policy=initial_policy(dns)
 bundle=build_bundle(policy,api_secret=secrets.token_urlsafe(32))
 validate_bundle(bundle)
 destination.mkdir(mode=0o700,parents=False)
 try:
  panel=destination/'var/lib/okopy-panel';runtime=destination/'var/lib/okopy-candidate'
  backup=destination/'var/lib/okopy-backup';recovery=destination/'var/lib/okopy-recovery'
  for directory in (panel,runtime,backup,recovery,recovery/'anchors',destination/'var/lib/okopy-recovery-ui'):
   directory.mkdir(parents=True,exist_ok=True);directory.chmod(0o700)
  (backup/'jobs').mkdir(mode=0o700)
  (destination/'var/lib/okopy-recovery-ui').chmod(0o750)
  (destination/'var/lib/okopy-recovery-ui/tls').mkdir(mode=0o700)
  socket_root=destination/'var/www/certbot/.farvater-recovery'
  socket_root.mkdir(parents=True,mode=0o770);socket_root.chmod(0o770)
  auth=json.dumps({'username':username,
      'password_hash':generate_password_hash(secret.decode('utf-8')),
      'session_secret':secrets.token_urlsafe(48)},separators=(',',':')).encode()
  write(panel/'auth.json',auth)
  panel_auth=json.loads(auth)
  rescue_auth=json.dumps({'username':panel_auth['username'],'password_hash':panel_auth['password_hash'],
                          'session_secret':secrets.token_urlsafe(48)},separators=(',',':')).encode()
  write(destination/'var/lib/okopy-recovery-ui/auth.json',rescue_auth,0o640)
  write(panel/'policy.json',bundle['applied-policy.json'])
  for directory in ('backup-uploads','backup-downloads'):
   (panel/directory).mkdir(mode=0o700)
  for name,data in bundle.items():write(runtime/name,data)
  for name in ('apply.lock','routing.lock','lan.lock','vpn.lock'):write(runtime/name,b'')
  write(runtime/'transaction.json',json.dumps({'id':'bootstrap','status':'bootstrap','runtime_ready':False,
      'previous_files':{name:hashlib.sha256(data).hexdigest() for name,data in bundle.items()}},
      sort_keys=True,separators=(',',':')).encode())
  write(backup/'signing.key',Ed25519PrivateKey.generate().private_bytes(
      Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
  key=backup/'recovery.agekey'
  key.parent.mkdir(parents=True,exist_ok=True)
  generated=subprocess.run([age_keygen,'-o',str(key)],capture_output=True,text=True,timeout=20)
  if generated.returncode:raise ValueError('age-keygen не создал ключ восстановления')
  key.chmod(0o600)
  derived=subprocess.run([age_keygen,'-y',str(key)],capture_output=True,text=True,timeout=10)
  recipient=derived.stdout.strip()
  if derived.returncode or not re.fullmatch('age1[0-9a-z]{58}',recipient):
   raise ValueError('age-keygen вернул неверный recipient')
  backup_config={'version':1,'recipient':recipient,'host_id':secrets.token_hex(16),'scope':'server',
      'exclusions':['recovery capsule','backup archives and recovery key'],
      'required':['opt/farvater/app/web.py','var/lib/okopy-candidate/config.json',
                  'var/lib/okopy-panel/auth.json','var/lib/okopy-panel/policy.json',
                  'var/lib/okopy-backup/signing.key',
                  'var/lib/okopy-backup/settings.json','etc/systemd/system/okopy-panel.service',
                  'etc/systemd/system/okopy-candidate.service'],
      'trees':['opt/farvater/app','opt/farvater/engines','opt/farvater/venv',
               'var/lib/okopy-candidate',
               'var/lib/okopy-wireguard','var/lib/okopy-openconnect',
               'var/lib/okopy-trusttunnel','var/lib/okopy-amnezia','var/lib/okopy-monitor',
               'etc/wireguard','etc/amnezia/amneziawg',
               'etc/letsencrypt','var/lib/okopy-backup/signing.key','var/lib/okopy-backup/settings.json'],
      'globs':['var/lib/okopy-panel/auth.json','var/lib/okopy-panel/policy.json',
               'var/lib/okopy-panel/server.json','var/lib/okopy-panel/monitor-view.json',
               'var/lib/okopy-panel/policy.before-import.json',
               'etc/systemd/system/okopy-*','etc/systemd/system/farvater-*',
               'etc/systemd/system/*.wants/okopy-*','etc/systemd/system/*.wants/farvater-*',
               'etc/systemd/system/*.wants/wg-quick@*.service',
               'etc/systemd/system/*.requires/okopy-*','etc/systemd/system/*.requires/farvater-*',
               'etc/systemd/system/*.requires/wg-quick@*.service',
               'etc/systemd/system/wg-quick@.service.d/50-okopy-recovery.conf'],
      'exclude':['var/lib/okopy-panel/backup-uploads*','var/lib/okopy-panel/backup-downloads*',
                 'var/lib/okopy-panel/health.json','var/lib/okopy-panel/health-transport.json',
                 'var/lib/okopy-panel/*.lock',
                 'var/lib/okopy-candidate/cache.db','var/lib/okopy-candidate/*.lock',
                 'var/lib/okopy-candidate/*.log','var/lib/okopy-candidate/routing-state.json',
                 'var/lib/okopy-candidate/routing-events.json',
                 'var/lib/okopy-wireguard/*.lock','var/lib/okopy-openconnect/*.lock',
                 'var/lib/okopy-openconnect/*.runtime*','var/lib/okopy-openconnect/*.started.json',
                 'var/lib/okopy-trusttunnel/*.lock','var/lib/okopy-trusttunnel/*.started.json',
                 'var/lib/okopy-amnezia/*.lock','var/lib/okopy-monitor/health*.json',
                 'var/lib/okopy-monitor/slow-health.json','var/lib/okopy-monitor/*events.json',
                 'var/lib/okopy-monitor/*.lock','var/lib/okopy-monitor/*.log',
                 'var/lib/okopy-backup/recovery.agekey'],
      'units':['okopy-panel.service','okopy-candidate.service']}
  write(backup/'settings.json',(json.dumps(backup_config,sort_keys=True,separators=(',',':'))+'\n').encode())
  recovery_config={'version':1,'before_checks':checks_before,'after_checks':checks_after,
                   'deferred_writers':['okopy-panel.service','okopy-routing.service','okopy-routing.timer'],
                   'tls_chain_source':tls_chain,'tls_key_source':tls_key}
  write(recovery/'settings.json',(json.dumps(recovery_config,sort_keys=True,separators=(',',':'))+'\n').encode())
  write(destination/'var/lib/okopy-recovery-ui/barrier.json',
        b'{"job_id":null,"status":"inactive","version":1}',0o640)
  write(destination/'etc/farvater/panel.env',('OKOPY_TRUSTED_HOSTS='+host+'\n').encode())
  write(destination/'etc/farvater/recovery-ui.env',('FARVATER_RECOVERY_HOSTS='+host+'\n').encode())
  return {'status':'private-overlay','files':len([p for p in destination.rglob('*') if p.is_file()]),
          'requires_chown':{'panel':'okopy-panel:okopy-panel','other':'root:root'},
          'recovery_key':'var/lib/okopy-backup/recovery.agekey'}
 except BaseException:
  shutil.rmtree(destination)
  raise


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--destination',required=True,type=Path)
 parser.add_argument('--username',required=True)
 parser.add_argument('--dns',required=True)
 parser.add_argument('--host',required=True)
 parser.add_argument('--before-url',required=True)
 parser.add_argument('--after-url',required=True)
 parser.add_argument('--tls-chain',required=True)
 parser.add_argument('--tls-key',required=True)
 parser.add_argument('--password-file',type=Path)
 parser.add_argument('--age-keygen',default='age-keygen')
 parser.add_argument('--source',type=Path,default=SOURCE,
                     help='Путь к текущему staged app source, если install/src не доступен')
 args=parser.parse_args()
 result=provision(args.destination,username=args.username,dns=args.dns,host=args.host,
                  before_url=args.before_url,after_url=args.after_url,tls_chain=args.tls_chain,
                  tls_key=args.tls_key,password_file=args.password_file,age_keygen=args.age_keygen,source=args.source)
 print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
