"""Rebuild a signed snapshot into a NEW private tree, never over the live host.

The caller owns the parent directory exclusively. This is the preparation step
for recovery, not the service activation or rollback coordinator.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import backup_archive as archive


def signed_manifest(staged,public_key):
 staged=Path(staged)
 raw=(staged/'manifest.json').read_bytes()
 if len(raw)>archive.MAX_MANIFEST:raise ValueError('Манифест превышает допустимый размер')
 try:Ed25519PublicKey.from_public_bytes(public_key).verify((staged/'manifest.sig').read_bytes(),raw)
 except (InvalidSignature,ValueError):raise ValueError('Подпись подготовленного комплекта не совпадает') from None
 value=json.loads(raw)
 if not isinstance(value,dict) or value.get('format')!='okopy-system-backup' or value.get('version')!=archive.VERSION:raise ValueError('Неизвестный формат снимка')
 records=value.get('files')
 if not isinstance(records,list) or not 1<=len(records)<=archive.MAX_FILES:raise ValueError('Некорректное число файлов')
 names={};total=0
 for r in records:
  name=archive.relative(r.get('path'));kind=r.get('kind')
  if name in names or kind not in ('file','directory','symlink'):raise ValueError('Некорректная структура снимка')
  if any(type(r.get(k)) is not int or not 0<=r[k]<2**32 for k in ('uid','gid')) or type(r.get('mode')) is not int or not 0<=r['mode']<=0o7777:raise ValueError('Некорректные права или владелец')
  if kind=='file':
   digest=r.get('sha256');size=r.get('size')
   if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):raise ValueError('Некорректный SHA-256')
   if type(size) is not int or not 0<=size<=archive.MAX_FILE:raise ValueError('Некорректный размер файла')
   total+=size
  elif kind=='symlink':
   target=r.get('target')
   if not isinstance(target,str) or not target or len(target)>1024 or any(ord(c)<32 for c in target):raise ValueError('Некорректная ссылка')
  names[name]=r
 if total>archive.MAX_TOTAL or total!=value.get('total_bytes'):raise ValueError('Общий размер снимка не совпадает')
 for name in names:
  for parent in Path(name).parents:
   if str(parent) in names and names[str(parent)]['kind']!='directory':raise ValueError('Путь проходит через ссылку или файл')
 return value


def copy_object(staged,record,destination):
 """Use no-follow descriptors and verify the bytes that were actually copied."""
 objects=os.open(staged/'objects',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:source=os.open(record['sha256'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=objects)
 finally:os.close(objects)
 with os.fdopen(source,'rb') as src:
  st=os.fstat(src.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_size!=record['size']:raise ValueError('Размер или тип подготовленного файла не совпадает')
  target=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(target,'wb') as dst:
   digest=hashlib.sha256();count=0
   while data:=src.read(1024*1024):
    count+=len(data)
    if count>record['size']:raise ValueError('Подготовленный файл изменился')
    digest.update(data);dst.write(data)
   if count!=record['size'] or digest.hexdigest()!=record['sha256']:raise ValueError('Подготовленный файл повреждён')
   os.fchown(dst.fileno(),record['uid'],record['gid']);os.fchmod(dst.fileno(),record['mode'])
   dst.flush();os.fsync(dst.fileno())


def materialize(staged,destination,public_key):
 """Require an absent destination under a private parent; publish after validation.

 Absolute symlinks retain their original meaning for eventual installation.
 They are created LAST and never followed here. No program from the tree runs.
 """
 staged=Path(staged);destination=Path(destination)
 if not destination.is_absolute() or destination.name in ('','.','..') or destination==Path('/'):
  raise ValueError('Нужен новый абсолютный путь отдельного комплекта')
 if destination.exists() or destination.is_symlink():raise ValueError('Каталог назначения уже существует; замена работающих файлов запрещена')
 parent=destination.parent
 if parent.resolve()!=parent or not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode)&0o077 or parent.stat().st_uid!=os.geteuid():
  raise ValueError('Родительский каталог должен принадлежать исполнителю, иметь права 0700 и не проходить через ссылки')
 manifest=signed_manifest(staged,public_key)
 if shutil.disk_usage(parent).free<manifest['total_bytes']+64*1024*1024:raise ValueError('Недостаточно места для восстановления')
 temp=Path(tempfile.mkdtemp(prefix='.restore-',dir=parent))
 try:
  records=manifest['files']
  # All parent directories are made before any symlink; umask cannot expose keys.
  for r in records:
   target=temp/r['path']
   missing=[];p=target if r['kind']=='directory' else target.parent
   while p!=temp and not p.exists():missing.append(p);p=p.parent
   for p in reversed(missing):p.mkdir(mode=0o700)
  for r in records:
   if r['kind']=='file':copy_object(staged,r,temp/r['path'])
  for r in records:
   if r['kind']=='symlink':
    target=temp/r['path'];target.symlink_to(r['target']);os.lchown(target,r['uid'],r['gid'])
  for r in sorted((r for r in records if r['kind']=='directory'),key=lambda r:len(Path(r['path']).parts),reverse=True):
   target=temp/r['path'];os.chown(target,r['uid'],r['gid']);os.chmod(target,r['mode'])
  # Parent is owner-only; refuse an unexpected new name even in our own process.
  if destination.exists() or destination.is_symlink():raise ValueError('Каталог назначения появился во время подготовки')
  os.rename(temp,destination)
  fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 except BaseException:
  # Restore traversal permission if archived directory modes prevented cleanup.
  if temp.exists():
   os.chmod(temp,0o700)
   for r in sorted((r for r in manifest['files'] if r['kind']=='directory'),key=lambda r:len(Path(r['path']).parts)):
    target=temp/r['path']
    if target.is_dir() and not target.is_symlink():os.chmod(target,0o700)
   shutil.rmtree(temp)
  raise
 return {'destination':str(destination),'files':len(records),'bytes':manifest['total_bytes'],
         'manifest_sha256':hashlib.sha256((staged/'manifest.json').read_bytes()).hexdigest(),
         'signature_verified':True,'content_verified':True,'services_started':False,'live_host_modified':False}


def main():
 parser=argparse.ArgumentParser(description='Подготовить отдельный каталог восстановления из проверенного снимка; службы не запускаются')
 parser.add_argument('--staged',required=True);parser.add_argument('--destination',required=True);parser.add_argument('--public-key',required=True)
 args=parser.parse_args()
 print(json.dumps(materialize(args.staged,args.destination,Path(args.public_key).read_bytes()),ensure_ascii=False))

if __name__=='__main__':main()
