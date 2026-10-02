"""Signed tar stream. No archive member is ever extracted into the host tree."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey

VERSION=1
MAX_FILES=20000
MAX_TOTAL=1024*1024*1024
MAX_FILE=256*1024*1024
MAX_MANIFEST=8*1024*1024


def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def digest(data):return hashlib.sha256(data).hexdigest()

def relative(name):
 if not isinstance(name,str) or not name or len(name)>1024 or '\\' in name or any(ord(c)<32 for c in name):raise ValueError('Некорректный путь в архиве')
 path=PurePosixPath(name)
 if path.is_absolute() or any(part in ('.','..') for part in name.split('/')) or str(path)!=name:raise ValueError('Путь архива выходит за допустимую структуру')
 return name


def add_bytes(archive,name,data):
 info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600
 archive.addfile(info,io.BytesIO(data))


class HashReader:
 def __init__(self,file):self.file=file;self.hash=hashlib.sha256();self.count=0
 def read(self,size):
  data=self.file.read(size);self.hash.update(data);self.count+=len(data);return data


def write(stream,paths,*,source_root,private_key,metadata):
 """Caller holds configuration locks; metadata contains no secret file contents."""
 source_root=Path(source_root);records=[];total=0
 with gzip.GzipFile(fileobj=stream,mode='wb',compresslevel=3,mtime=0) as compressed, tarfile.open(fileobj=compressed,mode='w|',format=tarfile.PAX_FORMAT) as archive:
  for name in sorted(set(paths)):
   relative(name)
   if len(records)>=MAX_FILES:raise ValueError('Слишком много файлов для одного архива')
   path=source_root/name;st=path.lstat();record={'path':name,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}
   info=tarfile.TarInfo('files/'+name);info.mode=record['mode'];info.uid=st.st_uid;info.gid=st.st_gid;info.mtime=int(st.st_mtime)
   if stat.S_ISDIR(st.st_mode):record['kind']='directory';info.type=tarfile.DIRTYPE;archive.addfile(info)
   elif stat.S_ISLNK(st.st_mode):
    target=os.readlink(path)
    if len(target)>1024 or any(ord(c)<32 for c in target):raise ValueError('Некорректная ссылка в снимке')
    record.update(kind='symlink',target=target);info.type=tarfile.SYMTYPE;info.linkname=target;archive.addfile(info)
   elif stat.S_ISREG(st.st_mode):
    if st.st_size>MAX_FILE or total+st.st_size>MAX_TOTAL:raise ValueError('Снимок превышает допустимый размер')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as file:
     before=os.fstat(file.fileno())
     if (before.st_dev,before.st_ino,before.st_size)!=(st.st_dev,st.st_ino,st.st_size):raise ValueError('Файл изменился во время снимка; повторите экспорт')
     reader=HashReader(file);info.size=before.st_size;archive.addfile(info,reader);after=os.fstat(file.fileno())
     if (before.st_mtime_ns,before.st_ctime_ns,before.st_size)!=(after.st_mtime_ns,after.st_ctime_ns,after.st_size) or reader.count!=before.st_size:raise ValueError('Файл изменился во время снимка; повторите экспорт')
     record.update(kind='file',size=reader.count,sha256=reader.hash.hexdigest());total+=reader.count
   else:raise ValueError('Снимок содержит неподдержанный тип файла')
   records.append(record)
  manifest={'format':'okopy-system-backup','version':VERSION,'created_at':int(time.time()),'metadata':metadata,'files':records,'total_bytes':total}
  data=canonical(manifest)
  if len(data)>MAX_MANIFEST:raise ValueError('Манифест слишком велик')
  signature=Ed25519PrivateKey.from_private_bytes(private_key).sign(data)
  add_bytes(archive,'manifest.json',data);add_bytes(archive,'manifest.sig',signature)
 return manifest


class BoundedTarInfo(tarfile.TarInfo):
 @classmethod
 def frombuf(cls,buf,encoding,errors):
  info=super().frombuf(buf,encoding,errors)
  if info.type in (tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_LONGLINK) and info.size>32768:raise ValueError('Служебный заголовок архива слишком велик')
  return info


def read(stream,*,public_key,staging):
 """Validate every signed member and stage regular data as content-addressed blobs.

 Absolute/sibling symlink targets are metadata only. No symlink is created, and
 uploaded paths are never opened in the running host filesystem.
 """
 staging=Path(staging);staging.mkdir(mode=0o700,exist_ok=False);objects=staging/'objects';objects.mkdir(mode=0o700)
 records={};raw_manifest=None;signature=None;total=0
 with tarfile.open(fileobj=stream,mode='r|gz',tarinfo=BoundedTarInfo) as archive:
  for member in archive:
   if len(records)>MAX_FILES:raise ValueError('Архив содержит слишком много файлов')
   name=member.name
   if name in ('manifest.json','manifest.sig'):
    if not member.isfile() or member.size>(MAX_MANIFEST if name.endswith('.json') else 64):raise ValueError('Некорректный манифест/подпись')
    body=archive.extractfile(member).read()
    if name=='manifest.json':
     if raw_manifest is not None:raise ValueError('Манифест повторяется')
     raw_manifest=body
    else:
     if signature is not None:raise ValueError('Подпись повторяется')
     signature=body
    continue
   if not name.startswith('files/'):raise ValueError('Неизвестный раздел архива')
   path=relative(name[6:])
   if path in records:raise ValueError('Путь повторяется в архиве')
   if type(member.uid) is not int or type(member.gid) is not int or not 0<=member.uid<2**32 or not 0<=member.gid<2**32 or not 0<=member.mode<=0o7777:raise ValueError('Некорректный владелец или режим файла')
   record={'path':path,'uid':member.uid,'gid':member.gid,'mode':member.mode}
   if member.isdir():record['kind']='directory'
   elif member.issym():
    if len(member.linkname)>1024 or any(ord(c)<32 for c in member.linkname):raise ValueError('Некорректная ссылка')
    record.update(kind='symlink',target=member.linkname)
   elif member.isfile():
    if not 0<=member.size<=MAX_FILE or total+member.size>MAX_TOTAL:raise ValueError('Распакованный архив превышает допустимый размер')
    reader=archive.extractfile(member);hasher=hashlib.sha256();count=0;temp=objects/'incoming'
    with temp.open('xb') as file:
     os.chmod(temp,0o600)
     while True:
      data=reader.read(1024*1024)
      if not data:break
      count+=len(data)
      if count>member.size:raise ValueError('Файл длиннее объявленного размера')
      file.write(data);hasher.update(data)
    if count!=member.size:raise ValueError('Файл архива оборван')
    value=hasher.hexdigest();dest=objects/value
    if dest.exists():temp.unlink()
    else:os.replace(temp,dest)
    record.update(kind='file',size=count,sha256=value);total+=count
   else:raise ValueError('Ссылки hardlink, устройства и специальные файлы запрещены')
   records[path]=record
 if raw_manifest is None or signature is None or len(signature)!=64:raise ValueError('Нет манифеста или подписи новой системы')
 try:Ed25519PublicKey.from_public_bytes(public_key).verify(signature,raw_manifest)
 except (InvalidSignature,ValueError):raise ValueError('Подпись архива не принадлежит этому комплекту восстановления') from None
 try:manifest=json.loads(raw_manifest)
 except (ValueError,UnicodeError):raise ValueError('Повреждён манифест') from None
 expected={'format','version','created_at','metadata','files','total_bytes'}
 if not isinstance(manifest,dict) or set(manifest)!=expected or manifest['format']!='okopy-system-backup' or manifest['version']!=VERSION or not isinstance(manifest['metadata'],dict) or type(manifest['created_at']) is not int:raise ValueError('Неизвестный формат или версия архива')
 if manifest['files']!=[records[name] for name in sorted(records)] or manifest['total_bytes']!=total:raise ValueError('Файлы не соответствуют подписанному манифесту')
 # Refuse file/symlink ancestors even though staging never follows them.
 for name in records:
  for parent in PurePosixPath(name).parents:
   if str(parent) in records and records[str(parent)]['kind']!='directory':raise ValueError('Вложенный файл находится под ссылкой или обычным файлом')
 (staging/'manifest.json').write_bytes(raw_manifest);(staging/'manifest.sig').write_bytes(signature)
 os.chmod(staging/'manifest.json',0o600);os.chmod(staging/'manifest.sig',0o600)
 return manifest
