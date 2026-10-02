"""Manage typed probes with CAS; network policy and service state are untouched."""
import fcntl
import json
import os
from pathlib import Path
import time
import uuid
from health_settings import edit_check,form_fields,read_settings,removable,new_check,pending_row
from safe_apply import atomic_write

ROOT=Path('/var/lib/okopy-monitor')

def invalidate_snapshot(path,snapshot):
 stat=path.stat();temp=path.with_name('.invalidate-'+uuid.uuid4().hex)
 try:
  atomic_write(temp,json.dumps(snapshot,ensure_ascii=False).encode())
  os.chown(temp,stat.st_uid,stat.st_gid);temp.chmod(stat.st_mode & 0o777)
  os.replace(temp,path)
  directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(directory)
  finally:os.close(directory)
 finally:temp.unlink(missing_ok=True)

def control(request,root=ROOT):
 action=request.get('action')
 fields={'monitor-status':{'check_id'},'monitor-set':{'check_id','revision','values'},
         'monitor-add':{'kind','revision','values'},'monitor-remove':{'check_id','revision'}}
 if action not in fields or set(request)!=({'version','action'}|fields[action]):raise ValueError('Некорректный запрос настроек мониторинга')
 with (root/'settings.lock').open('a') as lock:
  try:fcntl.flock(lock,(fcntl.LOCK_SH if action=='monitor-status' else fcntl.LOCK_EX)|fcntl.LOCK_NB)
  except BlockingIOError:raise ValueError('Настройки заняты; обновите страницу') from None
  config,revision=read_settings(root)
  selected=next((c for c in config['checks'] if c['id']==request.get('check_id')),None)
  if request.get('check_id') is not None and selected is None:raise ValueError('Датчик не найден')
  if action!='monitor-status':
   if request['revision']!=revision:raise ValueError('Настройки уже изменились; обновите страницу')
   if action=='monitor-add':
    if len(config['checks'])>=64:raise ValueError('Допустимо до 64 серверных датчиков')
    edited=edit_check(new_check(request['kind'],'custom:'+uuid.uuid4().hex),request['values'])
    if edited['kind']=='https_slow' and sum(c['kind']=='https_slow' for c in config['checks'])>=4:
     raise ValueError('Допустимо до четырёх медленных HTTP-проверок')
    changed=[*config['checks'],edited]
   elif action=='monitor-remove':
    if selected is None or not removable(selected):raise ValueError('Можно удалить только собственную проверку; обязательные датчики остаются')
    if len(config['checks'])<=1:raise ValueError('Нельзя удалить последний датчик')
    edited=None;changed=[c for c in config['checks'] if c['id']!=selected['id']]
   else:
    if selected is None:raise ValueError('Датчик не найден')
    values=dict(request['values'])
    kind=values.pop('kind',selected['kind'])
    original=selected
    if kind!=selected['kind']:
     if not removable(selected):raise ValueError('Тип системного датчика менять нельзя')
     original=new_check(kind,selected['id'])
     if kind=='https_slow' and sum(c['kind']=='https_slow' for c in config['checks'])>=4:
      raise ValueError('Допустимо до четырёх медленных HTTP-проверок')
    edited=edit_check(original,values)
    changed=[edited if c['id']==selected['id'] else c for c in config['checks']]
   if changed!=config['checks']:
    # Collector publishes under this same lock: an old in-flight result cannot
    # overwrite the invalidation after a definition changes.
    from health_model import read_snapshot
    for snapshot_path in (root/'health.json',root/'slow-health.json'):
     try:snapshot=read_snapshot(snapshot_path)
     except (OSError,ValueError,TypeError):snapshot=None
     if not snapshot:continue
     for row in snapshot['checks']:
      if selected and row['id']==selected['id']:
       row.update(status='unknown',detail='Параметры датчика изменены; ожидается новое измерение',duration_ms=0,observed_at=time.time())
       row.pop('retained_observation',None);row.pop('in_progress',None)
       row.pop('next_check_at',None)
     if action=='monitor-remove':snapshot['checks']=[r for r in snapshot['checks'] if r['id']!=selected['id']]
     if action=='monitor-add' and (snapshot_path.name=='health.json' or edited['kind']=='https_slow'):
      snapshot['checks'].append(pending_row(edited,time.time()))
     # Invalidate first: interruption leaves at worst an unknown old probe.
     invalidate_snapshot(snapshot_path,snapshot)
    atomic_write(root/'checks.previous.json',(root/'checks.json').read_bytes())
    config['checks']=changed
    atomic_write(root/'checks.json',json.dumps(config,ensure_ascii=False,indent=2).encode())
    config,revision=read_settings(root);selected=edited
  return {'revision':revision,'checks':[{**{k:c[k] for k in ('id','name','scope','kind')},'removable':removable(c)} for c in config['checks']],
          'selected':None if selected is None else {'id':selected['id'],'kind':selected['kind'],'fields':form_fields(selected),'removable':removable(selected)},'observed_at':time.time()}
