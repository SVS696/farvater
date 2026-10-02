"""Finish one terminal restore's boot guard from protected installer code.

The independent rescue path invokes this fixed UUID-only command through PID 1.
It never imports Python from the restored application tree or changes data files.
"""

import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

CODE_ROOT=Path('/opt/okopy-recovery-ui')
CAPSULE_ROOT=Path('/var/lib/okopy-recovery')
OWNER=0


def protected_module(path,name):
 path=Path(path)
 if path.is_symlink() or not path.is_file():raise ValueError('Защищённый recovery код изменён')
 info=path.stat()
 if info.st_uid!=OWNER or info.st_mode&0o022:raise ValueError('Защищённый recovery код доступен для записи')
 spec=importlib.util.spec_from_file_location(name,path)
 if spec is None or spec.loader is None:raise ValueError('Нет защищённого recovery кода')
 module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
 return module


def run(value):
 if os.geteuid()!=0 or not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value):
  raise ValueError('Требуется фиксированная root операция')
 root=CODE_ROOT
 if root.is_symlink() or root.resolve()!=root or root.stat().st_uid!=OWNER or root.stat().st_mode&0o022:
  raise ValueError('Защищённый recovery каталог изменён')
 files=protected_module(root/'restore_files.py','restore_files')
 boot=protected_module(root/'restore_boot.py','restore_boot')
 journal=CAPSULE_ROOT/value
 boot.capsule(journal)
 state=files.status(journal)
 if state['status'] not in ('confirmed','rolled_back'):
  raise ValueError('Загрузочную защиту можно снять только после завершения восстановления')
 if state.get('timer_cleanup_pending'):
  raise ValueError('Сначала нужно завершить остановку таймера')
 if state.get('boot_guard') in (None,'removed'):
  return {'status':'not_needed'}
 if state['boot_guard']=='installed':
  with files.locked(journal) as (_,plan,_,record):
   services=plan.get('services')
   gate=services.get('boot_gate') if services else None
   if not gate or record['status'] not in ('confirmed','rolled_back'):
    raise ValueError('Состав завершённого журнала изменился')
   side='after' if record['status']=='confirmed' else 'before'
  unit=files.service_capture([gate])[gate]
  if unit['ActiveState']!='active' or unit['Type']!='oneshot':
   raise ValueError('Загрузочная защита ещё завершает запуск')
  if not files.service_matches(services,side):
   raise ValueError('Службы ещё не вернулись в терминальное состояние')
 boot.remove(journal)
 verified=files.status(journal)
 if verified.get('boot_guard')!='removed':raise ValueError('Снятие загрузочной защиты не подтверждено')
 return {'status':'removed'}


def main():
 if len(sys.argv)!=2:raise SystemExit(64)
 try:print(json.dumps(run(sys.argv[1]),sort_keys=True))
 except (ValueError,OSError,KeyError,TypeError):
  print(json.dumps({'status':'cleanup_pending'}));raise SystemExit(1)


if __name__=='__main__':main()
