"""Discover systemd recovery state from the configured snapshot scope.

No commands, credentials or environment values are collected. This inventory
does not start services and is not itself a service activation plan.
"""
from pathlib import PurePosixPath
import re
import subprocess


UNIT=re.compile(r'[A-Za-z0-9_:][A-Za-z0-9_.:@\\-]*\.(?:service|timer|socket|target|path)\Z')
PROPERTIES='Id,Names,LoadState,ActiveState,SubState,UnitFileState,Type,User,Group,DynamicUser,FragmentPath,DropInPaths,Triggers,TriggeredBy,Requires,Wants,Before,After,PartOf,Conflicts'


def unit_name(value):
 if not isinstance(value,str) or len(value)>255 or not UNIT.fullmatch(value):raise ValueError('Некорректное имя службы в составе копии')
 return value


def discover(paths,configured,loaded=()):
 # Targets (for example remote-fs.target) are dependency aggregates, not
 # manageable workers. Their files remain in the snapshot, but stop/start of
 # a target could affect unrelated mounts and services outside the scope.
 names={unit_name(n) for n in configured if not unit_name(n).endswith('.target')};templates=set()
 for path in paths:
  parts=PurePosixPath(path).parts
  if parts[:3]!=('etc','systemd','system') or len(parts)<4:continue
  name=parts[3]
  if name.endswith(('.wants','.requires')):
   if len(parts)<5:continue
   name=parts[4]
  if name.endswith('.d'):name=name[:-2]
  if not UNIT.fullmatch(name):continue
  if name.endswith('.target'):continue
  if '@.' in name:templates.add(name)
  else:names.add(name)
 for name in loaded:
  if not UNIT.fullmatch(name):continue
  if name.endswith('.target'):continue
  for template in templates:
   prefix,suffix=template.split('@.',1)
   if name.startswith(prefix+'@') and name.endswith('.'+suffix) and name!=template:names.add(name)
 return sorted(names)


def capture(paths,configured):
 loaded=subprocess.run(['systemctl','list-units','--all','--plain','--no-legend','--no-pager'],
                       capture_output=True,text=True,timeout=10)
 if loaded.returncode:raise ValueError('Не удалось определить экземпляры служб для резервной копии')
 names=discover(paths,configured,[line.split()[0] for line in loaded.stdout.splitlines() if line.strip()])
 if not names:return {'version':1,'units':[]}
 result=subprocess.run(['systemctl','show',*names,'-p',PROPERTIES],capture_output=True,text=True,timeout=15)
 if result.returncode:raise ValueError('Не удалось сохранить состояния служб из состава копии')
 units={};covered=set()
 for block in result.stdout.strip().split('\n\n'):
  if not block:continue
  properties=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
  name=unit_name(properties.get('Id'));aliases=set(properties.get('Names',name).split())|{name}
  if not aliases.intersection(names):raise ValueError('systemd вернул непредусмотренную службу')
  covered.update(aliases.intersection(names));units[name]=properties
 if covered!=set(names):raise ValueError('Реестр служб неполон')
 return {'version':1,'units':[units[n] for n in sorted(units)]}


def legacy_states(registry):
 return '\n\n'.join('\n'.join(k+'='+u.get(k,'') for k in ('Id','ActiveState','UnitFileState')) for u in registry['units'])+'\n'
