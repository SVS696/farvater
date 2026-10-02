"""Non-secret Unix ownership prerequisites for a recovery snapshot."""
import grp
import os
from pathlib import Path
import pwd


def capture(paths,host=Path('/')):
 stats=[(Path(host)/p).lstat() for p in paths]
 uids={s.st_uid for s in stats};gids={s.st_gid for s in stats}
 users=[];missing_users=[];missing_groups=[]
 all_groups=grp.getgrall()
 for uid in sorted(uids):
  try:user=pwd.getpwuid(uid)
  except KeyError:missing_users.append(uid);continue
  memberships=sorted(g.gr_gid for g in all_groups if user.pw_name in g.gr_mem)
  gids.add(user.pw_gid);gids.update(memberships)
  users.append({'name':user.pw_name,'uid':uid,'gid':user.pw_gid,'home':user.pw_dir,
                'shell':user.pw_shell,'supplementary_gids':memberships})
 groups=[]
 for gid in sorted(gids):
  try:group=grp.getgrgid(gid)
  except KeyError:missing_groups.append(gid);continue
  groups.append({'name':group.gr_name,'gid':gid})
 return {'version':1,'users':users,'groups':groups,'unmapped_uids':missing_users,'unmapped_gids':missing_groups}


def compare(archived):
 """Report required identity work without creating users or changing membership."""
 if not isinstance(archived,dict) or archived.get('version')!=1:
  return {'ready':False,'issues':[{'kind':'missing_metadata','message':'В этой копии нет реестра пользователей и групп; автоматическая проверка владельцев невозможна'}]}
 issues=[]
 for uid in archived.get('unmapped_uids',[]):issues.append({'kind':'unmapped_uid','uid':uid})
 for gid in archived.get('unmapped_gids',[]):issues.append({'kind':'unmapped_gid','gid':gid})
 for group in archived['groups']:
  try:by_id=grp.getgrgid(group['gid'])
  except KeyError:by_id=None
  try:by_name=grp.getgrnam(group['name'])
  except KeyError:by_name=None
  if by_id is None and by_name is None:issues.append({'kind':'missing_group',**group})
  elif by_id is None or by_name is None or by_id.gr_name!=group['name'] or by_name.gr_gid!=group['gid']:
   issues.append({'kind':'conflicting_group',**group})
 for user in archived['users']:
  try:by_id=pwd.getpwuid(user['uid'])
  except KeyError:by_id=None
  try:by_name=pwd.getpwnam(user['name'])
  except KeyError:by_name=None
  if by_id is None and by_name is None:issues.append({'kind':'missing_user',**user})
  elif by_id is None or by_name is None or by_id.pw_name!=user['name'] or by_name.pw_uid!=user['uid']:
   issues.append({'kind':'conflicting_user','name':user['name'],'uid':user['uid']})
  else:
   if (by_id.pw_gid,by_id.pw_dir,by_id.pw_shell)!=(user['gid'],user['home'],user['shell']):
    issues.append({'kind':'different_user_settings','name':user['name'],'uid':user['uid']})
   actual={g.gr_gid for g in grp.getgrall() if user['name'] in g.gr_mem}
   if actual!=set(user['supplementary_gids']):issues.append({'kind':'different_memberships','name':user['name'],'uid':user['uid']})
 return {'ready':not issues,'issues':issues}
