"""Protected systemd ExecStartPre gate for the main panel writer.

The installer keeps this code and its drop-in outside the restored snapshot.
Only the independent root-owned lease can permit a start during recovery.
"""

import json
import grp
from pathlib import Path
import re
import stat
import sys

BARRIER_ROOT=Path('/var/lib/okopy-recovery-ui')
BARRIER=BARRIER_ROOT/'barrier.json'
WRITERS={'okopy-panel.service','okopy-routing.service'}
OWNER=0
GROUP_NAME='okopy-recovery'


def secure_metadata(parent,record,group):
 return (stat.S_ISDIR(parent.st_mode) and parent.st_uid==OWNER and parent.st_gid==group
         and stat.S_IMODE(parent.st_mode)==0o750 and stat.S_ISREG(record.st_mode)
         and record.st_uid==OWNER and record.st_gid==group
         and stat.S_IMODE(record.st_mode)==0o640 and record.st_size<=512)


def allowed(unit='okopy-panel.service',*,root=BARRIER_ROOT):
 if unit not in WRITERS:return False
 root=Path(root);path=root/'barrier.json'
 if root.is_symlink() or root.resolve()!=root or path.is_symlink():return False
 try:
  parent=root.stat();record=path.stat()
  if not secure_metadata(parent,record,grp.getgrnam(GROUP_NAME).gr_gid):return False
  value=json.loads(path.read_bytes())
 except (OSError,ValueError,TypeError,KeyError):return False
 if not isinstance(value,dict) or set(value)!={'version','status','job_id'} or value['version']!=1:return False
 if value['status']=='inactive':return value['job_id'] is None
 return (value['status'] in ('verifying_writers','rollback_writers') and
         isinstance(value['job_id'],str) and bool(re.fullmatch('[a-f0-9]{32}',value['job_id'])))


if __name__=='__main__':
 if len(sys.argv)!=2 or not allowed(sys.argv[1]):raise SystemExit(1)
