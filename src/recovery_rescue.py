"""Stdlib-only rescue CLI copied outside every restore snapshot.

An installer-owned HTTPS admin boundary may invoke this fixed command. It does
not accept paths, units, URLs or secrets from a request and never writes a
second transaction. The journal's frozen restore_files runtime owns actions.
"""

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


ROOT=Path('/var/lib/okopy-recovery')
CODE_ROOT=Path('/opt/okopy-recovery-ui')
PYTHON='/usr/bin/python3'
OWNER=0


def dispatch(frozen,action,journal):
    """PID 1 runs the one validated frozen action outside the UI's read-only mount."""
    if action not in ('status','start-guarded','confirm','rollback','recover-guarded'):
        raise ValueError('Неизвестная команда замороженного журнала')
    seconds=20 if action=='status' else 240
    unit='farvater-rescue-'+uuid.uuid4().hex
    command=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect',
             '--unit='+unit,'--service-type=exec',
             '--property=RuntimeMaxSec='+str(seconds)+'s','--property=KillMode=control-group',
             '--property=UMask=0077',PYTHON,'-I',str(frozen),action,str(journal)]
    try:return subprocess.run(command,capture_output=True,text=True,timeout=seconds+10)
    except (OSError,subprocess.TimeoutExpired):
        raise ValueError('Ответ независимого восстановления не получен; перечитайте статус перед повтором') from None


def dispatch_terminal_cleanup(value):
    """Only post-commit boot bookkeeping through a second fixed PID 1 action."""
    if not re.fullmatch('[a-f0-9]{32}',value):raise ValueError('Некорректный номер recovery cleanup')
    unit='farvater-rescue-cleanup-'+uuid.uuid4().hex
    command=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect',
             '--unit='+unit,'--service-type=exec','--property=RuntimeMaxSec=75s',
             '--property=KillMode=control-group','--property=UMask=0077',
             PYTHON,'-I',str(CODE_ROOT/'boot_cleanup.py'),value]
    try:result=subprocess.run(command,capture_output=True,text=True,timeout=85)
    except (OSError,subprocess.TimeoutExpired):raise ValueError('Независимая очистка требует повторного чтения статуса') from None
    if result.returncode:raise ValueError('Независимая очистка требует повторного чтения статуса')
    try:
        answer=json.loads(result.stdout)
        if answer.get('status') not in ('removed','not_needed'):raise ValueError()
    except (ValueError,TypeError):raise ValueError('Независимая очистка вернула неверный статус') from None
    return answer


def run(action,value):
    if os.geteuid()!=0:raise ValueError('Нужны права root')
    if action not in ('status','start','confirm','rollback') or not isinstance(value,str) or not re.fullmatch('[a-f0-9]{32}',value):
        raise ValueError('Некорректная команда восстановления')
    if ROOT.resolve()!=ROOT or ROOT.is_symlink():raise ValueError('Каталог восстановления изменён')
    owner=ROOT.stat()
    if not stat.S_ISDIR(owner.st_mode) or owner.st_uid!=OWNER or owner.st_mode&0o077:
        raise ValueError('Каталог восстановления недоступен')
    journal=ROOT/value
    if journal.resolve()!=journal or journal.is_symlink():raise ValueError('Журнал восстановления изменён')
    checked=journal.stat()
    if not stat.S_ISDIR(checked.st_mode) or checked.st_uid!=OWNER or checked.st_mode&0o077:
        raise ValueError('Журнал восстановления недоступен')
    frozen=journal/'rollback.py'
    source=frozen.lstat()
    if not stat.S_ISREG(source.st_mode) or source.st_uid!=OWNER or source.st_mode&0o077:
        raise ValueError('Код возврата изменён')
    if action!='status':
        previous=dispatch(frozen,'status',journal)
        if previous.returncode:raise ValueError('Независимый журнал не подтвердил текущее состояние')
        try:prior=json.loads(previous.stdout)
        except ValueError:raise ValueError('Независимый журнал вернул неверное состояние') from None
        if prior.get('status') in ('confirmed','rolled_back'):
            raise ValueError('Завершённая операция доступна только для чтения статуса')
        if action=='start' and (prior.get('status')!='prepared' or prior.get('boot_guard')!='installed'):
            raise ValueError('Для запуска требуется подготовленный журнал с загрузочной защитой')
    command=('start-guarded' if action=='start' else
             'recover-guarded' if action=='rollback' and (journal/'guard.json').exists() else action)
    result=dispatch(frozen,command,journal)
    if result.returncode:raise ValueError('Действие восстановления не подтверждено; прочитайте статус')
    try:
        answer=json.loads(result.stdout)
        if not isinstance(answer,dict) or answer.get('status') not in ('started','prepared','start_scheduled','recovery_required','applying','starting_services','awaiting_confirmation','rolling_back','rolled_back','confirmed','unknown'):
            raise ValueError()
    except ValueError:raise ValueError('Неверный ответ замороженного восстановления') from None
    if answer['status'] in ('confirmed','rolled_back'):
        try:
            cleanup=dispatch_terminal_cleanup(value)
            if cleanup['status']=='removed':answer['boot_guard']='removed'
        except ValueError:answer['boot_guard_cleanup_pending']=True
    return answer


def main():
    if len(sys.argv)!=3:raise SystemExit(64)
    try:print(json.dumps(run(sys.argv[1],sys.argv[2]),ensure_ascii=False))
    except ValueError as error:
        print(json.dumps({'status':'unknown','error':str(error)},ensure_ascii=False));raise SystemExit(1)


if __name__=='__main__':main()
