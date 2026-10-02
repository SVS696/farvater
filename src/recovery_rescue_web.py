"""Frozen minimal recovery UI behind the existing authenticated HTTPS proxy.

Install this code and its minimal venv outside the restored snapshot. It runs as
okopy-panel on a Unix socket; a fixed narrow sudo command invokes the frozen
root recovery CLI. No public listener and no browser-supplied path are used.
"""

from collections import OrderedDict
import grp
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import threading
import time

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash


ROOT=Path('/var/lib/okopy-recovery')
AUTH_ROOT=Path('/var/lib/okopy-recovery-ui')
CODE_ROOT=Path('/opt/okopy-recovery-ui')
SOCKET=Path('/var/www/certbot/.farvater-recovery/recovery.sock')
SUDO='/usr/bin/sudo'
PYTHON='/usr/bin/python3'
AUTH_OWNER=0
RECOVERY_GROUP='okopy-recovery'
BARRIER=AUTH_ROOT/'barrier.json'

LOGIN='''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Доступ к восстановлению</title><body><main><h1>Доступ к восстановлению</h1><p>Войдите под той же учётной записью администратора, которая была сохранена до временной замены панели.</p><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><label>Логин<input name="username" autocomplete="username" required></label><label>Пароль<input name="password" type="password" autocomplete="current-password" required></label><button>Войти</button></form></main></body></html>'''
STATUS_LABELS={
 'prepared':'подготовлено','start_scheduled':'запуск запланирован',
 'recovery_required':'нужен независимый возврат','applying':'заменяются файлы',
 'starting_services':'запускаются службы','awaiting_confirmation':'ожидает подтверждения',
 'rolling_back':'идёт возврат','rolled_back':'прежняя установка восстановлена',
 'confirmed':'восстановление подтверждено','unknown':'состояние неизвестно'
}
STATUS='''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Независимое восстановление</title><body><main>
<h1>Независимое восстановление</h1>
<p>Операция <code>{{ job }}</code>. Состояние: <strong>{{ labels.get(state.status,'состояние неизвестно') }}</strong>.</p>
{% if error %}<p role="alert">{{ error }}</p>{% endif %}
{% if state.boot_guard_cleanup_pending %}<p role="alert">Возврат файлов завершён, но загрузочная защита ещё снимается. Обновите статус; при повторной ошибке используйте консоль восстановления.</p>{% endif %}
{% if state.status=='recovery_required' %}<p role="alert">Таймер возврата не подтвердил запуск. Новый старт запрещён; выполните независимый возврат.</p>{% endif %}
{% if state.status not in ('confirmed','rolled_back') and state.seconds_left is defined %}<p>До автоматического возврата: {{ state.seconds_left }} секунд.</p>{% endif %}
<p><a href="{{ url_for('recovery_state',job=job) }}">Обновить состояние</a></p>
{% if state.status=='prepared' and state.boot_guard=='installed' %}<form method="post" action="{{ url_for('recovery_action',job=job,action='start') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><label><input type="checkbox" name="confirm" required>Временно применить проверенную копию; прежняя панель будет остановлена</label><button>Начать восстановление</button></form>{% endif %}
{% if state.status=='awaiting_confirmation' and state.seconds_left|default(0)>0 %}<form method="post" action="{{ url_for('recovery_action',job=job,action='confirm') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><label><input type="checkbox" name="confirm" required>Я проверил работу восстановленной установки</label><button>Подтвердить</button></form>{% endif %}
{% if state.status in ('prepared','start_scheduled','recovery_required','applying','starting_services','awaiting_confirmation') %}<form method="post" action="{{ url_for('recovery_action',job=job,action='rollback') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><label><input type="checkbox" name="confirm" required>Вернуть прежнюю установку</label><button>Выполнить возврат</button></form>{% endif %}
</main></body></html>'''


def admin_auth(path):
 path=Path(path)
 if path.is_symlink():raise ValueError('Копия администратора изменена')
 parent=path.parent.stat();s=path.stat();group=grp.getgrnam(RECOVERY_GROUP).gr_gid
 if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=AUTH_OWNER or parent.st_gid!=group
     or stat.S_IMODE(parent.st_mode)!=0o750 or not stat.S_ISREG(s.st_mode)
     or s.st_uid!=AUTH_OWNER or s.st_gid!=group or stat.S_IMODE(s.st_mode)!=0o640
     or s.st_size>32768):
  raise ValueError('Небезопасная копия администратора')
 value=json.loads(path.read_text())
 if not isinstance(value,dict) or set(value)!={'username','password_hash','session_secret'} or any(not isinstance(v,str) or not v for v in value.values()):
  raise ValueError('Копия администратора повреждена')
 return value


def main_access_allowed(path=BARRIER):
 """No root journal read or secret disclosure on Caddy's auth subrequest."""
 path=Path(path)
 try:
  if path.is_symlink():return False
  parent=path.parent.stat();owner=path.stat()
  group=grp.getgrnam(RECOVERY_GROUP).gr_gid
  if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=AUTH_OWNER or
      parent.st_gid!=group or stat.S_IMODE(parent.st_mode)!=0o750 or not stat.S_ISREG(owner.st_mode) or
      owner.st_uid!=AUTH_OWNER or owner.st_gid!=group or
      stat.S_IMODE(owner.st_mode)!=0o640 or owner.st_size>512):return False
  value=json.loads(path.read_bytes())
  return (isinstance(value,dict) and set(value)=={'version','status','job_id'} and
          value['version']==1 and value['status']=='inactive' and value['job_id'] is None)
 except (OSError,ValueError,TypeError,KeyError):return False


def fixed_run(action,job,root=ROOT):
 if action not in ('status','start','confirm','rollback') or not re.fullmatch('[a-f0-9]{32}',job):raise ValueError('Некорректное действие восстановления')
 try:process=subprocess.run([SUDO,'-n',PYTHON,'-I',str(CODE_ROOT/'rescue.py'),action,job],
                            capture_output=True,text=True,timeout=135 if action=='status' else 390)
 except (OSError,subprocess.TimeoutExpired):
  raise ValueError('Ответ восстановления не получен; обновите независимый статус перед повтором') from None
 if process.returncode:raise ValueError('Независимый контроллер не подтвердил действие. Перечитайте статус или используйте консоль')
 try:
  result=json.loads(process.stdout)
  if not isinstance(result,dict) or not isinstance(result.get('status'),str):raise ValueError()
 except ValueError:raise ValueError('Независимый контроллер вернул неверный статус') from None
 return result


def create_app(*,auth_path=AUTH_ROOT/'auth.json',runner=fixed_run,trusted_hosts=None):
 auth=admin_auth(auth_path)
 hosts=trusted_hosts or [v.strip() for v in os.environ['FARVATER_RECOVERY_HOSTS'].split(',') if v.strip()]
 if not hosts:raise ValueError('Не задан доверенный HTTPS Host')
 app=Flask(__name__)
 app.config.update(SECRET_KEY=auth['session_secret'],TRUSTED_HOSTS=hosts,
                   SESSION_COOKIE_NAME='farvater_recovery',SESSION_COOKIE_SECURE=True,
                   SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',
                   MAX_CONTENT_LENGTH=16*1024,PERMANENT_SESSION_LIFETIME=1800)
 attempts=OrderedDict();attempt_lock=threading.Lock()

 @app.before_request
 def protect():
  from werkzeug.exceptions import SecurityError
  if isinstance(request.routing_exception,SecurityError):return 'Неизвестный Host',400
  if request.endpoint=='recovery_access_check':return None
  if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(32)
  if request.method=='POST':
   token=request.form.get('csrf','')
   if not isinstance(token,str) or not hmac.compare_digest(token.encode(),session['csrf'].encode()):abort(403)
   if request.headers.get('Origin')!=request.host_url.rstrip('/'):abort(403)
  if request.endpoint not in ('recovery_login','recovery_access_check') and not session.get('authenticated'):
   return redirect(url_for('recovery_login',job=(request.view_args or {}).get('job')))

 @app.after_request
 def headers(response):
  response.headers['Cache-Control']='no-store'
  response.headers['Content-Security-Policy']="default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  response.headers['X-Content-Type-Options']='nosniff'
  response.headers['X-Frame-Options']='DENY'
  return response

 @app.route('/recovery/login',methods=['GET','POST'])
 def recovery_login():
  if request.method=='POST':
   source=request.remote_addr or 'local';now=time.monotonic()
   with attempt_lock:
    recent=[t for t in attempts.get(source,[]) if now-t<60]
    attempts[source]=recent;attempts.move_to_end(source)
    while len(attempts)>256:attempts.popitem(last=False)
    if len(recent)>=5:abort(429)
   username=request.form.get('username','')
   password=request.form.get('password','')
   valid=(isinstance(username,str) and isinstance(password,str) and
          hmac.compare_digest(username.encode(),auth['username'].encode()) and
          check_password_hash(auth['password_hash'],password))
   if not valid:
    with attempt_lock:
     attempts.setdefault(source,[]).append(now)
     attempts.move_to_end(source)
     while len(attempts)>256:attempts.popitem(last=False)
    abort(403)
   with attempt_lock:attempts.pop(source,None)
   session.clear();session['authenticated']=True;session['csrf']=secrets.token_urlsafe(32)
   session.permanent=True
   job=request.args.get('job','')
   if re.fullmatch('[a-f0-9]{32}',job):return redirect(url_for('recovery_state',job=job))
   return 'Вход выполнен. Откройте сохранённую ссылку recovery с идентификатором операции.',200
  return render_template_string(LOGIN,csrf=session['csrf'])

 @app.get('/recovery/access-check')
 def recovery_access_check():
  return ('',200) if main_access_allowed() else ('',503)

 @app.get('/recovery/<job>')
 def recovery_state(job):
  if not re.fullmatch('[a-f0-9]{32}',job):abort(404)
  try:state=runner('status',job)
  except ValueError as error:return render_template_string(STATUS,job=job,state={'status':'unknown'},csrf=session['csrf'],labels=STATUS_LABELS,error=str(error)),503
  return render_template_string(STATUS,job=job,state=state,csrf=session['csrf'],labels=STATUS_LABELS,error=None)

 @app.post('/recovery/<job>/<action>')
 def recovery_action(job,action):
  if action not in ('start','confirm','rollback') or not re.fullmatch('[a-f0-9]{32}',job):abort(404)
  if request.form.get('confirm')!='on':abort(400)
  try:runner(action,job)
  except ValueError:abort(409,'Действие не подтверждено; обновите состояние')
  return redirect(url_for('recovery_state',job=job))

 return app


def main():
 from waitress import serve
 hosts=[v.strip() for v in os.environ['FARVATER_RECOVERY_HOSTS'].split(',') if v.strip()]
 serve(create_app(trusted_hosts=hosts),unix_socket=str(SOCKET),unix_socket_perms='660',
       url_scheme='https',threads=2,trusted_proxy='localhost',trusted_proxy_count=1,
       trusted_proxy_headers={'x-forwarded-for'},clear_untrusted_proxy_headers=True)


if __name__=='__main__':main()
