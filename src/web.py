"""Authenticated local workspace for network policy drafts.

Draft edits do not modify a running router or VPN. Runtime deployment is a
separate, explicitly checked transaction; this UI does not pretend otherwise.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for, send_file
from werkzeug.security import check_password_hash

from policy import explain, validate_policy
from safe_apply import atomic_write
from dns_form import DNS_TYPES, parse_dns, hosts_text
from tunnel_form import OUTBOUND_TYPES, SS_METHODS, parse_outbound, external_connection
from tunnel_advanced import FINGERPRINTS, TRANSPORTS, VERSIONS, transport_hosts
from failover_form import parse_failover, primary_pair
from rule_options import parse_options, FAMILIES, FILTERING, DNS_RESPONSES, QUERY_TYPES
from rule_fallback import parse_pairs, validate_pairs
from health_model import MAX_AGE, present_snapshot, transport_message
from candidate_remote import RemoteError
from pair_probes import probe_queue_labels,validate_target_for_queue
from adguard_adapter import settings as filter_settings,list_id
from policy_sections import section_hashes, changed_section_labels


NAV = [('overview','Обзор'),('health','Мониторинг'),('rules','Правила'),('tunnels','Подключения'),('dns','DNS и фильтрация'),
       ('lan','Устройства'),('changes','Изменения'),('backups','Резервные копии'),('help','Помощь')]
TITLES = dict(NAV)
TITLES['filtering'] = 'Фильтрация AdGuard'
TITLES['overview'] = 'Обзор'
TITLES['changes'] = 'Проверить изменения'
TITLES['health'] = 'Мониторинг'


def token_equal(provided, expected):
    """Reject malformed form tokens before compare_digest can raise on Unicode."""
    return (isinstance(provided, str) and isinstance(expected, str)
            and len(provided) <= 128 and len(expected) <= 128
            and provided.isascii() and expected.isascii()
            and hmac.compare_digest(provided, expected))


def username_equal(provided, expected):
    return (isinstance(provided, str) and isinstance(expected, str)
            and len(provided) <= 256 and len(expected) <= 256
            and hmac.compare_digest(provided.encode('utf-8'), expected.encode('utf-8')))


def login_source(address):
    try:return str(ipaddress.ip_address(address))
    except (TypeError, ValueError):return 'unknown'


class DraftStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory/'policy.json'

    def read(self) -> tuple[dict,str]:
        data=self.path.read_bytes()
        return json.loads(data),hashlib.sha256(data).hexdigest()

    @contextmanager
    def edit(self, revision: str):
        with (self.directory/'draft.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            policy,current=self.read()
            if not token_equal(revision,current):
                abort(409,'Черновик уже изменён. Обновите страницу перед сохранением.')
            yield policy
            atomic_write(self.path,json.dumps(policy,ensure_ascii=False,indent=2).encode())


def create_app(directory: Path, candidate=None, router_monitor=None, *, trusted_hosts=None, secure_cookie=False) -> Flask:
    directory=Path(directory)
    auth=json.loads((directory/'auth.json').read_text())
    app=Flask(__name__)
    app.config.update(SECRET_KEY=auth['session_secret'],MAX_CONTENT_LENGTH=256*1024,
                      SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',
                      PERMANENT_SESSION_LIFETIME=3600,SESSION_COOKIE_SECURE=secure_cookie,
                      TRUSTED_HOSTS=list(trusted_hosts or ('127.0.0.1','localhost')))
    store=DraftStore(directory)
    attempts={};global_failures=[];attempt_lock=threading.Lock()
    from domain_document import text_for,parse as parse_domain_document
    from ui_view import SCOPE_LABELS, protocol_label, dns_summary, accepted_drill
    from ui_help import help_for
    app.jinja_env.filters['protocol_label']=protocol_label
    app.jinja_env.filters['dns_summary']=dns_summary
    app.jinja_env.globals['scope_labels']=SCOPE_LABELS
    app.jinja_env.globals['accepted_drill']=accepted_drill
    app.jinja_env.globals['help_for']=help_for
    app.jinja_env.filters['domain_text']=text_for
    app.jinja_env.filters['domain_groups']=lambda profile:parse_domain_document(text_for(profile))['groups']

    @app.template_filter('utc_time')
    def utc_time(value):return datetime.fromtimestamp(value,timezone.utc).strftime('%d.%m %H:%M:%S UTC')

    @app.before_request
    def protect():
        # Flask validates Host against the explicit deployment allowlist.
        from werkzeug.exceptions import SecurityError
        if isinstance(request.routing_exception,SecurityError):
            # An untrusted Host has no URL adapter, so do not render a template
            # whose navigation calls url_for().
            return 'Неизвестное имя сервера',400
        if request.endpoint=='backup_upload':
            if not session.get('authenticated'):return redirect(url_for('login'))
            from system_backup import MAX_UPLOAD
            request.max_content_length=MAX_UPLOAD+128*1024
        if request.endpoint=='policy_import':
            if not session.get('authenticated'):return redirect(url_for('login'))
            from policy_exchange import MAX_BYTES
            request.max_content_length=MAX_BYTES+128*1024
        if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(32)
        if request.method=='POST':
            if not token_equal(request.form.get('csrf',''),session['csrf']):
                abort(403,'Недействительный код формы. Обновите страницу.')
            origin=request.headers.get('Origin')
            if origin and origin!=request.host_url.rstrip('/'):
                abort(403,'Запрос с другого сайта отклонён')
        if request.endpoint not in ('login','static') and not session.get('authenticated'):
            return redirect(url_for('login'))

    @app.after_request
    def headers(response):
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        # no-referrer turns a browser's form POST Origin into "null", which
        # conflicts with the same-origin write check above.
        response.headers['Referrer-Policy']='same-origin'
        response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' blob:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.context_processor
    def common():
        from protocol_modules import choices
        return {'nav':NAV,'csrf':session.get('csrf'),'title':'Сеть','outgoing_protocols':choices('outgoing'),
                'recovery_ui_ready':'backup_restore_page' in app.view_functions and 'recovery_runbook' in app.view_functions}

    @app.route('/login',methods=['GET','POST'])
    def login():
        if request.method=='POST':
            now=time.monotonic()
            source=login_source(request.remote_addr)
            with attempt_lock:
                global_failures[:]=[stamp for stamp in global_failures if now-stamp<60]
                for key in tuple(attempts):
                    attempts[key][:]=[stamp for stamp in attempts[key] if now-stamp<60]
                    if not attempts[key]:del attempts[key]
                limit=1 if len(global_failures)>=60 else 5
                if len(attempts.get(source,()))>=limit:abort(429,'Слишком много попыток. Подождите минуту.')
                valid=username_equal(request.form.get('username',''),auth['username']) and check_password_hash(auth['password_hash'],request.form.get('password',''))
                if valid:attempts.pop(source,None)
                else:
                    if source not in attempts and len(attempts)>=1024:
                        oldest=min(attempts,key=lambda key:attempts[key][-1])
                        del attempts[oldest]
                    attempts.setdefault(source,[]).append(now)
                    global_failures.append(now)
                    if len(global_failures)>1024:del global_failures[:-1024]
            if valid:
                session.clear();session['authenticated']=True;session['csrf']=secrets.token_urlsafe(32);session.permanent=True
                return redirect(url_for('page',name='overview'))
            flash('Логин или пароль не подошёл.','error')
        return render_template('login.html',title='Вход в панель')

    @app.post('/logout')
    def logout():
        session.clear();return redirect(url_for('login'))

    @app.get('/')
    def index():return redirect(url_for('page',name='overview'))

    @app.get('/<name>')
    def page(name):
        if name=='failover':return redirect(url_for('page',name='rules')+'#rule-automation')
        if name not in TITLES:abort(404)
        if name=='backups':
            view=None;error=None
            if candidate is None:error='Создание копий недоступно: подключите сетевое ядро в настройках панели'
            else:
                try:view=candidate.call('backup-status')
                except RemoteError as exception:error=str(exception)
            return render_template('backups.html',name=name,title=TITLES[name],view=view,error=error,new_id=uuid.uuid4().hex,upload_id=uuid.uuid4().hex)
        policy,revision=store.read();issues=validate_policy(policy)
        answer=None
        if name=='rules' and request.args.get('domain'):
            try:
                port=request.args.get('port','').strip()
                answer=explain(policy,request.args['domain'],request.args.get('source'),
                               network=request.args.get('network') or None,port=int(port) if port else None)
            except ValueError as error:flash(str(error),'error')
        if name in ('health','overview'):
            from monitor_view import read_view, arrange, group_cards, EXTERNAL_KINDS
            excluded=set();editable_ids=set();metadata_error=None
            if candidate is not None:
                try:
                    definitions=candidate.call('monitor-status',check_id=None)
                    excluded={c['id'] for c in definitions['checks'] if c['kind'] in EXTERNAL_KINDS}
                    editable_ids={c['id'] for c in definitions['checks']}-excluded
                except RemoteError as error:metadata_error=str(error)
            health=present_snapshot(directory/'health.json',excluded_ids=excluded)
            if name=='overview':
                return render_template('overview.html',name=name,title=TITLES[name],policy=policy,health=health,issues=issues,metadata_error=metadata_error)
            view,_=read_view(directory)
            visible=arrange(health['checks'],view,visible_only=True)
            return render_template('health.html',name=name,title=TITLES[name],health=health,visible_checks=visible,check_groups=group_cards(visible),
                hidden_count=len(health['checks'])-len(visible),metadata_error=metadata_error,editable_ids=editable_ids,
                monitor_enabled=candidate is not None,max_age=MAX_AGE,transport=transport_message(directory/'health-transport.json')
                if os.environ.get('OKOPY_HEALTH_SOURCE') in ('ssh','local') else 'Приём снимков выключен. Подключите сборщик мониторинга.')
        if name=='lan':
            from lan_ingress import settings
            from vpn_ingress import settings as vpn_settings
            return render_template('lan.html',name=name,title=TITLES[name],lan=settings(policy),vpn=vpn_settings(policy),revision=revision)
        if name=='filtering':
            return render_template('filtering.html',name=name,title='Фильтрация AdGuard',
                filtering=filter_settings(policy),revision=revision)
        candidate_state=None;candidate_error=None
        if name=='changes' and candidate is not None:
            try:candidate_state=candidate.call('status')
            except RemoteError as error:candidate_error=str(error)
        routing_state=None;routing_error=None
        if name=='rules' and candidate is not None:
            try:routing_state=candidate.call('routing-status')
            except RemoteError as error:routing_error=str(error)
        draft_policy_sha256=hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest()
        section_delta=None
        if name=='changes' and candidate_state and candidate_state.get('integrity'):
            section_delta=([] if candidate_state.get('policy_sha256')==draft_policy_sha256
                           else changed_section_labels(section_hashes(policy),candidate_state.get('policy_section_sha256')))
            if candidate_state.get('policy_sha256')!=draft_policy_sha256 and section_delta==[]:
                section_delta=None
        return render_template('panel.html',name=name,title=TITLES[name],policy=policy,
                               revision=revision,issues=issues,answer=answer,
                               candidate_enabled=candidate is not None,candidate=candidate_state,candidate_error=candidate_error,
                               routing=routing_state,routing_error=routing_error,queue_labels={'default':'Весь остальной трафик',**{'rule:'+p['id']:p['name'] for p in policy['profiles']}},
                               probe_queues={**probe_queue_labels(policy),**{key:'Удалённая очередь: '+key for key in policy.get('health_probes',{}) if key not in probe_queue_labels(policy)}},
                               draft_policy_sha256=draft_policy_sha256,section_delta=section_delta)

    @app.get('/server/access')
    def server_access():
        from candidate_remote import CandidateRemote
        from server_connection import snapshot
        remote_mode=isinstance(candidate,CandidateRemote)
        value=None;revision='empty';error=None
        if remote_mode:
            try:value,revision=snapshot(candidate.connection)
            except (OSError,ValueError):error='Не удалось прочитать закрытые настройки подключения. Проверьте права файла при установке.'
        return render_template('server_access.html',name='help',title='Подключение к сетевому ядру',remote_mode=remote_mode,backend_enabled=candidate is not None,error=error,
                               revision=revision,targets=value['targets'] if value else [{'port':22}],password_present=bool(value and value['sudo_password']))

    @app.post('/server/access')
    def server_access_save():
        from candidate_remote import CandidateRemote
        from server_connection import save
        if not isinstance(candidate,CandidateRemote):abort(400,'Панель использует локальное управление; SSH не требуется.')
        try:save(candidate.connection,request.form.get('revision',''),request.form)
        except ValueError as error:abort(400,str(error))
        except OSError:abort(400,'Не удалось записать закрытые настройки подключения. Проверьте права каталога при установке.')
        flash('Доступ сохранён. Следующие команды используют эти адреса; сетевые настройки не изменялись.','success')
        return redirect(url_for('server_access'))

    @app.post('/backups/create')
    def backup_create():
        if candidate is None:abort(404)
        from system_backup import identifier
        try:
            result=candidate.call('backup-create',id=identifier(request.form.get('id')))
            if result.get('status')=='ready':flash('Зашифрованная копия создана. Скачайте её и храните отдельно от этой установки.','success')
            else:flash('Состояние операции прочитано; проверьте её запись ниже.','info')
        except (ValueError,RemoteError) as error:flash(str(error),'error')
        return redirect(url_for('page',name='backups'))

    @app.post('/backups/upload')
    def backup_upload():
        if candidate is None:abort(404)
        from system_backup import identifier,MAX_UPLOAD
        value=None;path=None;sent=False;created=False
        try:
            value=identifier(request.form.get('id'))
            existing=candidate.call('backup-status')
            if any(item['id']==value for item in existing['jobs']):raise ValueError('Эта загрузка уже обрабатывалась. Обновите список перед новой загрузкой')
            archive=request.files.get('archive');identity=request.files.get('identity')
            if archive is None or identity is None:raise ValueError('Выберите зашифрованный архив и файл ключа восстановления')
            key=identity.read(4097)
            if len(key)>4096:raise ValueError('Файл ключа превышает 4 КиБ')
            try:key=key.decode('utf-8-sig')
            except UnicodeError:raise ValueError('Ключ age должен быть текстовым файлом') from None
            path=directory/'backup-uploads'/(value+'.age')
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            created=True
            with os.fdopen(fd,'wb') as target:
                count=0
                while data:=archive.stream.read(1024*1024):
                    count+=len(data)
                    if count>MAX_UPLOAD:raise ValueError('Архив превышает 384 МиБ')
                    target.write(data)
                if not count:raise ValueError('Архив пуст')
            fields={'id':value,'recovery_key':key}
            anchor_id=request.form.get('anchor_id','').strip()
            if anchor_id:
                fields['anchor_id']=identifier(anchor_id)
            sent=True
            result=candidate.call('backup-inspect',**fields)
            if result.get('status')=='checked':flash('Подпись, расшифровка и содержимое проверены. Рабочие файлы и сеть не изменены.','success')
            else:flash('Состояние проверки прочитано; проверьте её запись ниже.','info')
        except (ValueError,OSError,RemoteError) as error:
            if path is not None and created and not sent:path.unlink(missing_ok=True)
            flash(str(error) if not isinstance(error,OSError) else 'Не удалось сохранить загрузку. Обновите список перед повтором.','error')
        return redirect(url_for('page',name='backups'))

    @app.post('/backups/<value>/download')
    def backup_download(value):
        if candidate is None:abort(404)
        from system_backup import identifier
        import stat
        try:
            value=identifier(value);view=candidate.call('backup-status')
            item=next((item for item in view['jobs'] if item['id']==value),None)
            if item is None or item['kind']!='export' or item['status']!='ready':abort(409,'Копия ещё не готова к скачиванию')
            fd=os.open(directory/'backup-downloads'/(value+'.age'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);file=os.fdopen(fd,'rb');st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size!=item['bytes']:file.close();abort(409,'Файл копии изменился; обновите список')
        except (ValueError,OSError,RemoteError):abort(409,'Копию сейчас нельзя скачать. Обновите список')
        response=send_file(file,as_attachment=True,download_name='okopy-server-'+datetime.fromtimestamp(item['created_at'],timezone.utc).strftime('%Y%m%d-%H%M%S')+'.tar.gz.age',mimetype='application/octet-stream',conditional=False)
        response.content_length=item['bytes'];response.headers['X-Backup-SHA256']=item['sha256'];response.call_on_close(file.close);return response

    @app.post('/backups/<value>/delete')
    def backup_delete(value):
        if candidate is None:abort(404)
        from system_backup import identifier
        try:
            candidate.call('backup-delete',id=identifier(value));flash('Серверная запись копии удалена. Скачанные файлы и рабочая сеть не затронуты.','success')
        except (ValueError,RemoteError) as error:flash(str(error),'error')
        return redirect(url_for('page',name='backups'))

    @app.get('/configuration')
    def policy_configuration():
        policy,revision=store.read()
        return render_template('configuration.html',name='backups',title='Перенос настроек',revision=revision,policy=policy,preview=None)

    @app.post('/configuration/export')
    def policy_export():
        from policy_exchange import encode
        policy,revision=store.read()
        if request.form.get('revision')!=revision:abort(409,'Черновик изменился. Обновите страницу перед экспортом.')
        return connection_download({'filename':'network-policy.json','encoding':'utf-8','content':encode(policy),'mimetype':'application/json'})

    @app.post('/configuration/import')
    def policy_import():
        from policy_exchange import decode,MAX_BYTES,check_shape
        upload=request.files.get('configuration')
        if upload is None:abort(400,'Выберите файл настроек')
        try:incoming=decode(upload.read(MAX_BYTES+1))
        except ValueError as error:abort(400,str(error))
        with (directory/'draft.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            policy,revision=store.read()
            if request.form.get('revision')!=revision:abort(409,'Черновик изменился. Обновите страницу перед импортом.')
            preview={'token':secrets.token_urlsafe(32),'draft_revision':revision,'created_at':time.time(),'policy':incoming}
            atomic_write(directory/'policy-import.json',json.dumps(preview,ensure_ascii=False).encode())
        summary={key:len(incoming[key]) for key in ('profiles','dns','exits')}
        return render_template('configuration.html',name='backups',title='Проверка импорта',revision=revision,policy=policy,
                               preview={'token':preview['token'],'summary':summary,'warnings':check_shape(incoming)})

    @app.post('/configuration/confirm')
    def policy_import_confirm():
        if request.form.get('confirm')!='on':abort(400,'Подтвердите замену черновика')
        from policy_exchange import check_shape
        with store.edit(request.form.get('revision','')) as policy:
            try:preview=json.loads((directory/'policy-import.json').read_text())
            except (OSError,ValueError):abort(409,'Предпросмотр отсутствует. Загрузите файл ещё раз.')
            if not token_equal(request.form.get('token',''),preview['token']) or preview['draft_revision']!=request.form.get('revision') or not 0<=time.time()-preview['created_at']<=900:
                abort(409,'Предпросмотр изменился или устарел. Загрузите файл ещё раз.')
            try:check_shape(preview['policy'])
            except ValueError as error:abort(400,str(error))
            atomic_write(directory/'policy.before-import.json',json.dumps(policy,ensure_ascii=False,indent=2).encode())
            policy.clear();policy.update(preview['policy'])
        flash('Настройки импортированы в черновик. Рабочая сеть не менялась. Проверьте и примените их на странице «Изменения».','success')
        return redirect(url_for('page',name='changes'))

    @app.get('/configuration/<group>/<identifier>/delete')
    def entity_delete_preview(group,identifier):
        if group not in ('dns','exits'):abort(404)
        from policy_exchange import references
        policy,revision=store.read()
        if identifier not in policy[group]:abort(404)
        return render_template('entity_delete.html',name='dns' if group=='dns' else 'tunnels',title='Удаление записи',
                               group=group,identifier=identifier,entity=policy[group][identifier],revision=revision,used=references(policy,group,identifier))

    @app.post('/configuration/<group>/<identifier>/delete')
    def entity_delete(group,identifier):
        if group not in ('dns','exits'):abort(404)
        if request.form.get('confirm')!='on':abort(400,'Подтвердите удаление записи из черновика')
        from policy_exchange import remove
        with store.edit(request.form.get('revision','')) as policy:
            try:remove(policy,group,identifier)
            except ValueError as error:abort(409,str(error))
        flash('Запись удалена из черновика. Для изменения действующих правил примените черновик.','success')
        return redirect(url_for('page',name='dns' if group=='dns' else 'tunnels'))

    @app.post('/lan/save')
    def lan_save():
        from lan_ingress import settings
        value = {'enabled':request.form.get('enabled')=='on'}
        if value['enabled'] or any(request.form.get(k,'').strip() for k in ('listen','interface','gateway','clients')):
            value.update({k:request.form.get(k,'').strip() for k in ('listen','interface','gateway')})
            value['return_via_gateway'] = request.form.get('return_via_gateway')=='on'
            value['gateway_probe_domains'] = [x.strip() for x in request.form.get('gateway_probe_domains','').splitlines() if x.strip()]
            value['transparent_targets'] = [x.strip() for x in request.form.get('transparent_targets','').splitlines() if x.strip()]
            value['clients'] = [x.strip() for x in request.form.get('clients','').splitlines() if x.strip()]
        try:value = settings({'lan_ingress':value})
        except (ValueError,TypeError) as error:abort(400,str(error))
        with store.edit(request.form.get('revision','')) as policy:policy['lan_ingress']=value
        flash('LAN-вход сохранён в черновике. Применение и подтверждение доступны в разделе «Изменения».','success')
        return redirect(url_for('page',name='lan'))

    @app.post('/vpn-ingress/save')
    def vpn_ingress_save():
        from vpn_ingress import settings
        value={'enabled':request.form.get('enabled')=='on'}
        if value['enabled'] or any(request.form.get(k,'').strip() for k in ('interface','clients','bypass','clients_v6','bypass_v6')):
            value['interface']=request.form.get('interface','').strip()
            for key in ('clients','bypass'):
                value[key]=[line.strip() for line in request.form.get(key,'').splitlines() if line.strip()]
            if any(request.form.get(k,'').strip() for k in ('clients_v6','bypass_v6')):
                for key in ('clients_v6','bypass_v6'):
                    value[key]=[line.strip() for line in request.form.get(key,'').splitlines() if line.strip()]
        if ('clients_v6' in request.form)!=('bypass_v6' in request.form):
            abort(400,'Для IPv6 передайте оба поля: источники и сети обхода')
        if 'dns_before_bypass_present' in request.form and 'interface' in value:
            value['dns_before_bypass']=request.form.get('dns_before_bypass')=='on'
        try:value=settings({'vpn_ingress':value})
        except (ValueError,TypeError) as error:abort(400,str(error))
        with store.edit(request.form.get('revision','')) as policy:
            if 'clients_v6' not in request.form and policy.get('vpn_ingress',{}).get('clients_v6'):
                abort(409,'Форма устарела и не содержит настройки IPv6. Обновите страницу перед сохранением.')
            if 'dns_before_bypass_present' not in request.form and 'dns_before_bypass' in policy.get('vpn_ingress',{}):
                abort(409,'Форма устарела и не содержит настройку DNS. Обновите страницу перед сохранением.')
            policy['vpn_ingress']=value
        flash('VPN-вход сохранён в черновике. Проверьте и примените изменения с автоматическим откатом.','success')
        return redirect(url_for('page',name='lan'))

    @app.post('/filtering/save')
    def filtering_save():
        value={'default_enabled':request.form.get('default_enabled')=='on','blocklists':[],'allowlists':[],
               'rules':[line.strip() for line in request.form.get('rules','').splitlines() if line.strip()]}
        try:
            for key in ('blocklists','allowlists'):
                names=request.form.getlist(key+'_name');urls=request.form.getlist(key+'_url');enabled=request.form.getlist(key+'_enabled')
                if len(names)!=len(urls) or len(names)!=len(enabled) or len(names)>33:raise ValueError('Некорректный список фильтров')
                for name,url,active in zip(names,urls,enabled):
                    if active not in ('true','false'):raise ValueError('Некорректный признак включения списка')
                    if not url.strip():continue
                    value[key].append({'id':list_id(url.strip()),'name':name.strip(),'url':url.strip(),'enabled':active=='true'})
            value=filter_settings({'filtering':value})
        except (ValueError,TypeError) as error:abort(400,str(error))
        with store.edit(request.form.get('revision','')) as policy:policy['filtering']=value
        flash('Настройки AdGuard сохранены в черновике. Они применяются вместе с общими сетевыми настройками.','success')
        return redirect(url_for('page',name='filtering'))

    def monitor_visible(settings):
        from monitor_view import EXTERNAL_KINDS,read_view,arrange
        if settings.get('selected') and settings['selected']['kind'] in EXTERNAL_KINDS:abort(404)
        settings['checks']=[c for c in settings['checks'] if c['kind'] not in EXTERNAL_KINDS]
        view,view_revision=read_view(directory)
        settings['checks']=arrange(settings['checks'],view)
        settings['view_revision']=view_revision
        for check in settings['checks']:
            check['settings_id']='server:'+check['id']
            check['visible']=check['id'] not in view['hidden']
        if settings.get('selected'):settings['selected']['settings_id']='server:'+settings['selected']['id']
        return settings

    def monitor_editor(settings):
        from health_settings import CUSTOM_KINDS,new_check,form_fields
        labels={**CUSTOM_KINDS,'resources':'Ресурсы','runtime':'Состояние ядра','candidate_adguard':'Настройки AdGuard',
                'candidate_lan':'LAN-вход','candidate_vpn':'VPN-вход','dns_filter':'Фильтрация DNS'}
        selected=settings.get('selected') if settings else None
        fields={}
        if selected:
            fields[selected['kind']]=selected['fields']
            if selected['removable'] or selected['id'] is None:
                for kind in CUSTOM_KINDS:
                    if kind not in fields:fields[kind]=form_fields(new_check(kind,''))
        return {'editor_fields':fields,'kind_labels':labels}

    @app.get('/health/settings')
    @app.get('/health/settings/<identifier>')
    def monitor_settings(identifier=None):
        if candidate is None:abort(404)
        settings=None;error=None
        try:settings=monitor_visible(candidate.call('monitor-status',check_id=identifier.removeprefix('server:') if identifier else None))
        except RemoteError as failure:error=str(failure)
        from health_settings import CUSTOM_KINDS
        return render_template('monitor_settings.html',name='health',title='Управление датчиками',settings=settings,error=error,custom_kinds=CUSTOM_KINDS,**monitor_editor(settings))

    @app.post('/health/dashboard')
    def monitor_dashboard():
        if candidate is None:abort(404)
        from monitor_view import save_view
        try:
            settings=monitor_visible(candidate.call('monitor-status',check_id=None))
            save_view(directory,request.form.get('view_revision',''),request.form.getlist('order'),request.form.getlist('visible'),
                      {c['id'] for c in settings['checks']})
        except ValueError as error:abort(409,str(error))
        except RemoteError as error:abort(409,str(error))
        flash('Порядок и видимость датчиков сохранены. Сами проверки продолжают работать.','success')
        return redirect(url_for('monitor_settings'))

    @app.get('/health/settings/new')
    def monitor_new():
        if candidate is None:abort(404)
        from health_settings import CUSTOM_KINDS,new_check,form_fields
        kind=request.args.get('kind','dns')
        if kind not in CUSTOM_KINDS:abort(400,'Неизвестный тип проверки')
        try:settings=monitor_visible(candidate.call('monitor-status',check_id=None))
        except RemoteError as failure:
            flash(str(failure),'error');return redirect(url_for('monitor_settings'))
        for check in settings['checks']:check['settings_id']='server:'+check['id']
        settings['selected']={'id':None,'kind':kind,'fields':form_fields(new_check(kind,'')),'removable':False}
        return render_template('monitor_settings.html',name='health',title='Добавить проверку',settings=settings,error=None,creating=True,custom_kinds=CUSTOM_KINDS,**monitor_editor(settings))

    @app.post('/health/settings/new')
    def monitor_add():
        if candidate is None:abort(404)
        from health_settings import new_check,form_fields
        kind=request.form.get('kind','')
        try:fields=form_fields(new_check(kind,''))
        except ValueError as error:abort(400,str(error))
        values={f['key']:(request.form.get(f['key'])=='on' if f['type']=='bool' else request.form.get(f['key'],'')) for f in fields}
        try:
            result=candidate.call('monitor-add',kind=kind,revision=request.form.get('revision',''),values=values)
            flash('Датчик добавлен. Результат появится после первого измерения.','success')
            return redirect(url_for('monitor_settings',identifier=result['selected']['id']))
        except RemoteError as failure:
            flash(str(failure),'error');return redirect(url_for('monitor_settings'))

    @app.post('/health/settings/<identifier>/remove')
    def monitor_remove(identifier):
        if candidate is None:abort(404)
        if request.form.get('confirm')!='on':abort(400,'Подтвердите удаление собственной проверки')
        identifier=identifier.removeprefix('server:')
        try:
            result=candidate.call('monitor-remove',check_id=identifier,revision=request.form.get('revision',''))
            from health_pull import invalidate_local_check
            invalidate_local_check(directory,identifier,result['observed_at'],removed=True)
            flash('Собственная проверка удалена. Записи прежних событий остаются в истории.','success')
        except RemoteError as failure:flash(str(failure),'error')
        return redirect(url_for('monitor_settings'))

    @app.post('/health/settings/<identifier>')
    def monitor_save(identifier):
        if candidate is None:abort(404)
        try:
            server_id=identifier.removeprefix('server:')
            current=monitor_visible(candidate.call('monitor-status',check_id=server_id))
            from health_settings import new_check,form_fields
            kind=request.form.get('kind',current['selected']['kind'])
            fields=current['selected']['fields']
            if kind!=current['selected']['kind']:
                if not current['selected']['removable']:abort(400,'Тип системного датчика менять нельзя')
                try:fields=form_fields(new_check(kind,server_id))
                except ValueError as error:abort(400,str(error))
            values={f['key']:(request.form.get(f['key'])=='on' if f['type']=='bool' else request.form.get(f['key'],'')) for f in fields}
            if kind!=current['selected']['kind']:values['kind']=kind
            result=candidate.call('monitor-set',check_id=server_id,revision=request.form.get('revision',''),values=values)
            from health_pull import invalidate_local_check
            invalidate_local_check(directory,server_id,result['observed_at'])
            flash('Настройки датчика сохранены. Ожидается новое измерение.','success')
        except RemoteError as failure:flash(str(failure),'error')
        return redirect(url_for('monitor_settings',identifier=identifier))

    @app.get('/health/switches')
    def routing_history():
        policy,_=store.read();routing=None;error=None
        if candidate is None:error='Сетевое ядро не подключено.'
        else:
            try:routing=candidate.call('routing-status')
            except RemoteError as failure:error=str(failure)
        labels={'default':'Весь остальной трафик',**{'rule:'+p['id']:p['name'] for p in policy['profiles']}}
        queue=request.args.get('queue','')
        return render_template('routing_history.html',name='health',title='Журнал переключений',
                               routing=routing,error=error,queue=queue,labels=labels)

    @app.post('/failover/control')
    def routing_save():
        if candidate is None:abort(404)
        queues=request.form.getlist('queue');pins=request.form.getlist('pin')
        if len(queues)!=len(pins) or len(set(queues))!=len(queues) or len(queues)>32:abort(400,'Некорректные закрепления')
        fields={'expected_config_sha256':request.form.get('config_sha256',''),'expected_transaction_id':request.form.get('transaction_id',''),
                'expected_preferences_revision':request.form.get('preferences_revision',''),
                'expected_mode':request.form.get('mode',''),'enabled':request.form.get('enabled')=='on',
                'pins':{q:p for q,p in zip(queues,pins) if p!='auto'}}
        try:
            candidate.call('routing-set',**fields)
            flash('Настройки переключения обновлены. Ручные закрепления сохраняются и при отказе выбранной пары.','success')
        except RemoteError as error:flash(str(error),'error')
        return redirect(url_for('page',name='rules')+'#rule-automation')

    @app.post('/failover/probes')
    def probe_save():
        queue=request.form.get('queue','')
        with store.edit(request.form.get('revision','')) as policy:
            settings=policy.setdefault('health_probes',{})
            if request.form.get('enabled')!='on':settings.pop(queue,None)
            else:
                try:
                    value={'dns_name':request.form.get('dns_name',''),'urls':[x.strip() for x in request.form.get('urls','').splitlines() if x.strip()],
                           'codes':[int(x.strip()) for x in request.form.get('codes','').split(',') if x.strip()]}
                    checked=validate_target_for_queue(policy,queue,value)
                except ValueError as error:abort(400,str(error))
                settings[queue]={key:checked[key] for key in ('dns_name','urls','codes')}
        flash('Параметры проверки сохранены в черновике. Чтобы использовать новые параметры, примените изменения.','success')
        return redirect(url_for('page',name='rules')+'#rule-automation')

    @app.post('/candidate/<action>')
    def candidate_action(action):
        if candidate is None or action not in ('apply','confirm','rollback'):abort(404)
        expected=request.form.get('candidate_revision')
        if expected=='missing':expected=None
        elif not expected or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):
            abort(400,'Некорректная версия конфигурации. Обновите страницу.')
        fields={'expected_config_sha256':expected}
        if action=='apply':
            policy,current=store.read()
            if not token_equal(request.form.get('revision',''),current):
                abort(409,'Черновик изменён. Обновите страницу перед применением.')
            if any(issue['severity']=='error' for issue in validate_policy(policy)):
                abort(400,'Сначала устраните ошибки в черновике.')
            fields['policy']=policy
        else:
            identifier=request.form.get('transaction','')
            if len(identifier)!=32 or any(c not in '0123456789abcdef' for c in identifier):abort(400,'Некорректный идентификатор операции.')
            fields['transaction']=identifier
        try:
            result=candidate.call(action,**fields)
            status=result.get('transaction',{}).get('status')
            expected_status={'apply':'pending','confirm':'confirmed','rollback':'rolled_back'}[action]
            if status!=expected_status:
                flash('Состояние операции изменилось. Проверьте сведения сервера ниже.','error')
            else:
                flash({'apply':'Настройки применены. На подтверждение отведено 120 секунд от начала применения; иначе сервер вернёт прежний пакет.',
                       'confirm':'DNS и HTTPS проверены; настройки подтверждены.',
                       'rollback':'Прежние сетевые настройки восстановлены.'}[action],'success')
        except RemoteError as error:flash(str(error),'error')
        return redirect(url_for('page',name='changes'))

    @app.get('/rules/default')
    def default_rule_form():
        from default_rule import view
        policy,revision=store.read()
        return render_template('rule.html',name='rules',title='Весь остальной трафик',
                               policy=policy,revision=revision,profile=view(policy),is_default=True,
                               families=FAMILIES,filtering=FILTERING,dns_responses=DNS_RESPONSES,query_types=QUERY_TYPES)

    @app.get('/rules/new')
    @app.get('/rules/<identifier>/edit')
    def rule_form(identifier=None):
        policy,revision=store.read()
        profile=next((p for p in policy['profiles'] if p['id']==identifier),None) if identifier else {}
        if identifier and profile is None:abort(404)
        return render_template('rule.html',name='rules',title='Изменить правило' if identifier else 'Добавить правило',
                               policy=policy,revision=revision,profile=profile,families=FAMILIES,filtering=FILTERING,dns_responses=DNS_RESPONSES,query_types=QUERY_TYPES)

    @app.post('/rules/save')
    def rule_save():
        if request.form.get('id')=='__default__':
            from default_rule import save
            with store.edit(request.form.get('revision','')) as policy:
                try:save(policy,request.form)
                except ValueError as error:abort(400,str(error))
            flash('Последнее правило сохранено в черновике. Примените его на странице «Изменения».','success')
            return redirect(url_for('page',name='rules')+'#default-route')
        try:document=parse_domain_document(request.form.get('domains',''))
        except ValueError as error:abort(400,str(error))
        identifier=request.form.get('id') or uuid.uuid4().hex
        profile={'id':identifier,'name':request.form.get('name','').strip()[:120],
                 'kind':request.form.get('kind'),'enabled':request.form.get('enabled')=='on',
                 'dns_only':request.form.get('dns_only')=='on',
                 'domains':document['domains'],'domain_document':document['text'],
                 'exclude_domains':[v.strip() for v in request.form.get('exclude_domains','').splitlines() if v.strip()],
                 'networks':[v.strip() for v in request.form.get('networks','').splitlines() if v.strip()],
                 'exit':request.form.get('exit'),'dns':request.form.get('dns'),
                 'fallback':request.form.getlist('fallback')}
        if not profile['name']:abort(400,'Укажите название правила')
        try:profile.update(parse_options(request.form))
        except ValueError as error:abort(400,str(error))
        try:profile['fallback_pairs']=parse_pairs(request.form)
        except ValueError as error:abort(400,str(error))
        with store.edit(request.form.get('revision','')) as policy:
            if profile['exit'] not in policy['exits'] or profile['dns'] not in policy['dns']:
                abort(400,'Выберите основной выход и DNS из текущего черновика')
            try:validate_pairs(profile,policy)
            except ValueError as error:abort(400,str(error))
            old=next((i for i,p in enumerate(policy['profiles']) if p['id']==identifier),None)
            if request.form.get('id') and old is None:abort(404)
            if old is not None and policy['profiles'][old].get('fallback'):
                if request.form.get('replace_legacy_fallback')!='on':
                    abort(400,'Укажите пары DNS/выхода и подтвердите замену прежнего списка резерва')
                profile['fallback']=[]
            if old is None:policy['profiles'].append(profile)
            else:policy['profiles'][old].update(profile)
        flash('Черновик сохранён. Перед применением проверьте конфликты.','success')
        return redirect(url_for('page',name='rules'))

    @app.post('/rules/reorder')
    def rule_reorder():
        order=request.form.getlist('order')
        with store.edit(request.form.get('revision','')) as policy:
            by_id={p['id']:p for p in policy['profiles']}
            if len(order)!=len(by_id) or len(set(order))!=len(order) or set(order)!=set(by_id):
                abort(400,'Порядок должен содержать каждое обычное правило ровно один раз. Последнее правило закреплено.')
            policy['profiles']=[by_id[key] for key in order]
        flash('Порядок правил сохранён в черновике.','success')
        return redirect(url_for('page',name='rules'))

    @app.post('/rules/<identifier>/move')
    def rule_move(identifier):
        if identifier=='__default__':abort(400,'Последнее правило всегда находится в конце списка')
        direction=request.form.get('direction')
        if direction not in ('up','down'):abort(400)
        with store.edit(request.form.get('revision','')) as policy:
            index=next((i for i,p in enumerate(policy['profiles']) if p['id']==identifier),None)
            if index is None:abort(404)
            target=index+(-1 if direction=='up' else 1)
            if 0<=target<len(policy['profiles']):
                policy['profiles'][index],policy['profiles'][target]=policy['profiles'][target],policy['profiles'][index]
        return redirect(url_for('page',name='rules'))

    @app.post('/rules/<identifier>/delete')
    def rule_delete(identifier):
        if identifier=='__default__':abort(400,'Последнее правило нельзя удалить')
        with store.edit(request.form.get('revision','')) as policy:
            target=next((p for p in policy['profiles'] if p['id']==identifier),None)
            if target is None:abort(404)
            if request.form.get('confirm')!='on':abort(400,'Подтвердите удаление. Трафик этого правила будет обрабатываться следующими правилами.')
            policy['profiles']=[p for p in policy['profiles'] if p['id']!=identifier]
        flash('Правило удалено из черновика. Действующая сеть не менялась.','success')
        return redirect(url_for('page',name='rules'))

    @app.post('/failover/timing')
    def failover_timing():
        from werkzeug.datastructures import MultiDict
        with store.edit(request.form.get('revision','')) as policy:
            from default_rule import view
            rule=view(policy)
            pairs=[{'exit':rule['exit'],'dns':rule['dns']},*rule['fallback_pairs']]
            values=MultiDict([('exit',p['exit']) for p in pairs]+[('dns',p['dns']) for p in pairs]+
                             [('failures',request.form.get('failures','')),('recovery',request.form.get('recovery',''))])
            try:settings=parse_failover(values,policy)
            except ValueError as error:abort(400,str(error))
            policy['failover']={**policy.get('failover',{}),**settings}
        flash('Общие пороги переключения сохранены в черновике.','success')
        return redirect(url_for('page',name='rules')+'#rule-automation')

    @app.post('/failover/save')
    def failover_save():
        with store.edit(request.form.get('revision','')) as policy:
            try:policy['failover']={**policy.get('failover',{}),**parse_failover(request.form,policy)}
            except ValueError as error:abort(400,str(error))
            pair=primary_pair(policy)
            policy.update(default_exit=pair['exit'],default_dns=pair['dns'])
        flash('Пары выхода и DNS сохранены в черновике.','success')
        return redirect(url_for('page',name='rules')+'#rule-automation')

    @app.get('/dns/new')
    @app.get('/dns/<identifier>/edit')
    def dns_form(identifier=None):
        policy,revision=store.read()
        if identifier and identifier not in policy['dns']:abort(404)
        resolver=policy['dns'].get(identifier,{'native':{'type':'udp'}})
        interfaces=[];interface_error=None
        if candidate is not None:
            try:interfaces=candidate.call('dns-interfaces').get('interfaces',[])
            except RemoteError as error:interface_error=str(error)

        return render_template('dns.html',name='dns',title=resolver.get('name','Настройки DNS') if identifier else 'Добавить DNS',
                               identifier=identifier,resolver=resolver,policy=policy,revision=revision,types=DNS_TYPES,interfaces=interfaces,interface_error=interface_error,
                               hosts=hosts_text(resolver['native']) if resolver.get('native',{}).get('type')=='hosts' else '')

    @app.post('/dns/<identifier>/hosts-export')
    def dns_hosts_export(identifier):
        policy,revision=store.read()
        if request.form.get('revision')!=revision:abort(409,'Черновик изменился. Обновите страницу.')
        resolver=policy['dns'].get(identifier,{})
        if resolver.get('native',{}).get('type')!='hosts':abort(404)
        return connection_download({'content':hosts_text(resolver['native']),'encoding':'utf-8',
                                    'filename':'dns-records.hosts','mimetype':'text/plain'})

    @app.post('/dns/save')
    def dns_save():
        identifier=request.form.get('id') or 'dns-'+uuid.uuid4().hex[:12]
        with store.edit(request.form.get('revision','')) as policy:
            previous=policy['dns'].get(identifier,{})
            if request.form.get('id') and not previous:abort(404)
            try:policy['dns'][identifier]=parse_dns(request.form,previous,identifier,policy)
            except ValueError as error:abort(400,str(error))
        flash('DNS сохранён в черновике. Проверьте зависимости перед применением.','success')
        return redirect(url_for('page',name='dns'))

    @app.get('/connections/new')
    def connection_new():
        protocol=request.args.get('protocol','')
        if not protocol:
            return render_template('connection_new.html',name='tunnels',title='Добавить подключение',revision=store.read()[1])
        factories={'amnezia':amnezia_new,'wireguard':wireguard_new,'openvpn':openvpn_new,'trusttunnel':trusttunnel_new,
                   'shadowsocks-import':shadowsocks_import_form}
        if protocol in factories:return factories[protocol]()
        if protocol in OUTBOUND_TYPES:return tunnel_form()
        abort(400,'Выберите протокол из списка')

    @app.get('/tunnels/new')
    @app.get('/tunnels/<identifier>/edit')
    def tunnel_form(identifier=None):
        policy,revision=store.read()
        if identifier and identifier not in policy['exits']:abort(404)
        kind=request.args.get('protocol','socks') if identifier is None else 'socks'
        if kind not in OUTBOUND_TYPES:abort(400,'Неизвестный тип подключения')
        outbound=policy['exits'].get(identifier,{'native':{'type':kind}})
        if outbound.get('native',{}).get('type')=='openvpn-client':
            from openvpn_profile import form_view
            return render_template('openvpn.html',name='tunnels',title=outbound.get('name',identifier),identifier=identifier,outbound=outbound,policy=policy,revision=revision,groups=form_view(outbound['native']))
        if outbound.get('protocol')=='AmneziaWG':
            return redirect(url_for('amnezia_page',profile=outbound.get('profile','')))
        if external_connection(outbound):
            if outbound.get('protocol')=='TrustTunnel' and candidate is not None:
                connection=None;error=None
                try:
                    connection=candidate.call('trusttunnel-status',connection=identifier);error=connection.get('error')
                except RemoteError as failure:error=str(failure)
                return render_template('trusttunnel_service.html',name='tunnels',title=outbound.get('name',identifier),outbound=outbound,identifier=identifier,connection=connection,error=error)
            if outbound.get('protocol')=='OpenConnect' and candidate is not None:
                from openconnect_profile import NUMBERS
                connection=None;error=None
                try:
                    connection=candidate.call('openconnect-status',connection=identifier)
                    error=connection.get('error')
                except RemoteError as failure:error=str(failure)
                return render_template('openconnect_service.html',name='tunnels',title=outbound.get('name',identifier),
                    outbound=outbound,identifier=identifier,connection=connection,error=error,number_limits=NUMBERS)
            return render_template('external_connection.html',name='tunnels',
                title=outbound.get('name',identifier),outbound=outbound)
        return render_template('tunnel.html',name='tunnels',title=outbound.get('name','Настройки подключения') if identifier else 'Новое подключение',
            identifier=identifier,outbound=outbound,policy=policy,revision=revision,types=OUTBOUND_TYPES,methods=SS_METHODS,
            fingerprints=FINGERPRINTS,transports=TRANSPORTS,tls_versions=VERSIONS,transport_hosts=transport_hosts(outbound.get('native',{})))

    def connection_download(result):
        import base64,re
        filename=result.get('filename','')
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}',filename):raise RemoteError('Некорректное имя экспортируемого файла')
        if result.get('encoding')=='base64':
            try:content=base64.b64decode(result['content'],validate=True)
            except (ValueError,KeyError):raise RemoteError('Повреждён ответ экспорта') from None
        elif result.get('encoding')=='utf-8':content=result['content'].encode()
        else:raise RemoteError('Неизвестный формат ответа экспорта')
        response=app.response_class(content,mimetype=result.get('mimetype','application/octet-stream'))
        response.headers['Content-Disposition']='attachment; filename="'+filename+'"'
        return response

    from incoming_web import register as register_incoming
    register_incoming(app, store, connection_download)
    from recovery_web import register as register_recovery
    register_recovery(app, candidate, connection_download)

    @app.get('/trusttunnel-new')
    def trusttunnel_new():
        from trusttunnel_profile import DEFAULT
        policy,revision=store.read();catalog=[];error=None
        if candidate is None:error='Нет соединения с сервером управления'
        else:
            try:catalog=candidate.call('trusttunnel-catalog')['connections']
            except RemoteError as failure:error=str(failure)
        return render_template('trusttunnel_new.html',name='tunnels',title='Новый TrustTunnel',
            identifier='tt-'+uuid.uuid4().hex[:12],revision=revision,policy=policy,catalog=catalog,error=error,
            model={**DEFAULT,'saved_secrets':{'password':False,'client_random':False}},creating=True)

    @app.post('/trusttunnel-create')
    @app.post('/trusttunnel-complete/<identifier>')
    def trusttunnel_create(identifier=None):
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        from trusttunnel_profile import values_from_form,MAX_BYTES
        from trusttunnel_create import connection_id
        try:
            fields={'connection':connection_id(identifier or request.form.get('connection',''))}
            if identifier is None:
                kind=request.form.get('format','form');text='';values=None
                if kind=='form':values=values_from_form(request.form)
                elif kind=='deeplink' and request.form.get('connection_text','').strip():
                    text=request.form['connection_text'].strip()
                else:
                    upload=request.files.get('connection_file')
                    if upload is None:raise ValueError('Выберите файл TOML')
                    raw=upload.read(MAX_BYTES+1)
                    if len(raw)>MAX_BYTES:raise ValueError('Файл превышает 128 КиБ')
                    try:text=raw.decode('utf-8-sig')
                    except UnicodeError:raise ValueError('Нужен TOML в UTF-8') from None
                fields.update(name=request.form.get('name',''),scope=request.form.get('scope',''),values=values,text=text,format=kind)
            with store.edit(request.form.get('revision','')) as policy:
                if fields['connection'] in policy['exits']:raise ValueError('Подключение уже есть в списке')
                result=candidate.call('trusttunnel-complete' if identifier else 'trusttunnel-create',**fields)
                if result.get('id')!=fields['connection'] or result.get('created') is not True:raise RemoteError('Создание не подтверждено; перечитайте список новых подключений')
                policy['exits'][result['id']]=result['outbound']
        except ValueError as error:abort(400,str(error))
        except (RemoteError,OSError) as error:
            flash(str(error) if isinstance(error,RemoteError) else 'Не удалось сохранить список панели. Подключение можно добавить из списка сохранённых ниже.','error')
            return redirect(url_for('trusttunnel_new'))
        flash('TrustTunnel создан выключенным, без автозапуска. После запуска и проверки выберите его в общих правилах и примените правила отдельно.','success')
        return redirect(url_for('tunnel_form',identifier=result['id']))

    @app.post('/trusttunnel/<identifier>/<action>')
    def trusttunnel_action(identifier,action):
        if candidate is None or action not in ('save','export','discard','import','check','apply','confirm','rollback','start','stop','enable','disable'):abort(404)
        from trusttunnel_profile import values_from_form,MAX_BYTES
        policy,_=store.read();outbound=policy['exits'].get(identifier,{})
        if outbound.get('protocol')!='TrustTunnel' or not external_connection(outbound):abort(404)
        fields={'connection':identifier}
        if action in ('confirm','rollback'):fields['transaction']=request.form.get('transaction','')
        else:fields.update(file_revision=request.form.get('file_revision',''),draft_revision=request.form.get('draft_revision',''))
        try:
            if action=='export':
                fields['source']=request.form.get('source','')
                if request.form.get('format'):fields['format']=request.form['format']
            if action in ('start','stop','enable','disable'):
                try:fields['expected_state']=json.loads(request.form.get('expected_state',''))
                except (ValueError,TypeError):raise ValueError('Обновите состояния связанных служб') from None
            if action in ('apply','start','enable'):
                from openconnect_runtime import probe_values
                try:codes=[int(v.strip()) for v in request.form.get('probe_codes','').split(',') if v.strip()]
                except ValueError:raise ValueError('Коды ответа должны быть числами') from None
                fields['probe']=probe_values({'url':request.form.get('probe_url','').strip(),'codes':codes})
            if action=='save':fields['values']=values_from_form(request.form)
            elif action=='import':
                fields['format']=request.form.get('format','')
                if fields['format']=='deeplink' and request.form.get('connection_text','').strip():fields['text']=request.form['connection_text'].strip()
                else:
                    upload=request.files.get('connection_file')
                    if upload is None:raise ValueError('Выберите файл или вставьте ссылку TrustTunnel')
                    raw=upload.read(MAX_BYTES+1)
                    if len(raw)>MAX_BYTES:raise ValueError('Файл превышает 128 КиБ')
                    try:fields['text']=raw.decode('utf-8-sig')
                    except UnicodeError:raise ValueError('Нужен текстовый файл UTF-8') from None
            result=candidate.call('trusttunnel-'+action,**fields)
            if action=='export':return connection_download(result)
            if action in ('apply','start','stop','confirm') and result.get('transaction',{}).get('status')!=('confirmed' if action=='confirm' else 'pending'):raise RemoteError('Действие не подтверждено сервером; перечитайте состояние')
        except ValueError as error:abort(400,str(error))
        except RemoteError as error:abort(409,str(error))
        flash({'save':'Черновик TrustTunnel сохранён; действующее подключение не менялось.',
               'start':'TrustTunnel запущен и проверен. Подтвердите результат до срока возврата.',
               'stop':'TrustTunnel остановлен. Подтвердите результат до срока возврата.',
               'enable':'Автозапуск клиента и связанных входящих служб включён. Соединения не перезапускались.',
               'disable':'Автозапуск клиента и связанных входящих служб выключен. Соединения не останавливались.',
               'apply':'Параметры TrustTunnel сохранены; подключение осталось выключенным. Подтвердите сохранение до срока возврата.' if not result.get('transaction',{}).get('target_active') else 'TrustTunnel и связанные службы восстановлены с новыми параметрами. Подтвердите результат до срока автоматического возврата.',
               'confirm':('Остановка TrustTunnel подтверждена. Параметры подключения и автозапуск не менялись.' if result.get('transaction',{}).get('kind')=='runtime' else 'Параметры TrustTunnel сохранены. Подключение осталось выключенным; проверка связи ещё не выполнялась.') if not result.get('transaction',{}).get('target_active') else 'Изменение TrustTunnel подтверждено после проверки трафика.',
               'rollback':'Результат возврата TrustTunnel прочитан; проверьте состояние ниже.',
               'import':'TrustTunnel импортирован в черновик; проверьте параметры.',
               'discard':'Черновик удалён; показаны действующие настройки.',
               'check':'Параметры TrustTunnel проверены. Вход на VPN-сервер не выполнялся; сеть не менялась.'}[action],'success')
        return redirect(url_for('tunnel_form',identifier=identifier))

    @app.post('/openconnect/<identifier>/<action>')
    def openconnect_action(identifier,action):
        if candidate is None or action not in ('save','export','discard','import','check','apply','confirm','rollback','start','stop','enable','disable'):abort(404)
        from openconnect_profile import values_from_form,MAX_BYTES
        policy,_=store.read();outbound=policy['exits'].get(identifier,{})
        if outbound.get('protocol')!='OpenConnect' or not external_connection(outbound):abort(404)
        fields={'connection':identifier}
        if action in ('confirm','rollback'):fields['transaction']=request.form.get('transaction','')
        else:fields.update(file_revision=request.form.get('file_revision',''),draft_revision=request.form.get('draft_revision',''))
        try:
            if action=='export':fields['source']=request.form.get('source','')
            if action in ('start','stop','enable','disable'):
                active=request.form.get('expected_active');boot=request.form.get('expected_boot')
                if active not in ('true','false') or boot not in ('enabled','disabled'):raise ValueError('Обновите состояние службы перед изменением')
                fields['expected_state']={'active':active=='true','boot':boot}
            if action in ('apply','start','enable'):
                from openconnect_runtime import probe_values
                try:codes=[int(v.strip()) for v in request.form.get('probe_codes','').split(',') if v.strip()]
                except ValueError:raise ValueError('Проверка: коды ответа должны быть числами') from None
                fields['probe']=probe_values({'url':request.form.get('probe_url','').strip(),'codes':codes})
            if action=='save':fields['values']=values_from_form(request.form)
            elif action=='import':
                upload=request.files.get('connection_file')
                if upload is None:raise ValueError('Выберите файл подключения')
                data=upload.read(MAX_BYTES+1)
                if len(data)>MAX_BYTES:raise ValueError('Файл превышает 128 КиБ')
                fields['format']=request.form.get('format','')
                if fields['format']=='native-bundle':
                    import base64
                    fields['text']=base64.b64encode(data).decode()
                else:
                    try:fields['text']=data.decode('utf-8-sig')
                    except UnicodeError:raise ValueError('Нужен текстовый файл UTF-8') from None
            result=candidate.call('openconnect-'+action,**fields)
            if action=='export':return connection_download(result)
            if action in ('apply','start','stop') and result.get('transaction',{}).get('status')!='pending':raise RemoteError('Применение не подтверждено сервером; перечитайте состояние')
            if action=='confirm' and result.get('transaction',{}).get('status')!='confirmed':raise RemoteError('Подтверждение не принято; перечитайте состояние')
        except ValueError as error:abort(400,str(error))
        except RemoteError as error:abort(409,str(error))
        flash({'save':'Черновик OpenConnect сохранён; действующее подключение не менялось.',
               'import':'Файл импортирован в черновик. Проверьте параметры; действующее подключение не менялось.',
               'discard':'Черновик удалён; показаны действующие настройки.',
               'start':'VPN запущен и проверен. Подтвердите результат до срока автоматического возврата.',
               'stop':'VPN остановлен. Подтвердите остановку до срока автоматического возврата.',
               'enable':'Автозапуск VPN включён. Текущее соединение не перезапускалось.',
               'disable':'Автозапуск VPN выключен. Текущее соединение не останавливалось.',
               'apply':'OpenConnect переподключён и проверен. Подтвердите результат до указанного срока, иначе сервер вернёт прежние настройки.',
               'confirm':'Изменение OpenConnect подтверждено. Состояние службы и необходимые проверки приняты.',
               'rollback':'Результат возврата OpenConnect прочитан; проверьте состояние ниже.',
               'check':'Параметры проверены. Авторизация на VPN-сервере не выполнялась; соединение не менялось.'}[action],'success')
        return redirect(url_for('tunnel_form',identifier=identifier))

    @app.get('/openvpn-new')
    def openvpn_new():
        from openvpn_profile import DEFAULT,form_view
        policy,revision=store.read();outbound={'native':DEFAULT,'scope':'public'}
        return render_template('openvpn.html',name='tunnels',title='Новый OpenVPN',identifier=None,
            outbound=outbound,policy=policy,revision=revision,groups=form_view(DEFAULT))

    @app.post('/openvpn/<action>')
    def openvpn_action(action):
        if action not in ('save','import','export'):abort(404)
        from openvpn_profile import MAX_BYTES
        from openvpn_form import saved,imported
        from openvpn_format import render
        identifier=request.form.get('id','')
        if action=='export':
            policy,revision=store.read()
            if not token_equal(request.form.get('revision',''),revision):abort(409,'Черновик изменился; перечитайте настройки перед экспортом')
            outbound=policy['exits'].get(identifier,{})
            if outbound.get('native',{}).get('type')!='openvpn-client':abort(404)
            try:content=render(outbound)
            except ValueError as error:abort(400,str(error))
            return connection_download({'filename':'openvpn-draft.ovpn','encoding':'utf-8','content':content,'mimetype':'application/x-openvpn-profile'})
        new_id=identifier or 'exit-'+uuid.uuid4().hex[:12]
        try:
            raw=None;files={}
            if action=='import':
                upload=request.files.get('connection_file')
                if upload is None:raise ValueError('Выберите .ovpn')
                data=upload.read(MAX_BYTES+1)
                if len(data)>MAX_BYTES:raise ValueError('Профиль превышает 128 КиБ')
                try:raw=data.decode('utf-8-sig')
                except UnicodeError:raise ValueError('Нужен .ovpn в UTF-8') from None
                for file in request.files.getlist('related_files'):
                    if not file.filename:continue
                    filename=file.filename
                    if '/' in filename or '\\' in filename or filename in files or len(files)>=16:raise ValueError('Сопутствующие файлы должны иметь разные имена без пути; до 16 файлов')
                    data=file.read(MAX_BYTES+1)
                    if len(data)>MAX_BYTES:raise ValueError('Сопутствующий файл превышает 128 КиБ')
                    try:files[filename]=data.decode('utf-8-sig')
                    except UnicodeError:raise ValueError('Сопутствующие файлы нужны в текстовом PEM/UTF-8; PKCS12 пока не поддержан') from None
            with store.edit(request.form.get('revision','')) as policy:
                previous=policy['exits'].get(new_id,{})
                if identifier and previous.get('native',{}).get('type')!='openvpn-client':abort(404)
                result=saved(request.form,previous,new_id,policy) if action=='save' else imported(request.form,raw,files,new_id,policy)
                policy['exits'][new_id]=result
        except ValueError as error:abort(400,str(error))
        flash('OpenVPN сохранён в черновике. VPN не запускался; проверьте изменения перед применением общей политики.','success')
        return redirect(url_for('tunnel_form',identifier=new_id))

    @app.get('/shadowsocks-import')
    def shadowsocks_import_form():
        _,revision=store.read()
        return render_template('shadowsocks_import.html',name='tunnels',title='Импорт Shadowsocks',revision=revision)

    @app.post('/shadowsocks-import')
    def shadowsocks_import():
        from shadowsocks_uri import parse,LIMIT
        try:
            raw=request.form.get('uri','');upload=request.files.get('connection_file')
            if upload and upload.filename:
                if raw.strip():raise ValueError('Выберите ссылку или файл, не оба сразу')
                data=upload.read(LIMIT+1)
                if len(data)>LIMIT:raise ValueError('Файл превышает 64 КиБ')
                try:raw=data.decode('utf-8-sig')
                except UnicodeError:raise ValueError('Нужен текстовый файл UTF-8 с одной ссылкой ss://') from None
            outbound=parse(raw);scope=request.form.get('scope','')
            if scope not in ('public','work','special'):raise ValueError('Выберите назначение подключения')
            identifier='exit-'+uuid.uuid4().hex[:12]
            outbound['scope']=scope;outbound['native']['tag']=identifier
            with store.edit(request.form.get('revision','')) as policy:policy['exits'][identifier]=outbound
        except ValueError as error:abort(400,str(error))
        flash('Shadowsocks импортирован в новый черновик выхода. Проверьте параметры; работающая сеть не менялась.','success')
        return redirect(url_for('tunnel_form',identifier=identifier))

    @app.post('/tunnels/<identifier>/export-ss')
    def shadowsocks_export(identifier):
        from shadowsocks_uri import render
        with (store.directory/'draft.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_SH)
            policy,revision=store.read()
            if not token_equal(request.form.get('revision',''),revision):abort(409,'Настройки изменились; перечитайте сохранённый черновик перед экспортом')
            outbound=policy['exits'].get(identifier)
            if not outbound or external_connection(outbound):abort(404)
            try:content=render(outbound)
            except ValueError as error:abort(400,str(error))
        return connection_download({'filename':'shadowsocks-draft.txt','encoding':'utf-8','content':content,'mimetype':'text/plain'})

    @app.post('/vless-import')
    def vless_import():
        from vless_uri import parse,LIMIT
        try:
            raw=request.form.get('uri','');upload=request.files.get('connection_file')
            if upload and upload.filename:
                if raw.strip():raise ValueError('Выберите ссылку или файл, не оба сразу')
                data=upload.read(LIMIT+1)
                if len(data)>LIMIT:raise ValueError('Файл превышает 64 КиБ')
                try:raw=data.decode('utf-8-sig')
                except UnicodeError:raise ValueError('Нужен текстовый файл UTF-8 с одной ссылкой vless://') from None
            outbound=parse(raw);scope=request.form.get('scope','')
            if scope not in ('public','work','special'):raise ValueError('Выберите назначение подключения')
            identifier='exit-'+uuid.uuid4().hex[:12]
            outbound['scope']=scope;outbound['native']['tag']=identifier
            with store.edit(request.form.get('revision','')) as policy:policy['exits'][identifier]=outbound
        except ValueError as error:abort(400,str(error))
        flash('VLESS импортирован. Проверьте параметры и примените изменения, когда будете готовы. Действующая сеть не менялась.','success')
        return redirect(url_for('tunnel_form',identifier=identifier))

    @app.post('/tunnels/<identifier>/export-vless')
    def vless_export(identifier):
        from vless_uri import render
        with (store.directory/'draft.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_SH)
            policy,revision=store.read()
            if not token_equal(request.form.get('revision',''),revision):abort(409,'Настройки изменились; обновите страницу перед экспортом')
            outbound=policy['exits'].get(identifier)
            if not outbound or outbound.get('native',{}).get('type')!='vless':abort(404)
            try:content=render(outbound)
            except ValueError as error:abort(400,str(error))
        return connection_download({'filename':'vless-draft.txt','encoding':'utf-8','content':content,'mimetype':'text/plain'})

    @app.post('/connections/import-native')
    def outbound_import_native():
        from native_exchange import decode,MAX_BYTES
        upload=request.files.get('connection_file')
        if upload is None:abort(400,'Выберите JSON подключения')
        identifier='exit-'+uuid.uuid4().hex[:12]
        try:
            native=decode(upload.read(MAX_BYTES+1),identifier)
            name=request.form.get('name','').strip();scope=request.form.get('scope','')
            if not name or len(name)>120 or scope not in ('public','work','special'):raise ValueError('Укажите название и назначение')
            with store.edit(request.form.get('revision','')) as policy:
                policy['exits'][identifier]={'name':name,'scope':scope,'protocol':native['type'],'native':native}
                # The imported fragment may refer to DNS or another connection; require existing names.
                resolver=native.get('domain_resolver');resolver=resolver.get('server') if isinstance(resolver,dict) else resolver
                if resolver and resolver not in policy['dns']:raise ValueError('DNS из файла отсутствует. Сначала добавьте его или исправьте domain_resolver.')
                refs=[*native.get('outbounds',[]),*([native['detour']] if native.get('detour') else [])]
                if any(key not in policy['exits'] for key in refs):raise ValueError('Связанное подключение из файла отсутствует')
                from native_endpoints import validate_bootstrap
                validate_bootstrap(policy)
        except (ValueError,TypeError) as error:abort(400,str(error))
        flash('Подключение импортировано в черновик. Проверьте его поля перед применением.','success')
        return redirect(url_for('tunnel_form',identifier=identifier))

    @app.post('/openconnect-import')
    def embedded_openconnect_import():
        from openconnect_exchange import import_native
        from openconnect_profile import MAX_BYTES
        import base64
        upload=request.files.get('connection_file')
        if upload is None:abort(400,'Выберите .conf, XML или ZIP подключения')
        raw=upload.read(MAX_BYTES+1)
        if len(raw)>MAX_BYTES:abort(400,'Файл превышает 128 КиБ')
        kind=request.form.get('format','')
        if kind not in ('conf','xml','native-bundle'):abort(400,'Выберите формат файла')
        try:text=base64.b64encode(raw).decode() if kind=='native-bundle' else raw.decode('utf-8-sig')
        except UnicodeError:abort(400,'Нужен текстовый файл UTF-8')
        identifier='exit-'+uuid.uuid4().hex[:12]
        try:
            with store.edit(request.form.get('revision','')) as policy:
                resolver=request.form.get('resolver','');scope=request.form.get('scope','')
                if resolver not in policy['dns'] or policy['dns'][resolver].get('native',{}).get('type')=='fakeip':raise ValueError('Выберите обычный DNS для адреса VPN')
                if scope not in ('public','work','special'):raise ValueError('Выберите назначение')
                name=request.form.get('name','').strip()
                if not name or len(name)>120:raise ValueError('Укажите название до 120 символов')
                native=import_native(text,kind,resolver);native['tag']=identifier
                policy['exits'][identifier]={'name':name,'scope':scope,'protocol':'openconnect','native':native}
        except ValueError as error:abort(400,str(error))
        flash('OpenConnect импортирован в черновик. Проверьте реквизиты и примените настройки отдельно.','success')
        return redirect(url_for('tunnel_form',identifier=identifier))

    @app.post('/tunnels/<identifier>/export-native')
    def outbound_export_native(identifier):
        policy,revision=store.read()
        if request.form.get('revision')!=revision:abort(409,'Настройки изменились. Обновите страницу.')
        outbound=policy['exits'].get(identifier)
        if not outbound or external_connection(outbound):abort(404)
        native=outbound.get('native',{});kind=request.form.get('format','json')
        if kind=='openconnect' and native.get('type')=='openconnect':
            from openconnect_exchange import export_native
            try:content=export_native(native)
            except ValueError as error:abort(400,str(error))
            return connection_download({'filename':'openconnect.zip','encoding':'base64','content':content,'mimetype':'application/zip'})
        if kind!='json':abort(400,'Неизвестный формат')
        from native_endpoints import ENDPOINT_TYPES
        key='endpoints' if native.get('type') in ENDPOINT_TYPES else 'outbounds'
        return connection_download({'filename':'sing-box-connection.json','encoding':'utf-8','content':json.dumps({key:[native]},ensure_ascii=False,indent=2)+'\n','mimetype':'application/json'})

    @app.post('/tunnels/save')
    def tunnel_save():
        identifier=request.form.get('id') or 'exit-'+uuid.uuid4().hex[:12]
        with store.edit(request.form.get('revision','')) as policy:
            previous=policy['exits'].get(identifier,{})
            if request.form.get('id') and not previous:abort(404)
            if external_connection(previous):
                abort(409,'Настройки этого ранее созданного VPN ещё не перенесены в панель. Подключение не изменено.')
            try:policy['exits'][identifier]=parse_outbound(request.form,previous,identifier,policy)
            except ValueError as error:abort(400,str(error))
        flash('Выход сохранён в черновике. Действующий VPN не менялся.','success')
        return redirect(url_for('page',name='tunnels'))

    @app.get('/devices/trusttunnel')
    def tt_clients_page():
        state=None;error=None
        if candidate is None:error='Нет соединения с сервером управления'
        else:
            try:state=candidate.call('tt-clients-status')
            except RemoteError as exc:error=str(exc)
        return render_template('tt_clients.html',name='lan',title='Устройства TrustTunnel',state=state,error=error)

    @app.post('/devices/trusttunnel/<server_id>/<action>')
    def tt_clients_action(server_id,action):
        if action not in ('save','delete','import','export','settings','recover'):abort(404)
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        fields={'endpoint':server_id,'revision':request.form.get('revision','')}
        if action in ('save','delete','export'):fields['id']=request.form.get('id','')
        if action in ('save','delete','import') and request.form.get('confirm')!='on':abort(400,'Подтвердите краткое переподключение клиентов этого сервера')
        if action=='save':fields['values']={key:request.form.get(key,'') for key in ('username','password','max_http2_conns','max_http3_conns')}
        if action=='settings':fields['values']={'local_address':request.form.get('local_address',''),'external_address':request.form.get('external_address',''),'dns_upstreams':[v.strip() for v in request.form.get('dns_upstreams','').splitlines() if v.strip()]}
        if action=='recover':fields['operation']=request.form.get('operation','')
        if action=='import':
            upload=request.files.get('credentials_file')
            if not upload or not upload.filename:abort(400,'Выберите файл credentials.toml')
            raw=upload.read(128*1024+1)
            if len(raw)>128*1024:abort(400,'Файл превышает 128 КиБ')
            try:fields['text']=raw.decode('utf-8-sig')
            except UnicodeError:abort(400,'Нужен файл UTF-8')
        if action=='export':
            format=request.form.get('format','')
            if format not in ('qr','toml','deeplink','credentials'):abort(400,'Выберите TOML, ссылку или QR')
            fields.update(mode=request.form.get('mode',''),format='deeplink' if format=='qr' else format)
        try:result=candidate.call('tt-clients-'+action,**fields)
        except RemoteError as exc:abort(409,str(exc))
        if action=='export':
            if format=='qr':
                import subprocess
                try:
                    qr=subprocess.run(['/usr/bin/qrencode','-t','SVG','-o','-'],input=result['content'],capture_output=True,text=True,timeout=4)
                    if qr.returncode or not qr.stdout.lstrip().startswith('<?xml'):raise ValueError()
                except (OSError,ValueError,subprocess.SubprocessError):abort(503,'QR-код не создан. Можно скачать ссылку подключения.')
                return app.response_class(qr.stdout,mimetype='image/svg+xml')
            response=app.response_class(result['content'],mimetype='application/toml' if format in ('toml','credentials') else 'text/plain')
            response.headers['Content-Disposition']='attachment; filename="'+result['filename']+'"'
            return response
        flash('Адреса сохранены. Они используются при следующей выдаче конфигурации.' if action=='settings' else 'Прежний список восстановлен.' if action=='recover' else 'Список клиентов сохранён. Входящий сервер переподключил клиентов.' if result.get('endpoint_restarted') else 'Список клиентов сохранён; сервер не перезапускался.','success')
        return redirect(url_for('tt_clients_page')+'#server-'+server_id)

    @app.get('/devices')
    def clients_page():
        state=None;error=None
        if candidate is None:error='Нет соединения с сервером управления'
        else:
            try:state=candidate.call('clients-status')
            except RemoteError as exc:error=str(exc)
        return render_template('wg_clients.html',name='lan',title='Устройства WireGuard',state=state,error=error)

    @app.post('/devices/add')
    def clients_add():
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        values={k:request.form.get(k,'') for k in ('name','dns','routes','mtu','keepalive')}
        values['ipv6']=request.form.get('ipv6')=='on'
        try:result=candidate.call('clients-add',file_revision=request.form.get('file_revision',''),values=values)
        except RemoteError as exc:abort(409,str(exc))
        flash('Клиент создан. Скачайте конфиг или отсканируйте QR-код в его карточке.','success')
        return redirect(url_for('clients_page')+'#client-'+result['id'])

    @app.post('/devices/<client_id>/<action>')
    def clients_toggle(client_id,action):
        if action not in ('disable','enable'):abort(404)
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        if action=='disable' and request.form.get('confirm')!='on':abort(400,'Подтвердите отключение выбранного устройства')
        try:candidate.call('clients-'+action,id=client_id,file_revision=request.form.get('file_revision',''))
        except RemoteError as exc:abort(409,str(exc))
        flash('Доступ устройства отключён; его ключи сохранены для повторного включения.' if action=='disable' else 'Доступ устройства включён. Подойдёт прежний конфиг; если связь не восстановилась, выключите и включите WireGuard на устройстве.','success')
        return redirect(url_for('clients_page'))

    @app.post('/devices/finish')
    def clients_finish():
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        try:result=candidate.call('clients-finish',operation=request.form.get('operation',''))
        except RemoteError as exc:abort(409,str(exc))
        if result.get('operation')!='completed':abort(409,'Операция ещё не завершена; обновите состояние')
        flash('Операция клиента завершена.','success')
        return redirect(url_for('clients_page'))

    @app.post('/devices/settings')
    def clients_settings():
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        fields={k:request.form.get(k,'') for k in ('settings_revision','local_endpoint','external_endpoint')}
        try:candidate.call('clients-settings',**fields)
        except RemoteError as exc:abort(409,str(exc))
        flash('Адреса для выдачи конфигов сохранены. Уже подключённые устройства не изменены.','success')
        return redirect(url_for('clients_page'))

    @app.post('/devices/<client_id>/rename')
    def clients_rename(client_id):
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        try:candidate.call('clients-rename',id=client_id,file_revision=request.form.get('file_revision',''),name=request.form.get('name',''),previous_name=request.form.get('previous_name',''))
        except RemoteError as exc:abort(409,str(exc))
        flash('Название сохранено. Подключение не изменено.','success')
        return redirect(url_for('clients_page')+'#client-'+client_id)

    @app.post('/devices/<client_id>/import')
    def clients_import(client_id):
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        upload=request.files.get('connection_file')
        if not upload or not upload.filename:abort(400,'Выберите клиентский файл .conf')
        raw=upload.read(256*1024+1)
        if len(raw)>256*1024:abort(400,'Файл превышает 256 КиБ')
        try:config=raw.decode('utf-8-sig')
        except UnicodeError:abort(400,'Нужен файл UTF-8')
        try:candidate.call('clients-import',id=client_id,file_revision=request.form.get('file_revision',''),config=config)
        except RemoteError as exc:abort(409,str(exc))
        flash('Клиентский конфиг проверен и сохранён. Доступны скачивание и QR; подключение не изменено.','success')
        return redirect(url_for('clients_page')+'#client-'+client_id)

    @app.post('/devices/<client_id>/export')
    def clients_export(client_id):
        if candidate is None:abort(503,'Нет соединения с сервером управления')
        format=request.form.get('format','config')
        if format not in ('config','qr'):abort(400,'Выберите конфиг или QR-код')
        try:result=candidate.call('clients-export',id=client_id,mode=request.form.get('mode',''),file_revision=request.form.get('file_revision',''))
        except RemoteError as exc:abort(409,str(exc))
        if format=='qr':
            import subprocess
            try:
                qr=subprocess.run(['/usr/bin/qrencode','-t','SVG','-o','-'],input=result['config'],capture_output=True,text=True,timeout=4)
                if qr.returncode or not qr.stdout.lstrip().startswith('<?xml'):raise ValueError()
            except (OSError,ValueError,subprocess.SubprocessError):abort(503,'QR-код не создан. Можно скачать конфиг подключения.')
            response=app.response_class(qr.stdout,mimetype='image/svg+xml')
        else:
            response=app.response_class(result['config'],mimetype='text/plain')
            response.headers['Content-Disposition']='attachment; filename="'+result['filename']+'"'
        return response

    @app.get('/amnezia-new')
    def amnezia_new():
        _,revision=store.read()
        return render_template('amnezia_new.html',name='tunnels',title='Новый AmneziaWG',revision=revision,interface={})

    @app.post('/amnezia/create')
    def amnezia_create():
        if candidate is None:abort(400,'Сетевое ядро не подключено.')
        from amnezia_form import parse_form,register
        from amnezia_profile import MAX_BYTES
        upload=request.files.get('connection_file')
        try:
            if upload and upload.filename:
                raw=upload.read(MAX_BYTES+1)
                if len(raw)>MAX_BYTES:raise ValueError('Файл превышает 256 КиБ')
                values={'text':raw.decode('utf-8-sig')}
            else:values=parse_form(request.form)
            with store.edit(request.form.get('revision','')) as policy:
                title=request.form.get('name','').strip();scope=request.form.get('scope','public')
                if not title or len(title)>120 or scope not in ('public','work','special'):raise ValueError('Проверьте название и назначение подключения')
                result=candidate.call('amnezia-create',profile=None,values=values)
                register(policy,result['name'],title,scope,result.get('dns',[]))
        except UnicodeError:abort(400,'Нужен файл UTF-8')
        except ValueError as error:abort(400,str(error))
        except RemoteError as error:abort(409,str(error))
        flash('AmneziaWG создан выключенным. Выход и DNS из файла добавлены в черновик. Включите и проверьте туннель, затем выберите его в нужном правиле.','success')
        return redirect(url_for('amnezia_page',profile=result['name']))

    @app.post('/amnezia/<profile>/register')
    def amnezia_register(profile):
        if candidate is None:abort(400,'Сетевое ядро не подключено.')
        from amnezia_form import register
        try:
            state=candidate.call('amnezia-status',profile=profile)
            if state.get('error') or not state.get('model'):raise ValueError('Сначала исправьте профиль AWG')
            with store.edit(request.form.get('revision','')) as policy:
                register(policy,profile,request.form.get('name',''),request.form.get('scope','public'),state['model']['interface'].get('DNS',[]))
        except ValueError as error:abort(400,str(error))
        except RemoteError as error:abort(409,str(error))
        flash('Выход и DNS добавлены в черновик. Рабочие правила не менялись.','success')
        return redirect(url_for('amnezia_page',profile=profile))

    def wg_context(amnezia,profile=None):
        values={'is_amnezia':amnezia,'wg_label':'AmneziaWG' if amnezia else 'WireGuard',
                'wg_save_endpoint':'amnezia_save' if amnezia else 'wireguard_save',
                'wg_page_endpoint':'amnezia_page' if amnezia else 'wireguard_page',
                'wg_new_endpoint':'amnezia_new' if amnezia else 'wireguard_new'}
        if amnezia:
            policy,revision=store.read()
            values.update(awg_registered='amnezia-'+str(profile) in policy['exits'],revision=revision)
        return values

    @app.get('/wireguard-new')
    def wireguard_new():
        return render_template('wireguard_new.html',name='tunnels',title='Новый WireGuard')

    @app.post('/wireguard/create')
    def wireguard_create():
        if candidate is None:abort(400,'Сетевое ядро не подключено.')
        from wireguard_form import parse_form
        from wireguard_control import profile_name
        try:
            profile=profile_name(request.form.get('profile','').strip())
            values=parse_form(request.form)
        except ValueError as error:abort(400,str(error))
        try:candidate.call('wireguard-create',profile=profile,values=values)
        except RemoteError as error:abort(409,str(error))
        flash('Профиль WireGuard создан выключенным, без автозапуска. Открытый ключ доступен в карточке профиля.','success')
        return redirect(url_for('wireguard_page',profile=profile))

    @app.get('/amnezia',endpoint='amnezia_page')
    @app.get('/amnezia/<profile>',endpoint='amnezia_page')
    @app.get('/wireguard')
    @app.get('/wireguard/<profile>')
    def wireguard_page(profile=None):
        amnezia=request.endpoint=='amnezia_page';prefix='amnezia' if amnezia else 'wireguard'
        state=None;error=None
        if candidate is None:error='Сетевое ядро не подключено.'
        else:
            try:state=candidate.call(prefix+'-status',profile=profile)
            except RemoteError as failure:error=str(failure)
        return render_template('wireguard.html',name='tunnels',title=('AmneziaWG' if amnezia else 'WireGuard')+(' · '+profile if profile else ''),
                               wg=state,wg_error=error,profile=profile,**wg_context(amnezia,profile))

    @app.post('/amnezia/<profile>/<action>',endpoint='amnezia_save')
    @app.post('/wireguard/<profile>/<action>')
    def wireguard_save(profile,action):
        amnezia=request.endpoint=='amnezia_save';prefix='amnezia' if amnezia else 'wireguard'
        if action not in ('save','import','export','discard','check','apply','confirm','rollback','start','stop','enable','disable','abandon'):abort(404)
        if candidate is None:abort(400,'Сетевое ядро не подключено.')
        fields={'profile':profile,'file_revision':request.form.get('file_revision',''),
                'draft_revision':request.form.get('draft_revision','')}
        if action in ('confirm','rollback','abandon'):
            fields={'profile':profile,'transaction':request.form.get('transaction','')}
        if action in ('start','stop','enable','disable'):
            active=request.form.get('expected_active');enabled=request.form.get('expected_enabled')
            if active not in ('true','false') or enabled not in ('enabled','disabled'):abort(400,'Обновите состояние службы перед переключением.')
            fields['expected_state']={'active':active=='true','enabled':enabled}
        if action=='start':fields['probe']=None
        if action in ('apply','enable'):
            address=request.form.get('probe_address','').strip()
            try:
                fields['probe']=None if not address else {'address':address,'port':int(request.form.get('probe_port','443')),'mark':int(request.form.get('probe_mark','0'))}
            except ValueError:abort(400,'Порт и марка маршрута должны быть целыми числами.')
        if action=='export':fields['source']=request.form.get('source','')
        if action=='import':
            from wireguard_profile import MAX_BYTES
            upload=request.files.get('connection_file')
            if upload is None:abort(400,'Выберите файл .conf')
            raw=upload.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:abort(400,'Файл превышает 256 КиБ')
            try:fields['text']=raw.decode('utf-8-sig')
            except UnicodeError:abort(400,'Нужен текстовый файл UTF-8')
        if action=='save':
            if amnezia:
                from amnezia_form import parse_form
            else:
                from wireguard_form import parse_form
            try:fields['values']=parse_form(request.form)
            except ValueError as error:abort(400,str(error))
        try:result=candidate.call(prefix+'-'+action,**fields)
        except RemoteError as error:abort(409,str(error))
        if action=='export':return connection_download(result)
        if action=='check':
            return render_template('wireguard.html',name='tunnels',title=('AmneziaWG' if amnezia else 'WireGuard')+' · '+profile,
                                   wg=result,wg_error=None,profile=profile,**wg_context(amnezia,profile))
        messages={'import':'Файл WireGuard импортирован в черновик. Рабочее подключение не менялось.',
                  'save':'Черновик WireGuard сохранён на сервере. Рабочий профиль и служба не менялись.',
                  'discard':'Черновик WireGuard удалён. Форма заново читает рабочий файл.',
                  'apply':'Новый файл WireGuard применён временно. Подтвердите результат до указанного срока, иначе сервер вернёт прежний файл и состояние.',
                  'confirm':'Изменение WireGuard подтверждено. Для работающего туннеля TCP-проверка через его интерфейс успешна.',
                  'rollback':'Прежний файл и состояние WireGuard восстановлены.'}
        messages.update(start='Туннель включён временно. Подтвердите доступ до указанного срока; автозапуск не изменён.',
                        stop='Туннель выключен временно. Подтвердите доступ до указанного срока; автозапуск не изменён.',
                        enable='Автозапуск включён и проверен. Текущее соединение не перезапускалось.',
                        disable='Автозапуск выключен и проверен. Текущее соединение не останавливалось.')
        messages['abandon']='Проверка закрыта без восстановления. Файл и соединение не изменялись. Проверьте состояние и при необходимости исправьте профиль перед новым запуском.'
        if action=='confirm' and result.get('transaction',{}).get('kind')=='runtime':
            messages['confirm']='Состояние службы WireGuard подтверждено. Доступность удалённой сети проверяется отдельно в мониторинге.'
        if action=='rollback' and result.get('transaction',{}).get('recovery_reason')=='boot_policy_restored':
            messages[action]='После перезагрузки подтверждено состояние по сохранённому автозапуску; операция закрыта.'
        elif action=='rollback' and result.get('transaction',{}).get('status')=='recovered':
            messages[action]='Прежний файл восстановлен после перезагрузки. Соединение этой операцией не запускалось; проверьте состояние службы.'
        flash(messages[action].replace('WireGuard','AmneziaWG') if amnezia else messages[action],'success')
        return redirect(url_for('amnezia_page' if amnezia else 'wireguard_page',profile=profile))

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(429)
    def error_page(error):
        return render_template('error.html',title='Действие не выполнено',message=error.description),error.code

    return app


if __name__=='__main__':
    from waitress import serve
    directory=Path(os.environ['OKOPY_STATE_DIR'])
    if os.environ.get('OKOPY_HEALTH_SOURCE') in ('ssh','local'):
        from health_pull import start_pull
        start_pull(directory,os.environ['OKOPY_HEALTH_SOURCE'])
    candidate=None
    if os.environ.get('OKOPY_CANDIDATE_CONTROL')=='ssh':
        from candidate_remote import CandidateRemote
        candidate=CandidateRemote()
    elif os.environ.get('OKOPY_CANDIDATE_CONTROL')=='local':
        from candidate_remote import CandidateLocal
        candidate=CandidateLocal()
    secure=os.environ.get('OKOPY_HTTPS')=='1'
    hosts=[x.strip() for x in os.environ.get('OKOPY_TRUSTED_HOSTS','127.0.0.1,localhost').split(',') if x.strip()]
    app=create_app(directory,candidate,trusted_hosts=hosts,secure_cookie=secure)
    socket=os.environ.get('OKOPY_UNIX_SOCKET')
    if socket:
        # This socket is reachable only by the local HTTPS reverse proxy.
        serve(app,unix_socket=socket,unix_socket_perms='660',url_scheme='https' if secure else 'http',
              threads=4,trusted_proxy='localhost',trusted_proxy_count=1,
              trusted_proxy_headers={'x-forwarded-for'},clear_untrusted_proxy_headers=True)
    else:
        serve(app,host='127.0.0.1',port=int(os.environ.get('OKOPY_PORT','18081')),
              threads=4,clear_untrusted_proxy_headers=True)
