"""Incoming-module draft routes use the application's existing auth, CSRF and store."""
import copy
import json
from flask import abort, flash, redirect, render_template, request, url_for
from incoming_connections import TYPES, validate, compile_entries, client_config, client_link, import_native, MAX_BYTES
from incoming_form import parse
from protocol_modules import MODULES as CATALOG
MODULES={**CATALOG,'openvpn-server':CATALOG['openvpn'],'amneziawg':CATALOG['amnezia'],'openconnect-server':CATALOG['openconnect']}


def register(app, store, download):
    def selected(policy, identifier):
        item=next((e for e in policy.get('incoming_connections',[]) if e['id']==identifier),None)
        if item is None:abort(404)
        return item

    @app.get('/devices/incoming')
    def incoming_page():
        policy,revision=store.read()
        return render_template('incoming.html',name='lan',title='Входящие подключения',entries=policy.get('incoming_connections',[]),revision=revision,modules=MODULES)

    @app.get('/devices/incoming/new')
    @app.get('/devices/incoming/<identifier>/edit')
    def incoming_edit(identifier=None):
        policy,revision=store.read();kind=request.args.get('protocol','socks')
        if identifier:item=selected(policy,identifier);kind=item['native']['type']
        else:item={'name':'','enabled':False,'local_host':'','external_host':'','native':{'type':kind,'listen':'0.0.0.0','users':[]}}
        if kind not in TYPES:abort(400,'Выберите поддерживаемый входящий модуль')
        from tunnel_form import SS_METHODS
        t=item['native'].get('transport',{});host=t.get('host') or t.get('headers',{}).get('Host','')
        if isinstance(host,list):host='\n'.join(host)
        if kind=='openconnect-server':
            return render_template('incoming_ocserv.html',name='lan',title='Сервер OpenConnect / AnyConnect',entry=item,identifier=identifier,revision=revision)
        if kind=='amneziawg':
            from amnezia_profile import FIELDS
            return render_template('incoming_awg.html',name='lan',title='Сервер AmneziaWG',entry=item,identifier=identifier,revision=revision,mask_fields=[v for v in FIELDS if v!='DNS'])
        return render_template('incoming_edit.html',name='lan',title='Настройка входящего подключения',entry=item,identifier=identifier,revision=revision,kind=kind,modules=MODULES,transport_host=host,methods=[m for m in SS_METHODS if m!='none'])

    @app.post('/devices/incoming/save')
    def incoming_save():
        identifier=request.form.get('id','')
        try:
            with store.edit(request.form.get('revision','')) as policy:
                previous=selected(policy,identifier) if identifier else None
                item=parse(request.form,previous)
                entries=policy.setdefault('incoming_connections',[])
                updated=[item if e['id']==identifier else e for e in entries] if identifier else [*entries,item]
                validate(updated)
                enabled_ports=[e['native']['listen_port'] for e in updated if e['enabled']]
                if len(enabled_ports)!=len(set(enabled_ports)):raise ValueError('Порт другого включённого входа уже занят')
                policy['incoming_connections']=updated
        except ValueError as error:abort(400,str(error))
        flash('Черновик сохранён. Примените его на странице «Изменения».','success')
        return redirect(url_for('incoming_edit',identifier=item['id']))

    @app.post('/devices/incoming/<identifier>/delete')
    def incoming_delete(identifier):
        if request.form.get('confirm')!='on':abort(400,'Подтвердите удаление подключения')
        with store.edit(request.form.get('revision','')) as policy:
            selected(policy,identifier)
            policy['incoming_connections']=[e for e in policy['incoming_connections'] if e['id']!=identifier]
        flash('Вход удалён из черновика. Для отключения действующего сервера примените изменения.','success')
        return redirect(url_for('incoming_page'))

    @app.post('/devices/incoming/<identifier>/import')
    def incoming_import(identifier):
        upload=request.files.get('connection_file')
        if upload is None:abort(400,'Выберите JSON входящего сервера sing-box')
        try:
            with store.edit(request.form.get('revision','')) as policy:
                old=selected(policy,identifier)
                raw=upload.read(MAX_BYTES+1)
                if old['native']['type']=='openconnect-server':
                    from ocserv_exchange import import_server
                    new=import_server(raw,old)
                elif old['native']['type']=='amneziawg':
                    from amnezia_incoming import import_server
                    if len(raw)>MAX_BYTES:raise ValueError('Конфиг превышает 256 КиБ')
                    new=copy.deepcopy(old);new['native']=import_server(raw.decode('utf-8-sig'),old['native'])
                    names={u['name'] for u in new['native']['users']}
                    new['disabled_clients']=[v for v in old.get('disabled_clients',[]) if v in names]
                else:new=import_native(raw,old)
                if new['native']['type']!=old['native']['type']:raise ValueError('Импортируйте тот же протокол или создайте другой вход')
                policy['incoming_connections']=[new if e['id']==identifier else e for e in policy['incoming_connections']]
                validate(policy['incoming_connections'])
        except ValueError as error:abort(400,str(error))
        flash('Серверный конфиг импортирован в черновик.','success')
        return redirect(url_for('incoming_edit',identifier=identifier))

    @app.post('/devices/incoming/<identifier>/import-client')
    def incoming_import_client(identifier):
        upload=request.files.get('client_file')
        if upload is None:abort(400,'Выберите клиентский .conf')
        try:
            raw=upload.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:raise ValueError('Конфиг превышает 256 КиБ')
            with store.edit(request.form.get('revision','')) as policy:
                e=selected(policy,identifier)
                if e['native']['type']!='amneziawg':raise ValueError('Импорт .conf доступен для AmneziaWG')
                from amnezia_incoming import import_client
                before={u['public_key']:u['name'] for u in e['native']['users']}
                disabled=set(e.get('disabled_clients',[]))
                e['native']=import_client(raw.decode('utf-8-sig'),e['native'],request.form.get('client_name',''))
                e['disabled_clients']=[u['name'] for u in e['native']['users'] if before.get(u['public_key']) in disabled]
                validate(policy['incoming_connections'])
        except ValueError as error:abort(400,str(error))
        flash('Клиент импортирован в черновик.','success')
        return redirect(url_for('incoming_edit',identifier=identifier))

    @app.post('/devices/incoming/<identifier>/export')
    def incoming_export(identifier):
        policy,revision=store.read()
        if revision!=request.form.get('revision'):abort(409,'Черновик изменился; обновите страницу')
        e=selected(policy,identifier);format=request.form.get('format','json')
        try:
            if e['native']['type']=='openconnect-server':
                import base64
                if format=='server':
                    from ocserv_exchange import export_server
                    content=base64.b64encode(export_server(e)).decode();suffix='server.zip'
                elif format=='zip':
                    from ocserv_incoming import client_model
                    from openconnect_export import export_bundle
                    content=export_bundle(client_model(e,request.form.get('client',''),request.form.get('mode','')));suffix='client.zip'
                else:raise ValueError('OpenConnect использует стандартный архив конфигурации')
                return download({'filename':'incoming-'+identifier+'-'+suffix,'encoding':'base64','content':content,'mimetype':'application/zip'})
            elif e['native']['type']=='amneziawg':
                from amnezia_profile import render
                from amnezia_incoming import client_config as awg_client,server_model
                if format=='server':content=render(server_model(e['native'],e.get('disabled_clients',[])));suffix='server.conf'
                elif format in ('conf','qr'):
                    content=render(awg_client(e,request.form.get('client',''),request.form.get('mode','')));suffix='client.conf'
                    if format=='qr':
                        import subprocess
                        r=subprocess.run(['/usr/bin/qrencode','-t','SVG','-o','-'],input=content,capture_output=True,text=True,timeout=4)
                        if r.returncode:raise ValueError('QR не сформирован; скачайте конфиг')
                        return app.response_class(r.stdout,mimetype='image/svg+xml')
                else:raise ValueError('AmneziaWG использует стандартный .conf')
            elif format=='server':
                compiled=compile_entries([{**e,'enabled':True}])
                if not compiled:raise ValueError('Все клиенты отключены; для переноса с состоянием клиентов используйте резервную копию системы')
                content=json.dumps({'endpoints' if e['native']['type']=='openvpn-server' else 'inbounds':compiled},ensure_ascii=False,indent=2);suffix='server.json'
            elif format=='json':
                content=json.dumps({'endpoints' if e['native']['type']=='openvpn-server' else 'outbounds':[client_config(e,request.form.get('client',''),request.form.get('mode',''))]},ensure_ascii=False,indent=2);suffix='client.json'
            elif format=='ovpn':
                from openvpn_format import render
                native=client_config(e,request.form.get('client',''),request.form.get('mode',''))
                content=render({'native':native});suffix='client.ovpn'
            elif format in ('link','qr'):
                content=client_link(e,request.form.get('client',''),request.form.get('mode',''));suffix='client.txt'
                if format=='qr':
                    import subprocess
                    result=subprocess.run(['/usr/bin/qrencode','-t','SVG','-o','-'],input=content,capture_output=True,text=True,timeout=4)
                    if result.returncode:raise ValueError('QR не сформирован; скачайте конфиг')
                    return app.response_class(result.stdout,mimetype='image/svg+xml')
            else:abort(400,'Неизвестный формат экспорта')
        except (ValueError,OSError) as error:abort(400,str(error))
        return download({'filename':'incoming-'+identifier+'-'+suffix,'encoding':'utf-8','content':content,'mimetype':'application/json' if suffix.endswith('json') else 'text/plain'})
