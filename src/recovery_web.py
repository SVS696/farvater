"""Small authenticated Flask routes for the fixed recovery control actions.

create_app registers these routes inside its existing auth, Origin and CSRF
checks. The independent rescue control remains outside the restored snapshot.
"""

import json
from flask import abort, flash, jsonify, redirect, render_template, request, url_for

from candidate_remote import RemoteError


def register(app, candidate, download):
    def backend():
        if candidate is None:abort(404)
        return candidate

    @app.post('/backups/trust/export')
    def backup_trust_export():
        result=backend().call('backup-trust-export')
        return download({'filename':'farvater-recovery-identity.json','encoding':'utf-8',
                         'content':json.dumps(result,ensure_ascii=False,indent=2)+'\n',
                         'mimetype':'application/json'})

    @app.get('/backups/<value>/restore/status')
    def backup_restore_status(value):
        from system_backup import identifier
        try:result=backend().call('restore-status',job_id=identifier(value))
        except (ValueError,RemoteError) as error:abort(409,str(error))
        return jsonify(result)

    @app.get('/backups/restore/<job_id>')
    def backup_restore_page(job_id):
        from system_backup import identifier
        try:value=identifier(job_id)
        except ValueError:abort(404)
        try:
            catalogue=backend().call('backup-status')
            item=next((row for row in catalogue['jobs'] if row['id']==value and row.get('kind')=='import'),None)
            if item is None:abort(404)
            state=backend().call('restore-status',job_id=value)
            error=None
        except RemoteError as failure:
            catalogue=None;item=None;state=None;error=str(failure)
        return render_template('recovery.html',name='backups',title='Восстановление установки',
                               backup=item,recovery=state,recovery_error=error,backup_view=catalogue)

    @app.get('/backups/recovery/help')
    def recovery_runbook():
        return render_template('recovery_runbook.html',name='backups',title='Как восстановить Фарватер')

    @app.post('/backups/<value>/restore/<action>')
    def backup_restore_action(value,action):
        from system_backup import identifier
        if action not in ('prepare','start','confirm','rollback'):abort(404)
        if request.form.get('confirm')!='on':abort(400,'Подтвердите это действие восстановления')
        try:value=identifier(value)
        except ValueError:abort(404)
        if action=='start':
            return redirect('/recovery/'+value,code=303)
        try:
            fields={'job_id':identifier(value)}
            if action=='prepare':fields['expected_manifest_sha256']=request.form.get('manifest_sha256','')
            else:fields['transaction']=request.form.get('transaction','')
            result=backend().call('restore-'+action,**fields)
            flash({'prepare':'Восстановление подготовлено; рабочие файлы ещё не менялись.',
                   'start':'Защищённое восстановление запущено. Читайте статус перед повторным действием.',
                   'confirm':'Восстановление подтверждено.',
                   'rollback':'Возврат прежней установки запрошен.'}[action],'success')
        except (ValueError,RemoteError) as error:flash(str(error),'error')
        return redirect(url_for('backup_restore_page',job_id=value))
