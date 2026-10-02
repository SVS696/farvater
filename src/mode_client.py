"""One serialized writer for precompiled native DNS/route mode changes."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.request


class ModeClient:
    def __init__(self, modes, *, api_secret, lock_path, api_port=9092, require_bundle=True, bound_config_sha256=None,
                 bound_transaction=None, require_settled=False):
        if type(api_port) is not int or not 1024 <= api_port <= 65535:
            raise ValueError('Некорректный порт API')
        if type(require_bundle) is not bool:raise ValueError('Некорректный режим привязки к политике')
        if require_bundle and (not isinstance(bound_config_sha256,str) or len(bound_config_sha256)!=64
                or any(c not in '0123456789abcdef' for c in bound_config_sha256)):
            raise ValueError('Нужен SHA-256 конфигурации, для которой выбраны эти режимы')
        if not require_bundle and bound_config_sha256 is not None:raise ValueError('Противоречивая привязка к конфигурации')
        self.require_bundle=require_bundle
        self.bound_config_sha256=bound_config_sha256
        self.bound_transaction=bound_transaction
        self.require_settled=require_settled
        self.modes = copy.deepcopy(modes)
        if not self.modes or len({m['name'] for m in self.modes}) != len(self.modes):
            raise ValueError('Список режимов пуст или содержит повторения')
        self.api_secret, self.lock_path = api_secret, Path(lock_path)
        self.base = 'http://127.0.0.1:'+str(api_port)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(self, method, data=None):
        request = urllib.request.Request(self.base+'/configs', method=method,
            data=None if data is None else json.dumps(data).encode(),
            headers={'Authorization':'Bearer '+self.api_secret,'Content-Type':'application/json'})
        with self.opener.open(request, timeout=4) as response:
            body=response.read()
            return json.loads(body) if body else None

    def _known(self, actual):
        mode = next((m for m in self.modes if m['name']==actual.get('mode')), None)
        if mode is None:
            raise ValueError('Текущий режим не соответствует загруженной политике; перечитайте конфигурацию')
        return mode

    def choose(self, updates, *, expected_mode=None):
        """Update queue indices, preserving other queues under a shared lock.

        All automatic and UI writers must use this same lock. An API success
        alone is never reported as a successful transition: read-back is final.
        """
        # Configuration writers take this same lock exclusively. A mode change
        # must not race the replacement/restart of a complete policy package.
        fd=os.open(self.lock_path.with_name('apply.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'r+') as deployment_lock:
            fcntl.flock(deployment_lock,fcntl.LOCK_SH)
            self._check_applied_bundle()
            return self._choose_locked(updates,expected_mode=expected_mode)

    def _check_applied_bundle(self):
        root=self.lock_path.parent
        state=json.loads((root/'transaction.json').read_text()) if (root/'transaction.json').exists() else {}
        if self.bound_transaction is not None and state.get('id')!=self.bound_transaction:
            raise ValueError('Операция применения изменилась; перечитайте состояние')
        if self.require_settled and state.get('status') not in ('confirmed','rolled_back'):
            raise ValueError('Автоматическое управление запрещено до завершения применения')
        if state.get('status') in ('prepared','rollback_failed') or (
                state.get('status')=='pending' and state.get('runtime_ready') is not True):
            raise ValueError('Применение не завершено или откат требует восстановления')
        manifest_path=root/'policy-manifest.json'
        if not manifest_path.exists():
            if self.require_bundle:raise ValueError('Манифест применённой политики отсутствует')
            return  # Explicit opt-out for isolated mode fixtures only.
        manifest=json.loads(manifest_path.read_text())
        if manifest.get('bundle_version')!=1:
            if self.require_bundle:raise ValueError('Требуется применённый пакет политики')
            return
        files={name:(root/name).read_bytes() for name in ('config.json','policy-manifest.json','applied-policy.json')}
        reference='next_files' if state.get('status') in ('confirmed','pending') else 'previous_files'
        expected=state.get(reference,{})
        if set(expected)!=set(files) or any(hashlib.sha256(data).hexdigest()!=expected[name] for name,data in files.items()):
            raise ValueError('Файлы политики не совпадают с принятой ревизией')
        actual=hashlib.sha256(files['config.json']).hexdigest()
        if (manifest.get('config_sha256')!=actual or manifest.get('modes')!=self.modes
                or (self.require_bundle and self.bound_config_sha256!=actual)):
            raise ValueError('Применённая политика изменилась; перечитайте режимы')

    def _choose_locked(self, updates, *, expected_mode=None):
        fd=os.open(self.lock_path, os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            actual=self._request('GET');before=self._known(actual)
            if expected_mode is not None and expected_mode!=before['name']:
                raise ValueError('Режим уже изменился; обновите страницу перед переключением')
            selection=dict(before['selection'])
            if any(key not in selection or type(value) is not int or value<0 for key,value in updates.items()):
                raise ValueError('Неизвестная очередь или номер пары')
            selection.update(updates)
            target=next((m for m in self.modes if m['selection']==selection),None)
            if target is None or target['name'] not in actual.get('mode-list',[]):
                raise ValueError('Выбранное сочетание отсутствует в действующей конфигурации')
            if target['name']==before['name']:
                return {'changed':False, **copy.deepcopy(target)}
            try:
                self._request('PATCH', {'mode':target['name']})
            except (urllib.error.URLError, TimeoutError, ValueError):
                # A lost acknowledgement is inconclusive. Do not reapply it;
                # read the actual mode while retaining the writer lock.
                pass
            confirmed=self._request('GET')
            if confirmed.get('mode')!=target['name']:
                raise RuntimeError('Переключение не подтверждено: API сохранил другой режим')
            return {'changed':True, **copy.deepcopy(target)}
