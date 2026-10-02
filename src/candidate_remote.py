"""Existing SSH/sudo access; mutation requests are never automatically retried."""
import json
import os
from pathlib import Path
import subprocess
import re

from candidate_control import MAX_REQUEST, MAX_CREDENTIAL_BYTES, FRAME

COMMAND='LC_ALL=C sudo -k -S -p "" /usr/bin/python3 -E -s -B /var/lib/okopy-candidate/candidate_control.py'
MAX_RESPONSE=512*1024
READ_ACTIONS=('dns-interfaces','status','routing-status','monitor-status','amnezia-status','wireguard-status','clients-status','tt-clients-status','openconnect-status','trusttunnel-status','trusttunnel-catalog','backup-status','backup-trust-export','restore-status')


def request_timeout(action):
    if action in ('restore-prepare','restore-confirm','restore-rollback'):
        return 180
    if action=='restore-start':
        return 30
    return (100 if action.startswith('tt-clients-') else 90 if action.startswith('amnezia-') and action not in ('amnezia-status','amnezia-export','amnezia-save','amnezia-import','amnezia-create') else 150 if action in ('backup-create','backup-inspect') else 40 if action in ('trusttunnel-create','trusttunnel-complete') else 170 if action in ('trusttunnel-apply','trusttunnel-confirm','trusttunnel-rollback','trusttunnel-start','trusttunnel-stop') else 120 if action in ('openconnect-apply','openconnect-confirm','openconnect-rollback','openconnect-start','openconnect-stop','openconnect-enable','openconnect-disable') else 90 if action in ('wireguard-apply','wireguard-confirm','wireguard-rollback','wireguard-start','wireguard-stop','wireguard-enable','wireguard-disable') else 50 if action in ('apply','confirm','rollback','routing-set','wireguard-check') else 12)


class RemoteError(Exception):
    pass


class CandidateLocal:
    """One fixed sudo command on the server; no root password or SSH in the UI."""
    COMMAND=['/usr/bin/sudo','-n','/usr/bin/python3','-E','-s','-B',
             '/var/lib/okopy-candidate/candidate_control.py']

    def call(self,action,**fields):
        payload=json.dumps({'version':1,'action':action,**fields},ensure_ascii=False).encode()
        if len(payload)>MAX_REQUEST:raise RemoteError('Политика превышает допустимый размер запроса.')
        timeout=request_timeout(action)
        try:
            result=subprocess.run(self.COMMAND,input=FRAME+b'\n'+payload+b'\n',capture_output=True,timeout=timeout,cwd='/')
            if result.returncode or len(result.stdout)>MAX_RESPONSE:raise ValueError('Invalid command response')
            response=json.loads(result.stdout)
            if not isinstance(response,dict) or type(response.get('ok')) is not bool:raise ValueError('Invalid packet')
            if not response['ok']:
                message=response.get('message')
                raise RemoteError(message if isinstance(message,str) else 'Сервер отклонил действие.')
            if not isinstance(response.get('result'),dict):raise ValueError('Invalid result')
            return response['result']
        except (subprocess.SubprocessError,OSError,ValueError):
            if action.startswith('restore-'):
                raise RemoteError('Ответ восстановления не получен. Перечитайте независимый статус восстановления; действие могло выполниться. Повтор автоматически не отправлялся.') from None
            if action.startswith('tt-clients-'):
                raise RemoteError('Ответ управления клиентами TrustTunnel не получен. Обновите список перед повтором; незавершённое изменение возвращает серверный таймер.') from None
            if action in ('backup-create','backup-inspect','backup-delete'):
                raise RemoteError('Ответ операции с копией не получен. Обновите список: операция могла завершиться или ещё выполняется. Повтор автоматически не отправлялся; сеть не переключалась.') from None
            if action in ('trusttunnel-create','trusttunnel-complete'):
                raise RemoteError('Ответ создания TrustTunnel не получен. Откройте список новых подключений: выключенная служба могла сохраниться. Повтор не отправлялся.') from None
            if action in ('clients-rename','clients-import'):
                raise RemoteError('Ответ сохранения не получен. Обновите карточку перед повтором; подключение не изменялось.') from None
            if action in ('clients-add','clients-disable','clients-enable','clients-finish'):
                raise RemoteError('Ответ изменения клиента не получен. Обновите список устройств: операция могла уже выполниться или завершится на сервере. Повтор автоматически не отправлялся.') from None
            if action in ('trusttunnel-enable','trusttunnel-disable'):
                raise RemoteError('Ответ автозапуска TrustTunnel не получен. Перечитайте флаги клиента и входящих служб: команда могла изменить часть настроек. Повтор не отправлялся; автоматического возврата нет.') from None
            if action in ('openconnect-enable','openconnect-disable'):
                raise RemoteError('Ответ настройки автозапуска не получен. Перечитайте состояние; повтор не отправлялся. У автозапуска нет таймера возврата.') from None
            if action in ('openconnect-apply','openconnect-confirm','openconnect-rollback','openconnect-start','openconnect-stop','openconnect-enable','openconnect-disable'):
                raise RemoteError('Ответ применения OpenConnect не получен. Перечитайте состояние; независимый возврат работает на сервере. Повтор не отправлялся.') from None
            if action in ('trusttunnel-apply','trusttunnel-confirm','trusttunnel-rollback','trusttunnel-start','trusttunnel-stop'):
                raise RemoteError('Ответ применения TrustTunnel не получен. Перечитайте состояние; независимый возврат работает на сервере. Повтор не отправлялся.') from None
            if action in ('trusttunnel-save','trusttunnel-discard','trusttunnel-import','trusttunnel-check'):
                raise RemoteError('Ответ редактора TrustTunnel не получен. Перечитайте черновик; рабочее подключение не менялось. Повтор не отправлялся.') from None
            if action in ('openconnect-save','openconnect-discard','openconnect-import','openconnect-check'):
                raise RemoteError('Ответ редактора OpenConnect не получен. Перечитайте настройки: черновик мог сохраниться. Действующая служба этими действиями не меняется; повтор не отправлялся.') from None
            if action=='clients-export':
                raise RemoteError('Конфиг не получен. Сеть не менялась; обновите список устройств перед повтором.') from None
            if action=='clients-settings':
                raise RemoteError('Ответ сохранения адресов не получен. Обновите страницу перед повтором; существующие подключения не менялись.') from None
            if action=='wireguard-abandon':
                raise RemoteError('Ответ закрытия проверки не получен. Обновите профиль: проверка и её таймер могли уже завершиться. Повтор не отправлялся.') from None
            if action in ('wireguard-enable','wireguard-disable'):
                raise RemoteError('Ответ настройки автозапуска не получен. Обновите профиль: настройка могла сохраниться. Повтор не отправлялся; таймера отката у автозапуска нет.') from None
            if action=='amnezia-create':
                raise RemoteError('Ответ создания AWG не получен. Обновите список профилей: выключенное подключение могло сохраниться. Повтор не отправлялся.') from None
            if action=='wireguard-create':
                raise RemoteError('Ответ создания не получен. Обновите список WireGuard: выключенный профиль мог сохраниться. Повтор не отправлялся; создание файла не имеет таймера отката.') from None
            raise RemoteError('Достоверный ответ команды управления не получен. Обновите состояние перед повторным действием; изменение могло выполниться. Серверный откат сетевой конфигурации работает независимо от панели.') from None


class CandidateRemote:
    def __init__(self, connection=None):
        from server_connection import connection_path
        self.connection=Path(connection) if connection else connection_path()

    def call(self, action, **fields):
        payload=json.dumps({'version':1,'action':action,**fields},ensure_ascii=False).encode()
        if len(payload)>MAX_REQUEST:raise RemoteError('Политика превышает допустимый размер запроса.')
        try:
            from server_connection import read,ssh
            settings=read(self.connection);password=settings['sudo_password']
            if len(password.encode())>MAX_CREDENTIAL_BYTES:raise ValueError('Invalid credential')
        except (OSError,KeyError,ValueError):raise RemoteError('Не удалось прочитать настройки SSH-доступа к серверу. Проверьте закрытый файл server.json.') from None
        # Read-only fallback is safe. A timed-out write may already be running.
        hosts=settings['targets']
        if action not in READ_ACTIONS:
            selected=None
            # Probe connectivity only. Once selected, issue exactly one write.
            for host in hosts:
                try:
                    if subprocess.run(ssh(host)+['true'],capture_output=True,timeout=6).returncode==0:
                        selected=host;break
                except (subprocess.TimeoutExpired,OSError):pass
            if selected is None:raise RemoteError('Нет SSH-соединения с сервером. Изменение не отправлено.')
            hosts=(selected,)
        for host in hosts:
            try:
                command=COMMAND if password else COMMAND.replace('sudo -k -S -p ""','sudo -n')
                credential=password.encode()+b'\n' if password else b''
                result=subprocess.run(ssh(host)+[command],input=credential+FRAME+b'\n'+payload+b'\n',
                    capture_output=True,timeout=request_timeout(action))
                if result.returncode and re.search(rb'^sudo: (?:\d+ incorrect password attempts?|no password was provided|a password is required)\s*$',result.stderr,re.M):
                    raise RemoteError('sudo не принял пароль. Команда управления не запущена; проверьте пароль sudo в закрытых настройках подключения.')
                if result.returncode or len(result.stdout)>MAX_RESPONSE:continue
                response=json.loads(result.stdout)
                if not isinstance(response,dict) or type(response.get('ok')) is not bool:continue
                if not response['ok']:
                    # Server messages are fixed and never embed request/config data.
                    message=response.get('message')
                    raise RemoteError(message if isinstance(message,str) else 'Сервер отклонил действие.')
                if not isinstance(response.get('result'),dict):continue
                return response['result']
            except (subprocess.TimeoutExpired,OSError,ValueError):continue
        if action in READ_ACTIONS:raise RemoteError('Нет достоверного ответа от сервера. Старые данные не считаются текущим состоянием.')
        if action.startswith('restore-'):raise RemoteError('Ответ восстановления не получен. Перечитайте независимый статус восстановления; действие могло выполниться. Повтор автоматически не отправлялся.')
        if action.startswith('tt-clients-'):raise RemoteError('Ответ управления клиентами TrustTunnel не получен. Обновите список перед повтором; незавершённое изменение возвращает серверный таймер.')
        if action in ('backup-create','backup-inspect','backup-delete'):raise RemoteError('Ответ операции с копией не получен. Обновите список перед повтором; сеть не переключалась.')
        if action in ('trusttunnel-create','trusttunnel-complete'):raise RemoteError('Ответ создания TrustTunnel не получен. Откройте список новых подключений: выключенная служба могла сохраниться. Повтор не отправлялся.')
        if action in ('clients-add','clients-disable','clients-enable','clients-finish'):raise RemoteError('Ответ изменения клиента не получен. Обновите список устройств: операция могла уже выполниться или завершится на сервере. Повтор автоматически не отправлялся.')
        if action in ('trusttunnel-enable','trusttunnel-disable'):raise RemoteError('Ответ автозапуска TrustTunnel не получен. Перечитайте флаги клиента и входящих служб: команда могла изменить часть настроек. Повтор не отправлялся; автоматического возврата нет.')
        if action in ('openconnect-enable','openconnect-disable'):raise RemoteError('Ответ настройки автозапуска не получен. Перечитайте состояние; повтор не отправлялся. У автозапуска нет таймера возврата.')
        if action in ('openconnect-apply','openconnect-confirm','openconnect-rollback','openconnect-start','openconnect-stop','openconnect-enable','openconnect-disable'):raise RemoteError('Ответ применения OpenConnect не получен. Перечитайте состояние; независимый возврат работает на сервере. Повтор не отправлялся.')
        if action in ('trusttunnel-apply','trusttunnel-confirm','trusttunnel-rollback','trusttunnel-start','trusttunnel-stop'):raise RemoteError('Ответ применения TrustTunnel не получен. Перечитайте состояние; независимый возврат работает на сервере. Повтор не отправлялся.')
        if action in ('trusttunnel-save','trusttunnel-discard','trusttunnel-import','trusttunnel-check'):raise RemoteError('Ответ редактора TrustTunnel не получен. Перечитайте черновик; рабочее подключение не менялось. Повтор не отправлялся.')
        if action in ('openconnect-save','openconnect-discard','openconnect-import','openconnect-check'):raise RemoteError('Ответ редактора OpenConnect не получен. Перечитайте настройки: черновик мог сохраниться. Действующая служба этими действиями не меняется; повтор не отправлялся.')
        if action=='clients-export':raise RemoteError('Конфиг не получен. Сеть не менялась; обновите список устройств перед повтором.')
        if action=='clients-settings':raise RemoteError('Ответ сохранения адресов не получен. Обновите страницу перед повтором; существующие подключения не менялись.')
        if action=='wireguard-abandon':raise RemoteError('Ответ закрытия проверки не получен. Обновите профиль: проверка и её таймер могли уже завершиться. Повтор не отправлялся.')
        if action in ('wireguard-enable','wireguard-disable'):raise RemoteError('Ответ настройки автозапуска не получен. Обновите профиль: настройка могла сохраниться. Повтор не отправлялся; таймера отката у автозапуска нет.')
        if action=='amnezia-create':raise RemoteError('Ответ создания AWG не получен. Обновите список профилей: выключенное подключение могло сохраниться. Повтор не отправлялся.')
        if action=='wireguard-create':raise RemoteError('Ответ создания не получен. Обновите список WireGuard: выключенный профиль мог сохраниться. Повтор не отправлялся; создание файла не имеет таймера отката.')
        if action=='wireguard-check':raise RemoteError('Результат проверки WireGuard не получен. Рабочие файлы, маршруты и службы не менялись; повторите проверку.')
        if action in ('wireguard-save','wireguard-discard'):raise RemoteError('Ответ изменения черновика не получен. Перечитайте профиль: черновик мог сохраниться или удалиться. Рабочий файл и служба этой операцией не меняются; повтор не отправлялся.')
        if action in ('monitor-set','monitor-add','monitor-remove'):raise RemoteError('Ответ сохранения не получен. Перечитайте настройки: изменение могло сохраниться. Повтор автоматически не отправлялся; таймер отката сетевой политики к датчикам не относится.')
        if action=='routing-set':raise RemoteError('Ответ управления не получен. Обновите состояние: режим автоматики или ручное закрепление могли уже сохраниться. Эта операция не имеет таймера отката.')
        raise RemoteError('Ответ операции не получен. Не повторяйте применение: обновите состояние; серверный таймер отката работает независимо.')
