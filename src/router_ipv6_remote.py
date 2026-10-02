"""Authenticated settings transactions executed and rolled back on the router."""
import hashlib
import re
import uuid
import paramiko
from candidate_remote import RemoteError
from router_health import LOCK, connect, exchange
from router_ipv6_settings import validate, revision, compile_settings

ROOT='/tmp/okopy-router-ipv6'
CONTROL=f'exec {ROOT}/opt/lib/ld.so.1 --library-path {ROOT}/opt/lib {ROOT}/opt/bin/busybox sh {ROOT}/ipv6-control.sh'
ERRORS={
    'unchanged':'Эти параметры уже действуют. Изменять их не требуется.',
    'busy':'Роутер выполняет другую операцию. Перечитайте состояние.',
    'conflict':'Параметры уже изменились. Перечитайте форму.',
    'pending':'Сначала подтвердите или отмените предыдущее изменение.',
    'payload':'Роутер отклонил пакет настроек.',
    'baseline':'Выбранная политика не содержит штатных резервных IPv6-маршрутов к провайдеру. Сначала настройте их в веб-панели роутера.',
    'stop':'Не подтверждена остановка прежнего контроллера. Новые параметры не применены.',
    'start':'Контроллер не запустился. Проверьте состояние автоматического возврата.',
    'persist':'Запись на USB не подтверждена. Перечитайте состояние; автоматический повтор не выполнялся.',
    'expired':'Время подтверждения истекло. Перечитайте состояние.',
    'transaction':'Эта операция уже завершена или заменена другой.',
}


def checked(packet):
    if not isinstance(packet,dict):raise ValueError('Некорректный ответ роутера')
    if packet.get('error'):raise RemoteError(ERRORS.get(packet['error'],'Роутер отклонил операцию. Перечитайте состояние.'))
    return packet


def status_view(packet):
    packet=checked(packet)
    if set(packet)!={'settings','revision','persistent_matches','controller','path','transaction'}:raise ValueError('Неполное состояние аварийного режима')
    value=validate(packet['settings'])
    if packet['revision']!=revision(value) or type(packet['persistent_matches']) is not bool:raise ValueError('Ревизия аварийного режима не совпала')
    if packet['controller'] not in ('running','stopped','stale') or packet['path'] not in ('home','provider','unknown'):raise ValueError('Неизвестное состояние аварийного режима')
    tx=packet['transaction']
    if tx is not None:
        if not isinstance(tx,dict) or set(tx)!={'id','status','remaining_seconds'} or not re.fullmatch('[0-9a-f]{32}',tx.get('id','')):raise ValueError('Некорректная операция')
        if tx['status'] not in ('pending','confirmed','rolled_back','rollback_failed') or type(tx['remaining_seconds']) is not int or not 0<=tx['remaining_seconds']<=120:raise ValueError('Некорректное состояние операции')
    return packet


class RouterIPv6Remote:
    def __init__(self,credentials):self.credentials=credentials

    def _read(self,client):
        return status_view(exchange(client,'status',control=CONTROL,timeout=15))

    def choices(self):
        try:
            with LOCK,connect(self.credentials) as client:
                packet=checked(exchange(client,'inventory',control=CONTROL,timeout=10,max_bytes=131072))
            result={}
            for key in ('interfaces','policies'):
                rows=packet[key]
                if not isinstance(rows,dict) or len(rows)>256:raise ValueError('Неверный список соединений')
                result[key]=[]
                for identifier,item in rows.items():
                    if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}',identifier) or not isinstance(item,dict):continue
                    if key=='interfaces' and not item.get('address'):continue
                    name=item.get('description') or item.get('interface-name') or identifier
                    if not isinstance(name,str) or len(name)>200:raise ValueError('Неверное имя соединения')
                    result[key].append({'id':identifier,'label':name if name==identifier else name+' ('+identifier+')'})
            return result
        except RemoteError:raise
        except (OSError,ValueError,KeyError,TypeError,paramiko.SSHException):
            raise RemoteError('Не удалось получить список политик и соединений роутера. Перечитайте страницу.') from None

    def status(self):
        try:
            with LOCK,connect(self.credentials) as client:return self._read(client)
        except RemoteError:raise
        except (OSError,ValueError,KeyError,TypeError,paramiko.SSHException):
            raise RemoteError('Не удалось прочитать аварийный режим роутера. Доступ к роутеру по LAN должен работать.') from None

    def apply(self,expected,settings):
        settings=validate(settings)
        if not re.fullmatch('[a-f0-9]{64}',expected or ''):raise ValueError('Обновите форму настроек')
        sent=False
        try:
            with LOCK,connect(self.credentials) as client:
                before=self._read(client)
                if before['revision']!=expected:raise RemoteError(ERRORS['conflict'])
                if before['transaction'] and before['transaction']['status'] in ('pending','rollback_failed'):raise RemoteError(ERRORS['pending'])
                content=compile_settings(settings);tx=uuid.uuid4().hex
                sent=True
                result=checked(exchange(client,'apply '+expected+' '+hashlib.sha256(content).hexdigest()+' '+revision(settings)+' '+tx,content,control=CONTROL,timeout=40))
                after=self._read(client)
                if result.get('applied') is not True or after['revision']!=revision(settings) or not after['transaction'] or after['transaction']['id']!=tx or after['transaction']['status']!='pending':raise ValueError('Применение не подтверждено')
                return after
        except RemoteError:raise
        except (OSError,ValueError,KeyError,TypeError,paramiko.SSHException):
            raise RemoteError('Ответ применения не подтверждён. Перечитайте состояние; без подтверждения роутер вернёт прежние параметры.' if sent else 'Нет связи с роутером; параметры не отправлены.') from None

    def finish(self,action,tx):
        if action not in ('confirm','rollback') or not re.fullmatch('[a-f0-9]{32}',tx or ''):raise ValueError('Некорректная операция')
        try:
            with LOCK,connect(self.credentials) as client:
                checked(exchange(client,action+' '+tx,control=CONTROL,timeout=40))
                after=self._read(client)
                expected='confirmed' if action=='confirm' else 'rolled_back'
                if not after['transaction'] or after['transaction']['id']!=tx or after['transaction']['status']!=expected:raise ValueError('Операция не подтверждена')
                if action=='confirm' and not after['persistent_matches']:raise ValueError('USB не подтверждён')
                return after
        except RemoteError:raise
        except (OSError,ValueError,KeyError,TypeError,paramiko.SSHException):
            raise RemoteError('Результат операции не подтверждён. Перечитайте состояние: повтор автоматически не отправлялся.') from None
