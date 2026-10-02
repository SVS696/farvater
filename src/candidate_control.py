"""Fixed command boundary for the local authenticated panel.

JSON request on stdin, sanitized JSON response on stdout. No shell command,
arbitrary service name, path, API secret or build options can be supplied by a caller.
WireGuard profile identifiers are validated by its separate validated adapter.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from candidate_bundle import build_bundle, read_bundle, validate_bundle
from safe_apply import ROOT, Backend, Coordinator, atomic_write, digest

MAX_REQUEST = 256 * 1024
MAX_CREDENTIAL_BYTES = 4096
FRAME = b'OKOPY-CONTROL-V1'


class ControlError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def inspect(root, coordinator):
    try:state=coordinator.state();journal_ok=isinstance(state,dict) and bool(state)
    except Exception:state={};journal_ok=False
    if not isinstance(state,dict):state={}
    current=digest((root/'config.json').read_bytes()) if (root/'config.json').exists() else None
    manifest={};integrity=False;sections=None
    try:
        files=read_bundle(root);manifest=validate_bundle(files)
        reference='next_files' if state.get('status') in ('confirmed','pending') else 'previous_files'
        expected=state.get(reference,{})
        integrity=set(files)==set(expected) and all(digest(data)==expected[name] for name,data in files.items())
        if integrity:
            from policy_sections import section_hashes
            sections=section_hashes(json.loads(files['applied-policy.json']))
    except Exception:
        # A malformed policy may fail anywhere in the compiler. Status must
        # still expose the transaction and current hash so recovery is usable.
        manifest={}
    return {'config_sha256':current,'integrity':integrity,'journal_ok':journal_ok,
            'policy_sha256':manifest.get('policy_canonical_sha256'),
            'policy_section_sha256':sections,
            'transaction':{key:state[key] for key in ('id','status','deadline','created_at','finished_at','runtime_ready') if key in state},
            'observed_at':time.time(), 'mode_count':len(manifest.get('modes',[])),
            'lan_ingress':json.loads(files['applied-policy.json']).get('lan_ingress',{'enabled':False}) if manifest else {'enabled':False},
            'adguard_adapter':manifest.get('build_options',{}).get('adguard_adapter',False),
            'vpn_adapter':manifest.get('build_options',{}).get('vpn_adapter',False),
            'vpn_ingress':json.loads(files['applied-policy.json']).get('vpn_ingress',{'enabled':False}) if manifest else {'enabled':False},
            'default_filtering':(json.loads(files['applied-policy.json']).get('filtering',{}).get('default_enabled',False)
                if manifest.get('build_options',{}).get('adguard_adapter') else manifest.get('build_options',{}).get('default_filtering'))}


def smoke_check():
    """Basic candidate path check; never a claim about all policy rules."""
    results=[]
    for tcp in (False,True):
        args=['dig','@127.0.0.1','-p','5301','api.ipify.org','A','+time=2','+tries=1','+noall','+comments','+answer']
        if tcp:args+=['+tcp']
        response=subprocess.run(args,capture_output=True,text=True,timeout=4)
        import ipaddress
        valid=False
        for line in response.stdout.splitlines():
            fields=line.split()
            if len(fields)>=5 and fields[-2]=='A':
                try:valid=valid or ipaddress.IPv4Address(fields[-1]).is_global
                except ValueError:pass
        results.append(response.returncode==0 and 'status: NOERROR' in response.stdout and valid)
    response=subprocess.run(['curl','--noproxy','','--socks5-hostname','127.0.0.1:2081',
        '--silent','--connect-timeout','2','--max-time','6','--output','/dev/null',
        '--write-out','%{http_code}','https://example.com/'],capture_output=True,text=True,timeout=8)
    results.append(response.returncode==0 and response.stdout.strip()=='200')
    if not all(results):raise ControlError('probe_failed','Базовая проверка DNS/HTTPS не прошла. Подтверждение не выполнено; действует срок отката.')
    return {'dns_udp':True,'dns_tcp':True,'https':True,'checked_at':time.time()}


def handle(request, *, root=ROOT, backend=None, verify=smoke_check):
    if not isinstance(request,dict) or request.get('version')!=1:
        raise ControlError('request','Некорректный запрос управления кандидатом.')
    action=request.get('action')
    if action in ('backup-status','backup-create','backup-inspect','backup-delete','backup-trust-export'):
        from system_backup import control
        try:return control(request)
        except ValueError as error:raise ControlError('backup',str(error)) from None
    if action in ('restore-status','restore-prepare','restore-start','restore-confirm','restore-rollback'):
        from recovery_control import control
        try:return control(request)
        except (ValueError,OSError,BlockingIOError) as error:
            raise ControlError('restore','Операция восстановления не подтверждена: '+str(error)) from None
    if isinstance(action,str) and action.startswith('tt-clients-'):
        from trusttunnel_clients import control
        try:return control(request)
        except ValueError as error:raise ControlError('trusttunnel-clients',str(error)) from None
    if action in ('trusttunnel-create','trusttunnel-complete','trusttunnel-catalog'):
        from trusttunnel_create import control
        try:return control(request)
        except ValueError as error:raise ControlError('trusttunnel',str(error)) from None
    if action in ('trusttunnel-status','trusttunnel-export','trusttunnel-save','trusttunnel-import','trusttunnel-discard','trusttunnel-check','trusttunnel-apply','trusttunnel-confirm','trusttunnel-rollback','trusttunnel-start','trusttunnel-stop','trusttunnel-enable','trusttunnel-disable'):
        from trusttunnel_control import control
        try:return control(request)
        except ValueError as error:raise ControlError('trusttunnel',str(error)) from None
    if action in ('openconnect-status','openconnect-export','openconnect-save','openconnect-discard','openconnect-import','openconnect-check','openconnect-apply','openconnect-confirm','openconnect-rollback','openconnect-start','openconnect-stop','openconnect-enable','openconnect-disable'):
        from openconnect_control import control
        try:return control(request)
        except ValueError as error:raise ControlError('openconnect',str(error)) from None
    if action=='dns-interfaces':
        if set(request)!={'version','action'} or request.get('version')!=1:raise ControlError('dns','Некорректный запрос интерфейсов')
        from dns_interfaces import status
        try:return status()
        except (ValueError,OSError,subprocess.SubprocessError):raise ControlError('dns','Не удалось прочитать сетевые интерфейсы сервера') from None
    if isinstance(action,str) and action.startswith('amnezia-'):
        from amnezia_control import control
        try:return control(request)
        except ValueError as error:raise ControlError('amnezia',str(error)) from None
    if action in ('wireguard-status','wireguard-export','wireguard-import','wireguard-create','wireguard-save','wireguard-discard','wireguard-check','wireguard-apply','wireguard-confirm','wireguard-rollback','wireguard-start','wireguard-stop','wireguard-enable','wireguard-disable','wireguard-abandon'):
        from wireguard_control import control
        try:return control(request)
        except ValueError as error:raise ControlError('wireguard',str(error)) from None
    if action in ('clients-status','clients-export','clients-settings','clients-rename','clients-import','clients-add','clients-disable','clients-enable','clients-finish'):
        from wg_clients import control
        try:return control(request)
        except ValueError as error:raise ControlError('clients',str(error)) from None
    if action in ('monitor-status','monitor-set','monitor-add','monitor-remove'):
        from monitor_control import control
        try:return control(request)
        except ValueError as error:raise ControlError('monitor',str(error)) from None
    if action in ('routing-status','routing-set'):
        from routing_control import control
        try:return control(request,root)
        except ValueError as error:raise ControlError('routing',str(error)) from None
    if action not in ('status','apply','confirm','rollback'):
        raise ControlError('request','Неизвестное действие.')
    allowed={'version','action'} | ({'policy','expected_config_sha256'} if action=='apply' else
        {'transaction','expected_config_sha256'} if action in ('confirm','rollback') else set())
    if set(request)!=allowed:raise ControlError('request','Неполный запрос или неподдерживаемые поля.')
    backend=backend or Backend(root);coordinator=Coordinator(root,backend)
    with (root/'apply.lock').open('a') as lock:
        # Nonblocking makes concurrent operations explicit and avoids piling up
        # remote workers after the browser has already timed out.
        try:fcntl.flock(lock,(fcntl.LOCK_SH if action=='status' else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        except BlockingIOError:raise ControlError('busy','Кандидат занят применением или откатом. Обновите состояние.') from None
        if action=='status':return inspect(root,coordinator)
        try:state=coordinator.state()
        except Exception:raise ControlError('journal','Журнал операции повреждён. Используйте проверенную резервную копию по инструкции восстановления; автоматический выбор ревизии запрещён.') from None
        if not isinstance(state,dict) or not state:
            raise ControlError('journal','Нет журнала установленной ревизии. Сначала восстановите кандидат по инструкции.')
        current=digest((root/'config.json').read_bytes()) if (root/'config.json').exists() else None
        if request.get('expected_config_sha256')!=current:
            raise ControlError('stale','Конфигурация кандидата изменилась. Обновите страницу.')
        if action=='apply':
            from openconnect_apply import state as openconnect_state,PENDING as OPENCONNECT_PENDING
            if openconnect_state().get('status') in OPENCONNECT_PENDING or openconnect_state(Path('/var/lib/okopy-trusttunnel')).get('status') in OPENCONNECT_PENDING:
                raise ControlError('pending','Сначала подтвердите или восстановите изменение VPN.')
            from wg_client_ops import operation_state
            if operation_state(Path('/var/lib/okopy-wireguard')).get('status')=='pending':
                raise ControlError('pending','Сначала завершите изменение клиента WireGuard в разделе устройств.')
            from wireguard_apply import Transaction as WGTransaction,PENDING as WG_PENDING
            if any(WGTransaction(root).state().get('status') in WG_PENDING for root in (Path('/var/lib/okopy-wireguard'),Path('/var/lib/okopy-amnezia'))):
                raise ControlError('pending','Сначала подтвердите или восстановите изменение WireGuard.')
            if state.get('status') in ('prepared','pending','rollback_failed'):
                raise ControlError('pending','Сначала завершите текущее применение или восстановление.')
            if not inspect(root,coordinator)['integrity']:
                raise ControlError('integrity','Файлы кандидата не совпадают с принятой ревизией. Сначала восстановите её.')
            existing=read_bundle(root);manifest=validate_bundle(existing)
            secret=json.loads(existing['config.json'])['experimental']['clash_api']['secret']
            # Trusted options come from the installed package, never the browser.
            files=build_bundle(request.get('policy'),api_secret=secret,options=manifest['build_options'])
            coordinator.apply_bundle(files,120)
        else:
            transaction=request.get('transaction')
            if not isinstance(transaction,str) or transaction!=state.get('id'):
                raise ControlError('stale','Операция уже изменилась. Обновите страницу.')
            if action=='confirm':
                if state.get('status')!='pending' or state.get('runtime_ready') is not True:
                    raise ControlError('not_pending','Нет проверенного применения, ожидающего подтверждения.')
                # Keep the same writer lock through probes and final commit.
                # Timer callbacks will recheck durable state when the lock opens.
                verification=verify()
                coordinator.confirm(transaction)
            else:coordinator.rollback(transaction)
        result=inspect(root,coordinator)
        if action=='confirm':result['verification']=verification
        return result


def decode_request(raw):
    # sudo can consume the password line, or leave it untouched (NOPASSWD).
    # A fixed frame separates it from the one-line JSON in either case.
    lines=raw.split(b'\n')
    if lines and lines[-1]==b'':lines.pop()
    if len(lines)==2 and lines[0]==FRAME:payload=lines[1]
    elif len(lines)==3 and lines[1]==FRAME and len(lines[0])<=MAX_CREDENTIAL_BYTES:payload=lines[2]
    else:raise ControlError('request','Некорректный формат запроса управления.')
    if len(payload)>MAX_REQUEST:raise ControlError('request','Запрос слишком большой.')
    return json.loads(payload)


def main():
    if os.geteuid()!=0:raise ControlError('access','Команда должна выполняться на сервере с правами администратора.')
    os.umask(0o077)
    limit=MAX_REQUEST+MAX_CREDENTIAL_BYTES+len(FRAME)+3
    raw=sys.stdin.buffer.read(limit+1)
    if len(raw)>limit:raise ControlError('request','Запрос слишком большой.')
    return handle(decode_request(raw))


if __name__=='__main__':
    try:response={'ok':True,'result':main()}
    except ControlError as error:response={'ok':False,'code':error.code,'message':error.message}
    except Exception as error:
        # A compiler error may contain an outbound credential. Only the private
        # server log gets diagnostics; the browser receives a fixed message.
        try:atomic_write(ROOT/'last-control-error.log',(type(error).__name__+': '+str(error)).encode())
        except OSError:pass
        response={'ok':False,'code':'failed','message':'Операция не завершена. Обновите состояние; подробности сохранены на сервере.'}
    print(json.dumps(response,ensure_ascii=False))
