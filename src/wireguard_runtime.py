"""Linux-only operations for one guarded wg-quick profile update."""
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import signal
import time

from wireguard_profile import parse
from wireguard_preflight import check as preflight

CODE=Path('/var/lib/okopy-candidate')
GUARD=Path('/etc/systemd/system/wg-quick@.service.d/50-okopy-recovery.conf')


def command(args,*,data=None,timeout=8,required=True):
    p=subprocess.Popen(args,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,_=p.communicate(data,timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL);p.communicate()
        raise ValueError('Операция WireGuard превысила время ожидания') from None
    if len(out)>1024*1024 or required and p.returncode:
        raise ValueError('Штатная команда WireGuard не завершилась успешно')
    return p.returncode,out


def probe_values(value):
    if not isinstance(value,dict) or set(value)!={'address','port','mark'}:
        raise ValueError('Для проверки нужны контрольный IP, TCP-порт и марка маршрута')
    try:
        if not isinstance(value['address'],str) or '%' in value['address'] or len(value['address'])>45:raise ValueError()
        address=ipaddress.ip_address(value['address'])
        if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:raise ValueError()
        if type(value['port']) is not int or not 1<=value['port']<=65535:raise ValueError()
        if type(value['mark']) is not int or not 0<=value['mark']<=4294967295:raise ValueError()
    except (ValueError,TypeError):raise ValueError('Некорректный контрольный IP, порт или марка маршрута') from None
    return {'address':str(address),'port':value['port'],'mark':value['mark']}


class LinuxBackend:
    def __init__(self,profiles):self.profiles=profiles
    def boot_id(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    def unit(self,name):return 'wg-quick@'+name+'.service'
    def props(self,name):
        keys='ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,User,Group,DynamicUser,RootDirectory,RootImage,Type,RemainAfterExit,ExecStart,ExecStop,ExecStartPre,TimeoutStartUSec,TimeoutStopUSec'
        out=command(['systemctl','show',self.unit(name),'-p',keys])[1].decode()
        return dict(line.split('=',1) for line in out.splitlines() if '=' in line)
    def unit_signature(self,p):
        import hashlib
        paths=[p['FragmentPath'],*p['DropInPaths'].split()]
        return {str(path):hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths}
    def interface(self,name):
        rc,out=command(['ip','-j','address','show','dev',name],required=False)
        if rc:return None
        rows=json.loads(out)
        return rows[0] if len(rows)==1 else None
    def capture(self,name,original):
        p=self.props(name);live=self.interface(name)
        expected='argv[]=/usr/bin/python3 -E -s -B '+str(CODE/'wireguard_apply.py')+' recover-before-start '+name+' ; ignore_errors=no'
        if (p['FragmentPath']!='/usr/lib/systemd/system/wg-quick@.service' or str(GUARD) not in p['DropInPaths'].split()
            or p['NeedDaemonReload']!='no' or expected not in p.get('ExecStartPre','')
            or p.get('User') not in ('','root') or p.get('Group') not in ('','root') or p.get('DynamicUser')=='yes'
            or p.get('RootDirectory') or p.get('RootImage') or p.get('Type')!='oneshot' or p.get('RemainAfterExit')!='yes'
            or 'argv[]=/usr/bin/wg-quick up '+name+' ;' not in p.get('ExecStart','')
            or 'argv[]=/usr/bin/wg-quick down '+name+' ;' not in p.get('ExecStop','')
            or p.get('UnitFileState') not in ('enabled','disabled')
            or p.get('ActiveState') not in ('active','inactive','failed') or bool(live)!=(p['ActiveState']=='active')):
            raise ValueError('Профиль должен принадлежать штатной wg-quick с установленным восстановлением при загрузке')
        # Bound systemd jobs themselves, not merely the controlling SSH process.
        if p.get('TimeoutStartUSec') not in ('15s','25s','30s') or p.get('TimeoutStopUSec') not in ('10s','15s'):
            raise ValueError('У службы отсутствуют проверенные ограничения времени запуска и остановки')
        snapshot={'active':p['ActiveState']=='active','enabled':p['UnitFileState'],
                  'unit_files':self.unit_signature(p),'mode':(self.profiles/(name+'.conf')).stat().st_mode&0o777}
        if not self.matches(name,original,snapshot):raise ValueError('Рабочий интерфейс отличается от файла; сначала согласуйте текущее состояние')
        return snapshot
    def validate(self,name,model,activation=True):
        if not activation:
            from wireguard_preflight import native
            return {'native_valid':native(model),'blockers':[]}
        from wireguard_control import runtime,read_private
        result=preflight(name,model,self.profiles,observe=runtime,read_profile=lambda p:parse(read_private(p).decode()))
        if result['blockers']:raise ValueError('Применение заблокировано: '+result['blockers'][0]['message'])
        return result
    def matches(self,name,content,snapshot,*,environment=True):
        try:
            p=self.props(name);live=self.interface(name)
            if environment and (p['UnitFileState']!=snapshot['enabled'] or p['NeedDaemonReload']!='no' or self.unit_signature(p)!=snapshot['unit_files']):return False
            if not snapshot['active']:return p['ActiveState'] in ('inactive','failed') and live is None
            if p['ActiveState']!='active' or p['SubState']!='exited' or live is None:return False
            expected=parse(content.decode())
            raw=command(['wg','showconf',name])[1].decode()
            actual=parse(raw.replace('[Interface]','[Interface]\nAddress = '+', '.join(expected['interface']['Address']),1))
            public=command(['wg','pubkey'],data=(expected['interface']['PrivateKey']+'\n').encode())[1].strip()
            if public!=command(['wg','show',name,'public-key'])[1].strip():return False
            port=expected['interface'].get('ListenPort',0)
            if port and actual['interface'].get('ListenPort')!=port:return False
            def peers(model):
                return {x['PublicKey']:{'allowed':sorted(x['AllowedIPs']),'psk':x.get('PresharedKey'),
                                        'keepalive':x.get('PersistentKeepalive',0)} for x in model['peers']}
            if peers(actual)!=peers(expected):return False
            expected_ips=set(expected['interface']['Address'])
            actual_ips={str(ipaddress.ip_interface(str(a['local'])+'/'+str(a['prefixlen']))) for a in live['addr_info'] if a.get('family') in ('inet','inet6') and (a.get('scope')!='link' or str(ipaddress.ip_interface(str(a['local'])+'/'+str(a['prefixlen']))) in expected_ips)}
            return expected_ips==actual_ips and ('MTU' not in expected['interface'] or live['mtu']==expected['interface']['MTU'])
        except (ValueError,OSError,KeyError,TypeError):return False
    def environment_matches(self,name,snapshot):
        p=self.props(name)
        return p['UnitFileState']==snapshot['enabled'] and p['NeedDaemonReload']=='no' and self.unit_signature(p)==snapshot['unit_files']
    def stop(self,name):
        command(['systemctl','stop',self.unit(name)],timeout=20,required=False)
        if self.props(name)['ActiveState'] not in ('inactive','failed'):
            raise ValueError('Остановка службы ещё не завершена')
        # An interrupted wg-quick start can leave a kernel interface even when
        # systemd already says failed. The caller supplies its known config.
        if self.interface(name) is not None:command(['wg-quick','down',name],timeout=12)
        if self.interface(name) is not None:raise ValueError('Интерфейс не остановлен; исходный файл ещё не заменён')
        if self.props(name)['ActiveState']=='failed':command(['systemctl','reset-failed',self.unit(name)])
    def start(self,name):
        if self.props(name)['ActiveState']=='failed':command(['systemctl','reset-failed',self.unit(name)])
        command(['systemctl','start',self.unit(name)],timeout=35)
    def set_enabled(self,name,enabled):
        command(['systemctl','enable' if enabled else 'disable',self.unit(name)],timeout=15)
    def probe(self,name,value,model):
        value=probe_values(value);address=ipaddress.ip_address(value['address'])
        if not any(address.version==n.version and address in n for peer in model['peers'] for n in map(ipaddress.ip_network,peer['AllowedIPs'])):
            raise ValueError('Контрольный адрес должен находиться в AllowedIPs этого профиля')
        if address in {ipaddress.ip_interface(a).ip for a in model['interface']['Address']}:
            raise ValueError('Контрольный адрес должен находиться за пиром, а не на самом сервере')
        start=time.monotonic()
        try:
            with socket.socket(socket.AF_INET6 if address.version==6 else socket.AF_INET,socket.SOCK_STREAM) as s:
                s.settimeout(4);s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,name.encode()+b'\0')
                if value['mark']:s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,struct.pack('=I',value['mark']))
                s.connect((str(address),value['port']))
        except OSError:raise ValueError('TCP-проверка через выбранный WireGuard не прошла; подтверждение невозможно') from None
        return {'address':str(address),'port':value['port'],'mark':value['mark'],'interface':name,'status':'connected','duration_ms':round((time.monotonic()-start)*1000),'checked_at':time.time()}
    def arm(self,identifier):
        timer='okopy-wireguard-restore-'+identifier
        command(['systemd-run','--quiet','--unit='+timer,'--on-active=180s','--on-unit-active=30s',
                 '--timer-property=AccuracySec=1s','--property=Type=oneshot','--property=TimeoutStartSec=120s',
                 '--property=TimeoutStopSec=5s','--property=UMask=0077','/usr/bin/python3','-E','-s','-B',
                 str(CODE/'wireguard_apply.py'),'rollback',identifier])
        command(['systemctl','is-active','--quiet',timer+'.timer'])
    def cancel(self,identifier):command(['systemctl','stop','okopy-wireguard-restore-'+identifier+'.timer'],required=False)
