"""AWG adapter for the existing guarded profile transaction."""
import ipaddress,json
from pathlib import Path
import amnezia_profile as codec
from amnezia_native import BIN,native
from amnezia_service import PROFILES,routing_table,check_table,RULE_PRIORITY,ROUTE_PROTOCOL
from wireguard_runtime import LinuxBackend,command,CODE
from wireguard_control import runtime as wg_runtime,read_private
from wireguard_preflight import check

ROOT=Path('/var/lib/okopy-amnezia')
UNIT='/etc/systemd/system/okopy-amnezia@.service'


def runtime(names):return wg_runtime(names,unit_prefix='okopy-amnezia')


class AmneziaBackend(LinuxBackend):
    def unit(self,name):return 'okopy-amnezia@'+name+'.service'
    def capture(self,name,original):
        p=self.props(name);live=self.interface(name)
        prefix='/usr/bin/python3 -E -s -B '+str(CODE)+'/amnezia_'
        if (p.get('FragmentPath')!=UNIT or p.get('DropInPaths') or p.get('NeedDaemonReload')!='no'
            or p.get('User') not in ('','root') or p.get('Group') not in ('','root') or p.get('DynamicUser')=='yes'
            or p.get('RootDirectory') or p.get('RootImage') or p.get('Type')!='oneshot' or p.get('RemainAfterExit')!='yes'
            or 'argv[]='+prefix+'apply.py recover-before-start '+name+' ;' not in p.get('ExecStartPre','')
            or 'argv[]='+prefix+'service.py up '+name+' ;' not in p.get('ExecStart','')
            or 'argv[]='+prefix+'service.py down '+name+' ;' not in p.get('ExecStop','')
            or p.get('UnitFileState') not in ('enabled','disabled')
            or p.get('ActiveState') not in ('active','inactive','failed') or bool(live)!=(p.get('ActiveState')=='active')
            or p.get('TimeoutStartUSec')!='30s' or p.get('TimeoutStopUSec')!='15s'):
            raise ValueError('Служба AWG отличается от установленного управляемого шаблона')
        s={'active':p['ActiveState']=='active','enabled':p['UnitFileState'],'unit_files':self.unit_signature(p),'mode':(self.profiles/(name+'.conf')).stat().st_mode&0o777}
        if not self.matches(name,original,s):raise ValueError('Текущее состояние AWG отличается от сохранённого профиля')
        return s
    def preflight(self,name,model):
        check_table(name,model)
        result=check(name,model,self.profiles,observe=runtime,read_profile=lambda p:codec.parse(read_private(p).decode()),native_check=native)
        result['note']='Параметры приняты официальным клиентом AWG в изолированной сети. Передача трафика проверяется при включении.'
        return result
    def validate(self,name,model,activation=True):
        routing_table(model)
        result=self.preflight(name,model) if activation else {'native_valid':native(model),'blockers':[]}
        if result['blockers']:raise ValueError('Применение заблокировано: '+result['blockers'][0]['message'])
        return result
    def matches(self,name,content,snapshot,*,environment=True):
        try:
            p=self.props(name);live=self.interface(name)
            if environment and not self.environment_matches(name,snapshot):return False
            if not snapshot['active']:return p['ActiveState'] in ('inactive','failed') and live is None
            if p['ActiveState']!='active' or p['SubState']!='exited' or live is None:return False
            expected=codec.parse(content.decode());raw=command([str(BIN/'awg'),'showconf',name])[1].decode()
            actual=codec.parse(raw.replace('[Interface]','[Interface]\nAddress = '+', '.join(expected['interface']['Address']),1))
            public=command([str(BIN/'awg'),'pubkey'],data=(expected['interface']['PrivateKey']+'\n').encode())[1].strip()
            if public!=command([str(BIN/'awg'),'show',name,'public-key'])[1].strip():return False
            for key,value in expected['interface'].items():
                if key in ('PrivateKey','Address','DNS','MTU','Table'):continue
                if key=='ListenPort' and not value:continue
                if str(actual['interface'].get(key,'0'))!=str(value):return False
            def peers(m):
                return {x['PublicKey']:(sorted(x['AllowedIPs']),x.get('PresharedKey'),str(x.get('PersistentKeepalive','0'))) for x in m['peers']}
            if peers(actual)!=peers(expected):return False
            expected_ips=set(expected['interface']['Address'])
            actual_ips={str(ipaddress.ip_interface(str(a['local'])+'/'+str(a['prefixlen']))) for a in live['addr_info'] if a.get('family') in ('inet','inet6') and (a.get('scope')!='link' or str(ipaddress.ip_interface(str(a['local'])+'/'+str(a['prefixlen']))) in expected_ips)}
            if actual_ips!=expected_ips or live['mtu']!=expected['interface'].get('MTU',1280):return False
            table=routing_table(expected)
            for family in ('-4','-6'):
                rules=json.loads(command(['ip',family,'-N','-j','rule','show'])[1])
                if not any(r.get('oif')==name and str(r.get('table'))==str(table) and r.get('priority')==RULE_PRIORITY for r in rules):return False
            return True
        except (ValueError,OSError,KeyError,TypeError):return False
    def stop(self,name):
        command(['systemctl','stop',self.unit(name)],timeout=20,required=False)
        if self.props(name)['ActiveState'] not in ('inactive','failed'):raise ValueError('Остановка AWG ещё не завершена')
        from amnezia_service import stop
        stop(name)
        if self.props(name)['ActiveState']=='failed':command(['systemctl','reset-failed',self.unit(name)])
    def arm(self,identifier):
        timer='okopy-amnezia-restore-'+identifier
        command(['systemd-run','--quiet','--unit='+timer,'--on-active=180s','--on-unit-active=30s','--timer-property=AccuracySec=1s',
                 '--property=Type=oneshot','--property=TimeoutStartSec=120s','--property=TimeoutStopSec=5s','--property=UMask=0077',
                 '/usr/bin/python3','-E','-s','-B',str(CODE/'amnezia_apply.py'),'rollback',identifier])
        command(['systemctl','is-active','--quiet',timer+'.timer'])
    def cancel(self,identifier):command(['systemctl','stop','okopy-amnezia-restore-'+identifier+'.timer'],required=False)
