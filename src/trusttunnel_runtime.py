"""Native TrustTunnel service adapter for the existing guarded transaction."""
import json
import os
from pathlib import Path
import time
from safe_apply import digest
from wireguard_control import read_private
from openconnect_control import regular
from openconnect_runtime import command,probe_values
from trusttunnel_profile import render

CODE=Path('/var/lib/okopy-candidate')
ROOT=Path('/var/lib/okopy-trusttunnel')


def installation(root,binding):
    from trusttunnel_control import observe
    runtime=observe(binding)
    material=json.dumps(binding,sort_keys=True).encode()
    for path in binding.get('dependent_files',[]):material+=b'\0'+regular(Path(path))
    companions={unit:digest(regular(Path(v['unit_file']))) for unit,v in runtime['dependents'].items()}
    return {'unit_sha256':digest(regular(Path(binding['unit_file']))),'script_sha256':digest(material),'companions':companions}


class LinuxBackend:
    def __init__(self,root,binding,name):self.root=Path(root);self.binding=binding;self.name=name;self.health_probe=None
    def boot_id(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    def capture(self,stable=True):
        from trusttunnel_control import observe
        r=observe(self.binding);client=r['client'];proof=installation(self.root,self.binding)
        expected='ExecStart=+/usr/bin/python3 -E -s -B '+str(CODE/'trusttunnel_start.py')+' '+self.name
        if expected not in regular(Path(self.binding['unit_file'])).decode().splitlines():raise ValueError('Служба не использует установленный загрузчик TrustTunnel')
        receipt=json.loads(read_private(self.root/(self.name+'.installation.json')))
        if receipt!=proof:raise ValueError('Привязка или связанные файлы TrustTunnel изменились вне панели')
        for unit in [client,*r['dependents'].values()]:
            if unit['boot'] not in ('enabled','disabled') or stable and unit['active'] not in ('active','inactive','failed'):raise ValueError('Дождитесь устойчивого состояния служб TrustTunnel')
        if stable and client['active']=='active':
            started=json.loads(read_private(self.root/(self.name+'.started.json')))
            if started.get('pid')!=client['pid'] or started.get('boot_id')!=self.boot_id() or started.get('model_sha256')!=digest(read_private(self.root/(self.name+'.active.json'))):raise ValueError('Процесс TrustTunnel не соответствует действующим параметрам')
        return {'active':client['active']=='active','boot':client['boot'],'unit_sha256':proof['unit_sha256'],'script_sha256':proof['script_sha256'],
            'companions':{unit:{'active':v['active']=='active','boot':v['boot'],'unit_sha256':proof['companions'][unit]} for unit,v in r['dependents'].items()}}
    def environment_matches(self,snapshot):
        now=self.capture(stable=False)
        return all(now[k]==snapshot[k] for k in ('boot','unit_sha256','script_sha256')) and set(now['companions'])==set(snapshot['companions']) and all(all(now['companions'][unit][k]==v[k] for k in ('boot','unit_sha256')) for unit,v in snapshot['companions'].items())
    def active(self):
        current=self.capture(stable=False)
        if self.operation().get('status') in ('prepared','pending'):
            if any(current['companions'][u]['active']!=wanted for u,wanted in self.desired_companions().items()):
                raise ValueError('Состояние зависимых служб изменилось; подтверждение запрещено')
        return current['active']
    def validate(self,model):render(model,self.binding)
    def operation(self):
        from openconnect_apply import state
        s=state(self.root)
        return s if s.get('connection')==self.name else {}
    def desired_companions(self):
        s=self.operation()
        if not s:return {}
        original=s['snapshot']['companions']
        if s['kind']=='runtime' and s['status'] in ('prepared','pending') and not s.get('recovering'):
            return {unit:s['target_active'] for unit in original}
        return {unit:v['active'] for unit,v in original.items()}
    def stop(self):
        for unit in [*reversed(self.binding['dependents']),self.binding['unit']]:command(['systemctl','stop',unit],timeout=15)
        r=self.capture(stable=False)
        if r['active'] or any(v['active'] for v in r['companions'].values()):raise ValueError('Службы TrustTunnel не подтвердили остановку')
    def start(self):
        desired=self.desired_companions()
        for unit in [self.binding['unit'],*(u for u,wanted in desired.items() if wanted)]:
            command(['systemctl','reset-failed',unit],required=False);command(['systemctl','start',unit],timeout=15)
    def probe(self,value):
        value=probe_values(value)
        rc,out=command(['curl','--noproxy','','--proxy','socks5h://'+self.binding['socks_address'],
            '--silent','--connect-timeout','3','--max-time','7','--output','/dev/null','--write-out','%{http_code}',value['url']],timeout=9,required=False)
        code=out.decode(errors='replace').strip()
        if rc or not code.isdigit() or int(code) not in value['codes']:raise ValueError('HTTPS через TrustTunnel не прошёл проверку')
        return {'http_code':int(code),'checked_at':time.time(),'via_registered_socks':True}
    def wait_ready(self,expected_hash):
        from trusttunnel_control import observe
        deadline=time.monotonic()+25;s=self.operation();probe=s.get('probe') or self.health_probe;desired=self.desired_companions()
        while time.monotonic()<deadline:
            try:
                r=observe(self.binding);client=r['client'];started=json.loads(read_private(self.root/(self.name+'.started.json')))
                if client['active']!='active' or started.get('pid')!=client['pid'] or started.get('boot_id')!=self.boot_id() or started.get('model_sha256')!=expected_hash:raise ValueError('Запуск ещё не подтверждён')
                _,raw=command(['ss','-H','-ltnp'],timeout=3)
                if not any(self.binding['socks_address'] in line.split() and ('pid='+str(client['pid'])+',') in line for line in raw.decode().splitlines()):raise ValueError('Слушатель не принадлежит запущенному клиенту')
                if any((r['dependents'][unit]['active']=='active')!=wanted for unit,wanted in desired.items()):raise ValueError('Зависимая служба ещё не готова')
                if probe:self.probe(probe)
                return
            except (ValueError,OSError):time.sleep(.5)
        raise ValueError('TrustTunnel не подтвердил готовность и передачу трафика')
    def set_enabled(self,enabled):
        # Requires= can pull the client back in on boot if an enabled endpoint
        # is left behind. Change the complete registered group, without --now.
        command(['systemctl','enable' if enabled else 'disable',self.binding['unit'],*self.binding['dependents']],timeout=15)
    def arm(self,identifier):
        command(['systemd-run','--quiet','--unit=okopy-trusttunnel-'+identifier,'--on-active=180s','--timer-property=AccuracySec=1s',
            '--property=TimeoutStartSec=100s','/usr/bin/python3','-E','-s','-B',str(CODE/'trusttunnel_apply.py'),'rollback',identifier],timeout=8)
    def cancel(self,identifier):command(['systemctl','stop','okopy-trusttunnel-'+identifier+'.timer'],required=False)
