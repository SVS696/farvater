"""Bounded native OpenConnect checks; configuration never supplies commands."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

from openconnect_render import render_files
from safe_apply import atomic_write

CODE=Path('/var/lib/okopy-candidate')


def command(args,*,data=None,timeout=10,required=True):
    p=subprocess.Popen(args,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,err=p.communicate(data,timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL);p.communicate()
        raise ValueError('Команда OpenConnect превысила время ожидания') from None
    if len(out)>128*1024 or required and p.returncode:raise ValueError('Штатная команда OpenConnect завершилась с ошибкой')
    return p.returncode,out


def probe_values(value):
    if not isinstance(value,dict) or set(value)!={'url','codes'}:raise ValueError('Для проверки укажите HTTPS-сайт и ожидаемые коды ответа')
    try:
        url=value['url']
        if not isinstance(url,str) or len(url)>2048 or any(c.isspace() or ord(c)<32 for c in url):raise ValueError()
        parsed=urlsplit(url)
        if parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query or parsed.port not in (None,443):raise ValueError()
        codes=value['codes']
        if not isinstance(codes,list) or not 1<=len(codes)<=8 or len(set(codes))!=len(codes) or any(type(c) is not int or not 200<=c<=399 for c in codes):raise ValueError()
    except (ValueError,TypeError):raise ValueError('Проверка: нужен HTTPS URL без логина, пароля, query и фрагмента, порт 443 и коды 200–399') from None
    return {'url':url,'codes':codes}


def native_check(root,binding,model):
    with tempfile.TemporaryDirectory(prefix='validate-',dir=root) as temporary:
        directory=Path(temporary);files=render_files(model,binding,directory)
        for name,data in files.items():atomic_write(directory/name,data)
        rc,out=command([binding['binary'],'--config='+str(directory/'client.conf'),'--version'],data=files['stdin.txt'],timeout=6,required=False)
        if rc or b'OpenConnect version' not in out:raise ValueError('Установленный OpenConnect не принял параметры; рабочее подключение не изменено')
    return {'native_format':True,'authentication_tested':False}


class LinuxBackend:
    def __init__(self,root,binding,name):self.root=Path(root);self.binding=binding;self.name=name
    def boot_id(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    def capture(self,stable=True):
        from openconnect_control import observe,regular,digest
        state=observe(self.binding)
        expected='ExecStart=/usr/bin/python3 -E -s -B '+str(CODE/'openconnect_start.py')+' '+self.name
        if expected not in regular(Path(self.binding['unit_file'])).decode().splitlines():raise ValueError('Служба не использует установленный загрузчик управляемых настроек')
        if stable and state['active']=='active':
            from wireguard_control import read_private
            started=json.loads(read_private(self.root/(self.name+'.started.json')))
            active_hash=digest(read_private(self.root/(self.name+'.active.json')))
            if started.get('model_sha256')!=active_hash or started.get('boot_id')!=self.boot_id() or started.get('pid')!=state['pid']:
                raise ValueError('Действующие параметры отличаются от запущенного процесса; применение не начиналось')
        if (stable and state['active'] not in ('active','inactive','failed')) or state['boot'] not in ('enabled','disabled'):
            raise ValueError('Дождитесь устойчивого состояния службы OpenConnect')
        return {'active':state['active']=='active','boot':state['boot'],
                'unit_sha256':digest(regular(Path(self.binding['unit_file']))),
                'script_sha256':digest(regular(Path(self.binding['script'])))}
    def environment_matches(self,snapshot):
        actual=self.capture(stable=False)
        return all(actual[k]==snapshot[k] for k in ('boot','unit_sha256','script_sha256'))
    def active(self):return self.capture(stable=False)['active']
    def stop(self):command(['systemctl','stop',self.binding['unit']],timeout=20)
    def start(self):command(['systemctl','reset-failed',self.binding['unit']],required=False);command(['systemctl','start',self.binding['unit']],timeout=20)
    def set_enabled(self,enabled):command(['systemctl','enable' if enabled else 'disable',self.binding['unit']],timeout=10)
    def validate(self,model):return native_check(self.root,self.binding,model)
    def probe(self,value):
        value=probe_values(value)
        rc,out=command(['curl','--noproxy','*','--interface',self.binding['interface'],'--silent',
                        '--connect-timeout','3','--max-time','8','--output','/dev/null','--write-out','%{http_code}',value['url']],timeout=10,required=False)
        code=out.decode(errors='replace').strip()
        if rc or not code.isdigit() or int(code) not in value['codes']:raise ValueError('HTTPS через интерфейс VPN не прошёл проверку; изменение не подтверждено')
        return {'http_code':int(code),'checked_at':time.time(),'bound_to_vpn':True}
    def wait_ready(self,expected_hash):
        from wireguard_control import read_private
        receipt=self.root/(self.name+'.started.json')
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            try:
                value=json.loads(read_private(receipt))
                rc,out=command(['ip','-j','address','show','dev',self.binding['interface']],timeout=3,required=False)
                addresses=json.loads(out) if rc==0 else []
                if self.active() and value.get('model_sha256')==expected_hash and value.get('boot_id')==self.boot_id() and any(a.get('scope')=='global' for row in addresses for a in row.get('addr_info',[])):return
            except (ValueError,OSError):pass
            time.sleep(1)
        raise ValueError('OpenConnect не подтвердил запуск с новыми параметрами')
    def arm(self,identifier):
        command(['systemd-run','--quiet','--unit=okopy-openconnect-'+identifier,'--on-active=180s',
                 '--timer-property=AccuracySec=1s','--property=TimeoutStartSec=80s',
                 '/usr/bin/python3','-E','-s','-B',str(CODE/'openconnect_apply.py'),'rollback',identifier],timeout=8)
    def cancel(self,identifier):command(['systemctl','stop','okopy-openconnect-'+identifier+'.timer'],required=False)
