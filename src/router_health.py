"""Independent роутера measurements and typed settings over authenticated LAN SSH."""
import base64,contextlib,hashlib,json,re,threading,time,os
from pathlib import Path
import paramiko
from health_model import timestamp,validate_snapshot,LABELS
from health_settings import edit_check,fingerprint
from router_settings import DEFAULT,validate,compile_settings,status_view
from candidate_remote import RemoteError
from safe_apply import atomic_write

ROOT='/tmp/okopy-router-monitor'
CONTROL=f'exec {ROOT}/opt/lib/ld.so.1 --library-path {ROOT}/opt/lib {ROOT}/opt/bin/busybox sh {ROOT}/settings-control.sh'
MAX_AGE=30
FIELDS={'status','observed_at','uptime_seconds','dns_udp','dns_tcp','https','http_code'}
LOCK=threading.RLock()

def settings_status(packet):
    if isinstance(packet,dict) and packet.get('error')=='busy':
        raise RemoteError('Настройки роутера заняты другой операцией. Повторите чтение позже; восстановление описано в инструкции измерителя.')
    return status_view(packet)


def snapshot(value,check=DEFAULT):
    validate(check)
    if not isinstance(value,dict) or set(value)!=FIELDS:raise ValueError('Invalid router measurement')
    if not timestamp(value['observed_at']) or type(value['uptime_seconds']) is not int or value['uptime_seconds']<0:raise ValueError('Invalid router time')
    states=[value[k] for k in ('dns_udp','dns_tcp','https')]
    if any(s not in ('up','down','unknown') for s in states):raise ValueError('Invalid router state')
    expected='up' if all(s=='up' for s in states) else 'unknown' if all(s=='unknown' for s in states) else 'down'
    if value['status']!=expected or type(value['http_code']) is not int or value['http_code'] not in ({0}|set(range(100,600))):raise ValueError('Inconsistent router state')
    if value['https']=='up' and value['http_code'] not in (200,204):raise ValueError('Inconsistent HTTP result')
    checks=[]
    for key,name in [('dns_udp','DNS UDP'),('dns_tcp','DNS TCP'),('https','HTTPS')]:
        checks.append({'id':check['id']+':'+key,'name':name+' · '+check['name'],'scope':check['scope'],
            'status':value[key],'observed_at':value['observed_at'],'duration_ms':0,'definition_sha256':fingerprint(check),
            'detail':(check['domain']+' через '+check['server']+':'+str(check['dns_port'])+'.' if key.startswith('dns') else check['url']+' через LAN-прокси, код '+str(value['http_code'])+'.'),
            'action':check['action']})
    return validate_snapshot({'version':1,'generated_at':value['observed_at'],'interval_seconds':5,'checks':checks,'events':[]})


def unknown(check,observed_at=0):
    return snapshot({'status':'unknown','observed_at':observed_at,'uptime_seconds':0,'dns_udp':'unknown','dns_tcp':'unknown','https':'unknown','http_code':0},check)


def decode_packet(packet):
    if not isinstance(packet,dict) or set(packet)!={'settings','snapshot'}:raise ValueError('Invalid router packet')
    settings=status_view(packet['settings']);wire=packet['snapshot']
    if wire is None:return unknown(settings['check'])
    if not isinstance(wire,dict) or type(wire.get('version')) is not int or wire['version'] not in (1,2):raise ValueError('Invalid router packet version')
    expected={'version','revision','measurement'}|({'history'} if wire['version']==2 else set())
    if set(wire)!=expected:raise ValueError('Invalid router packet fields')
    value=snapshot(wire['measurement'],settings['check'])
    history=wire.get('history',[])
    if not isinstance(history,list) or len(history)>10:raise ValueError('Invalid router history')
    prior=None
    for record in history:
        if not isinstance(record,dict) or set(record)!={'revision','measurement'} or not isinstance(record['revision'],str) or not re.fullmatch('[a-f0-9]{64}',record['revision']):raise ValueError('Invalid router history record')
        snapshot(record['measurement'],settings['check'])
        measurement=record['measurement'];changed=prior is not None and prior['revision']!=record['revision']
        for key,label in [('dns_udp','DNS UDP'),('dns_tcp','DNS TCP'),('https','HTTPS')]:
            if prior is None or changed or prior['measurement'][key]!=measurement[key] or (key=='https' and prior['measurement']['http_code']!=measurement['http_code']):
                detail=LABELS[measurement[key]]+'.'
                if key=='https':detail+=' HTTP '+str(measurement['http_code'])+'.'
                if changed:detail+=' Изменились параметры измерителя.'
                detail+=' Ревизия '+record['revision'][:12]+'.'
                value['events'].append({'at':measurement['observed_at'],'id':settings['check']['id']+':'+key,'name':settings['check']['name']+' · '+label,'status':measurement[key],'detail':detail})
        prior=record
    if wire['revision']!=settings['revision']:
        for row in value['checks']:row.update(status='unknown',detail='Параметры изменились; ожидается соответствующее им измерение.')
    if not settings['persistent_matches']:
        for row in value['checks']:
            if row['status']=='up':row['status']='degraded'
            row['detail']+=' Сохранение текущих параметров на USB не подтверждено. Перечитайте форму настроек.'
    return value


@contextlib.contextmanager
def connect(credentials):
    client=paramiko.SSHClient()
    try:
        if isinstance(credentials,dict):
            from router_registry import validate
            row=validate(credentials)
        else:
            values={k:json.loads(v) for k,v in (line.split('=',1) for line in Path(credentials).read_text().splitlines() if line and not line.startswith('#'))}
            row={'host':values['ROUTER_HOST'],'port':int(values.get('ROUTER_PORT',22)),'username':values['ROUTER_USERNAME'],'password':values['ROUTER_PASSWORD'],'host_key':values.get('ROUTER_HOST_KEY','')}
        client.load_system_host_keys()
        if row.get('host_key'):
            entry=paramiko.hostkeys.HostKeyEntry.from_line('router '+row['host_key'])
            lookup=row['host'] if row['port']==22 else '['+row['host']+']:'+str(row['port'])
            client.get_host_keys().add(lookup,entry.key.get_name(),entry.key)
        client.connect(row['host'],port=row['port'],username=row['username'],password=row['password'],
                       allow_agent=False,look_for_keys=False,timeout=3,banner_timeout=3,auth_timeout=3)
        yield client
    finally:client.close()


def control_command(control,action):
    # NDM exec does not preserve the longer argument vector. Pass one command
    # string to the RAM shell. Only protocol verbs and hex tokens may enter it.
    if not re.fullmatch(r'(?:status|read|inventory|apply|confirm|rollback)(?: [0-9a-f]+)*',action):
        raise ValueError('Invalid router control action')
    if not re.fullmatch(r'exec /[A-Za-z0-9_./ -]+',control) or ' sh ' not in control:
        raise ValueError('Invalid router control executable')
    launcher=control.split(' sh ',1)[0]
    return launcher+' sh -c "'+control.removeprefix('exec ')+' '+action+'"'


def exchange(client,action,payload=None,*,control=CONTROL,timeout=5,max_bytes=32768):
    stream,out,_=client.exec_command(control_command(control,action),timeout=timeout)
    if payload is not None:
        stream.write(base64.b64encode(payload).decode()+'\n');stream.flush();stream.channel.shutdown_write()
    channel=out.channel;data=b'';deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if channel.recv_ready():
            data+=channel.recv(4097)
            if len(data)>max_bytes:raise ValueError('Oversized router response')
        elif channel.exit_status_ready():break
        else:time.sleep(.02)
    else:raise TimeoutError('Router response deadline')
    if channel.recv_exit_status()!=0:raise ValueError('Router command failed')
    return json.loads(re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',data.decode()))


def pull_once(directory,credentials=Path('/etc/okopy-panel/router.env')):
    with LOCK:
        try:
            with connect(credentials) as client:value=decode_packet(exchange(client,'read'))
            atomic_write(directory/'router-health.json',json.dumps(value,ensure_ascii=False).encode())
            atomic_write(directory/'router-health-transport.json',json.dumps({'at':time.time(),'ok':True}).encode())
            return True
        except (OSError,ValueError,KeyError,TypeError,paramiko.SSHException):
            atomic_write(directory/'router-health-transport.json',json.dumps({'at':time.time(),'ok':False}).encode())
            return False


class RouterRemote:
    def __init__(self,directory,credentials=Path('/etc/okopy-panel/router.env')):
        self.directory=Path(directory);self.credentials=credentials if isinstance(credentials,dict) else Path(credentials)

    def status(self):
        try:
            with LOCK,connect(self.credentials) as client:return settings_status(exchange(client,'status'))
        except (OSError,ValueError,KeyError,TypeError,paramiko.SSHException):
            raise RemoteError('Не удалось прочитать параметры роутера по LAN SSH. Проверьте доступ и измеритель роутера.') from None

    def native_status(self):
        from router_baseline import project
        def read(client,command):
            _,out,_=client.exec_command(command,timeout=5)
            channel=out.channel;data=b'';deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                if channel.recv_ready():
                    data+=channel.recv(65536)
                    if len(data)>1024*1024:raise ValueError('Oversized native response')
                elif channel.exit_status_ready():break
                else:time.sleep(.02)
            else:raise TimeoutError('Native read deadline')
            if channel.recv_exit_status()!=0:raise ValueError('Native read failed')
            text=data.decode()
            if re.search(r'error\[|no such command',text,re.I):raise ValueError('Native read rejected')
            return text
        try:
            with LOCK,connect(self.credentials) as client:
                before=read(client,'show last-change')
                running=read(client,'show running-config');startup=read(client,'more startup-config')
                resolvers=read(client,'show ip name-server');after=read(client,'show last-change')
                from router_baseline import canonical
                if canonical(before)!=canonical(after):raise ValueError('Native state changed during read')
                return project(running,startup,resolvers,after)
        except (OSError,ValueError,KeyError,TypeError,paramiko.SSHException):
            raise RemoteError('Не удалось проверить штатные настройки роутера. Обновите страницу или откройте роутер напрямую.') from None

    def save(self,revision,values):
        attempted=False
        try:
            with LOCK,connect(self.credentials) as client:
                current=settings_status(exchange(client,'status'))
                if revision!=current['revision']:raise RemoteError('Параметры роутера уже изменились. Перечитайте форму перед сохранением.')
                check=validate(edit_check(current['check'],values));content=compile_settings(check)
                atomic_write(self.directory/'router-health.json',json.dumps(unknown(check,time.time()),ensure_ascii=False).encode())
                attempted=True
                result=exchange(client,'apply '+revision+' '+hashlib.sha256(content).hexdigest(),content)
                if result.get('error')=='conflict':raise RemoteError('Параметры роутера уже изменились. Перечитайте форму перед сохранением.')
                failures={'busy':'Настройки не сохранены: другая запись роутера ещё выполняется или оставила блокировку. Повторите позже; восстановление описано в инструкции измерителя.',
                          'payload':'Настройки не сохранены: роутера не получил корректный пакет параметров.',
                          'persist':'Настройки не сохранены: не удалось подготовить запись на USB. Проверьте накопитель и перечитайте форму.'}
                if result.get('error') in failures:raise RemoteError(failures[result['error']])
                after=settings_status(exchange(client,'status'))
                if result.get('saved') is not True or after['revision']!=fingerprint(check) or not after['persistent_matches']:raise ValueError('Unconfirmed router save')
                return after
        except RemoteError:raise
        except (OSError,ValueError,KeyError,TypeError,paramiko.SSHException) as error:
            if not attempted and isinstance(error,ValueError):raise RemoteError(str(error)) from None
            if attempted:raise RemoteError('Ответ сохранения роутера не подтверждён. Перечитайте параметры: изменение могло сохраниться; повтор автоматически не отправлялся.') from None
            raise RemoteError('Нет связи с роутера; параметры не отправлены.') from None


def start_pull(directory,credentials=Path('/etc/okopy-panel/router.env')):
    def loop():
        while True:
            try:pull_once(directory,credentials)
            except Exception:
                try:atomic_write(directory/'router-health-transport.json',json.dumps({'at':time.time(),'ok':False}).encode())
                except OSError:pass
            time.sleep(15)
    thread=threading.Thread(target=loop,name='router-health-reader',daemon=True);thread.start();return thread
