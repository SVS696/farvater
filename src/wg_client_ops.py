"""Durable, single-peer changes; never restart an interface or routing core."""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

from safe_apply import atomic_write
from wireguard_control import read_private,revision
from wireguard_profile import parse,render,key,addresses,integer,MAX_BYTES
from wg_clients import ROOT,PROFILES,settings,inventory,derive,run,peer_id,matches_client


def valid_name(value):
    if not isinstance(value,str) or not 1<=len(value.strip())<=80 or any(not (c.isalnum() or c in ' ._-()') for c in value):
        raise ValueError('Имя: от 1 до 80 букв, цифр, пробелов и знаков . _ - ( )')
    return value.strip()


def operation_state(root):
    p=root/'client-operation.json'
    return json.loads(read_private(p)) if p.exists() else {}


def defaults(model):
    ips=[ipaddress.ip_interface(a) for a in model['interface']['Address']]
    v4=next((a for a in ips if a.version==4),None);v6=next((a for a in ips if a.version==6),None)
    return {'dns':str((v4 or v6).ip),'routes':'0.0.0.0/0'+('\n::/0' if v6 else ''),
            'mtu':'','keepalive':'25','ipv6':v6 is not None}


def allocate(model,files,ipv6):
    used=[ipaddress.ip_network(n) for p in model['peers'] for n in p['AllowedIPs']]
    for _,client,_ in files.values():
        used.extend(ipaddress.ip_network(str(ipaddress.ip_interface(a).ip)+'/'+str(ipaddress.ip_interface(a).max_prefixlen)) for a in client['interface']['Address'])
    interfaces=[ipaddress.ip_interface(a) for a in model['interface']['Address']]
    locals={a.ip for a in interfaces};result=[]
    for version in ([4,6] if ipv6 else [4]):
        pools=[a.network for a in interfaces if a.version==version and a.network.num_addresses>2]
        if len(pools)!=1:raise ValueError('На интерфейсе нужна одна сеть каждого выбранного семейства для автоматической выдачи адреса')
        pool=pools[0];selected=None
        # At most 64 peers are supported, but delegated subnets may occupy much
        # more space. Skip occupied networks instead of iterating IPv6 addresses.
        value=int(pool.network_address)+1;end=int(pool.broadcast_address)-(1 if version==4 else 0)
        while value<=end:
            candidate=ipaddress.ip_address(value)
            overlap=[n for n in used if n.version==version and candidate in n]
            if overlap:value=max(int(n.broadcast_address) for n in overlap)+1
            elif candidate in locals:value+=1
            else:selected=candidate;break
        if selected is None:raise ValueError('В сети WireGuard нет свободного адреса')
        result.append(str(selected)+'/'+str(selected.max_prefixlen))
    return result


def build_client(model,files,values,config,command=run):
    if not isinstance(values,dict) or set(values)!={'name','ipv6','dns','routes','mtu','keepalive'} or type(values['ipv6']) is not bool:
        raise ValueError('Некорректные параметры клиента')
    name=valid_name(values['name']);allocated=allocate(model,files,values['ipv6'])
    try:dns=[str(ipaddress.ip_address(v.strip())) for v in re.split('[,\n]',values['dns']) if v.strip()]
    except (ValueError,TypeError):raise ValueError('DNS: укажите IP-адреса серверов') from None
    if not 1<=len(dns)<=4:raise ValueError('Укажите от одного до четырёх DNS-серверов')
    routes=addresses(values['routes'].replace('\n',','),interface=False)
    if not values['ipv6'] and (any(ipaddress.ip_network(n).version==6 for n in routes) or any(ipaddress.ip_address(a).version==6 for a in dns)):
        raise ValueError('Для IPv6-маршрутов и DNS включите IPv6 клиента')
    mtu=integer(values['mtu'],'MTU',1280 if values['ipv6'] else 576,9000) if values['mtu'] else None
    keepalive=integer(values['keepalive'],'Keepalive',0,65535)
    private=key(command(['/usr/bin/wg','genkey']).strip(),'PrivateKey');public=derive(private,command)
    if public in files or any(p['PublicKey']==public for p in model['peers']):raise ValueError('Сгенерирован уже используемый ключ')
    interface={'PrivateKey':private,'Address':allocated}
    if mtu:interface['MTU']=mtu
    client={'interface':interface,'peers':[{'PublicKey':derive(model['interface']['PrivateKey'],command),'Endpoint':config['external_endpoint'],
                                         'AllowedIPs':routes,'PersistentKeepalive':keepalive}]}
    content=render(client).replace('[Interface]\n','[Interface]\n# '+name+'\nDNS = '+', '.join(dns)+'\n',1)
    peer={'PublicKey':public,'AllowedIPs':allocated}
    return name,peer,content


def peer_block(peer,name,interface):
    # Reuse the validated serializer without reformatting any existing peers.
    sample={'interface':interface,'peers':[peer]}
    return '[Peer]\n# roaming '+name+'\n'+render(sample).split('[Peer]\n',1)[1]


def write_job(root,job):
    data=json.dumps(job,ensure_ascii=False,indent=2).encode()
    if len(data)>MAX_BYTES:raise ValueError('Операция клиента превышает допустимый размер журнала')
    atomic_write(root/'client-operation.json',data)


def finish_locked(root,profiles,identifier,command=run):
    job=operation_state(root)
    if job.get('id')!=identifier or job.get('status')=='completed':return job
    config,_=settings(root)
    if config['interface']!=job['interface']:raise ValueError('Серверный интерфейс изменился; завершение остановлено')
    server=profiles/(job['interface']+'.conf');actual=revision(read_private(server))
    if actual not in (job['before_revision'],revision(job['after'].encode())):
        raise ValueError('Конфигурация WG изменена другим действием. Незавершённая операция сохранена для восстановления')
    directory=Path(config['directory'])
    if job.get('client_file'):
        path=directory/job['client_file'];content=job['client_config'].encode()
        if path.exists():
            if read_private(path)!=content:raise ValueError('Файл клиента уже занят другим содержимым')
        else:atomic_write(path,content)
    if job['action']=='disable':
        atomic_write(root/('disabled-'+peer_id(job['peer'])+'.json'),json.dumps({'peer':job['peer'],'name':job['name']},ensure_ascii=False).encode())
    if actual==job['before_revision']:atomic_write(server,job['after'].encode())
    public=job['peer']['PublicKey'];args=['/usr/bin/wg','set',job['interface'],'peer',public]
    if job['action']=='disable':command(args+['remove'])
    else:
        # A stored server peer can include a PSK; send it only on stdin.
        peer=job['peer'];data=None;args+=['allowed-ips',','.join(peer['AllowedIPs'])]
        if 'PresharedKey' in peer:args+=['preshared-key','/dev/stdin'];data=peer['PresharedKey']+'\n'
        if 'Endpoint' in peer:args+=['endpoint',peer['Endpoint']]
        if 'PersistentKeepalive' in peer:args+=['persistent-keepalive',str(peer['PersistentKeepalive'])]
        command(args,data)
    live={}
    for line in command(['/usr/bin/wg','show',job['interface'],'allowed-ips']).splitlines():
        fields=line.split(maxsplit=1);live[fields[0]]={n for n in re.split(r'[,\s]+',fields[1]) if n and n!='(none)'}
    if (public in live if job['action']=='disable' else live.get(public)!=set(job['peer']['AllowedIPs'])):
        raise ValueError('Изменение сохранено, но состояние пира не подтверждено. Операция будет завершена повторно')
    if job['action']!='disable':(root/('disabled-'+peer_id(job['peer'])+'.json')).unlink(missing_ok=True)
    job['status']='completed';job['finished_at']=time.time();write_job(root,job)
    return job


def mutate(request,config,root,profiles,command=run,network=Path('/var/lib/okopy-candidate')):
    # Caller holds the same exclusive lock as the interface editor.
    from wireguard_apply import PENDING
    p=root/'transaction.json'
    if p.exists() and json.loads(read_private(p)).get('status') in PENDING:
        raise ValueError('Сначала завершите изменение интерфейса WireGuard')
    pending=operation_state(root)
    if pending and pending.get('status')!='completed':raise ValueError('Сначала завершите предыдущую операцию клиента')
    with (network/'apply.lock').open('r') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Сейчас меняется сетевая политика. Повторите после завершения') from None
        if json.loads((network/'transaction.json').read_text()).get('status')!='confirmed':raise ValueError('Сначала подтвердите сетевую политику')
        raw=read_private(profiles/(config['interface']+'.conf'));rows,files,model,rev,_,_=inventory(config,profiles,command)
        if request['file_revision']!=rev:raise ValueError('Список клиентов изменился. Обновите страницу')
        action=request['action'].removeprefix('clients-');content=None;filename=None
        if action=='add':
            if len(model['peers'])>=64:raise ValueError('Поддерживается до 64 пиров')
            name,peer,content=build_client(model,files,request['values'],config,command)
            # Every allocated address must already be admitted to common policy.
            ingress=json.loads((network/'applied-policy.json').read_text()).get('vpn_ingress',{})
            if not ingress.get('enabled') or ingress.get('interface')!=config['interface']:raise ValueError('Сначала включите вход этой сети WG в общей политике')
            for address in peer['AllowedIPs']:
                ip=ipaddress.ip_interface(address).ip;scope=ingress.get('clients' if ip.version==4 else 'clients_v6',[])
                if not any(ip in ipaddress.ip_network(n) for n in scope):raise ValueError('Адрес нового клиента не допущен в общую политику. Добавьте сеть WG в разделе подключения устройств')
            filename=str(ipaddress.ip_interface(peer['AllowedIPs'][0]).ip)+'.conf'
            if os.path.lexists(Path(config['directory'])/filename):raise ValueError('Файл для нового адреса уже существует')
            after=raw.decode().rstrip()+'\n\n'+peer_block(peer,name,model['interface'])
        elif action=='disable':
            row=next((r for r in rows if r['id']==request['id'] and r['downloadable']),None)
            if not row:raise ValueError('Сначала импортируйте и проверьте клиентский конфиг устройства')
            name=row['name'];peer=next(p for p in model['peers'] if peer_id(p)==row['id'])
            blocks=re.split(r'(?m)(?=^\s*\[Peer\]\s*$)',raw.decode());kept=[]
            for block in blocks:
                if re.search(r'(?m)^PublicKey\s*=\s*'+re.escape(peer['PublicKey'])+r'\s*$',block):continue
                kept.append(block)
            after=''.join(kept);assert len(parse(after)['peers'])==len(model['peers'])-1
        elif action=='enable':
            identifier=request['id']
            if not re.fullmatch('[0-9a-f]{24}',identifier):raise ValueError('Некорректный клиент')
            saved=json.loads(read_private(root/('disabled-'+identifier+'.json')));peer=saved['peer'];name=saved['name']
            if peer_id(peer)!=identifier or any(p['PublicKey']==peer['PublicKey'] for p in model['peers']):raise ValueError('Клиент уже включён или изменён')
            if peer['PublicKey'] not in files:raise ValueError('Закрытый конфиг клиента не найден')
            client=files[peer['PublicKey']][1]
            if not matches_client(client,peer,derive(model['interface']['PrivateKey'],command)):
                raise ValueError('Сохранённый конфиг отключённого клиента изменён')
            used=[ipaddress.ip_network(n) for p in model['peers'] for n in p['AllowedIPs']]
            if any(ipaddress.ip_network(n).overlaps(u) for n in peer['AllowedIPs'] for u in used if ipaddress.ip_network(n).version==u.version):raise ValueError('Адрес отключённого клиента занят другим пиром')
            after=raw.decode().rstrip()+'\n\n'+peer_block(peer,name,model['interface'])
        else:raise ValueError('Неизвестное действие клиента')
        parse(after)
        job={'id':uuid.uuid4().hex,'status':'pending','created_at':time.time(),'action':action,'name':name,'peer':peer,
             'interface':config['interface'],'before_revision':rev,'after':after,'client_file':filename,'client_config':content}
        write_job(root,job)
        command(['/usr/bin/systemd-run','--quiet','--unit=okopy-wg-client-'+job['id'],'--on-active=10s','--property=TimeoutStartSec=60s',
                 '/usr/bin/python3','-E','-s','-B',str(Path(__file__).resolve()),job['id']])
        result=finish_locked(root,profiles,job['id'],command)
        return {'id':peer_id(peer),'name':name,'operation':result['status'],'interface_restarted':False}


def finish(root,profiles,identifier,command=run):
    if not re.fullmatch('[0-9a-f]{32}',identifier):raise ValueError('Некорректная операция')
    fd=os.open(root/'control.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        return finish_locked(root,profiles,identifier,command)


if __name__=='__main__':
    if os.geteuid()!=0 or len(sys.argv)!=2:raise SystemExit(2)
    try:finish(ROOT,PROFILES,sys.argv[1])
    except Exception:raise SystemExit(1) from None
