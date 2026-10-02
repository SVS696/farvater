"""Bounded checks before a WG transaction; this module never changes host routes."""
import copy
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import time


def networks(model):
    return [ipaddress.ip_network(n) for peer in model['peers'] for n in peer['AllowedIPs']]


def table(model):
    value=model['interface'].get('Table','auto')
    return 'main' if value in ('auto','254') else value


def conflicts(name,model,others,addresses,routes):
    """others contains only profiles currently active or with a live interface."""
    blocked=[];warnings=[]
    def add(code,message):
        if not any(x['code']==code and x['message']==message for x in blocked):
            blocked.append({'code':code,'message':message})
    own=model['interface'];target_table=table(model);wanted=networks(model)
    other_networks={key:networks(value) for key,value in others.items() if value is not None and key!=name}
    if len(wanted)*(len(routes)+sum(map(len,other_networks.values())))>250000:
        raise ValueError('Слишком много сетей для ограниченной проверки конфликтов; результат не определён')
    def brief(items):
        values=list(dict.fromkeys(items))
        return ', '.join(values[:8])+(' и ещё '+str(len(values)-8) if len(values)>8 else '')
    explicit_port=own.get('ListenPort',0)
    seen={}
    for index,peer in enumerate(model['peers'],1):
        for value in peer['AllowedIPs']:
            if value in seen and seen[value]!=index:
                add('peer-network',f'Сеть {value} назначена пирам {seen[value]} и {index}. У сети должен быть один пир.')
            seen[value]=index
    if target_table=='255':add('local-table','Таблица 255 зарезервирована для локальных адресов системы.')
    if target_table=='main' and any(n.prefixlen==0 for n in wanted):
        add('default-route','Маршрут всего интернета требует отдельной числовой таблицы или Table=off и явной политики. Автоматический общий маршрут может перехватить управление и другие VPN.')
    if target_table=='off':warnings.append('Table=off: маршруты создаёт внешний механизм. Проверка файла не подтверждает его наличие или правильность.')
    for other_name,other in others.items():
        if other_name==name:continue
        if other is None:
            add('unreadable-profile',f'Работающий профиль {other_name} нельзя разобрать. Проверка конфликтов неполна.');continue
        if explicit_port and explicit_port==other['interface'].get('ListenPort',0):
            add('listen-port',f'Порт {explicit_port} уже задан работающему профилю {other_name}.')
        if target_table!='off' and target_table==table(other):
            collisions=[str(n) for n in wanted if any(n.version==r.version and n.overlaps(r) for r in other_networks[other_name])]
            if collisions:add('vpn-network',f'Таблица {target_table}: сети {brief(collisions)} пересекаются с профилем {other_name}. Оставьте один путь или разделите таблицы и политику маршрутизации.')
    for addr in own['Address']:
        proposed=ipaddress.ip_interface(addr)
        for link in addresses:
            if link['ifname']==name:continue
            for existing in link.get('addr_info',[]):
                if existing.get('family') not in ('inet','inet6'):continue
                current=ipaddress.ip_interface(str(existing['local'])+'/'+str(existing['prefixlen']))
                if proposed.version!=current.version:continue
                if proposed.ip==current.ip:add('local-address',f'Адрес {proposed.ip} уже принадлежит интерфейсу {link["ifname"]}.')
                elif proposed.network.prefixlen<proposed.network.max_prefixlen and proposed.network.overlaps(current.network) and not current.ip.is_link_local:
                    add('connected-network',f'Подсеть адреса {addr} пересекается с сетью интерфейса {link["ifname"]}. Подключённый маршрут создаётся в main даже при отдельной Table.')
    if target_table!='off':
        for route in routes:
            rt=str(route.get('table','main'));rt='main' if rt=='254' else rt
            if rt!=target_table or route.get('dev')==name or route.get('dst','default')=='default':continue
            try:existing=ipaddress.ip_network(route['dst'])
            except (ValueError,KeyError):continue
            hits=[str(n) for n in wanted if n.version==existing.version and n.overlaps(existing)]
            if hits:add('host-route',f'Таблица {target_table}: {brief(hits)} пересекается с существующим маршрутом {existing} через {route.get("dev",route.get("type","другой путь"))}.')
    # Responses must remain below the authenticated transport's size limit.
    if len(blocked)>20:blocked=blocked[:19]+[{'code':'more-conflicts','message':'Найдены дополнительные конфликты. Исправьте показанные и повторите проверку.'}]
    return {'blockers':blocked,'warnings':warnings}


def run(args,*,data=None,timeout=8):
    child=subprocess.Popen(args,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:out,_=child.communicate(data,timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid,signal.SIGKILL);child.communicate()
        raise ValueError('Проверка WireGuard не завершилась вовремя; настройки сети не менялись') from None
    if child.returncode or len(out)>1024*1024:
        raise ValueError('Не удалось выполнить проверку WireGuard; настройки сети не менялись')
    return out


def native(model):
    # The namespace has no host links/routes. It dies with the child, including
    # when the whole process group is killed. No named netns or secret temp file.
    from wireguard_profile import render
    candidate=copy.deepcopy(model)
    for peer in candidate['peers']:
        peer.pop('Endpoint',None)  # host/DNS reachability is a separate check
        peer['PersistentKeepalive']=0
    raw=render(candidate)
    stripped='\n'.join(line for line in raw.splitlines() if line.split('=',1)[0].strip() not in ('Address','MTU','Table'))+'\n'
    script="""import subprocess,sys
subprocess.run(['/usr/sbin/ip','link','add','wgcheck','type','wireguard'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
p=subprocess.run(['/usr/bin/wg','setconf','wgcheck','/dev/stdin'],input=sys.stdin.buffer.read(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
sys.exit(p.returncode)
"""
    run(['/usr/bin/unshare','--net','--',sys.executable,'-I','-c',script],data=stripped.encode())
    return True


def check(name,model,profiles,*,observe,read_profile,native_check=native):
    paths=sorted(p for p in profiles.glob('*.conf') if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',p.stem))
    if len(paths)>64:raise ValueError('Проверка поддерживает до 64 профилей WireGuard')
    observed=observe([p.stem for p in paths]);others={}
    for p in paths:
        if p.stem==name:continue
        row=observed[p.stem]
        if row['service']=='unknown' or row['interface'] is None:
            raise ValueError('Не удалось проверить состояние остальных профилей WireGuard')
        if row['interface'] or row['service'] in ('active','activating','reloading','deactivating'):
            try:others[p.stem]=read_profile(p)
            except ValueError:others[p.stem]=None
    try:
        addresses=json.loads(run(['/usr/sbin/ip','-j','address','show']))
        routes=json.loads(run(['/usr/sbin/ip','-N','-j','route','show','table','all']))+json.loads(run(['/usr/sbin/ip','-N','-j','-6','route','show','table','all']))
    except (ValueError,TypeError):raise ValueError('Не удалось прочитать текущие адреса и маршруты для проверки WireGuard') from None
    result=conflicts(name,model,others,addresses,routes)
    # Validate kernel fields even if route conflicts exist; no tunnel is started.
    result['native_valid']=native_check(model)
    result.update(checked_at=time.time(),scope='activation',traffic_verified=False,
                  note='Проверка оценивает включение этого профиля. Ключи и AllowedIPs приняты ядром в изолированном пространстве; Endpoint, DNS и передача трафика этим не проверены.')
    return result
