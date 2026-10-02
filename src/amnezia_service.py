"""Start one AWG interface with routes used only by sockets bound to it.

No resolver or main-table changes; all addresses use noprefixroute. User shell
hooks are excluded by the native profile parser. Source .conf retains DNS.
"""
import ipaddress,json,os,sys,time
from pathlib import Path
from amnezia_profile import parse
from amnezia_native import BIN,stripped
from wireguard_control import profile_name,read_private
from wireguard_runtime import command
from safe_apply import atomic_write

PROFILES=Path('/etc/amnezia/amneziawg')
RUNTIME=Path('/run/okopy-amnezia')
RULE_PRIORITY=10000
ROUTE_PROTOCOL=186


def routing_table(model):
    value=str(model['interface'].get('Table',''))
    if not value.isascii() or not value.isdigit() or not 256<=int(value)<=4294967294:
        raise ValueError('AWG требует отдельную числовую таблицу маршрутов; она назначается при создании подключения')
    return int(value)


def route_rows(table):
    return [r for family in ('-4','-6') for r in json.loads(command(['ip',family,'-N','-j','route','show','table','all'])[1]) if str(r.get('table'))==str(table)]


def check_table(name,model):
    table=routing_table(model)
    for row in route_rows(table):
        if row.get('dev')==name and str(row.get('protocol'))==str(ROUTE_PROTOCOL):continue
        if str(row.get('type')) in ('unreachable','7') and str(row.get('protocol'))==str(ROUTE_PROTOCOL) and (RUNTIME/(name+'.json')).exists():continue
        raise ValueError('Таблица маршрутов занята другим подключением; выберите свободную в дополнительных настройках')
    for family in ('-4','-6'):
        for row in json.loads(command(['ip',family,'-N','-j','rule','show'])[1]):
            if str(row.get('table'))==str(table) and row.get('oif')!=name:
                raise ValueError('На эту таблицу уже ссылается чужое правило маршрутизации')
    return table


def stop(name):
    path=RUNTIME/(name+'.json')
    # Only a runtime receipt created before this interface is our cleanup owner.
    if not path.exists():
        if command(['ip','link','show','dev',name],required=False)[0]==0:raise ValueError('Интерфейс существует без записи запуска; автоматическое удаление запрещено')
        return
    state=json.loads(read_private(path));table=state['table']
    if type(table) is not int or not 256<=table<=4294967294:raise ValueError('Запись маршрутов AWG повреждена')
    for family in ('-4','-6'):
        command(['ip',family,'rule','del','priority',str(RULE_PRIORITY),'oif',name,'lookup',str(table)],required=False)
        command(['ip',family,'route','flush','table',str(table),'proto',str(ROUTE_PROTOCOL)],required=False)
    command(['ip','link','delete',name],required=False)
    if command(['ip','link','show','dev',name],required=False)[0]==0:raise ValueError('Не удалось остановить интерфейс AWG')
    for family in ('-4','-6'):
        rows=json.loads(command(['ip',family,'-N','-j','rule','show'])[1])
        if any(r.get('oif')==name and str(r.get('table'))==str(table) for r in rows):raise ValueError('Правило AWG ещё не удалено')
    if any(str(r.get('protocol'))==str(ROUTE_PROTOCOL) for r in route_rows(table)):raise ValueError('Маршруты AWG ещё не удалены')
    path.unlink()


def start(name):
    model=parse(read_private(PROFILES/(name+'.conf')).decode());raw=stripped(model)
    if command(['ip','link','show','dev',name],required=False)[0]==0:raise ValueError('Имя интерфейса уже занято')
    table=check_table(name,model)
    RUNTIME.mkdir(mode=0o700,exist_ok=True)
    if RUNTIME.is_symlink() or RUNTIME.stat().st_uid!=0 or RUNTIME.stat().st_mode&0o077:raise ValueError('Небезопасный каталог состояния AWG')
    receipt=RUNTIME/(name+'.json')
    if receipt.exists():raise ValueError('Есть незавершённая запись запуска AWG; сначала остановите профиль')
    atomic_write(receipt,json.dumps({'table':table}).encode())
    try:
        command([str(BIN/'amneziawg-go'),name],timeout=6)
        for _ in range(40):
            if Path('/run/amneziawg',name+'.sock').exists():break
            time.sleep(.05)
        else:raise ValueError('Не появился управляющий сокет AWG')
        command([str(BIN/'awg'),'setconf',name,'/dev/stdin'],data=raw.encode())
        for address in model['interface']['Address']:
            command(['ip','address','add',address,'dev',name,'noprefixroute'])
        mtu=model['interface'].get('MTU',1280)
        command(['ip','link','set','dev',name,'addrgenmode','none'])
        Path('/proc/sys/net/ipv4/conf',name,'rp_filter').write_text('2')
        command(['ip','link','set','dev',name,'mtu',str(mtu),'up'])
        for family in ('-4','-6'):
            command(['ip',family,'route','add','unreachable','default','table',str(table),'metric','32767','proto',str(ROUTE_PROTOCOL)])
        for network in sorted({n for peer in model['peers'] for n in peer['AllowedIPs']}):
            family='-4' if ipaddress.ip_network(network).version==4 else '-6'
            command(['ip',family,'route','add',network,'dev',name,'table',str(table),'proto',str(ROUTE_PROTOCOL)])
        for family in ('-4','-6'):
            command(['ip',family,'rule','add','priority',str(RULE_PRIORITY),'oif',name,'lookup',str(table)])
    except Exception:
        stop(name);raise


if __name__=='__main__':
    try:
        if os.geteuid()!=0:raise ValueError('Нужны права root')
        action,name=sys.argv[1:];profile_name(name)
        if action not in ('up','down'):raise ValueError('Неизвестное действие')
        (start if action=='up' else stop)(name)
    except Exception:
        print('Запуск или остановка AmneziaWG не завершены; проверьте профиль и состояние интерфейса',file=sys.stderr);sys.exit(1)
