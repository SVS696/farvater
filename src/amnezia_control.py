"""AWG profiles use the existing WG editor and guarded transaction.

An interface and a private routing table are allocated on creation. Importing
another client config keeps that allocation; only this interface's bound traffic
may use its routes. DNS stays in the profile for explicit rule-level selection.
"""
import copy
import json
import uuid
from pathlib import Path
import amnezia_profile as codec
from amnezia_runtime import ROOT,PROFILES,AmneziaBackend,runtime
from amnezia_service import routing_table
from wireguard_control import control as wg_control,read_private
from wireguard_runtime import command


def occupied_tables(profiles):
    used=set()
    for path in profiles.glob('*.conf'):
        # An unreadable existing profile must not silently release its table.
        used.add(routing_table(codec.parse(read_private(path).decode())))
    for family in ('-4','-6'):
        for args in (['route','show','table','all'],['rule','show']):
            rows=json.loads(command(['ip',family,'-N','-j',*args])[1])
            used.update(int(str(r['table'])) for r in rows if str(r.get('table','')).isdigit())
    return used


def prepare_create(name,values,profiles,drafts):
    if name is not None:raise ValueError('Имя интерфейса AWG назначается автоматически')
    if not isinstance(values,dict):raise ValueError('Нужны параметры AWG или файл .conf')
    if set(values)=={'text'}:
        values=codec.parse(values['text'])
    else:
        values=copy.deepcopy(values)
        if not isinstance(values.get('interface'),dict):raise ValueError('Нужны параметры интерфейса AWG')
    # Do not apply Table=auto or a foreign numeric Table from imported configs.
    used=occupied_tables(profiles)
    table=next((n for n in range(30000,31000) if n not in used),None)
    if table is None:raise ValueError('Нет свободной таблицы маршрутов для AWG')
    values['interface']['Table']=str(table)
    for _ in range(8):
        name='awg'+uuid.uuid4().hex[:10]
        if not (profiles/(name+'.conf')).exists() and not (drafts/(name+'.json')).exists():break
    else:raise ValueError('Не удалось назначить свободное имя AWG')
    return name,values


class ManagedCodec:
    parse=staticmethod(codec.parse)
    render=staticmethod(codec.render)
    update=staticmethod(codec.update)
    public_view=staticmethod(codec.public_view)

    @staticmethod
    def prepare_managed(proposed,previous):
        proposed=copy.deepcopy(proposed)
        proposed['interface']['Table']=str(routing_table(previous))
        return proposed


def control(request,*,profiles=PROFILES,drafts=ROOT,observe=runtime,backend=None,**kwargs):
    action=request.get('action','')
    if not isinstance(action,str) or not action.startswith('amnezia-'):raise ValueError('Неизвестное действие AWG')
    translated={**request,'action':'wireguard-'+action[len('amnezia-'):]}
    try:
        result=wg_control(translated,profiles=profiles,drafts=drafts,observe=observe,
                          backend=backend or AmneziaBackend(profiles),codec=ManagedCodec,
                          prepare_create=prepare_create,**kwargs)
        if action=='amnezia-export':
            portable=codec.parse(result['content']);portable['interface'].pop('Table',None)
            result['content']=codec.render(portable)
        if action=='amnezia-create':
            result['dns']=codec.parse(read_private(profiles/(result['name']+'.conf')).decode())['interface'].get('DNS',[])
        return result
    except ValueError as error:
        raise ValueError(str(error).replace('WireGuard','AmneziaWG')) from None
