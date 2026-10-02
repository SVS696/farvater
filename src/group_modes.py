"""Compile several DNS/exit selections to one native sing-box mode switch.

Only configured combinations are generated. The bounded state space keeps the
configuration inspectable; it does not add a DNS daemon or restart the engine.
"""
import itertools
import math
import re
from policy import singbox_match, profiles_overlap


def compile_group_modes(groups, exits, resolvers):
    if not groups:raise ValueError('Нужна хотя бы одна группа переключения')
    identifiers=set()
    for index,group in enumerate(groups):
        identifier=group.get('id','')
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}',identifier) or identifier in identifiers:
            raise ValueError('Идентификаторы групп должны быть уникальны: латиница, цифры и дефис')
        identifiers.add(identifier)
        if group.get('kind') not in ('public','work','special'):
            raise ValueError('Неизвестная категория группы')
        if group.get('networks'):
            raise ValueError('Группы DNS/выхода пока поддерживают только домены; подсети задайте защищённым профилем')
        if not group.get('states'):raise ValueError('В группе нет вариантов')
        if not group.get('domains') and index!=len(groups)-1:
            raise ValueError('Группа по умолчанию должна быть последней')
        if group.get('kind') in ('work','special'):
            for prior in groups[:index]:
                if prior.get('kind') not in ('work','special') and (
                    not group.get('domains') or profiles_overlap(prior,group)):
                    raise ValueError('Публичная группа перекрывает защищённую: '+identifier)
        for name,pair in group['states'].items():
            if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}',name):raise ValueError('Некорректное имя варианта')
            if pair.get('blocked'):
                if pair.get('exit') or pair.get('dns'):raise ValueError('Блокировка не должна одновременно задавать DNS или выход')
                continue
            if pair.get('exit') not in exits or pair.get('dns') not in resolvers:
                raise ValueError('Вариант ссылается на неизвестный DNS или выход')
            if group.get('kind') in ('work','special') and (
                exits[pair['exit']].get('scope') not in ('work','special') or resolvers[pair['dns']].get('scope') not in ('work','special')):
                raise ValueError('Защищённая группа не может переключаться на публичный DNS или выход')
    combinations=math.prod(len(g['states']) for g in groups)
    # simplicity: at most 64 combined states; revisit before enabling more;
    # upgrade requires a measured alternative, not silently exponential output.
    if combinations>64:raise ValueError('Больше 64 сочетаний резервирования: сократите число независимых групп или вариантов')
    modes=[];dns_rules=[];route_rules=[]
    for selection in itertools.product(*(g['states'] for g in groups)):
        name='__'.join(g['id']+'-'+state for g,state in zip(groups,selection))
        modes.append({'name':name,'selection':dict(zip((g['id'] for g in groups),selection))})
        for group,state in zip(groups,selection):
            pair=group['states'][state]
            match={'clash_mode':name}
            if group.get('domains'):
                match={'type':'logical','mode':'and','rules':[
                    singbox_match(group['domains'],[],group.get('exclude_domains')),match]}
            if pair.get('blocked'):
                dns_rules.append({**match,'action':'reject'})
                route_rules.append({**match,'action':'reject'})
            else:
                dns_rules.append({**match,'action':'route','server':pair['dns']})
                route_rules.append({**match,'action':'route','outbound':pair['exit']})
    return {'modes':modes,'dns_rules':dns_rules,'route_rules':route_rules}
