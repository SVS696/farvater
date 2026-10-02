"""Compile complete ordered policy fragments for atomic DNS/exit modes.

Uses sing-box's single mode update already exercised by the candidate. There is
no second runtime or independently switched DNS selector. The state-space limit
is checked before generation, never silently truncating a user's queue.
"""
import copy
import hashlib
import itertools
import json
import math

from policy import validate_policy
from rule_compiler import compile_profiles, conjunction
from failover_form import default_group


ACTION_FIELDS = {'action', 'server', 'outbound', 'rcode', 'answer', 'ns', 'extra', 'no_drop', 'method'}


def in_mode(rule, mode):
    match = {k: v for k, v in rule.items() if k not in ACTION_FIELDS}
    action = {k: v for k, v in rule.items() if k in ACTION_FIELDS}
    return {**conjunction(match, {'clash_mode': mode}), **action}


def compile_policy_modes(policy, *, default_filtering, source_identity=False, filtered_resolvers=None):
    issues = [issue for issue in validate_policy(policy) if issue['severity'] == 'error']
    if issues:
        raise ValueError('; '.join(i['profile']+': '+i['message'] for i in issues))
    queues = {}
    for profile in policy.get('profiles', []):
        if not profile.get('enabled', True):
            continue
        if profile.get('fallback'):
            raise ValueError(profile['name']+': резерв без DNS необходимо заменить согласованными парами')
        if profile.get('fallback_pairs'):
            queues['rule:'+profile['id']] = [
                {'exit': profile['exit'], 'dns': profile['dns']},
                *copy.deepcopy(profile['fallback_pairs'])]
    if policy.get('failover'):
        queues['default'] = list(default_group(policy['failover'])['states'].values())
    else:
        queues['default'] = [{'exit': policy['default_exit'], 'dns': policy['default_dns']}]
    combinations = math.prod(len(queue) for queue in queues.values())
    if combinations > 64:
        raise ValueError('Больше 64 сочетаний резервирования: сократите число независимых очередей или вариантов')
    modes, dns_rules, route_rules = [], [], []
    for values in itertools.product(*(range(len(queue)) for queue in queues.values())):
        selection = dict(zip(queues, values))
        pairs = {key: queues[key][index] for key, index in selection.items()}
        encoded = json.dumps(pairs, sort_keys=True, separators=(',', ':')).encode()
        name = 'okopy-'+hashlib.sha256(encoded).hexdigest()[:24]
        selected = copy.deepcopy(policy)
        for profile in selected.get('profiles', []):
            key = 'rule:'+profile['id']
            if key in pairs:
                profile.update(pairs[key])
                profile['fallback_pairs'] = []
        default = pairs['default']
        selected.update(default_exit=default['exit'], default_dns=default['dns'])
        compiled = compile_profiles(selected, default_filtering=default_filtering,
                                    source_identity=source_identity, filtered_resolvers=filtered_resolvers)
        dns_rules.extend(in_mode(rule, name) for rule in compiled['dns_rules'])
        route_rules.extend(in_mode(rule, name) for rule in compiled['route_rules'])
        resolver = default['dns']
        if default_filtering:
            if resolver not in (filtered_resolvers or {}):
                raise ValueError('Основной маршрут: нет проверенного пути AdGuard к выбранному DNS')
            resolver = filtered_resolvers[resolver]
        dns_rules.append({'clash_mode': name, 'action': 'route', 'server': resolver})
        route_rules.append({'clash_mode': name, 'action': 'route', 'outbound': default['exit']})
        modes.append({'name': name, 'selection': selection, 'pairs': copy.deepcopy(pairs)})
    # An unrecognized mode must not fall through to a public engine default.
    dns_rules.append({'action': 'reject', 'no_drop': True})
    route_rules.append({'action': 'reject'})
    return {'modes': modes, 'queues': copy.deepcopy(queues), 'dns_rules': dns_rules,
            'route_rules': route_rules, 'initial_mode': modes[0]['name']}
