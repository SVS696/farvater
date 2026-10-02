"""Ordered resolver/exit pairs for an ordinary, work or special rule."""


def validate_pairs(profile, policy):
    pairs = profile.get('fallback_pairs', [])
    if not isinstance(pairs, list) or len(pairs) > 31:
        raise ValueError('Резерв правила должен содержать не более 31 пары')
    seen = {(profile.get('exit'), profile.get('dns'))}
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {'exit', 'dns'}:
            raise ValueError('Для каждого резерва нужны только выход и DNS')
        outbound, resolver = pair['exit'], pair['dns']
        if not isinstance(outbound, str) or not isinstance(resolver, str):
            raise ValueError('Выход и DNS резерва должны быть идентификаторами')
        if outbound not in policy.get('exits', {}) or resolver not in policy.get('dns', {}):
            raise ValueError('Резерв ссылается на неизвестный выход или DNS')
        identity = (outbound, resolver)
        if identity in seen:
            raise ValueError('Пара выхода и DNS повторяется в очереди')
        seen.add(identity)
        if profile.get('kind') in ('work', 'special'):
            if (not profile.get('dns_only') and policy['exits'][outbound].get('scope') not in ('work', 'special')):
                raise ValueError('Резерв защищённого правила не может использовать публичный выход')
            if policy['dns'][resolver].get('scope') not in ('work', 'special'):
                raise ValueError('Резерв защищённого правила не может использовать публичный DNS')
    return pairs


def parse_pairs(form):
    exits, resolvers = form.getlist('fallback_exit'), form.getlist('fallback_dns')
    if len(exits) != len(resolvers) or len(exits) > 32:
        raise ValueError('Повреждён список резервных пар')
    pairs = []
    for outbound, resolver in zip(exits, resolvers):
        if not outbound and not resolver:
            continue
        if not outbound or not resolver:
            raise ValueError('У каждого резервного варианта выберите и выход, и DNS')
        pairs.append({'exit': outbound, 'dns': resolver})
    return pairs
