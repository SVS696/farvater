"""One ordered public failover group; each state owns both exit and DNS."""

def parse_failover(form,policy):
    try:failures=int(form.get('failures',''));recovery=int(form.get('recovery',''))
    except ValueError:raise ValueError('Порог и время должны быть целыми числами')
    if not 1<=failures<=20 or not 0<=recovery<=3600:
        raise ValueError('Порог отказов: 1–20; время возврата: 0–3600 секунд')
    exits=form.getlist('exit');resolvers=form.getlist('dns')
    if len(exits)!=len(resolvers) or len(exits)>32:
        raise ValueError('Повреждён список пар выхода и DNS')
    priority=[];dns_by_exit={}
    for outbound,resolver in zip(exits,resolvers):
        if not outbound and not resolver:continue
        if not outbound or not resolver:raise ValueError('У каждого варианта должны быть выбраны выход и DNS')
        if outbound in priority:raise ValueError('Выход повторяется в очереди')
        if policy['exits'].get(outbound,{}).get('scope')!='public':
            raise ValueError('Общий резерв допускает только публичные выходы; рабочие и специальные сети настраиваются отдельно')
        dns=policy['dns'].get(resolver,{})
        if dns.get('scope')!='public' or dns.get('native',{}).get('type')=='fakeip':
            raise ValueError('Для общего резерва нужен публичный DNS, способный разрешать обычные имена')
        priority.append(outbound);dns_by_exit[outbound]=resolver
    if not priority:raise ValueError('Добавьте хотя бы один вариант резервирования')
    return {'priority':priority,'dns_by_exit':dns_by_exit,'failures':failures,'recovery_seconds':recovery}

def default_group(failover):
    """Adapter to the tested paired DNS/route mode compiler."""
    mapping=failover.get('dns_by_exit',{})
    if not failover.get('priority') or any(not mapping.get(tag) for tag in failover['priority']):
        raise ValueError('Для каждого резервного выхода нужно явно выбрать DNS')
    return {'id':'default','kind':'public','domains':[],
            'states':{tag:{'exit':tag,'dns':mapping[tag]} for tag in failover['priority']}}

def primary_pair(policy):
    if policy.get('failover'):
        return next(iter(default_group(policy['failover'])['states'].values()))
    return {'exit':policy['default_exit'],'dns':policy['default_dns']}

def validate_failover(failover,policy):
    group=default_group(failover)
    if len(set(failover['priority']))!=len(failover['priority']):
        raise ValueError('Выход повторяется в очереди')
    for pair in group['states'].values():
        if policy['exits'].get(pair['exit'],{}).get('scope')!='public':
            raise ValueError('Общий резерв ссылается на непубличный или отсутствующий выход')
        dns=policy['dns'].get(pair['dns'],{})
        if dns.get('scope')!='public' or dns.get('native',{}).get('type')=='fakeip':
            raise ValueError('Общий резерв ссылается на непубличный, отсутствующий или FakeIP DNS')
