"""One final rule editor over the existing paired default-route storage.

Keep existing queue identity and applied mode hashes stable: the final rule is
not inserted among conditional profiles or duplicated in a second policy store.
"""
from werkzeug.datastructures import MultiDict
from failover_form import parse_failover
from rule_fallback import parse_pairs


def view(policy):
    fo=policy.get('failover',{})
    priority=fo.get('priority',[])
    pairs=[{'exit':key,'dns':fo.get('dns_by_exit',{}).get(key,policy['default_dns'] if index==0 else '')}
           for index,key in enumerate(priority)]
    if not pairs:pairs=[{'exit':policy['default_exit'],'dns':policy['default_dns']}]
    return {'id':'__default__','name':'Весь остальной трафик','kind':'public','enabled':True,
            **pairs[0],'fallback_pairs':pairs[1:]}


def save(policy,form):
    # Catch-all condition is fixed, not a hidden user-editable matching rule.
    forbidden=('domains','networks','source_networks','exclude_domains','dns_only','route_ports','route_network')
    if any(form.get(key) for key in forbidden):raise ValueError('У последнего правила нельзя задавать условия')
    pairs=[{'exit':form.get('exit',''),'dns':form.get('dns','')},*parse_pairs(form)]
    fo=policy.get('failover',{})
    values=MultiDict([('exit',p['exit']) for p in pairs]+[('dns',p['dns']) for p in pairs]+
                    [('failures',str(fo.get('failures',3))),('recovery',str(fo.get('recovery_seconds',30)))])
    settings=parse_failover(values,policy)
    policy['failover']={**fo,**settings}
    policy.update(default_exit=settings['priority'][0],default_dns=settings['dns_by_exit'][settings['priority'][0]])
