"""AWG form fields and explicit registration in the shared policy draft."""
import re
from amnezia_profile import FIELDS
from wireguard_form import parse_form as wg_form


def parse_form(form):
    value=wg_form(form)
    for key in FIELDS:
        raw=form.get('interface_'+key,'').strip()
        if raw:value['interface'][key]=[x.strip() for x in re.split('[,\n]',raw) if x.strip()] if key=='DNS' else raw
    value['interface']['clear_header_protection_key']=form.get('clear_header_protection_key')=='on'
    # Preserve the original peer indices even when a preceding peer is removed.
    peers=[]
    for index in range(int(form['peer_count'])+1):
        prefix='peer_'+str(index)+'_'
        if form.get(prefix+'remove')=='on':continue
        if index==int(form['peer_count']) and not any(form.get(prefix+k,'').strip() for k in ('PublicKey','PresharedKey','AllowedIPs','Endpoint','PersistentKeepalive','AdvancedSecurity')):continue
        peers.append(form.get(prefix+'AdvancedSecurity','').strip())
    if len(peers)!=len(value['peers']):raise ValueError('Поля пиров неполны; обновите форму')
    for peer,advanced in zip(value['peers'],peers):
        if advanced:peer['AdvancedSecurity']=advanced
    return value


def register(policy,profile,name,scope,dns):
    if not isinstance(name,str) or not 1<=len(name.strip())<=120:raise ValueError('Задайте название подключения до 120 символов')
    if scope not in ('public','work','special'):raise ValueError('Выберите назначение подключения')
    from wireguard_control import profile_name
    profile_name(profile)
    identifier='amnezia-'+profile
    if identifier in policy['exits']:raise ValueError('Это подключение уже добавлено в выходы')
    policy['exits'][identifier]={'name':name.strip(),'scope':scope,'protocol':'AmneziaWG','profile':profile,
                                  'native':{'type':'direct','tag':identifier,'bind_interface':profile}}
    import ipaddress
    for index,address in enumerate(dns,1):
        address=str(ipaddress.ip_address(address));tag=identifier+'-dns-'+str(index)
        if tag in policy['dns']:raise ValueError('Имя DNS уже занято')
        policy['dns'][tag]={'name':name.strip()+' · DNS '+str(index),'scope':scope,
                            'native':{'type':'udp','tag':tag,'server':address,'server_port':53,'detour':identifier}}
    return identifier
