"""Native HTML form to the bounded WireGuard model; no secret readback."""
import re


def parse_form(form):
    value=form.get('peer_count','')
    if not re.fullmatch(r'[0-9]{1,2}',value) or not 0<=int(value)<=64:
        raise ValueError('Некорректное количество пиров в форме')
    count=int(value)
    interface={}
    for key in ('PrivateKey','Address','ListenPort','MTU','Table'):
        value=form.get('interface_'+key,'').strip()
        if value:interface[key]=[x.strip() for x in re.split('[,\n]',value) if x.strip()] if key=='Address' else value
    peers=[]
    for index in range(count+1):
        prefix='peer_'+str(index)+'_'
        peer={}
        for key in ('PublicKey','PresharedKey','AllowedIPs','Endpoint','PersistentKeepalive'):
            value=form.get(prefix+key,'').strip()
            if value:peer[key]=[x.strip() for x in re.split('[,\n]',value) if x.strip()] if key=='AllowedIPs' else value
        clear=form.get(prefix+'clear_preshared_key')=='on'
        remove=form.get(prefix+'remove')=='on'
        if remove:
            if index==count:raise ValueError('Удалять можно только существующего пира')
            continue
        if index==count and not peer and not clear:continue
        peer['clear_preshared_key']=clear
        peers.append(peer)
    if len(peers)>64:raise ValueError('Поддерживается до 64 пиров')
    return {'interface':interface,'peers':peers}
