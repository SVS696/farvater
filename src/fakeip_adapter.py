"""Preserve remote names after a filtering resolver has returned a FakeIP.

sing-box's resolve action fills DestinationAddresses. A normal SOCKS outbound
then sends those addresses, even when inbound FakeIP lookup recovered the name.
A bounded authenticated loopback re-entry clears that resolved-address list by
creating a fresh inbound context, before routing to the original native exit.
"""
import copy
import hashlib
import re

PREFIX='okopy-unmap-'
BASE_PORT=17100
MAX_EXITS=128


def compile_unmapping(policy,config,queues,filtered_resolvers,default_filtering,api_secret):
    used=set()
    def consider(pair,filtering):
        if (filtering and policy['dns'][pair['dns']]['native']['type']=='fakeip'
                and (filtered_resolvers or {}).get(pair['dns'],pair['dns'])!=pair['dns']):
            used.add(pair['exit'])
    for pair in queues['default']:consider(pair,default_filtering)
    for profile in policy.get('profiles',[]):
        if not profile.get('enabled',True):continue
        filtering=profile.get('adguard','inherit')=='on' or (
            profile.get('adguard','inherit')=='inherit' and default_filtering)
        for pair in [{'exit':profile['exit'],'dns':profile['dns']},*profile.get('fallback_pairs',[])]:
            consider(pair,filtering)
    if not used:return []
    if len(used)>MAX_EXITS:raise ValueError('Допускается до 128 выходов с фильтрацией FakeIP')
    if any(e['tag'].startswith(PREFIX) for e in config['outbounds']):
        raise ValueError('Префикс '+PREFIX+' зарезервирован')
    occupied={i['listen_port'] for i in config['inbounds']}|{int(config['experimental']['clash_api']['external_controller'].rsplit(':',1)[1])}
    records=[];routes=[]
    for index,tag in enumerate(sorted(used)):
        port=BASE_PORT+index
        if port in occupied:raise ValueError('Порт восстановления имени FakeIP занят другим входом')
        inbound=PREFIX+str(index);raw_tag=PREFIX+'native-'+str(index)
        secret=hashlib.sha256((api_secret+'\0fakeip-unmapping\0'+tag).encode()).hexdigest()
        native=next(o for o in config['outbounds'] if o['tag']==tag)
        raw=copy.deepcopy(native);raw['tag']=raw_tag;config['outbounds'].append(raw)
        native.clear();native.update(type='socks',tag=tag,server='127.0.0.1',server_port=port,
                                    version='5',username='policy',password=secret)
        config['inbounds'].append({'type':'mixed','tag':inbound,'listen':'127.0.0.1','listen_port':port,
            'users':[{'username':'policy','password':secret}]})
        routes.append({'inbound':[inbound],'action':'route','outbound':raw_tag})
        records.append({'exit':tag,'inbound':inbound,'port':port,'native_exit':raw_tag})
    # This second pass must not resolve the recovered name into FakeIP again.
    # Authentication limits the bypass to this same policy's private adapter.
    config['route']['rules']=routes+config['route']['rules']
    return records


def validate_inbounds(inbounds):
    if len(inbounds)>MAX_EXITS:raise ValueError('Too many FakeIP re-entry listeners')
    for index,entry in enumerate(inbounds):
        users=entry.get('users')
        if (not isinstance(users,list) or len(users)!=1 or set(users[0])!={'username','password'}
                or users[0]['username']!='policy' or not isinstance(users[0]['password'],str)
                or not re.fullmatch('[0-9a-f]{64}',users[0]['password'])):
            raise ValueError('FakeIP re-entry requires private authentication')
        expected={'type':'mixed','tag':PREFIX+str(index),'listen':'127.0.0.1',
                  'listen_port':BASE_PORT+index,'users':users}
        if entry!=expected:raise ValueError('FakeIP re-entry must use reserved authenticated loopback listeners')
