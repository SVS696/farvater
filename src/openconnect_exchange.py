"""Standard OpenConnect files for the embedded client; reject lossy conversion."""
import copy
from openconnect_profile import DEFAULT,validate,import_config
from openconnect_export import export_bundle
from native_endpoints import validate_endpoint

TEXT_MAP={'server':'server','username':'username','authgroup':'auth_group','useragent':'user_agent','os':'reported_os','local_hostname':'local_hostname','password':'password','cookie':'cookie','mtu':'mtu','base_mtu':'base_mtu','dtls_local_port':'dtls_local_port'}
FLAGS_MAP={'no_dtls':'no_udp','disable_ipv6':'ipv6_disabled'}
DURATIONS={'force_dpd':'dpd_interval','reconnect_timeout':'reconnect_timeout'}

def from_model(model,resolver):
    model=validate(model)
    unsupported=('servercert','certificate','private_key','key_password','no_http_keepalive','no_system_trust','pfs','tcp_keepalive')
    if any(model[k]!=DEFAULT[k] for k in unsupported) or model['compression']=='all':
        raise ValueError('Встроенный клиент не переносит эти параметры без потерь. Используйте стандартный OpenConnect для сертификатов, pin и дополнительных режимов.')
    native={'type':'openconnect','system':False,'flavor':model['protocol'],'domain_resolver':resolver}
    for source,target in TEXT_MAP.items():
        if model[source] not in ('',None):native[target]=model[source]
    if model['usergroup']:native['server']=native['server'].rstrip('/')+'/'+model['usergroup'].lstrip('/')
    for source,target in FLAGS_MAP.items():native[target]=model[source]
    for source,target in DURATIONS.items():
        if model[source] is not None:native[target]=str(model[source])+'s'
    native['compression_disabled']=model['compression']=='none'
    if model['ca']:native['tls']={'certificate_authority':model['ca']}
    validate_endpoint(native)
    return native

def to_model(native):
    validate_endpoint(native)
    known={'type','tag','system','flavor','domain_resolver','compression_disabled','tls','tcp_keep_alive_enabled',*TEXT_MAP.values(),*FLAGS_MAP.values(),*DURATIONS.values()}
    if set(native)-known or native.get('tcp_keep_alive_enabled'):
        raise ValueError('Есть параметры без точного соответствия в OpenConnect .conf. Экспортируйте native JSON, чтобы сохранить их.')
    tls=native.get('tls',{})
    if set(tls)-{'enabled','insecure','certificate_authority'} or tls.get('insecure'):
        raise ValueError('Эти параметры TLS нельзя точно перенести в OpenConnect .conf. Экспортируйте native JSON.')
    model=copy.deepcopy(DEFAULT);model['protocol']=native.get('flavor','anyconnect')
    for target,source in TEXT_MAP.items():
        if source in native:model[target]=native[source]
    for target,source in FLAGS_MAP.items():model[target]=native.get(source,False)
    for target,source in DURATIONS.items():
        if source in native:
            value=native[source]
            if not isinstance(value,str) or not value.endswith('s') or not value[:-1].isdigit():raise ValueError('Интервал нельзя точно перенести в секунды')
            model[target]=int(value[:-1])
    model['compression']='none' if native.get('compression_disabled') else 'stateless'
    model['ca']=tls.get('certificate_authority','');model['auth_mode']='cookie' if model['cookie'] else 'password'
    return validate(model,ready=True)

def import_native(raw,format,resolver):
    return from_model(import_config(raw,copy.deepcopy(DEFAULT),{'conf':'openconnect','xml':'anyconnect'}.get(format,format)),resolver)

def export_native(native):return export_bundle(to_model(native))
