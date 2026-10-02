"""Render private native-client files from the validated OpenConnect model."""
from pathlib import Path
from openconnect_profile import validate,NUMBERS,FLAGS


def render_files(model,binding,directory):
    model=validate(model,ready=True);directory=Path(directory)
    if not directory.is_absolute() or any(c.isspace() for c in str(directory)):
        raise ValueError('Каталог управляемого подключения должен быть абсолютным и без пробелов')
    options=[('protocol',model['protocol']),('server',model['server']),('interface',binding['interface']),
             ('script',binding['script']),('non-inter',None),('compression',model['compression'])]
    for key,option in [('username','user'),('authgroup','authgroup'),('usergroup','usergroup'),('useragent','useragent'),
                       ('os','os'),('local_hostname','local-hostname'),('servercert','servercert')]:
        if model[key]:options.append((option,model[key]))
    for key in NUMBERS:
        if model[key] is not None:options.append((key.replace('_','-'),str(model[key])))
    for key in FLAGS:
        if model[key]:options.append((key.replace('_','-'),None))
    files={'ca.pem':model['ca'].encode(),'client.pem':model['certificate'].encode(),'key.pem':model['private_key'].encode()}
    for key,option,file in [('ca','cafile','ca.pem'),('certificate','certificate','client.pem'),('private_key','sslkey','key.pem')]:
        if model[key]:options.append((option,str(directory/file)))
    if model['key_password']:options.append(('key-password',model['key_password']))
    if model['auth_mode']=='password':
        options.append(('passwd-on-stdin',None));secret=model['password']
    elif model['auth_mode']=='cookie':
        options.append(('cookie-on-stdin',None));secret=model['cookie']
    else:options.append(('no-passwd',None));secret=''
    files['stdin.txt']=(secret+'\n').encode()
    files['client.conf']=('\n'.join(key+('='+value if value is not None else '') for key,value in options)+'\n').encode()
    return files
