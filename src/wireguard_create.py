"""Create one inactive wg-quick file without replacing existing resources."""
import os
import tempfile

import wireguard_profile as wg_codec
from wireguard_profile import key, render, update
from wireguard_runtime import command


def generate_key():
    return key(command(['/usr/bin/wg', 'genkey'])[1].decode().strip(), 'PrivateKey')


def public_key(private):
    return key(command(['/usr/bin/wg', 'pubkey'], data=(private+'\n').encode())[1].decode().strip(), 'PublicKey')


def create(name, values, profiles, drafts, observe, *, generate=generate_key, derive=public_key,codec=wg_codec):
    render,update=codec.render,codec.update
    from wireguard_control import profile_name, visible, revision
    profile_name(name)
    path=profiles/(name+'.conf')
    if os.path.lexists(path) or os.path.lexists(drafts/(name+'.json')):
        raise ValueError('Имя профиля уже занято файлом или черновиком. Выберите другое имя')
    if len(list(profiles.glob('*.conf')))>=64:
        raise ValueError('Поддерживается до 64 профилей WireGuard')
    observed=observe([name]).get(name,{})
    if observed.get('service')!='inactive' or observed.get('boot')!='disabled' or observed.get('interface') is not False:
        raise ValueError('Новый профиль требует свободного имени, выключенной службы и выключенного автозапуска; состояние должно быть проверено')
    if not isinstance(values,dict) or not isinstance(values.get('interface'),dict):
        raise ValueError('Нужны параметры нового интерфейса WireGuard')
    supplied=values['interface'].get('PrivateKey','')
    private=key(supplied,'PrivateKey') if supplied else generate()
    model=update({'interface':{'PrivateKey':private},'peers':[]},values)
    visible(model,codec)
    public=derive(model['interface']['PrivateKey'])
    content=render(model).encode()
    # link() publishes a fully written file atomically and fails if any actor
    # has occupied the destination since the initial name check.
    fd,temporary=tempfile.mkstemp(prefix='.okopy-create-',dir=profiles)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(content);stream.flush();os.fsync(stream.fileno())
        try:os.link(temporary,path,follow_symlinks=False)
        except FileExistsError:
            raise ValueError('Имя профиля занято во время создания; существующий файл не заменён') from None
        directory=os.open(profiles,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:os.unlink(temporary)
    return {'name':name,'created':True,'runtime_changed':False,'enabled':False,
            'file_revision':revision(content),'public_key':public}
