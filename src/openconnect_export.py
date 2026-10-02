"""Portable native OpenConnect files plus a lossless panel snapshot.

Archives are read in memory, never extracted or executed. Native files remain
usable with OpenConnect independently of the panel metadata.
"""
import base64
import io
import json
import stat
import zipfile

from openconnect_profile import validate,MAX_BYTES
from openconnect_render import render_files


def native_files(model):
    files=render_files(model,{'interface':'export0','script':'/unused'},'/portable')
    lines=[]
    for line in files['client.conf'].decode().splitlines():
        if line.startswith(('interface=','script=')):continue
        lines.append(line.replace('=/portable/','='))
    files['client.conf']=('\n'.join(lines)+'\n').encode()
    files={k:v for k,v in files.items() if v or k=='stdin.txt'}
    files['panel.json']=(json.dumps({'format':'okopy-openconnect','version':1,'settings':model},ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
    files['README.txt']=('OpenConnect: распакуйте архив в закрытый каталог и перейдите в него.\n'
        'Файлы содержат учётные данные и ключи. Ограничьте доступ к каталогу и файлам.\n'
        'Запуск на Linux с установленным OpenConnect и штатным vpnc-script:\n'
        'sudo openconnect --config=client.conf < stdin.txt\n'
        'Используются стандартные параметры OpenConnect и относительные пути к PEM.\n'
        'Серверные интерфейсы и обработчики маршрутов в архив не переносятся.\n'
        'panel.json дополнительно сохраняет все поля для обратного импорта в панель.\n'
        'Cookie сессии может истечь; экспорт не продлевает её действие.\n').encode()
    return files


def export_bundle(model):
    model=validate(model,ready=True);data=io.BytesIO()
    with zipfile.ZipFile(data,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,content in native_files(model).items():
            info=zipfile.ZipInfo(name);info.create_system=3;info.external_attr=(stat.S_IFREG|0o600)<<16
            info.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(info,content)
    result=data.getvalue()
    if len(result)>MAX_BYTES:raise ValueError('Архив подключения превышает 128 КиБ')
    return base64.b64encode(result).decode()


def import_bundle(encoded):
    def unique(items):
        result={}
        for k,v in items:
            if k in result:raise ValueError('Повторяющееся поле архива')
            result[k]=v
        return result
    try:
        if not isinstance(encoded,str) or len(encoded)>MAX_BYTES*4//3+4:raise ValueError()
        raw=base64.b64decode(encoded,validate=True)
        if len(raw)>MAX_BYTES:raise ValueError()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries=archive.infolist();names=[e.filename for e in entries]
            allowed={'client.conf','stdin.txt','ca.pem','client.pem','key.pem','panel.json','README.txt'}
            if not 4<=len(entries)<=7 or len(set(names))!=len(names) or set(names)-allowed:raise ValueError()
            if sum(e.file_size for e in entries)>4*MAX_BYTES:raise ValueError()
            if any(e.flag_bits&1 or stat.S_ISLNK(e.external_attr>>16) for e in entries):raise ValueError()
            contents={e.filename:archive.read(e) for e in entries}
        snapshot=json.loads(contents['panel.json'],object_pairs_hook=unique)
        if set(snapshot)!={'format','version','settings'} or snapshot['format']!='okopy-openconnect' or type(snapshot['version']) is not int or snapshot['version']!=1:raise ValueError()
        model=validate(snapshot['settings'],ready=True)
        if contents!=native_files(model):raise ValueError()
        return model
    except (ValueError,KeyError,TypeError,UnicodeError,zipfile.BadZipFile,RuntimeError,NotImplementedError,EOFError):
        raise ValueError('Нужен неизменённый ZIP подключения OpenConnect, выгруженный панелью; для другого конфига выберите импорт .conf') from None
