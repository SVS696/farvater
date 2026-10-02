"""Manual JSON export/apply when the web process is unavailable."""
import argparse,json,os
from pathlib import Path
from candidate_remote import RemoteError
from health_settings import form_fields
from router_health import RouterRemote
from router_settings import validate
from safe_apply import atomic_write


def main():
    parser=argparse.ArgumentParser(description='Настройки измерителя Giga: экспорт и применение без веб-панели')
    parser.add_argument('--state-dir',default=os.environ.get('OKOPY_STATE_DIR'),required=not os.environ.get('OKOPY_STATE_DIR'))
    parser.add_argument('action',choices=['export','apply']);parser.add_argument('file',type=Path)
    args=parser.parse_args();remote=RouterRemote(Path(args.state_dir))
    try:
        if args.action=='export':
            current=remote.status();value={'revision':current['revision'],'check':current['check']}
            atomic_write(args.file,(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode())
            print('Параметры экспортированы. Меняйте поля check; сохраните revision без изменений.')
        else:
            with args.file.open('rb') as stream:raw=stream.read(16385)
            if len(raw)>16384:raise ValueError('Слишком большой файл')
            value=json.loads(raw)
            if not isinstance(value,dict) or set(value)!={'revision','check'}:raise ValueError('Нужен экспорт с полями revision и check')
            check=validate(value['check'])
            result=remote.save(value['revision'],{f['key']:str(f['value']) for f in form_fields(check)})
            print('Параметры сохранены в RAM и на USB; ожидается новый замер. Ревизия: '+result['revision'])
    except (RemoteError,ValueError,OSError) as error:parser.exit(1,str(error)+'\n')

if __name__=='__main__':main()
