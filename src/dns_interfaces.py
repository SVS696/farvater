"""Read-only choices for the DHCP DNS form, collected on the network server."""
import json,re,subprocess


def status():
    def read(args):
        result=subprocess.run(args,capture_output=True,text=True,timeout=3,check=True)
        if len(result.stdout)>256*1024:raise ValueError('Слишком большой ответ о сетевых интерфейссах')
        return json.loads(result.stdout)
    routes=read(['ip','-j','route','show','default'])
    default=next((r.get('dev') for r in sorted(routes,key=lambda r:r.get('metric',0)) if r.get('dev')),None)
    interfaces=[]
    for link in read(['ip','-j','address','show']):
        name=link.get('ifname','')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}',name) or name=='lo':continue
        addresses=[a['local'] for a in link.get('addr_info',[]) if a.get('family')=='inet']
        if not addresses:continue
        interfaces.append({'name':name,'addresses':addresses,'default':name==default,'up':'UP' in link.get('flags',[])})
    interfaces.sort(key=lambda item:(not item['default'],not item['up'],item['name']))
    return {'interfaces':interfaces[:64]}
