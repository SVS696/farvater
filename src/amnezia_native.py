"""Official AWG userspace validation in a disposable network namespace."""
import copy,json,sys,uuid
from pathlib import Path
from wireguard_preflight import run
from amnezia_profile import render

BIN=Path('/opt/farvater/engines/amneziawg/current')


def stripped(model,*,isolated=False):
    model=copy.deepcopy(model)
    if isolated:
        for peer in model['peers']:
            peer.pop('Endpoint',None);peer['PersistentKeepalive']='0'
    raw=render(model,runtime=True)
    return '\n'.join(line for line in raw.splitlines() if line.split('=',1)[0].strip() not in ('Address','MTU','Table'))+'\n'


def native(model):
    raw=stripped(model,isolated=True)
    script='''import sys,json,subprocess,time,os
from pathlib import Path
value=json.load(sys.stdin);name=value['name'];base=Path(value['bin'])
p=subprocess.Popen([str(base/'amneziawg-go'),'-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
 for _ in range(40):
  if Path('/run/amneziawg',name+'.sock').exists():break
  if p.poll() is not None:raise ValueError('AWG validation process stopped')
  time.sleep(.05)
 else:raise ValueError('AWG validation socket unavailable')
 result=subprocess.run([str(base/'awg'),'setconf',name,'/dev/stdin'],input=value['raw'].encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if result.returncode:raise ValueError('AWG rejected parameters')
finally:
 p.terminate()
 try:p.wait(timeout=2)
 except subprocess.TimeoutExpired:p.kill();p.wait()
'''
    run(['/usr/bin/unshare','--net','--',sys.executable,'-I','-c',script],
        data=json.dumps({'name':'awgc'+uuid.uuid4().hex[:9],'bin':str(BIN),'raw':raw}).encode(),timeout=8)
    return True
