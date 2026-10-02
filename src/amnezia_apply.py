"""Run the common profile transaction with AWG's codec and runtime backend."""
import json,sys
from amnezia_runtime import ROOT,PROFILES,AmneziaBackend
from amnezia_profile import parse
from wireguard_apply import Transaction,main

if __name__=='__main__':
    try:print(json.dumps({'ok':True,'result':main(Transaction(ROOT,PROFILES,AmneziaBackend(PROFILES),parser=parse))}))
    except Exception as error:
        print(json.dumps({'ok':False,'message':str(error) if isinstance(error,ValueError) else 'Операция AWG не завершилась'}));sys.exit(1)
