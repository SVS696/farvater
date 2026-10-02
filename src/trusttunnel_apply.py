"""TrustTunnel adapter uses the same durable transaction as OpenConnect."""
import fcntl
import os
import re
import sys
from pathlib import Path
from openconnect_apply import Transaction as ServiceTransaction,state,PENDING,public,NETWORK
from trusttunnel_profile import validate
from trusttunnel_runtime import ROOT,LinuxBackend


class Transaction(ServiceTransaction):
    def __init__(self,root,binding,name,backend=None,network=NETWORK):
        super().__init__(root,binding,name,backend or LinuxBackend(root,binding,name),network,model_validator=validate)


def rollback_command(identifier):
    from trusttunnel_control import binding_for
    with (ROOT/'control.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        s=state(ROOT)
        if s.get('id')!=identifier or s.get('status') not in PENDING:return
        name=s['connection'];Transaction(ROOT,binding_for(ROOT,name),name).rollback(identifier)


if __name__=='__main__':
    os.umask(0o077)
    if len(sys.argv)!=3 or sys.argv[1]!='rollback' or not re.fullmatch('[0-9a-f]{32}',sys.argv[2]):raise SystemExit(64)
    rollback_command(sys.argv[2])
