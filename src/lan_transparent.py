"""Native nftables capture, with a persistent closed guard when the core stops.

The guard is derived from the same declared targets. Emptying the target list
detaches capture entirely; disabling the LAN listener retains an explicit drop
for those targets. This prevents forwarding via the host's default route while
its proxy socket is closed. No extra daemon or generic firewall API is exposed.
"""
import hashlib
import json

from lan_ingress import CAPTURE_MARK, TPROXY_PORT
from safe_apply import atomic_write, remove_created_file

TABLE = 'okopy_lan'
LOCAL_TABLE = '15455'


def configured(value): return bool(value.get('transparent_targets'))


def script(value, opened):
    if not configured(value): raise ValueError('Transparent targets missing')
    clients = ', '.join(value['clients'])
    targets = ', '.join(value['transparent_targets'])
    bypass = ', '.join(['0.0.0.0/8','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4','240.0.0.0/4',
                        value['listen'],value['gateway'],*value['clients']])
    action = (f'meta l4proto {{ tcp, udp }} tproxy to {value["listen"]}:{TPROXY_PORT} meta mark set {CAPTURE_MARK} accept\n'
              if opened else '') + 'drop\n'
    return f'''table ip {TABLE} {{
 chain capture {{
  type filter hook prerouting priority -151; policy accept;
  iifname {json.dumps(value['interface'])} ip saddr {{ {clients} }} ip daddr {{ {targets} }} meta l4proto {{ tcp, udp }} jump selected
 }}
 chain selected {{
  ip daddr {{ {bypass} }} return
  {action}
 }}
}}
'''


def exists(run):
    return 'table ip '+TABLE in run(['nft','list','tables']).stdout.splitlines()


def normalized(raw):
    """Ignore only kernel handles/version metadata; rule semantics remain exact."""
    def clean(value):
        if isinstance(value,dict): return {k:clean(v) for k,v in value.items() if k not in ('handle',)}
        if isinstance(value,list): return [clean(v) for v in value]
        return value
    rows=json.loads(raw)['nftables']
    return clean([row for row in rows if 'metainfo' not in row])


def signature(value, opened):
    return hashlib.sha256(script(value,opened).encode()).hexdigest()


def set_guard(root, value, opened, run):
    present=exists(run);stamp=root/'lan-nft.json'
    if present and not stamp.exists(): raise ValueError('Reserved nft table has another owner')
    prefix=f'delete table ip {TABLE}\n' if present else ''
    commands=prefix+script(value,opened)
    # The ownership intent is durable even if nft succeeds and the process dies
    # before reading its result. The full batch replaces the old guard atomically.
    atomic_write(stamp,json.dumps({'signature':signature(value,opened),'ready':False}).encode())
    run(['nft','-f','-'],input=commands)
    actual=normalized(run(['nft','-j','list','table','ip',TABLE]).stdout)
    atomic_write(stamp,json.dumps({'signature':signature(value,opened),'ready':True,'rules':actual}).encode())


def clear(root, run):
    stamp=root/'lan-nft.json'
    if exists(run):
        if not stamp.exists(): raise ValueError('Reserved nft table has another owner')
        run(['nft','delete','table','ip',TABLE])
    remove_created_file(stamp)


def verify(root, value, opened, run):
    stamp=root/'lan-nft.json'
    if not configured(value):
        if exists(run) or stamp.exists(): raise ValueError('Undeclared transparent guard remains')
        return
    expected=json.loads(stamp.read_text())
    if expected.get('ready') is not True or expected.get('signature')!=signature(value,opened):
        raise ValueError('Transparent guard does not match current policy')
    if normalized(run(['nft','-j','list','table','ip',TABLE]).stdout)!=expected.get('rules'):
        raise ValueError('Transparent nft rules changed')
