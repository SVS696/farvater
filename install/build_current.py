"""Build a secret-free, hash-verifiable Linux amd64 staging kit from current src.

This command never writes to the host root or starts a service. Installation
and acceptance happen only inside an independently provisioned Linux host.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile


ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'src'
VENDOR=ROOT/'install/vendor'
LOCK=ROOT/'install/requirements-linux-amd64-py311.lock'
ARCHIVES={
 'sing-box':('sing-box-1.14.1-linux-amd64.tar.gz','12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f',
             'sing-box-1.14.1-linux-amd64/',('sing-box','libcronet.so','LICENSE')),
 'trusttunnel-endpoint':('trusttunnel-v1.0.33-linux-x86_64.tar.gz','48802662bc745aed60207c6ed6465d9fed428b1e53532045689d89bcad19bdd9',
                         'trusttunnel-v1.0.33-linux-x86_64/',('trusttunnel_endpoint','LICENSE')),
 'trusttunnel-client':('trusttunnel_client-v1.1.7-linux-x86_64.tar.gz','791f00819e0242b2c38a04bb1403c30aa32701efbcdb059fbc3a6793ff0a45b5',
                       'trusttunnel_client-v1.1.7-linux-x86_64/',('trusttunnel_client','LICENSE')),
}


def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as stream:
  while data:=stream.read(1024*1024):h.update(data)
 return h.hexdigest()


def write(path,data,mode=0o644):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb') as target:target.write(data)
 path.chmod(mode)


def unpack_pinned(role,destination):
 name,expected,prefix,members=ARCHIVES[role];archive=VENDOR/name
 if sha(archive)!=expected:raise ValueError('Official archive digest mismatch: '+role)
 with tarfile.open(archive,'r:gz') as package:
  found={m.name:m for m in package.getmembers() if m.name in {prefix+n for n in members}}
  if set(found)!={prefix+n for n in members}:raise ValueError('Official archive has missing members: '+role)
  for member_name in sorted(found):
   member=found[member_name]
   if not member.isfile() or not 0<member.size<150*1024*1024:raise ValueError('Unsafe archive member: '+role)
   raw=package.extractfile(member).read(member.size+1)
   if len(raw)!=member.size:raise ValueError('Truncated archive member: '+role)
   short=member_name.removeprefix(prefix)
   write(destination/short,raw,0o644 if short=='LICENSE' or short.endswith('.so') else 0o755)
 return {'archive':name,'archive_sha256':expected,'members':{n:sha(destination/n) for n in members}}


def copy_engine(directory,destination,kind,expected_version=None):
 """Copy a prebuilt engine only after manifest, platform and every file match."""
 directory=Path(directory)
 if directory.is_symlink() or not directory.is_dir():raise ValueError('Engine directory is not ordinary')
 manifest=json.loads((directory/'manifest.json').read_text())
 if kind=='amneziawg':
  if manifest.get('version')!='tools-3.1.20260812-go-b5928ef-amd64' or manifest.get('platform')!='linux-amd64':
   raise ValueError('AWG engine version/platform differs from pinned build')
  records=manifest.get('files')
  if not isinstance(records,dict) or set(records)!={'awg','awg-quick','amneziawg-go','LICENSE-go','LICENSE-tools'}:
   raise ValueError('AWG manifest does not list exact pinned files')
 elif kind=='ocserv':
  if manifest.get('platform')!={'os':'ubuntu','version':'24.04','architecture':'amd64'} or manifest.get('package_version')!=expected_version:
   raise ValueError('ocserv engine platform/package version differs from selected pin')
  records=manifest.get('files')
  required={'usr/sbin/ocserv','usr/sbin/ocserv-worker','usr/bin/ocpasswd','usr/bin/occtl'}
  if not isinstance(records,dict) or not required<=set(records):raise ValueError('ocserv engine manifest is incomplete')
 else:raise ValueError('Unknown engine')
 existing={str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()}
 if existing!=set(records)|{'manifest.json'} or any(p.is_symlink() for p in directory.rglob('*')):
  raise ValueError('Engine directory has missing, extra or linked files')
 for name,record in records.items():
  if not isinstance(name,str) or not name or name.startswith('/') or '..' in Path(name).parts:raise ValueError('Unsafe engine path')
  digest=record if kind=='amneziawg' else record.get('sha256')
  if not isinstance(digest,str) or sha(directory/name)!=digest:raise ValueError('Engine file digest mismatch: '+name)
  mode=0o644 if name.startswith('LICENSE') or name.endswith('.so') or name.startswith('licenses/') else 0o755
  write(destination/name,(directory/name).read_bytes(),mode)
 write(destination/'manifest.json',(directory/'manifest.json').read_bytes())
 return {'manifest_sha256':sha(destination/'manifest.json'),'files':len(records),'version':manifest.get('version') or manifest.get('package_version')}


def selected_source():
 files=[]
 for path in SOURCE.rglob('*'):
  if not path.is_file() or path.is_symlink():continue
  rel=path.relative_to(SOURCE)
  if any(part in {'historical-install-materials','privileged-runtime','graphify-out','__pycache__'} for part in rel.parts):continue
  if any(part.startswith('.') for part in rel.parts):continue
  if path.name.startswith('test_'):continue
  files.append(path)
 return sorted(files)


def rootfs_inventory(rootfs):
 files={};links={};directories={}
 for path in sorted(rootfs.rglob('*')):
  name=path.relative_to(rootfs).as_posix()
  if path.is_symlink():links[name]=os.readlink(path)
  elif path.is_file():
   s=path.stat();files[name]={'sha256':sha(path),'bytes':s.st_size,'mode':stat.S_IMODE(s.st_mode)}
  elif path.is_dir():directories[name]=stat.S_IMODE(path.stat().st_mode)
  else:raise ValueError('Unsupported staged rootfs entry: '+name)
 return files,links,directories


def stage_units(destination,*,has_awg,has_ocserv):
 """Stage generic current units; activation and private state belong to install."""
 units=destination/'rootfs/etc/systemd/system'
 runtime_paths=' /run/amneziawg' if has_awg else ''
 runtime_paths+=' /run/farvater-ocserv' if has_ocserv else ''
 candidate=('''[Unit]
Description=Farvater policy core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/okopy-candidate
ExecStartPre=/usr/bin/python3 -E -s -B /var/lib/okopy-candidate/incoming_runtime.py prepare
ExecStart=/var/lib/okopy-candidate/sing-box run -c /var/lib/okopy-candidate/config.json
ExecStartPost=/usr/bin/python3 -E -s -B /var/lib/okopy-candidate/incoming_runtime.py activate
ExecStopPost=/usr/bin/python3 -E -s -B /var/lib/okopy-candidate/incoming_runtime.py cleanup
Restart=on-failure
RestartSec=3s
TimeoutStartSec=90s
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/okopy-candidate /run/farvater'''+runtime_paths+'''
RuntimeDirectory=farvater
RuntimeDirectoryMode=0700
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
''')
 panel='''[Unit]
Description=Farvater web panel
After=network-online.target okopy-candidate.service
Wants=network-online.target

[Service]
Type=simple
User=okopy-panel
Group=okopy-panel
WorkingDirectory=/opt/farvater/app
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=OKOPY_STATE_DIR=/var/lib/okopy-panel
Environment=OKOPY_CANDIDATE_CONTROL=local
Environment=OKOPY_HEALTH_SOURCE=local
Environment=OKOPY_HTTPS=1
Environment=OKOPY_UNIX_SOCKET=/var/www/certbot/.okopy-panel/panel.sock
EnvironmentFile=-/etc/farvater/panel.env
ExecStart=/opt/farvater/venv/bin/python -E -s -B /opt/farvater/app/web.py
Restart=on-failure
RestartSec=3s
UMask=0077
PrivateTmp=yes
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
'''
 write(units/'okopy-candidate.service',candidate.encode())
 write(units/'okopy-candidate.service.d/10-boot-recovery.conf',(
       '[Service]\nExecStartPre=\n'
       'ExecStartPre=/usr/bin/python3 -E -s -B /var/lib/okopy-candidate/safe_apply.py recover-before-start\n'
       'ExecStartPre=/usr/bin/python3 -E -s -B /var/lib/okopy-candidate/incoming_runtime.py prepare\n').encode())
 write(units/'okopy-panel.service',panel.encode())
 write(destination/'rootfs/etc/sudoers.d/okopy-panel',(
       'Defaults:okopy-panel !requiretty\n'
       'okopy-panel ALL=(root) NOPASSWD: /usr/bin/python3 -E -s -B /var/lib/okopy-candidate/candidate_control.py\n').encode(),0o440)
 write(destination/'rootfs/etc/sysusers.d/farvater-panel.conf',
       b'u okopy-panel - "Farvater web panel" /nonexistent /usr/sbin/nologin\n')
 write(units/'wg-quick@.service.d/50-okopy-recovery.conf',(
       '[Service]\nExecStartPre=/usr/bin/python3 -E -s -B /var/lib/okopy-candidate/wireguard_apply.py recover-before-start %i\n'
       'TimeoutStartSec=25s\nTimeoutStopSec=10s\n').encode())
 if has_awg:
  write(units/'okopy-amnezia@.service',(SOURCE/'deploy/okopy-amnezia@.service').read_bytes())
  write(destination/'rootfs/etc/tmpfiles.d/farvater-amneziawg.conf',b'd /run/amneziawg 0700 root root -\n')
 if has_ocserv:
  write(units/'farvater-incoming-ocserv@.service',(SOURCE/'farvater-incoming-ocserv@.service').read_bytes())
  write(destination/'rootfs/etc/sysusers.d/farvater-ocserv.conf',
        b'u farvater-ocserv - "Farvater OpenConnect worker" /nonexistent /usr/sbin/nologin\n')
  write(destination/'rootfs/etc/tmpfiles.d/farvater-ocserv.conf',b'd /run/farvater-ocserv 0711 root root -\n')


def build(destination,*,awg_engine=None,ocserv_engine=None,ocserv_version=None):
 destination=Path(destination).resolve()
 if destination.exists() or destination.is_symlink():raise ValueError('Destination must not exist')
 if not LOCK.is_file():raise ValueError('Current dependency lock is missing')
 destination.mkdir(mode=0o700,parents=False)
 try:
  app=destination/'rootfs/opt/farvater/app';candidate=destination/'rootfs/var/lib/okopy-candidate'
  copied={}
  for path in selected_source():
   rel=path.relative_to(SOURCE);data=path.read_bytes();write(app/rel,data)
   if path.suffix=='.py':write(candidate/path.name,data)
   copied[str(rel)]=hashlib.sha256(data).hexdigest()
  write(destination/'rootfs/opt/farvater/app/requirements-lock.txt',LOCK.read_bytes())
  engines=destination/'rootfs/opt/farvater/engines';result={}
  result['sing-box']=unpack_pinned('sing-box',candidate)
  result['trusttunnel-endpoint']=unpack_pinned('trusttunnel-endpoint',engines/'trusttunnel-endpoint/v1.0.33')
  result['trusttunnel-client']=unpack_pinned('trusttunnel-client',engines/'trusttunnel-client/v1.1.7')
  (engines/'trusttunnel-endpoint/current').symlink_to('v1.0.33',target_is_directory=True)
  (engines/'trusttunnel-client/current').symlink_to('v1.1.7',target_is_directory=True)
  backup_tools=destination/'rootfs/opt/okopy-backup-tools'
  backup_tools.mkdir(parents=True,exist_ok=True)
  (backup_tools/'age').symlink_to('/usr/bin/age')
  if awg_engine is not None:result['amneziawg']=copy_engine(awg_engine,engines/'amneziawg/current','amneziawg')
  if ocserv_engine is not None:
   if not ocserv_version or not re.fullmatch(r'[A-Za-z0-9.+~:-]{1,80}',ocserv_version):raise ValueError('Pin the Ubuntu ocserv package version')
   result['ocserv']=copy_engine(ocserv_engine,engines/'ocserv/current','ocserv',ocserv_version)
  if (awg_engine is None)!=(ocserv_engine is None):
   # The kit can be partial for one selected module, but its manifest must
   # never claim acceptance of a module whose engine was omitted.
   pass
  stage_units(destination,has_awg=awg_engine is not None,has_ocserv=ocserv_engine is not None)
  rescue=destination/'rootfs/opt/okopy-recovery-ui'
  write(rescue/'rescue.py',(SOURCE/'recovery_rescue.py').read_bytes(),0o400)
  write(rescue/'server.py',(SOURCE/'recovery_rescue_web.py').read_bytes(),0o444)
  write(rescue/'writer_guard.py',(SOURCE/'recovery_writer_guard.py').read_bytes(),0o444)
  write(rescue/'access.py',(SOURCE/'recovery_access.py').read_bytes(),0o444)
  write(rescue/'tls_refresh.py',(SOURCE/'recovery_tls_refresh.py').read_bytes(),0o444)
  write(rescue/'boot_cleanup.py',(SOURCE/'recovery_boot_cleanup.py').read_bytes(),0o444)
  write(rescue/'restore_files.py',(SOURCE/'restore_files.py').read_bytes(),0o444)
  write(rescue/'restore_boot.py',(SOURCE/'restore_boot.py').read_bytes(),0o444)
  write(destination/'rootfs/usr/local/lib/systemd/system/okopy-panel.service.d/80-infrastructure-recovery-access.conf',
        b'[Service]\nExecStartPre=+/usr/bin/python3 -I /opt/okopy-recovery-ui/writer_guard.py okopy-panel.service\n')
  write(destination/'rootfs/usr/local/lib/systemd/system/okopy-routing.service.d/80-infrastructure-recovery-access.conf',
        b'[Service]\nExecStartPre=+/usr/bin/python3 -I /opt/okopy-recovery-ui/writer_guard.py okopy-routing.service\n')
  write(destination/'rootfs/etc/systemd/system/infrastructure-recovery-ui.service',(
      '[Unit]\nDescription=Independent Farvater recovery UI\nAfter=network-online.target\n'
      '[Service]\nType=simple\nUser=okopy-recovery\nGroup=okopy-recovery\n'
      'WorkingDirectory=/opt/okopy-recovery-ui\n'
      'EnvironmentFile=/etc/farvater/recovery-ui.env\n'
      'ExecStart=/opt/okopy-recovery-ui/venv/bin/python -I /opt/okopy-recovery-ui/server.py\n'
      'Restart=on-failure\nRestartSec=3s\nUMask=0077\n'
      'ProtectSystem=strict\nProtectHome=yes\nNoNewPrivileges=no\n'
      'ReadWritePaths=/var/www/certbot/.farvater-recovery\n'
      '[Install]\nWantedBy=multi-user.target\n').encode())
  write(destination/'rootfs/usr/local/lib/systemd/system/infrastructure-recovery-https.service',(
      '[Unit]\nDescription=Farvater protected HTTPS ingress\n'
      'After=network-online.target infrastructure-recovery-ui.service\nWants=network-online.target\n'
      '[Service]\nType=simple\nUser=root\n'
      'SupplementaryGroups=okopy-panel okopy-recovery\n'
      'ExecStart=/usr/bin/caddy run --config /opt/okopy-panel/proxy/Caddyfile --adapter caddyfile\n'
      'Restart=on-failure\nRestartSec=3s\nUMask=0077\n'
      'ProtectSystem=strict\nProtectHome=yes\nNoNewPrivileges=yes\n'
      'ReadOnlyPaths=/var/lib/okopy-recovery-ui/tls /var/www/certbot/.okopy-panel /var/www/certbot/.farvater-recovery\n'
      'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n'
      'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
      '[Install]\nWantedBy=multi-user.target\n').encode())
  write(destination/'rootfs/etc/sudoers.d/farvater-recovery-ui',(
      'Defaults:okopy-recovery !requiretty\n'
      'okopy-recovery ALL=(root) NOPASSWD: /usr/bin/python3 -I /opt/okopy-recovery-ui/rescue.py *\n').encode(),0o440)
  write(destination/'rootfs/etc/sysusers.d/farvater-recovery.conf',
        b'u okopy-recovery - "Farvater independent recovery" /nonexistent /usr/sbin/nologin\n')
  write(destination/'rootfs/etc/tmpfiles.d/farvater-recovery.conf',
        b'd /var/www/certbot/.farvater-recovery 2770 root okopy-recovery -\n'
        b'd /var/www/certbot/.okopy-panel 2770 root okopy-panel -\n'
        b'd /var/lib/okopy-recovery-ui 0750 root okopy-recovery -\n')
  write(destination/'rootfs/etc/letsencrypt/renewal-hooks/deploy/infrastructure-recovery-tls.sh',
        b'#!/bin/sh\nset -eu\n'
        b'/usr/bin/python3 -I /opt/okopy-recovery-ui/tls_refresh.py\n'
        b'/usr/bin/systemctl reload-or-restart infrastructure-recovery-https.service\n',0o755)
  provision=ROOT/'install/provision_current.py'
  write(destination/'tools/provision_current.py',provision.read_bytes(),0o755)
  proxy=ROOT/'install/proxy_caddy.py'
  write(destination/'tools/proxy_caddy.py',proxy.read_bytes(),0o755)
  verifier=ROOT/'install/verify_current.py'
  write(destination/'tools/verify_current.py',verifier.read_bytes(),0o755)
  rootfs_files,rootfs_links,rootfs_directories=rootfs_inventory(destination/'rootfs')
  manifest={'format':'farvater-current-stage','version':1,'platform':'linux-amd64',
            'source_files':copied,'engines':result,
            'engine_links':{'trusttunnel-endpoint/current':'v1.0.33','trusttunnel-client/current':'v1.1.7'},
            'system_dependencies':['age','caddy','curl','sudo','systemd','python3-venv'],
            'requirements_sha256':sha(LOCK),
            'provision_tool_sha256':sha(provision),
            'proxy_tool_sha256':sha(proxy),
            'verify_tool_sha256':sha(verifier),
            'rootfs_files':rootfs_files,'rootfs_links':rootfs_links,
            'rootfs_directories':rootfs_directories,
            'status':'staged','runtime_ready':False,'secrets_included':False}
  write(destination/'manifest.json',(json.dumps(manifest,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode(),0o600)
  return manifest
 except BaseException:
  shutil.rmtree(destination);raise


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--destination',required=True,type=Path)
 parser.add_argument('--amnezia-engine',type=Path)
 parser.add_argument('--ocserv-engine',type=Path)
 parser.add_argument('--ocserv-package-version')
 args=parser.parse_args()
 result=build(args.destination,awg_engine=args.amnezia_engine,
              ocserv_engine=args.ocserv_engine,ocserv_version=args.ocserv_package_version)
 print(json.dumps({'status':result['status'],'source_files':len(result['source_files']),
                   'engines':list(result['engines']),'destination':str(args.destination)},ensure_ascii=False))


if __name__=='__main__':main()
