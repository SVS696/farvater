"""Verify an entire staged rootfs against its externally pinned manifest SHA.

Rejects changed bytes, modes, links, directories and any extra files before
installation. The caller must separately trust the manifest SHA256.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def sha(path):
 digest=hashlib.sha256()
 with Path(path).open('rb') as source:
  while data:=source.read(1024*1024):digest.update(data)
 return digest.hexdigest()


def inventory(root):
 files={};links={};directories={}
 for path in sorted(Path(root).rglob('*')):
  name=path.relative_to(root).as_posix()
  if path.is_symlink():links[name]=os.readlink(path)
  elif path.is_file():
   info=path.stat();files[name]={'sha256':sha(path),'bytes':info.st_size,'mode':stat.S_IMODE(info.st_mode)}
  elif path.is_dir():directories[name]=stat.S_IMODE(path.stat().st_mode)
  else:raise ValueError('Unsupported staged entry: '+name)
 return files,links,directories


def verify(stage,expected_sha256):
 stage=Path(stage).resolve()
 if not expected_sha256 or len(expected_sha256)!=64 or any(c not in '0123456789abcdef' for c in expected_sha256):
  raise ValueError('Pin the trusted manifest SHA256')
 manifest=stage/'manifest.json'
 if sha(manifest)!=expected_sha256:raise ValueError('Stage manifest SHA256 differs from trusted pin')
 value=json.loads(manifest.read_text())
 if value.get('format')!='farvater-current-stage' or value.get('version')!=1 or value.get('secrets_included') is not False:
  raise ValueError('Unexpected stage format')
 files,links,directories=inventory(stage/'rootfs')
 if files!=value.get('rootfs_files') or links!=value.get('rootfs_links') or directories!=value.get('rootfs_directories'):
  raise ValueError('Staged rootfs has changed or contains extra entries')
 tools={'provision_current.py':'provision_tool_sha256','proxy_caddy.py':'proxy_tool_sha256',
        'verify_current.py':'verify_tool_sha256'}
 if sorted(p.name for p in (stage/'tools').iterdir())!=sorted(tools):raise ValueError('Stage tools changed')
 if any(sha(stage/'tools'/name)!=value[field] for name,field in tools.items()):raise ValueError('Stage tool digest mismatch')
 if sorted(p.name for p in stage.iterdir())!=['manifest.json','rootfs','tools']:
  raise ValueError('Stage has extra top-level entries')
 return {'status':'verified','rootfs_files':len(files),'rootfs_links':len(links),'rootfs_directories':len(directories)}


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--stage',required=True,type=Path)
 parser.add_argument('--manifest-sha256',required=True)
 args=parser.parse_args()
 print(json.dumps(verify(args.stage,args.manifest_sha256),sort_keys=True))


if __name__=='__main__':main()
