#!/usr/bin/env python3
"""Download a pinned native sing-box for a portable Farvater node."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request

VERSION='1.14.1'
DIGESTS={
    ('Darwin','arm64'):'b9024642ef7b4848252df5469b7f60ef3c18bb5e217a16a0934f0174f8ad11b4',
    ('Darwin','amd64'):'b34381b047106fe84895df14f7aaae06f3182130b728006944deb0d59d8590c3',
    ('Linux','arm64'):'6060b42fa84c5dcaeae1799af7f61b0f1ae4855d9d5ddc9e02baba17154b3ae2',
    ('Linux','amd64'):'12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f',
}


def download(destination):
    destination=Path(destination).expanduser().absolute()
    system=platform.system()
    architecture={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}.get(platform.machine().lower())
    expected=DIGESTS.get((system,architecture))
    if expected is None:raise ValueError('Portable core requires macOS/Linux arm64 or amd64')
    if destination.exists() or destination.is_symlink():raise ValueError('Use a new private destination directory')
    name=f'sing-box-{VERSION}-{system.lower()}-{architecture}'
    request=urllib.request.Request(f'https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{name}.tar.gz',headers={'User-Agent':'Farvater-pinned-core-downloader'})
    with tempfile.TemporaryFile() as archive, urllib.request.urlopen(request,timeout=60) as source:
        if not source.url.startswith('https://'):raise ValueError('Upstream redirect must retain HTTPS')
        digest=hashlib.sha256(); size=0
        while chunk:=source.read(1024*1024):
            size+=len(chunk)
            if size>150*1024*1024:raise ValueError('Core archive exceeds size limit')
            digest.update(chunk);archive.write(chunk)
        if digest.hexdigest()!=expected:raise ValueError('Official core archive digest mismatch')
        archive.seek(0)
        with tarfile.open(fileobj=archive,mode='r:gz') as package:
            allowed=['sing-box','LICENSE']+(['libcronet.so'] if system=='Linux' else [])
            members={short:package.getmember(name+'/'+short) for short in allowed}
            if any(not m.isfile() or not 0<m.size<150*1024*1024 for m in members.values()):raise ValueError('Unexpected upstream core member')
            missing=[]
            parent=destination.parent
            while not parent.exists():
                missing.append(parent)
                parent=parent.parent
            destination.mkdir(mode=0o700,parents=True)
            for parent in missing:
                parent.chmod(0o700)
            for short,member in members.items():
                target=destination/short
                target.write_bytes(package.extractfile(member).read())
                target.chmod(0o700 if short=='sing-box' else 0o600)
            manifest={
                'version':VERSION,'platform':system.lower()+'-'+architecture,
                'archive_sha256':expected,
                'files':{short:hashlib.sha256((destination/short).read_bytes()).hexdigest() for short in members},
            }
            (destination/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
            (destination/'manifest.json').chmod(0o600)
    print('Verified native core '+VERSION+' installed in '+str(destination))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',type=Path,required=True)
    download(parser.parse_args().destination)
