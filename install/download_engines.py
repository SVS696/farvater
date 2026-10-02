#!/usr/bin/env python3
"""Fetch the three fixed upstream Linux amd64 inputs and verify every digest."""

import argparse
import hashlib
from pathlib import Path
import tempfile
import urllib.request

from build_current import ARCHIVES, VENDOR

URLS = {
    'sing-box': 'https://github.com/SagerNet/sing-box/releases/download/v1.14.1/',
    'trusttunnel-endpoint': 'https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.0.33/',
    'trusttunnel-client': 'https://github.com/TrustTunnel/TrustTunnelClient/releases/download/v1.1.7/',
}


def download(directory):
    directory=Path(directory)
    directory.mkdir(parents=True,exist_ok=True)
    for role,(name,expected,_,_) in ARCHIVES.items():
        target=directory/name
        if target.exists():
            if target.is_symlink() or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest()!=expected:
                raise ValueError('Existing upstream input fails verification: '+name)
            print('Verified '+name)
            continue
        temporary=None
        try:
            digest=hashlib.sha256(); size=0
            request=urllib.request.Request(URLS[role]+name,headers={'User-Agent':'Farvater-pinned-release-downloader'})
            with urllib.request.urlopen(request,timeout=60) as source, tempfile.NamedTemporaryFile(dir=directory,prefix='.'+name+'.',delete=False) as output:
                temporary=Path(output.name)
                if not source.url.startswith('https://'):raise ValueError('Upstream redirect must retain HTTPS')
                while chunk:=source.read(1024*1024):
                    size+=len(chunk)
                    if size>150*1024*1024:raise ValueError('Upstream archive exceeds size limit')
                    digest.update(chunk);output.write(chunk)
            if digest.hexdigest()!=expected:raise ValueError('Upstream archive digest mismatch: '+name)
            temporary.replace(target);temporary=None
            print('Downloaded and verified '+name)
        finally:
            if temporary is not None:temporary.unlink(missing_ok=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',type=Path,default=VENDOR)
    download(parser.parse_args().destination)
