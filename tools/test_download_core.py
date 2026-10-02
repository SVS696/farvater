import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import download_core


class DownloadCoreTests(unittest.TestCase):
    def archive(self):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz') as package:
            for name,data in [('sing-box',b'fake native executable'),('LICENSE',b'upstream license')]:
                info=tarfile.TarInfo('sing-box-1.14.1-darwin-arm64/'+name)
                info.size=len(data);package.addfile(info,io.BytesIO(data))
        return output.getvalue()

    def context(self, data):
        response=io.BytesIO(data)
        response.url='https://release-assets.githubusercontent.com/test-fixture'
        return patch('download_core.urllib.request.urlopen',return_value=response)

    def test_first_download_creates_private_parent_and_provenance(self):
        data=self.archive()
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'Farvater'/'core'
            with patch('download_core.platform.system',return_value='Darwin'), patch('download_core.platform.machine',return_value='arm64'), patch.dict(download_core.DIGESTS,{('Darwin','arm64'):hashlib.sha256(data).hexdigest()}), self.context(data):
                download_core.download(target)
            self.assertEqual(target.parent.stat().st_mode&0o777,0o700)
            self.assertEqual(target.stat().st_mode&0o777,0o700)
            manifest=json.loads((target/'manifest.json').read_text())
            self.assertEqual(manifest['files']['sing-box'],hashlib.sha256((target/'sing-box').read_bytes()).hexdigest())

    def test_bad_digest_leaves_no_install_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'core'
            with patch('download_core.platform.system',return_value='Darwin'), patch('download_core.platform.machine',return_value='arm64'), self.context(self.archive()):
                with self.assertRaises(ValueError):download_core.download(target)
            self.assertFalse(target.exists())

    def test_unsupported_platform_never_downloads(self):
        with patch('download_core.platform.system',return_value='Windows'), patch('download_core.urllib.request.urlopen') as request:
            with self.assertRaises(ValueError):download_core.download(Path('/unused'))
            request.assert_not_called()
