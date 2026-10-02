import unittest
from pathlib import Path
from openconnect_profile import DEFAULT
from openconnect_render import render_files

class RenderTests(unittest.TestCase):
    def test_password_stays_off_arguments_and_config(self):
        m={**DEFAULT,'server':'https://vpn.test/?group=a','username':'worker','password':'UNIQUE_SECRET','no_dtls':True,'force_dpd':30}
        files=render_files(m,{'interface':'vpn0','script':'/etc/openconnect/route.sh'},Path('/private/work'))
        config=files['client.conf'].decode();self.assertNotIn('UNIQUE_SECRET',config)
        self.assertEqual(files['stdin.txt'],b'UNIQUE_SECRET\n');self.assertIn('server=https://vpn.test/?group=a\n',config)
        self.assertIn('no-dtls\n',config);self.assertIn('force-dpd=30\n',config)
    def test_cookie_is_stdin_and_inapplicable_material_is_empty(self):
        m={**DEFAULT,'server':'https://vpn.test/','auth_mode':'cookie','cookie':'SESSION_SECRET'}
        f=render_files(m,{'interface':'vpn0','script':'/etc/openconnect/route.sh'},Path('/private/work'))
        self.assertIn(b'cookie-on-stdin\n',f['client.conf']);self.assertNotIn(b'SESSION_SECRET',f['client.conf'])
        self.assertEqual(f['stdin.txt'],b'SESSION_SECRET\n');self.assertEqual(f['key.pem'],b'')

if __name__=='__main__':unittest.main()
