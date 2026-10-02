import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from router_registry import RouterRegistry,public
import test_web as fixtures

class RouterRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.registry=RouterRegistry(self.root)
    def tearDown(self):self.temp.cleanup()
    def add(self,**changes):
        values={'name':'A','driver':'keenetic','host':'router.example.net','username':'operator','password':'private-test','port':'2222','enabled':'on','capability_monitor':'on',**changes}
        return self.registry.save(self.registry.read()[1],values)
    def test_empty_optional_and_multiple_isolated_routers(self):
        self.assertEqual(self.registry.read(),([],'empty'))
        first=self.add();second=self.add(host='10.20.0.1',name='B')
        a=self.registry.remote(first);b=self.registry.remote(second)
        self.assertEqual(a.credentials['host'],'router.example.net');self.assertEqual(b.credentials['host'],'10.20.0.1')
        self.assertNotEqual(a.directory,b.directory)
        self.assertEqual(self.registry.path.stat().st_mode&0o777,0o600)
        self.assertNotIn('password',public(self.registry.get(first)))
    def test_crud_no_network_writes_secret_preserved_then_removed_and_stale_rejected(self):
        with patch('router_health.connect',side_effect=AssertionError('Must not connect')):
            key=self.add();_,rev=self.registry.read()
            self.add(id=key,password='',name='renamed')
            self.assertEqual(self.registry.get(key)['password'],'private-test')
            with self.assertRaisesRegex(ValueError,'изменился'):self.registry.save(rev,{},remove=True)
            self.add(id=key,driver='web',web_url='https://router.example.net:8443/',capability_monitor='')
            self.assertEqual(self.registry.get(key)['password'],'')
            with self.assertRaises(ValueError):self.registry.remote(key)
            self.registry.save(self.registry.read()[1],{'id':key},remove=True)
            self.assertEqual(self.registry.read()[0],[])
    def test_invalid_hosts_urls_and_unsafe_private_file(self):
        for values in [{'host':'$(touch x)'},{'web_url':'javascript:alert(1)'},{'port':'0'},{'web_url':'https://user:pass@example.com'}]:
            with self.subTest(values=values),self.assertRaises(ValueError):self.add(**values)
        self.registry.path.symlink_to(self.root/'missing')
        with self.assertRaises(OSError):self.registry.read()
        self.registry.path.unlink();self.add();self.registry.path.chmod(0o644)
        with self.assertRaises(ValueError):self.registry.read()

class RouterRegistryWebTests(unittest.TestCase):
    setUp=fixtures.WebTests.setUp
    tearDown=fixtures.WebTests.tearDown
    login=fixtures.WebTests.login
    def test_historical_router_routes_remain_unavailable(self):
        self.assertEqual(self.client.get('/routers').status_code,302)
        self.login();before=(self.path/'policy.json').read_bytes()
        self.assertEqual(self.client.get('/routers').status_code,404)
        self.assertEqual(self.client.get('/routers/unknown/ipv6').status_code,404)
        self.assertNotIn('routers',self.app.extensions)
        self.assertEqual((self.path/'policy.json').read_bytes(),before)
