import unittest
import test_web


class RouterFallbackTests(unittest.TestCase):
    setUp=test_web.WebTests.setUp
    tearDown=test_web.WebTests.tearDown
    login=test_web.WebTests.login

    def test_historical_router_page_is_not_registered(self):
        self.assertEqual(self.client.get('/lan/fallback').status_code,302)
        self.login();before=(self.path/'policy.json').read_bytes()
        self.assertEqual(self.client.get('/lan/fallback').status_code,404)
        self.assertEqual(self.client.get('/lan/guard').status_code,404)
        self.assertEqual((self.path/'policy.json').read_bytes(),before)
