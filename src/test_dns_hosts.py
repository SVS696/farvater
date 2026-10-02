import copy
import json
import unittest
from dns_form import parse_dns, parse_hosts, hosts_text
from policy import validate_policy
import test_web


class HostsTests(unittest.TestCase):
    def test_nodata_preserves_scope_order_and_external_rules(self):
        from candidate_config import local_hosts_nodata
        rules=[{'domain':['blocked.example'],'action':'reject'},
               {'source_ip_cidr':['10.0.0.1/32'],'action':'route','server':'local','disable_cache':True},
               {'action':'route','server':'external'}]
        hosts={**parse_hosts('192.0.2.2 nas.example\n2001:db8::1 v6.example'),'tag':'local'}
        before=copy.deepcopy(rules);actual=local_hosts_nodata(rules,[hosts])
        self.assertEqual(rules,before);self.assertEqual(actual[0],rules[0]);self.assertEqual(actual[-2:],rules[-2:])
        self.assertEqual(len(actual),5)
        for entry in actual[1:3]:
            self.assertEqual(entry['rules'][0],{'source_ip_cidr':['10.0.0.1/32']})
            self.assertEqual(entry['action'],'predefined');self.assertEqual(entry['rcode'],'NOERROR')
            self.assertNotIn('disable_cache',entry['rules'][0])
        self.assertEqual(local_hosts_nodata(rules,[]),rules)

    def test_standard_hosts_round_trip_and_canonical_names(self):
        native=parse_hosts('# comment\n192.0.2.2 NAS.Example. alias.example\n2001:db8::1 nas.example\n192.0.2.2 nas.example # duplicate\n')
        self.assertEqual(native['predefined'],{'nas.example':['192.0.2.2','2001:db8::1'],'alias.example':['192.0.2.2']})
        self.assertEqual(parse_hosts(hosts_text(native)),native)

    def test_invalid_input_is_rejected(self):
        for text in ('', '# empty', '192.0.2.1', '1.2.3.999 nas.example', '::1%lo0 nas.example',
                     '192.0.2.1 *.example', '192.0.2.1 https://example', 'x'*131073):
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):parse_hosts(text)

    def test_switch_from_network_dns_drops_stale_fields(self):
        old={'bootstrap':'other','native':{'type':'udp','tag':'dns','server':'1.1.1.1','detour':'direct'}}
        form={'type':'hosts','name':'Local','scope':'special','hosts':'192.0.2.1 nas.example'}
        value=parse_dns(form,copy.deepcopy(old),'dns',{'dns':{},'exits':{}})
        self.assertNotIn('bootstrap',value)
        self.assertEqual(set(value['native']),{'type','tag','path','predefined'})

    def test_policy_import_validates_files_and_addresses(self):
        base={'default_exit':'direct','default_dns':'local','exits':{'direct':{'scope':'public','native':{'type':'direct'}}},
              'dns':{'local':{'scope':'special','native':parse_hosts('192.0.2.1 nas.example')}},'profiles':[]}
        self.assertFalse([i for i in validate_policy(base) if i['severity']=='error'])
        for patch in ({'path':['/etc/shadow']},{'predefined':{'nas.example':['not an IP']}}, {'predefined':{}}):
            value=copy.deepcopy(base);value['dns']['local']['native'].update(patch)
            self.assertTrue([i for i in validate_policy(value) if i['severity']=='error'])


class HostsWebTests(unittest.TestCase):
    setUp=test_web.WebTests.setUp
    tearDown=test_web.WebTests.tearDown
    login=test_web.WebTests.login
    revision=test_web.WebTests.revision
    def test_editor_download_and_reimport_preserve_records(self):
        csrf=self.login()
        form={'csrf':csrf,'revision':self.revision(),'type':'hosts','name':'Local names',
              'scope':'special','hosts':'192.0.2.1 nas.example\n2001:db8::1 nas.example'}
        self.assertEqual(self.client.post('/dns/save',data=form).status_code,302)
        policy=json.loads((self.path/'policy.json').read_text())
        identifier=next(k for k in policy['dns'] if k!='isp')
        url='/dns/'+identifier
        html=self.client.get(url+'/edit').text
        self.assertIn('192.0.2.1 nas.example',html)
        self.assertIn('Локальные DNS-записи',html)
        self.assertEqual(self.client.post(url+'/hosts-export',data={'revision':self.revision()}).status_code,403)
        self.assertEqual(self.client.post(url+'/hosts-export',data={'csrf':csrf,'revision':'stale'}).status_code,409)
        r=self.client.post(url+'/hosts-export',data={'csrf':csrf,'revision':self.revision()})
        self.assertEqual(r.status_code,200);self.assertEqual(r.headers['Cache-Control'],'no-store')
        self.assertIn('dns-records.hosts',r.headers['Content-Disposition'])
        self.assertEqual(parse_hosts(r.text)['predefined'],policy['dns'][identifier]['native']['predefined'])
        form.update(id=identifier,revision=self.revision(),hosts='bad name')
        before=(self.path/'policy.json').read_bytes()
        self.assertEqual(self.client.post('/dns/save',data=form).status_code,400)
        self.assertEqual((self.path/'policy.json').read_bytes(),before)


if __name__=='__main__':unittest.main()
