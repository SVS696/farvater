import copy
import unittest
from dns_form import parse_dns
from policy import validate_policy


class DNSFormTests(unittest.TestCase):
    def setUp(self):
        self.policy={'dns':{'bootstrap':{}},'exits':{'plain':{'native':{'type':'direct','tag':'plain'}},'work':{'native':{'type':'direct','tag':'work','bind_interface':'work0'}}}}
        self.form={'name':'Resolver','scope':'public','type':'https','server':'1.1.1.1'}

    def test_basic_https_uses_safe_defaults(self):
        d=parse_dns(self.form,{},'resolver',self.policy)
        self.assertEqual(d['native']['server_port'],443)
        self.assertEqual(d['native']['path'],'/dns-query')
        self.assertNotIn('detour',d['native'])

    def test_hostname_requires_explicit_bootstrap(self):
        self.form['server']='dns.example.com'
        with self.assertRaisesRegex(ValueError,'начальный DNS'):parse_dns(self.form,{},'r',self.policy)
        self.form['bootstrap']='bootstrap'
        d=parse_dns(self.form,{},'r',self.policy)
        self.assertEqual(d['native']['domain_resolver'],'bootstrap')

    def test_preserves_unedited_tls_settings_without_mutating_previous(self):
        previous={'native':{'type':'https','tls':{'certificate':['PEM'], 'server_name':'old.example'},'headers':{'X-Example':'value'}}}
        saved=copy.deepcopy(previous)
        self.form['server_name']='new.example'
        d=parse_dns(self.form,previous,'r',self.policy)
        self.assertEqual(d['native']['tls']['certificate'],['PEM'])
        self.assertEqual(d['native']['headers'],{'X-Example':'value'})
        self.assertEqual(previous,saved)

    def test_protocol_change_clears_incompatible_native_fields(self):
        self.form['type']='udp'
        d=parse_dns(self.form,{'native':{'type':'https','tls':{'server_name':'example.com'},'path':'/old'}},'r',self.policy)
        self.assertNotIn('tls',d['native']);self.assertNotIn('path',d['native'])
        self.assertEqual(d['native']['server_port'],53)

    def test_plain_direct_detour_rejected_but_bound_interface_accepted(self):
        self.form['detour']='plain'
        with self.assertRaisesRegex(ValueError,'пустой direct'):parse_dns(self.form,{},'r',self.policy)
        self.form['detour']='work'
        self.assertEqual(parse_dns(self.form,{},'r',self.policy)['native']['detour'],'work')

    def test_fakeip_family_and_empty_ranges_rejected(self):
        self.form.update(type='fakeip',inet4_range='fc00::/18')
        with self.assertRaises(ValueError):parse_dns(self.form,{},'r',self.policy)
        self.form['inet4_range']=''
        with self.assertRaises(ValueError):parse_dns(self.form,{},'r',self.policy)

    def test_bad_port_and_invalid_host_are_rejected(self):
        for patch in [{'server_port':'70000'},{'server':'https://dns.example/dns-query'},{'server_port':'abc'}]:
            with self.subTest(patch=patch),self.assertRaises(ValueError):parse_dns({**self.form,**patch},{},'r',self.policy)

    def test_dhcp_uses_discovered_dns_instead_of_static_server(self):
        for interface in ('','enp0s25'):
            form={**self.form,'type':'dhcp','dhcp_interface':interface,'server':'1.1.1.1','path':'/dns-query'}
            result=parse_dns(form,{'native':{'type':'https','server':'8.8.8.8','tls':{}}},'lease',self.policy)
            self.assertEqual(result['native'],{'type':'dhcp','tag':'lease',**({'interface':interface} if interface else {})})
            self.assertNotIn('bootstrap',result)
        for interface in ('../x','eth 0','a'*16):
            with self.assertRaises(ValueError):parse_dns({**form,'dhcp_interface':interface},{},'lease',self.policy)


if __name__=='__main__':unittest.main()
