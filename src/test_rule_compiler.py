import copy,unittest
from werkzeug.datastructures import MultiDict
from policy import explain,validate_policy
from rule_compiler import compile_profiles
from rule_options import parse_options,normalize_options

class GeneralRuleTests(unittest.TestCase):
 def test_connection_conditions_only_limit_exit_not_dns_or_explicit_udp_rejection(self):
  p=self.base();p['profiles'][0].update(route_network='tcp',route_ports=[80,443],udp_blocked_ports=[443])
  r=self.compile(p)
  self.assertEqual(r['dns_rules'],self.compile(self.base())['dns_rules'])
  self.assertIn({'network':'tcp','port':[80,443]},r['route_rules'][-1]['rules'])
  self.assertIn({'network':'udp','port':[443]},r['route_rules'][0]['rules'])
 def test_connection_conditions_fall_through_and_keep_first_dns_in_explanation(self):
  p=self.base();p['profiles'][0].update(route_network='tcp',route_ports=[80,443],exit='web')
  p['exits']['web']={'scope':'public'}
  p['dns']['second']={'scope':'public'}
  p['profiles'].append({**self.base()['profiles'][0],'id':'rest','name':'Other connections','dns':'second'})
  with self.assertRaisesRegex(ValueError,'протокол'):explain(p,'a.example.com')
  with self.assertRaisesRegex(ValueError,'порт'):explain(p,'a.example.com',network='tcp')
  self.assertEqual(explain(p,'a.example.com',network='tcp',port=443)['exit'],'web')
  for network,port in [('tcp',5228),('udp',3478)]:
   answer=explain(p,'a.example.com',network=network,port=port)
   self.assertEqual(answer['exit'],'direct');self.assertEqual(answer['dns'],'isp')
 def test_connection_conditions_validate_before_save_and_protect_private_scope(self):
  options=parse_options(MultiDict({'route_network':'tcp','route_ports':'443, 80 443'}))
  self.assertEqual(options['route_ports'],[443,80]);self.assertEqual(options['route_network'],'tcp')
  for v in [{'route_network':'icmp'},{'route_network':[]},{'route_ports':[False]},
            {'route_ports':[0]},{'route_ports':['443']},{'route_ports':[65536]},
            {'route_network':'tcp','kind':'work'},{'route_ports':[80],'kind':'special'},
            {'route_network':'udp','dns_only':True}]:
   with self.subTest(v=v),self.assertRaises(ValueError):normalize_options(v)
 def test_explanation_reports_explicit_udp_rejection_before_route_conditions(self):
  p=self.base();p['profiles'][0].update(route_network='tcp',route_ports=[80,443],udp_blocked_ports=[443])
  self.assertEqual(explain(p,'a.example.com',network='udp',port=443)['exit'],'blocked')
 def test_udp_port_rejection_precedes_route_and_preserves_scope(self):
  p=self.base();p['profiles'][0].update(udp_blocked_ports=[443,8443],source_networks=['192.0.2.1/32'],exclude_domains=['keep.example.com'])
  r=self.compile(p,source_identity=True)
  reject,route=r['route_rules']
  self.assertEqual(reject['action'],'reject');self.assertTrue(reject['no_drop'])
  self.assertIn({'network':'udp','port':[443,8443]},reject['rules'])
  self.assertEqual(reject['rules'][0],{k:v for k,v in route.items() if k not in ('action','outbound')})
 def test_udp_block_applies_to_dns_only_without_selecting_exit(self):
  p=self.base();p['profiles'][0].update(udp_blocked_ports=[443],dns_only=True)
  r=self.compile(p);self.assertEqual(len(r['route_rules']),1)
  self.assertEqual(r['route_rules'][0]['action'],'reject')
 def test_udp_ports_validate_types_and_form_roundtrip(self):
  self.assertEqual(parse_options(MultiDict({'udp_blocked_ports':'443, 8443\n443'}))['udp_blocked_ports'],[443,8443])
  for v in [None,'443',[True],[0],[65536],[443.0],['443']]:
   with self.subTest(v=v),self.assertRaises(ValueError):normalize_options({'udp_blocked_ports':v})
  for v in ['443-445','abc','-1','0','65536','443;echo test']:
   with self.subTest(v=v),self.assertRaises(ValueError):parse_options(MultiDict({'udp_blocked_ports':v}))
 def base(self):
  return {'default_exit':'direct','default_dns':'isp','exits':{'direct':{'scope':'public'},'work':{'scope':'work'}},
   'dns':{'isp':{'scope':'public'},'private':{'scope':'work'}},'profiles':[
    {'id':'arbitrary','name':'Любое имя','kind':'public','domains':['*.example.com'],'exit':'direct','dns':'isp'}]}
 def compile(self,p,**kw):return compile_profiles(p,default_filtering=False,**kw)
 def test_arbitrary_name_has_no_effect_on_generated_rules(self):
  p=self.base();first=self.compile(p);p['profiles'][0]['name']='Другое устройство / новый сервис';second=self.compile(p)
  self.assertEqual(first['dns_rules'],second['dns_rules']);self.assertEqual(first['route_rules'],second['route_rules'])
 def test_source_scope_cannot_silently_expand_to_every_client(self):
  p=self.base();p['profiles'][0]['source_networks']=['192.168.2.82/32']
  with self.assertRaisesRegex(ValueError,'исходный IP'):self.compile(p)
  r=self.compile(p,source_identity=True)
  self.assertIn({'source_ip_cidr':['192.168.2.82/32']},r['dns_rules'][0]['rules'])
  self.assertIn({'source_ip_cidr':['192.168.2.82/32']},r['route_rules'][0]['rules'])
 def test_per_device_rule_needs_source_for_explanation(self):
  p=self.base();p['profiles'][0]['source_networks']=['192.168.2.82/32']
  with self.assertRaisesRegex(ValueError,'IP устройства'):explain(p,'a.example.com')
  self.assertTrue(explain(p,'a.example.com','192.168.2.82')['matched'])
  self.assertFalse(explain(p,'a.example.com','192.168.2.83')['matched'])
 def test_device_only_rule_matches_all_destinations_without_becoming_global(self):
  p=self.base();p['profiles'][0].update(domains=[],source_networks=['192.168.2.82/32'])
  self.assertEqual(validate_policy(p),[])
  self.assertTrue(explain(p,'unrelated.test','192.168.2.82')['matched'])
  self.assertFalse(explain(p,'unrelated.test','192.168.2.83')['matched'])
  r=self.compile(p,source_identity=True)
  self.assertEqual(r['dns_rules'][0]['source_ip_cidr'],['192.168.2.82/32'])
  self.assertEqual(r['route_rules'][0]['source_ip_cidr'],['192.168.2.82/32'])
 def test_ipv4_only_rejects_cached_ipv6_and_suppresses_aaaa(self):
  p=self.base();p['profiles'][0]['ip_family']='ipv4_only';r=self.compile(p)
  self.assertEqual(r['dns_rules'][0]['action'],'predefined');self.assertEqual(r['dns_rules'][0]['rcode'],'NOERROR')
  self.assertIn({'query_type':[28]},r['dns_rules'][0]['rules'])
  self.assertEqual(r['route_rules'][0]['action'],'reject');self.assertIn({'ip_version':6},r['route_rules'][0]['rules'])
 def test_special_dns_answer_is_scoped_and_does_not_change_other_types(self):
  p=self.base();p['profiles'][0]['dns_response']={'mode':'nodata','query_types':['HTTPS','SVCB']};r=self.compile(p)
  self.assertIn({'query_type':[65,64]},r['dns_rules'][0]['rules']);self.assertEqual(r['dns_rules'][1]['server'],'isp')
 def test_adguard_on_cannot_silently_use_unfiltered_resolver(self):
  p=self.base();p['profiles'][0]['adguard']='on'
  with self.assertRaisesRegex(ValueError,'AdGuard'):self.compile(p)
  r=self.compile(p,filtered_resolvers={'isp':'filtered-isp'})
  self.assertEqual(r['dns_rules'][-1]['server'],'filtered-isp')
 def test_global_filtering_must_be_explicit_and_can_be_overridden_per_rule(self):
  p=self.base()
  with self.assertRaisesRegex(ValueError,'явно'):compile_profiles(p)
  with self.assertRaisesRegex(ValueError,'AdGuard'):compile_profiles(p,default_filtering=True)
  p['profiles'][0]['adguard']='off'
  self.assertEqual(compile_profiles(p,default_filtering=True)['dns_rules'][-1]['server'],'isp')
 def test_disabled_private_profile_still_blocks_dns_and_route(self):
  p=self.base();p['profiles'][0].update(kind='work',enabled=False,exit='work',dns='private');r=self.compile(p)
  self.assertEqual(r['dns_rules'][0]['action'],'reject');self.assertTrue(r['dns_rules'][0]['no_drop'])
  self.assertEqual(r['route_rules'][0]['action'],'reject')
 def test_disjoint_device_scopes_do_not_create_false_protection_conflict(self):
  p=self.base();p['profiles'][0]['source_networks']=['192.168.2.82/32']
  p['profiles'].append({'id':'private','name':'Работа','kind':'work','source_networks':['192.168.2.83/32'],
   'domains':['*.example.com'],'exit':'work','dns':'private'})
  self.assertEqual(validate_policy(p),[])
  p['profiles'][0]['source_networks']=[]
  self.assertTrue(any('перекрывает' in i['message'] for i in validate_policy(p)))
 def test_legacy_exit_only_fallback_is_not_silently_dropped(self):
  p=self.base();p['profiles'][0]['fallback']=['direct']
  with self.assertRaisesRegex(ValueError,'одиночный список'):self.compile(p)
 def test_bad_typed_options_are_rejected_before_save(self):
  for fields in [{'ip_family':'typo'},{'adguard':'typo'},{'source_networks':'not-an-ip'},
                 {'dns_response_mode':'nodata'},{'dns_query_types':'AAAA'}]:
   with self.subTest(fields=fields),self.assertRaises(ValueError):parse_options(MultiDict(fields))
 def test_compilation_does_not_mutate_policy(self):
  p=self.base();before=copy.deepcopy(p);self.compile(p);self.assertEqual(p,before)
 def test_imported_malformed_options_fail_as_validation_errors(self):
  for fields in [{'source_networks':None},{'source_networks':'192.168.2.82'},
                 {'source_networks':[3232236114]},{'ip_family':[]},{'adguard':{}},
                 {'dns_response':None},{'dns_response':{'mode':[]}},
                 {'dns_response':{'mode':'nodata','query_types':[{}]}}]:
   with self.subTest(fields=fields):
    with self.assertRaises(ValueError):normalize_options(fields)
    p=self.base();p['profiles'][0].update(fields)
    self.assertTrue(any(i['severity']=='error' for i in validate_policy(p)))
 def test_disabled_public_scope_does_not_require_source_in_explanation(self):
  p=self.base();p['profiles'][0].update(enabled=False,source_networks=['192.168.2.82/32'])
  self.assertFalse(explain(p,'a.example.com')['matched'])
 def test_domain_exclusions_without_domains_are_not_silently_ignored(self):
  for condition in [{'source_networks':['192.168.2.82/32']},{'networks':['192.0.2.0/24']}]:
   p=self.base();p['profiles'][0].update(domains=[],exclude_domains=['keep.example.com'],**condition)
   with self.assertRaisesRegex(ValueError,'Исключённые имена'):self.compile(p,source_identity=True)
 def test_dns_only_network_rule_cannot_compile_to_nothing(self):
  for domains in ([],['example.com']):
   p=self.base();p['profiles'][0].update(domains=domains,networks=['192.0.2.0/24'],dns_only=True)
   with self.assertRaisesRegex(ValueError,'только для DNS'):self.compile(p)
 def test_dns_only_family_restriction_blocks_but_does_not_select_route(self):
  p=self.base();p['profiles'][0].update(dns_only=True,ip_family='ipv4_only')
  r=self.compile(p)
  self.assertEqual(len(r['route_rules']),1);self.assertEqual(r['route_rules'][0]['action'],'reject')
  self.assertIn({'ip_version':6},r['route_rules'][0]['rules'])
 def test_literal_destination_ip_does_not_claim_a_dns_lookup(self):
  p=self.base();p['profiles'][0].update(domains=[],networks=['192.0.2.0/24'])
  answer=explain(p,'192.0.2.1')
  self.assertTrue(answer['matched']);self.assertIsNone(answer['dns'])
  self.assertIsNone(explain(p,'198.51.100.1')['dns'])
 def test_dns_only_rule_keeps_later_route_in_compiled_order(self):
  p=self.base();p['profiles'][0]['dns_only']=True
  p['profiles'].append({**p['profiles'][0],'id':'route','name':'Маршрут','dns_only':False})
  r=self.compile(p)
  self.assertEqual(r['origins'][0]['route_indices'],[])
  self.assertEqual(r['origins'][1]['route_indices'],[0])
 def test_disabled_protected_source_scope_and_subnet_survive_exclusion(self):
  p=self.base();p['profiles'][0].update(kind='work',enabled=False,source_networks=['192.168.2.82/32'],
     networks=['10.20.0.0/16'],exclude_domains=['skip.example.com'])
  r=self.compile(p,source_identity=True)
  self.assertIn({'source_ip_cidr':['192.168.2.82/32']},r['route_rules'][0]['rules'])
  self.assertIn({'ip_cidr':['10.20.0.0/16']},r['route_rules'][0]['rules'][0]['rules'])
  self.assertTrue(r['dns_rules'][0]['no_drop']);self.assertEqual(r['route_rules'][0]['action'],'reject')
