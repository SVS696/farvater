import copy,unittest
from openvpn_format import parse,render
from openvpn_profile import validate,form_view,from_form,DEFAULT

BASIC='client\ndev tun\nremote 192.0.2.1 1194 udp\npeer-fingerprint '+':'.join(['aa']*32)+'\nremote-cert-tls server\n'
KEY='-----BEGIN OpenVPN Static key V1-----\n'+'\n'.join(['0123456789abcdef'*2]*16)+'\n-----END OpenVPN Static key V1-----'

class FormatTests(unittest.TestCase):
 def test_tls_roundtrip_with_credentials_key_wrap_and_common_options(self):
  raw=BASIC+'auth-user-pass\ntls-auth [inline] 1\n<tls-auth>\n'+KEY+'\n</tls-auth>\n'+'''data-ciphers AES-256-GCM:AES-128-GCM
persist-key
persist-tun
nobind
resolv-retry infinite
verb 3
pull-filter ignore "route "
route 10.50.0.0 255.255.0.0
route-ipv6 fd50::/64
mssfix 1300 mtu
replay-window 64 15
keepalive 10 60
reneg-sec 0
verify-x509-name "VPN Server" name
'''
  parsed=parse(raw,username='user',password='secret:@ pass ');self.assertEqual(parsed['native']['password'],'secret:@ pass ')
  exported=render(parsed);self.assertEqual(parse(exported),parsed);self.assertIn('pull-filter "ignore" "route "',exported)
 def test_static_key_and_addresses_roundtrip(self):
  raw='dev tun\nremote 192.0.2.1 1194\nproto udp\nifconfig 10.8.0.2 10.8.0.1\nkey-direction 1\ncipher AES-256-CBC\n<secret>\n'+KEY+'\n</secret>\n'
  parsed=parse(raw);self.assertEqual(parsed['native']['mode'],'static_key');self.assertEqual(parse(render(parsed)),parsed)
  with self.assertRaises(ValueError):parse(raw+'remote-cert-tls server\n')
 def test_uploaded_auth_file_retains_password_spaces_and_can_be_replaced(self):
  raw=BASIC+'auth-user-pass auth.txt\n';result=parse(raw,files={'auth.txt':'owner\n password \n'})
  self.assertEqual(result['native']['password'],' password ')
  self.assertEqual(parse(raw,username='different',password='override')['native']['username'],'different')
  with self.assertRaises(ValueError):parse(raw)
 def test_unsafe_unsupported_duplicate_and_incomplete_imports_rejected(self):
  for extra in ['up /tmp/run','script-security 2','plugin /tmp/plugin','ca /etc/passwd','config other.conf','auth-user-pass','proto udp\nproto tcp','remote-cert-tls server','<connection>\nremote other 443\n</connection>','tls-version-min 1.3\ntls-version-max 1.2']:
   with self.subTest(extra=extra),self.assertRaises(ValueError):parse(BASIC+extra+'\n')
  for value in [BASIC.replace('dev tun','dev tap'),BASIC.replace('client','tls-client'),BASIC.replace('client\n','')]:
   with self.assertRaises(ValueError):parse(value)
 def test_native_host_paths_system_interface_and_unmapped_export_are_rejected(self):
  original=parse(BASIC)
  for patch in [{'system':True},{'name':'ovpn0'},{'on_demand':True},{'tls':{'certificate_path':'/root/file'}},{'static_challenge':'MFA'},{'unknown':{}},{'tls':{'unknown':{}}}]:
   with self.subTest(patch=patch),self.assertRaises(ValueError):validate({**original['native'],**patch},ready=True)
  bad=copy.deepcopy(original);bad['native']['peer_address']='10.8.0.1'
  with self.assertRaises(ValueError):render(bad)
 def test_form_preserves_secrets_and_quoted_push_prefix(self):
  model=parse(BASIC+'auth-user-pass\npull-filter ignore "route "\n',username='user',password='PRIVATE')['native']
  form={}
  for _,rows in form_view(model):
   for row in rows:
    value=row['value'];key='ov_'+row['path']
    if row['kind']=='bool':
     if value:form[key]='on'
    else:form[key]=str(value)
  updated=from_form(form,model)
  self.assertEqual(updated,model);self.assertEqual(updated['pull_filters'][0]['text'],'route ')
  self.assertNotIn('PRIVATE',str(form_view(model)))
 def test_auth_override_still_rejects_extra_arguments(self):
  with self.assertRaises(ValueError):parse(BASIC+'auth-user-pass file.txt extra\n',username='user',password='pass')
 def test_multi_remote_transports_and_direction_stay_distinct(self):
  source=parse(BASIC+'remote vpn.test 443 tcp-client\nremote-random\n')
  self.assertEqual(parse(render(source)),source)
  self.assertEqual(source['native']['servers'][1]['network'],'tcp')

if __name__=='__main__':unittest.main()
