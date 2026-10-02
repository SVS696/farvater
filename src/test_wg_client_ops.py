import base64,json
from unittest.mock import patch
from wg_clients import control
from wg_client_ops import operation_state,finish_locked
from wireguard_profile import parse
from wireguard_control import read_private
from test_wg_clients import IncomingClients,PRIVATE,PUBLIC,SERVER_PRIVATE,SERVER_PUBLIC,ROUTER_PUBLIC,BASE

NEW_PRIVATE=base64.b64encode(b'n'*32).decode()
NEW_PUBLIC=base64.b64encode(b'N'*32).decode()

class ClientOperations(IncomingClients):
    def setUp(self):
        super().setUp();self.network=self.root/'network';self.network.mkdir()
        self.save(self.network/'transaction.json',json.dumps({'status':'confirmed'}));self.save(self.network/'apply.lock','')
        self.save(self.network/'applied-policy.json',json.dumps({'vpn_ingress':{'enabled':True,'interface':'wg0','clients':['10.77.0.0/24']}}))
        self.live={p['PublicKey']:p['AllowedIPs'] for p in parse(BASE)['peers']};self.fail_set=False
    def command(self,args,data=None):
        self.commands.append(args)
        if args==['/usr/bin/wg','genkey']:return NEW_PRIVATE+'\n'
        if args==['/usr/bin/wg','pubkey']:return {PRIVATE:PUBLIC,SERVER_PRIVATE:SERVER_PUBLIC,NEW_PRIVATE:NEW_PUBLIC}[data.strip()]+'\n'
        if args[:2]==['/usr/bin/wg','show']:
            if args[-1]=='latest-handshakes':return ''.join(k+'\t'+('12345' if k==PUBLIC else '0')+'\n' for k in self.live)
            if args[-1]=='allowed-ips':return ''.join(k+'\t'+','.join(v)+'\n' for k,v in self.live.items())
        if args[0]=='/usr/bin/systemd-run':return ''
        if args[:2]==['/usr/bin/wg','set']:
            if self.fail_set:raise ValueError('Injected set failure')
            public=args[4]
            if args[-1]=='remove':self.live.pop(public,None)
            else:self.live[public]=args[args.index('allowed-ips')+1].split(',')
            return ''
        raise AssertionError(args)
    def call(self,action='clients-status',**fields):
        return control({'version':1,'action':action,**fields},root=self.root,profiles=self.profiles,command=self.command,network=self.network)
    def fields(self):
        return {'file_revision':self.call()['file_revision'],'values':{'name':'Новый телефон','ipv6':False,'dns':'10.77.0.1','routes':'0.0.0.0/0','mtu':'1420','keepalive':'25'}}
    def test_router_disable_enable_preserves_its_lan_routes(self):
        from test_wg_clients import CLIENT
        router_private=base64.b64encode(b'r'*32).decode()
        command=self.command
        def with_router(args,data=None):
            if args==['/usr/bin/wg','pubkey'] and data.strip()==router_private:return ROUTER_PUBLIC+'\n'
            return command(args,data)
        self.command=with_router
        state=self.call();row=state['clients'][1]
        router=CLIENT.replace(PRIVATE,router_private).replace('10.77.0.8/32','10.77.0.2/32')
        self.call('clients-import',id=row['id'],file_revision=state['file_revision'],config=router)
        expected=self.live[ROUTER_PUBLIC][:]
        self.call('clients-disable',id=row['id'],file_revision=self.call()['file_revision'])
        self.assertNotIn(ROUTER_PUBLIC,self.live)
        self.call('clients-enable',id=row['id'],file_revision=self.call()['file_revision'])
        self.assertEqual(self.live[ROUTER_PUBLIC],expected)
        self.assertEqual(self.live[PUBLIC],['10.77.0.8/32'])

    def test_create_disable_reenable_only_changes_one_peer_and_preserves_keys(self):
        original={k:list(v) for k,v in self.live.items()};result=self.call('clients-add',**self.fields());identifier=result['id']
        self.assertFalse(result['interface_restarted']);self.assertEqual(len(self.live),3)
        for k,v in original.items():self.assertEqual(self.live[k],v)
        view=self.call();row=next(r for r in view['clients'] if r['id']==identifier);self.assertEqual(row['addresses'],['10.77.0.3/32'])
        export=self.call('clients-export',id=identifier,file_revision=view['file_revision'],mode='external')['config'];self.assertIn(NEW_PRIVATE,export)
        self.call('clients-disable',id=identifier,file_revision=view['file_revision']);self.assertEqual(self.live,original)
        view=self.call();self.assertEqual(view['disabled'][0]['id'],identifier)
        self.call('clients-enable',id=identifier,file_revision=view['file_revision']);self.assertEqual(self.live[NEW_PUBLIC],['10.77.0.3/32'])
        self.assertEqual(self.call()['disabled'],[])
        self.assertTrue(all('restart' not in a and 'syncconf' not in a for a in self.commands))
        self.assertEqual((self.directory/'10.77.0.3.conf').stat().st_mode&0o777,0o600)
    def test_crash_after_persistence_resumes_idempotently_and_stale_timer_is_noop(self):
        fields=self.fields();self.fail_set=True
        with self.assertRaisesRegex(ValueError,'Injected'):self.call('clients-add',**fields)
        job=operation_state(self.root);self.assertEqual(job['status'],'pending');self.assertIn(NEW_PUBLIC,(self.profiles/'wg0.conf').read_text())
        self.assertNotIn(NEW_PUBLIC,self.live)
        with self.assertRaisesRegex(ValueError,'предыдущую'):self.call('clients-add',**fields)
        self.fail_set=False;self.call('clients-finish',operation=job['id']);self.assertIn(NEW_PUBLIC,self.live)
        identifier=next(r['id'] for r in self.call()['clients'] if r['name']=='Новый телефон')
        self.call('clients-disable',id=identifier,file_revision=self.call()['file_revision']);self.assertNotIn(NEW_PUBLIC,self.live)
        before=(self.profiles/'wg0.conf').read_bytes();finish_locked(self.root,self.profiles,job['id'],self.command)
        self.assertEqual(before,(self.profiles/'wg0.conf').read_bytes());self.assertNotIn(NEW_PUBLIC,self.live)
    def test_crash_recovery_refuses_overwriting_newer_external_configuration(self):
        self.fail_set=True
        with self.assertRaises(ValueError):self.call('clients-add',**self.fields())
        path=self.profiles/'wg0.conf';path.write_text(path.read_text()+'\n# external change\n');before=path.read_bytes()
        self.fail_set=False
        with self.assertRaisesRegex(ValueError,'другим действием'):self.call('clients-finish',operation=operation_state(self.root)['id'])
        self.assertEqual(path.read_bytes(),before)
    def test_bad_name_dns_mtu_routes_and_nonadmitted_address_do_not_write(self):
        before=(self.profiles/'wg0.conf').read_bytes();fields=self.fields()
        for change in [{'name':'x\nPostUp = bad'},{'dns':'not an ip'},{'routes':'nonsense'},{'mtu':'999999'},{'ipv6':False,'routes':'::/0'}]:
            with self.assertRaises(ValueError):self.call('clients-add',**{**fields,'values':{**fields['values'],**change}})
            self.assertEqual((self.profiles/'wg0.conf').read_bytes(),before);self.assertFalse(operation_state(self.root))
        self.save(self.network/'applied-policy.json',json.dumps({'vpn_ingress':{'enabled':True,'interface':'wg0','clients':['10.77.0.8/32']}}))
        with self.assertRaisesRegex(ValueError,'не допущен'):self.call('clients-add',**fields)
        self.assertFalse(operation_state(self.root))
    def test_device_without_verified_client_config_cannot_be_disabled(self):
        view=self.call();identifier=view['clients'][1]['id'];before=(self.profiles/'wg0.conf').read_bytes()
        with self.assertRaisesRegex(ValueError,'клиентский конфиг'):self.call('clients-disable',id=identifier,file_revision=view['file_revision'])
        self.assertEqual(before,(self.profiles/'wg0.conf').read_bytes())
    def test_disabled_address_remains_reserved_and_altered_config_cannot_enable(self):
        view=self.call();identifier=view['clients'][0]['id'];self.call('clients-disable',id=identifier,file_revision=view['file_revision'])
        p=self.directory/'10.77.0.8.conf';p.write_text(p.read_text().replace('10.77.0.8/32','10.77.0.9/32'))
        with self.assertRaisesRegex(ValueError,'изменён'):self.call('clients-enable',id=identifier,file_revision=self.call()['file_revision'])
    # Base-class read-only expectations enumerate just wg commands.
    def test_export_preserves_keys_and_only_changes_endpoint(self):super().test_export_preserves_keys_and_only_changes_endpoint()

    def test_web_add_disable_confirmation_and_reenable_without_raw_interface_input(self):
        page=self.client.get('/devices');self.assertIn('Добавить устройство',page.text)
        values=self.fields()['values'];fields={'csrf':'test','file_revision':self.call()['file_revision'],**values};fields.pop('ipv6')
        response=self.client.post('/devices/add',data=fields,follow_redirects=True)
        self.assertEqual(response.status_code,200);self.assertIn('Клиент создан',response.text)
        view=self.call();row=next(r for r in view['clients'] if r['name']=='Новый телефон')
        fields={'csrf':'test','file_revision':view['file_revision']}
        url='/devices/'+row['id']+'/disable'
        self.assertEqual(self.client.post(url,data=fields).status_code,400);self.assertIn(NEW_PUBLIC,self.live)
        self.assertEqual(self.client.post(url,data={**fields,'confirm':'on'},follow_redirects=True).status_code,200)
        self.assertNotIn(NEW_PUBLIC,self.live)
        fields['file_revision']=self.call()['file_revision']
        self.assertEqual(self.client.post('/devices/'+row['id']+'/enable',data=fields,follow_redirects=True).status_code,200)
        self.assertIn(NEW_PUBLIC,self.live)
