import copy
import ipaddress
import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

import udp_health as udp
from health_collect import collect,probe
from health_settings import form_fields,edit_check

CHECK={'id':'udp:candidate','name':'UDP кандидата','scope':'Кандидат','action':'Проверьте UDP и выбранный выход',
       'kind':'udp_stun','host':'stun.cloudflare.com','port':3478,'proxy':'127.0.0.1:2081','timeout_seconds':3}


def response(tx,address='92.42.99.188'):
    ip=ipaddress.ip_address(address);mask=struct.pack('!I',udp.COOKIE)+tx
    value=bytes([0,1 if ip.version==4 else 2])+struct.pack('!H',42000^(udp.COOKIE>>16))
    value+=bytes(a^b for a,b in zip(ip.packed,mask))
    attr=struct.pack('!HH',0x20,len(value))+value
    return struct.pack('!HHI',0x101,len(attr),udp.COOKIE)+tx+attr


class UDPHealthTests(unittest.TestCase):
    def test_public_ipv4_and_ipv6_stun_values(self):
        tx=b'x'*12
        for address in ('92.42.99.188','2606:4700:4700::1111'):
            self.assertEqual(udp.mapped_address(response(tx,address),tx),address)

    def test_wrong_transaction_truncation_private_and_conflicting_answers_fail(self):
        tx=b'x'*12;valid=response(tx)
        conflicting=valid[20:]+response(tx,'1.1.1.1')[20:]
        for data in (response(b'z'*12),valid[:-1],b'bad',response(tx,'127.0.0.1'),
                     struct.pack('!HHI',0x101,len(conflicting),udp.COOKIE)+tx+conflicting):
            with self.subTest(data=data),self.assertRaises(udp.ProtocolError):udp.mapped_address(data,tx)

    def test_socks_fragments_wrong_port_and_truncated_frames_fail(self):
        for data in (b'\0\0\1\1'+b'x'*40,b'\0\0\0\1'+b'\x01'*4+struct.pack('!H',53)+b'payload',
                     b'\0\0\0\3\x20short'):
            with self.subTest(data=data),self.assertRaises(udp.ProtocolError):udp.udp_payload(data,3478)

    def test_real_socks_handshake_remote_domain_udp_and_control_lifetime(self):
        observations=[];errors=[]
        with socket.socket() as listener,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as relay:
            listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(2)
            relay.bind(('127.0.0.1',0));relay.settimeout(2)
            def server():
                try:
                    with listener.accept()[0] as control:
                        control.settimeout(2)
                        def read(n):
                            result=b''
                            while len(result)<n:
                                part=control.recv(n-len(result))
                                if not part:raise AssertionError('early EOF')
                                result+=part
                            return result
                        observations.append(read(3));control.sendall(b'\5\0')
                        observations.append(read(10));control.sendall(b'\5\0\0\1'+b'\0'*4+struct.pack('!H',relay.getsockname()[1]))
                        packet,peer=relay.recvfrom(4096)
                        self.assertEqual(packet[:4],b'\0\0\0\3')
                        size=packet[4];observations.append(packet[5:5+size].decode());port=struct.unpack('!H',packet[5+size:7+size])[0]
                        stun=packet[7+size:];tx=stun[8:20]
                        self.assertEqual(stun[:8],struct.pack('!HHI',1,0,udp.COOKIE))
                        wrapped=b'\0\0\0\1'+ipaddress.IPv4Address('162.159.207.0').packed+struct.pack('!H',port)+response(tx)
                        relay.sendto(wrapped,peer)
                        observations.append(control.recv(1))
                except BaseException as error:errors.append(error)
            thread=threading.Thread(target=server);thread.start()
            try:
                with patch('socket.getaddrinfo',side_effect=AssertionError('Local DNS used')):
                    actual=udp.binding('127.0.0.1:'+str(listener.getsockname()[1]),'stun.cloudflare.com',3478,2)
                self.assertEqual(actual,'92.42.99.188')
            finally:thread.join(3)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
            self.assertEqual(observations,[b'\5\1\0',b'\5\3\0\1'+b'\0'*6,'stun.cloudflare.com',b''])

    def test_tcp_control_success_without_udp_reply_is_not_healthy(self):
        with socket.socket() as listener,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as relay:
            listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(2)
            relay.bind(('127.0.0.1',0));relay.settimeout(2);seen=[]
            def server():
                with listener.accept()[0] as control:
                    control.settimeout(2)
                    self.assertEqual(control.recv(3,socket.MSG_WAITALL),b'\5\1\0');control.sendall(b'\5\0')
                    control.recv(10,socket.MSG_WAITALL)
                    control.sendall(b'\5\0\0\1'+socket.inet_aton('127.0.0.1')+struct.pack('!H',relay.getsockname()[1]))
                    packet,_=relay.recvfrom(4096);seen.append(bool(packet));control.recv(1)
            thread=threading.Thread(target=server);thread.start()
            try:
                result=udp.probe({**CHECK,'proxy':'127.0.0.1:'+str(listener.getsockname()[1]),'timeout_seconds':.1})
            finally:thread.join(3)
            self.assertEqual(result[0],'down');self.assertEqual(seen,[True]);self.assertFalse(thread.is_alive())

    def test_single_deadline_prevents_slow_header_from_extending_budget(self):
        deadline=time.monotonic()+.04
        class Slow:
            def settimeout(self,value):pass
            def recv(self,n):time.sleep(.03);return b'x'
        before=time.monotonic()
        with self.assertRaises(TimeoutError):udp.exact(Slow(),10,deadline)
        self.assertLess(time.monotonic()-before,.2)

    def test_failure_has_no_direct_retry_and_does_not_disclose_exception(self):
        with patch('udp_health.binding',side_effect=OSError('private-secret')) as binding:
            status,detail=probe(CHECK)
        self.assertEqual(status,'down');self.assertNotIn('private-secret',detail);binding.assert_called_once()

    def test_typed_web_settings_require_proxy_and_bound_timeout(self):
        values={f['key']:str(f['value']) for f in form_fields(CHECK)}
        self.assertEqual(edit_check(CHECK,values),CHECK)
        for field,value in [('proxy',''),('proxy','name.example:2081'),('timeout_seconds','99'),('host','stun.example; command')]:
            with self.subTest(field=field),self.assertRaises(ValueError):edit_check(CHECK,{**values,field:value})

    def test_exit_change_is_an_event_even_when_probe_remains_up(self):
        with patch('udp_health.binding',return_value='92.42.99.188'):
            prior,_=collect([CHECK])
        with patch('udp_health.binding',return_value='1.1.1.1'),patch('health_collect.time.time',return_value=prior['checks'][0]['next_check_at']+1):
            current,events=collect([CHECK],prior)
        self.assertEqual(current['checks'][0]['status'],'up');self.assertEqual(len(events),1)
        self.assertIn('1.1.1.1',events[0]['detail'])


if __name__=='__main__':unittest.main()
