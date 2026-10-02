"""Bounded STUN Binding through SOCKS5 UDP; no local DNS or direct fallback.

RFC 1928 UDP ASSOCIATE and RFC 8489 XOR-MAPPED-ADDRESS. This is a small
UDP-datagram check, not a QUIC, fragmentation or end-to-end client test.
"""
import ipaddress
import secrets
import socket
import struct
import time

COOKIE = 0x2112A442


class ProtocolError(Exception):
    pass


def remaining(deadline):
    value=deadline-time.monotonic()
    if value<=0:raise TimeoutError()
    return value


def exact(sock,size,deadline):
    result=b''
    while len(result)<size:
        sock.settimeout(remaining(deadline));part=sock.recv(size-len(result))
        if not part:raise ProtocolError('SOCKS5 закрыл контрольное соединение')
        result+=part
    return result


def address(read,kind):
    if kind==1:return str(ipaddress.IPv4Address(read(4)))
    if kind==4:return str(ipaddress.IPv6Address(read(16)))
    if kind==3:
        size=read(1)[0]
        if not size:raise ProtocolError('Пустой адрес SOCKS5')
        try:return read(size).decode('ascii').lower()
        except UnicodeError:raise ProtocolError('Некорректный адрес SOCKS5') from None
    raise ProtocolError('Неизвестный тип адреса SOCKS5')


def udp_payload(data,port):
    if len(data)<4 or data[:3]!=b'\0\0\0':
        raise ProtocolError('Некорректный или фрагментированный ответ SOCKS5 UDP')
    offset=4
    def read(size):
        nonlocal offset
        value=data[offset:offset+size];offset+=size
        if len(value)!=size:raise ProtocolError('Обрезанный ответ SOCKS5 UDP')
        return value
    address(read,data[3])
    if struct.unpack('!H',read(2))[0]!=port:raise ProtocolError('Ответ SOCKS5 UDP от другого порта')
    return data[offset:]


def mapped_address(data,transaction):
    if len(data)<20:raise ProtocolError('Обрезанный ответ STUN')
    kind,size,cookie=struct.unpack('!HHI',data[:8])
    if kind!=0x101 or cookie!=COOKIE or data[8:20]!=transaction or size%4 or len(data)!=20+size:
        raise ProtocolError('Ответ STUN не соответствует запросу')
    offset=20;found=None
    while offset<len(data):
        if offset+4>len(data):raise ProtocolError('Обрезанный атрибут STUN')
        kind,size=struct.unpack('!HH',data[offset:offset+4]);offset+=4
        end=offset+((size+3)&~3)
        if end>len(data):raise ProtocolError('Обрезанный атрибут STUN')
        value=data[offset:offset+size];offset=end
        if kind!=0x20:continue
        if len(value) not in (8,20) or value[0]!=0 or (value[1],len(value)) not in ((1,8),(2,20)):
            raise ProtocolError('Некорректный XOR-MAPPED-ADDRESS')
        mask=struct.pack('!I',COOKIE)+transaction
        ip=ipaddress.ip_address(bytes(a^b for a,b in zip(value[4:],mask)))
        if not ip.is_global or not (struct.unpack('!H',value[2:4])[0]^(COOKIE>>16)):
            raise ProtocolError('STUN не вернул публичный адрес выхода')
        if found is not None and found!=str(ip):raise ProtocolError('Противоречивые адреса STUN')
        found=str(ip)
    if found is None:raise ProtocolError('В ответе STUN нет адреса выхода')
    return found


def binding(proxy,host,port,timeout):
    proxy_host,proxy_port=proxy.rsplit(':',1);proxy_ip=ipaddress.ip_address(proxy_host.strip('[]'))
    family=socket.AF_INET6 if proxy_ip.version==6 else socket.AF_INET
    deadline=time.monotonic()+timeout;transaction=secrets.token_bytes(12)
    target=host.encode('ascii')
    if not 1<=len(target)<=253:raise ValueError('Invalid target')
    packet=b'\0\0\0\x03'+bytes([len(target)])+target+struct.pack('!H',port)
    packet+=struct.pack('!HHI',1,0,COOKIE)+transaction
    with socket.socket(family,socket.SOCK_STREAM) as control:
        control.settimeout(remaining(deadline));control.connect((str(proxy_ip),int(proxy_port)))
        control.sendall(b'\x05\x01\x00')
        if exact(control,2,deadline)!=b'\x05\x00':raise ProtocolError('SOCKS5 требует неподдерживаемую аутентификацию')
        control.sendall(b'\x05\x03\x00\x01'+b'\0'*6)
        header=exact(control,4,deadline)
        if header[:3]!=b'\x05\x00\x00':raise ProtocolError('SOCKS5 не открыл UDP ASSOCIATE')
        relay=address(lambda n:exact(control,n,deadline),header[3])
        relay_port=struct.unpack('!H',exact(control,2,deadline))[0]
        try:relay_ip=ipaddress.ip_address(relay)
        except ValueError:raise ProtocolError('SOCKS5 вернул имя вместо IP UDP-реле') from None
        if relay_ip.is_unspecified:relay_ip=proxy_ip
        if relay_ip!=proxy_ip or not relay_port:raise ProtocolError('UDP-реле должно находиться на адресе заданного SOCKS5')
        with socket.socket(family,socket.SOCK_DGRAM) as udp:
            udp.bind((control.getsockname()[0],0))
            udp.settimeout(remaining(deadline));udp.connect((str(relay_ip),relay_port));udp.send(packet)
            udp.settimeout(remaining(deadline));data=udp.recv(4096)
        return mapped_address(udp_payload(data,port),transaction)


def probe(check):
    try:
        ip=binding(check['proxy'],check['host'],check['port'],check.get('timeout_seconds',3))
        return 'up','UDP STUN через заданный SOCKS5; внешний IP: '+ip
    except ProtocolError as error:return 'down',str(error)
    except (TimeoutError,OSError):return 'down','Нет ответа UDP STUN через заданный SOCKS5 в отведённое время'
