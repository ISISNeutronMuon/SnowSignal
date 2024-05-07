import struct
import psutil
import socket

from dataclasses import dataclass

@dataclass
class MessageHeader:
    magic : str
    version : int
    flags : int
    messageCommand : int
    payloadSize : int

def unpack_pvahdr(msghdr : bytes):
    msghdr_struct = '!BBBBI'

    return MessageHeader(struct.unpack(msghdr_struct, msghdr))

host = psutil.net_if_addrs()['eth0'][0].broadcast
port = 5076
local_addr = psutil.net_if_addrs()['eth0'][0].address




sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#sd.setsockopt(socket.IPPROTO_IP, socket.IP_RECVPKTINO, 1)
sd.bind((host, port))


print(f"[ ] listening on {sd.getsockname()}")
while True:
    # Receive UDP broadcast messages
    buf, cmsg, flags, remote_addr = sd.recvmsg(4096, 1024)

    # Check that this is a message we want to forward
    # It must not be from this relay and it must be a PVAccess message
    if buf and remote_addr != local_addr and buf[0]==202:
        if cmsg:
            print(f'cmg: {cmsg}')
        for cmsg_level, cmsg_type, cmsg_data in cmsg:
            print(f'cmsg_data: {cmsg_data}')
        print(remote_addr, buf)
        print(unpack_pvahdr(buf[0:8]))
    elif buf and remote_addr != local_addr:
        print('Wont forward!')

