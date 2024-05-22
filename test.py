""" The PVASniffer class is """

import asyncio
import logging
import socket
import sys

from struct import *
import zlib

logger = logging.getLogger(__name__)


class UDPRelayTransmitProtocol(asyncio.Protocol):
    """Listen for PVAccess UDP broadcasts and transmit to the other relays"""

    # We can't use the handy asyncio.DatagramProtocol because we need
    # the raw socket to access the full UDP packet and not just its
    # payload

    def __init__(
        self,
        local_port: int = 5076,
        remote_relays = None,
        remote_port=7124,
        config = None
    ):
        super().__init__()
        logger.info("Initialising UDPRelayTransmitProtocol listening for UDP broadcasts "
                    "on port %i for relay to remote relays %s on port %i",
                    local_port, remote_relays, remote_port)
        self.local_port = local_port
        self.remote_port = remote_port
        self.remote_relays = remote_relays
        self.transport : asyncio.DatagramTransport = None  # Hasn't been initialised yet

        # If there's a config provided then use the setting from it,
        # otherwise use some sensible defaults
        if config:
            iface = config.target_interface
            mode = config.rebroadcast_mode
        else:
            mode = 'packet'
            iface = 'eth0'

    def connection_made(self, transport: asyncio.Transport):
        """Handle a connection being established"""
        self.transport = transport

    def connection_lost(self, exc):
        """Handle a connection being lost"""
        # What does connection lost even mean for UDP?
        # Seems only necessary to stop some spurious errors on server shutdown

    def data_received(self, data: bytes) -> None:
        """Receive a UDP message and forward it to the remote relays"""
        logger.debug(
            "Received UDP message from %r",
            data
        )

        sock : socket.socket = self.transport.get_extra_info('socket')
        print('data = ', data)
        print('sock = ', sock)

def human_readable_mac(macbytes : bytes) -> str:
    unseparated_mac_str = macbytes.hex()
    return ':'.join([i+j for i,j in zip(unseparated_mac_str[::2], unseparated_mac_str[1::2])])

async def main():
    # Listen to everything 
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))


#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
#define ETH_P_IP     0x0800          IP packets only
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0800))
except socket.error as msg:
    print('Socket could not be created. Error Code : ', msg)
    sys.exit()

# receive a packet
count = 0
while count < 3:
    packet = s.recvfrom(65565)
    print('packet: ', packet, hex(zlib.crc32(packet[0])))

    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    ETH_LENGTH = 14

    eth_header = packet[:ETH_LENGTH]
    print('eth_header: ', eth_header)
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    destination_mac = eth[0]
    print('Destination MAC : ' + human_readable_mac(destination_mac) +
          ' Source MAC : ' + human_readable_mac(eth[1]) +
          ' Protocol : ' + str(eth_protocol)
          )

    if destination_mac != b'\xff\xff\xff\xff\xff\xff' or eth_protocol != 8:
        print(destination_mac)
        print('Not broadcast or not IP')
        sys.exit()

    #Parse IP packets, IP Protocol v4 number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[ETH_LENGTH:20+ETH_LENGTH]
        print('ip_header:', ip_header)

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        ip_chksum = iph[7]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print('Version : ' + str(version) + 
              ' IP Header Length : ' + str(ihl) + 
              ' TTL : ' + str(ttl) + 
              ' Protocol : ' + str(protocol) + 
              ' Checksum : ' + str(ip_chksum) +
              ' Source Address : ' + str(s_addr) + 
              ' Destination Address : ' + str(d_addr))

        #TCP protocol
        if protocol == 6 :
            print('Identified TCP')
            t = iph_length + ETH_LENGTH
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))

            h_size = ETH_LENGTH + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print('Data : ', data)

        #ICMP Packets
        elif protocol == 1 :
            print('Identified ICMP')

            u = iph_length + ETH_LENGTH
            ICMPH_LENGTH = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            print('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))

            h_size = ETH_LENGTH + iph_length + ICMPH_LENGTH
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print('Data : ', data)

        #UDP packets
        elif protocol == 17 :
            print('Identified UDP')

            u = iph_length + ETH_LENGTH
            UDPH_LENGTH = 8
            udp_header = packet[u:u+8]
            print('udp_header', udp_header)

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))

            h_size = ETH_LENGTH + iph_length + UDPH_LENGTH
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print('Data : ', data)

            s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s2.bind(("eth0", 0))
            s2.send(packet)
        #some other IP packet like IGMP
        else :
            print('Protocol other than TCP/UDP/ICMP')

        print(20*'-')

        count = count + 1
    else:
        print('Non-IP protocol')
