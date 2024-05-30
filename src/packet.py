""" Simplified model of a Ethernet / IP / UDP packet """
import dataclasses
import logging
import socket

from enum import Enum, unique
from struct import unpack

logger = logging.getLogger(__name__)


ETH_LENGTH = 14

@unique
class EthernetProtocol(Enum):
    """ Meaning of protocol value from Ethernet frame header """
    UNKNOWN = 0         # We could classify more but we don't care!
    IPv4 = 0x0800
    IPv6 = 0x86DD

    @classmethod
    def _missing_(cls, _):
        return cls.UNKNOWN

class BadPacketException(Exception):
    """ Basic exception type raised by Packet class """
    pass


@dataclasses.dataclass
class Packet():
    """ How to deconstruct and modify a Ethernet / UDP Packet 
    This is a very limited implementation designed only to support the 
    operations needed by this code. For example, it does not attempt to 
    recompute the checksums if the payload is modified. """
    raw : bytes

    eth_protocol : EthernetProtocol = EthernetProtocol.UNKNOWN
    eth_dst_mac  : bytes = None
    eth_src_mac  : bytes = None

    _iph_length : int = dataclasses.field(default=None, repr=None)
    ip_version  : int = None
    ip_protocol : int = None
    ip_chksum   : int = None
    ip_src_addr : str = None
    ip_dst_addr : str = None

    udp_src_port : int = None
    udp_dst_port : int = None
    udp_length   : int = None
    udp_chksum   : int = None

    def __post_init__(self):

        # Always decode the Ethernet portion, but we're lazy about
        # decoding the higher protocols
        self.decode_ethernet()


    def decode_ethernet(self):
        """ Interpret input bytes as a Ethernet packet """
        # https://en.wikipedia.org/wiki/Ethernet_frame#Structure

        logger.debug('Decoding ethernet packet %r', self.raw)

        try:
            # TODO: Do we need to account for formats other than Ethernet-II or 
            # VPN frames, etc.
            eth_header = self.raw[:ETH_LENGTH]
            eth = unpack('!6s6sH' , eth_header)

            self.eth_protocol = EthernetProtocol(eth[2])
            self.eth_dst_mac  = eth[0]
            self.eth_src_mac  = eth[1]
        except Exception as e:
            raise BadPacketException from e

    def _decode_ipv4(self):
        """ Decode IPv4 protocol header """
        # https://en.wikipedia.org/wiki/IPv4#Packet_structure
        # Take the data for the IPv4 header from the packet
        ip_header = self.raw[ETH_LENGTH:20+ETH_LENGTH]

        # Unpack data from IP header
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        # Calculate the version
        version_ihl = iph[0]
        self.ip_version = version_ihl >> 4

        if self.ip_version != 4:
            return

        # Calculate the length (of the header?)
        ihl = version_ihl & 0xF
        self._iph_length = ihl * 4

        # ttl = iph[5] # Time to live
        self.ip_protocol = iph[6]
        self.ip_chksum   = iph[7]
        self.ip_src_addr = socket.inet_ntoa(iph[8])
        self.ip_dst_addr = socket.inet_ntoa(iph[9])

    def _decode_ipv6(self):
        """ Decode IPv6 protocol header """
        # https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
        ip_header = self.raw[ETH_LENGTH:40+ETH_LENGTH]

        # Unpack data from IP header
        iph = unpack('!IHBB16s16s', ip_header)

        # Calculate the version
        version_ihl = ip_header[0]
        self.ip_version = version_ihl >> 4

        if self.ip_version != 6:
            return

        # Calculate the length of the header
        self._iph_length = 40 # IPv6 header is a fixed length

        self.ip_protocol = iph[2]
        self.ip_chksum   = None   # IPv6 relies on other layers for the checksum
        self.ip_src_addr = iph[4]
        self.ip_dst_addr = iph[5]

    def decode_ip(self):
        """ Decode the IP Protocol header """
        try:
            match self.eth_protocol:
                case EthernetProtocol.UNKNOWN:
                    # If we don't know what this is then do nothing
                    return

                case EthernetProtocol.IPv4:
                    self._decode_ipv4()

                case EthernetProtocol.IPv6:
                    self._decode_ipv6()

                case _:
                    # This ought to be impossible so we will raise in this case
                    raise SyntaxError(f'Unhandled ip_protocol type {self.eth_protocol}')
        except Exception as e:
            raise BadPacketException from e

    def decode_udp(self):
        """ Decode UDP header information """
        try:
            # Get the UDP Header
            udp_packet_start = self._iph_length + ETH_LENGTH
            udp_packet_end   = udp_packet_start+8
            udp_header = self.raw[udp_packet_start:udp_packet_end]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            self.udp_src_port = udph[0]
            self.udp_dst_port = udph[1]
            self.udp_length   = udph[2]
            self.udp_chksum   = udph[3]
        except Exception as e:
            raise BadPacketException from e

    def get_udp_payload(self) -> bytes:
        """ Get the UDP payload from the packet """
        try:
            udp_packet_end   = self._iph_length + ETH_LENGTH + 8
            return self.raw[udp_packet_end:]
        except Exception as e:
            raise BadPacketException from e

    def change_ethernet_source(self, newmac):
        """ Change packet Ethernet source to a new MAC address """
        self.raw = self.raw[0:6] + newmac + self.raw[12:]
