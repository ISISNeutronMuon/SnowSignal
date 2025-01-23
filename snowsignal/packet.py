"""Simplified model of a Ethernet / IP / UDP packet"""

import dataclasses
import logging
import socket
from enum import Enum, unique
from struct import unpack

logger = logging.getLogger(__name__)


ETH_LENGTH = 14


@unique
class EthernetProtocol(Enum):
    """Meaning of protocol value from Ethernet frame header"""

    UNKNOWN = 0  # We could classify more but we don't care!
    IPv4 = 0x0800  # pylint: disable=invalid-name
    IPv6 = 0x86DD  # pylint: disable=invalid-name

    @classmethod
    def _missing_(cls, _):
        return cls.UNKNOWN


class BadPacketException(Exception):
    """Basic exception type raised by Packet class"""


@dataclasses.dataclass
class Packet:
    """How to deconstruct and modify a Ethernet / UDP Packet
    This is a very limited implementation designed only to support the
    operations needed by this code. For example, it does not attempt to
    recompute the checksums if the payload is modified."""

    raw: bytes

    eth_protocol: EthernetProtocol = EthernetProtocol.UNKNOWN
    eth_dst_mac: bytes | None = None
    eth_src_mac: bytes | None = None

    _iph_length: int = dataclasses.field(default=-1, repr=False)
    ip_version: int | None = None
    ip_protocol: int | None = None
    ip_chksum: int | None = None
    ip_src_addr: str | None = None
    ip_dst_addr: str | None = None

    udp_src_port: int | None = None
    udp_dst_port: int | None = None
    udp_length: int | None = None
    udp_chksum: int | None = None

    def __post_init__(self) -> None:
        # Always decode the Ethernet portion, but we're lazy about
        # decoding the higher protocols
        self.decode_ethernet()

    def decode_ethernet(self) -> None:
        """Interpret input bytes as a Ethernet packet"""
        # https://en.wikipedia.org/wiki/Ethernet_frame#Structure

        logger.debug("Decoding ethernet packet %r", self.raw)

        try:
            # TODO: Do we need to account for formats other than Ethernet-II or
            # VPN frames, etc.
            eth_header = self.raw[:ETH_LENGTH]
            eth = unpack("!6s6sH", eth_header)

            self.eth_protocol = EthernetProtocol(eth[2])
            self.eth_dst_mac = eth[0]
            self.eth_src_mac = eth[1]
        except Exception as e:
            raise BadPacketException from e

    def _decode_ipv4(self) -> None:
        """Decode IPv4 protocol header"""
        # https://en.wikipedia.org/wiki/IPv4#Packet_structure
        # Take the data for the IPv4 header from the packet
        ip_header = self.raw[ETH_LENGTH : 20 + ETH_LENGTH]  # noqa: E203

        # Unpack data from IP header
        iph = unpack("!BBHHHBBH4s4s", ip_header)

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
        self.ip_chksum = iph[7]
        self.ip_src_addr = socket.inet_ntoa(iph[8])
        self.ip_dst_addr = socket.inet_ntoa(iph[9])

    def _decode_ipv6(self) -> None:
        """Decode IPv6 protocol header"""
        # https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
        ip_header = self.raw[ETH_LENGTH : 40 + ETH_LENGTH]  # noqa: E203

        # Unpack data from IP header
        iph = unpack("!IHBB16s16s", ip_header)

        # Calculate the version
        version_ihl = ip_header[0]
        self.ip_version = version_ihl >> 4

        if self.ip_version != 6:
            return

        # Calculate the length of the header
        self._iph_length = 40  # IPv6 header is a fixed length

        self.ip_protocol = iph[2]
        self.ip_chksum = None  # IPv6 relies on other layers for the checksum
        self.ip_src_addr = iph[4]
        self.ip_dst_addr = iph[5]

    def decode_ip(self) -> None:
        """Decode the IP Protocol header"""
        try:
            match self.eth_protocol:
                case EthernetProtocol.IPv4:
                    self._decode_ipv4()
                case EthernetProtocol.IPv6:
                    self._decode_ipv6()
                case EthernetProtocol.UNKNOWN:
                    # If we don't know what this is then do nothing
                    return
                case _:
                    # This ought to be impossible so we will raise in this case
                    raise SyntaxError(f"Unhandled ip_protocol type {self.eth_protocol}")
        except Exception as e:
            raise BadPacketException from e

    def decode_udp(self) -> None:
        """Decode UDP header information"""
        try:
            # Get the UDP Header
            udp_packet_start = self._iph_length + ETH_LENGTH
            udp_packet_end = udp_packet_start + 8
            udp_header = self.raw[udp_packet_start:udp_packet_end]

            # now unpack them :)
            udph = unpack("!HHHH", udp_header)

            self.udp_src_port = udph[0]
            self.udp_dst_port = udph[1]
            self.udp_length = udph[2]
            self.udp_chksum = udph[3]
        except Exception as e:
            raise BadPacketException from e

    def get_udp_payload(self) -> bytes:
        """Get the UDP payload from the packet"""
        try:
            udp_packet_end = self._iph_length + ETH_LENGTH + 8
            return self.raw[udp_packet_end:]
        except Exception as e:
            raise BadPacketException from e

    def change_ethernet_source(self, newmac) -> None:
        """Change packet Ethernet source to a new MAC address"""
        self.raw = self.raw[0:6] + newmac + self.raw[12:]


@unique
class PVAccessMessageType(Enum):
    """PVAccess Application Message Type"""

    BEACON = 0x00
    VALIDATION = 0x01
    ECHO = 0x02
    SEARCH_REQUEST = 0x03
    SEARCH_RESPONSE = 0x04
    CREATE_CHANNEL = 0x07
    DESTROY_CHANNEL = 0x08
    GET = 0x0A
    PUT = 0x0B
    PUTGET = 0x0C
    MONITOR = 0x0D
    ARRAY = 0x0E
    DESTROY_REQUEST = 0x0F
    CHANNEL_PROCESS = 0x10
    GET_INTROSPECT = 0x11
    MESSAGE = 0x12
    CHANNEL_RPC = 0x14
    CANCEL_REQUEST = 0x15


@dataclasses.dataclass
class PVAccessMessageHeader:
    """PVAccess Message Header decoder"""

    raw: bytes

    magic: int
    version: int
    flags: int
    message_command: PVAccessMessageType
    payload_size: int

    def __init__(self, raw: bytes) -> None:
        """Decode message header bytes"""

        self.raw = raw

        try:
            msg_header = self.raw[0:8]

            pvh = unpack("!BBBBI", msg_header)
            if pvh[0] != 0xCA:
                raise BadPacketException

            self.magic = pvh[0]
            self.version = pvh[1]
            self.flags = pvh[2]
            self.message_command = PVAccessMessageType(pvh[3])
            self.payload_size = pvh[4]

        except Exception as e:
            raise BadPacketException from e


@dataclasses.dataclass
class PVAccessBeaconMessage:
    """PVAccess Beacon Message decode"""

    raw: bytes

    guid: str
    flags: bytes
    beacon_sequence_id: int
    change_count: int
    server_address: str  # IPv4Address | IPv6Address
    server_port: int
    protocol: str

    def __init__(self, raw: bytes) -> None:
        """Decode beacon message payload"""

        self.raw = raw

        try:
            msg_payload = self.raw

            pbm = unpack("!10sBBH16sHB", msg_payload[0:33])

            self.guid = pbm[0].hex()
            self.flags = pbm[1]
            self.beacon_sequence_id = pbm[2]
            self.change_count = pbm[3]
            self.server_address = pbm[4].hex()  # ip_address(pbm[4])
            self.server_port = pbm[5]

            # Quick hack here, but we won't bother supporting protocol string lengths of more than 255 chars
            protocol_str_length = pbm[6]
            pbm = unpack(f"{protocol_str_length}s", msg_payload[33 : 33 + protocol_str_length])
            self.protocol = pbm[0].decode("ascii")
        except Exception as e:
            raise BadPacketException from e


@dataclasses.dataclass
class PVAccessSearchMessage:
    """PVAccess Beacon Message decode"""

    raw: bytes

    search_sequence_id: int
    flags: bytes
    reponse_address: str  # IPv4Address | IPv6Address
    response_port: int
    protocols: list[str]
    channelnames: list[str]

    @dataclasses.dataclass
    class Channel:
        search_instance_id: int
        channelname: str

        def __repr__(self) -> str:
            return f"{self.search_instance_id} / {self.channelname}"

    channels: list[Channel]

    def __init__(self, raw: bytes) -> None:
        """Decode search message payload"""

        self.raw = raw

        try:
            msg_payload = self.raw

            psm = unpack("!IB3x16sHB", msg_payload[0:27])

            self.search_sequence_id = psm[0]
            self.flags = psm[1]
            self.reponse_address = psm[2].hex()  # ip_address(pbm[4])
            self.response_port = psm[3]

            # Decode the array of protocol strings
            protocol_strings_count = psm[4]
            bytes_consumed = 27

            self.protocols: list[str] = []

            for x in range(protocol_strings_count):
                sl_unpacked = unpack("!B", msg_payload[bytes_consumed : bytes_consumed + 1])
                string_len = sl_unpacked[0]
                bytes_consumed = bytes_consumed + 1

                ps_unpacked = unpack(f"!{string_len}s", msg_payload[bytes_consumed : bytes_consumed + string_len])
                protocol_string = ps_unpacked[0].decode("ascii")
                bytes_consumed = bytes_consumed + string_len

                self.protocols.append(protocol_string)

            # Decode the array of channel searches
            cc_unpacked = unpack("!H", msg_payload[bytes_consumed : bytes_consumed + 2])
            channels_count = cc_unpacked[0]
            bytes_consumed = bytes_consumed + 2

            self.channels: list[self.Channel] = []

            for x in range(channels_count):
                chans_unpacked = unpack("!IB", msg_payload[bytes_consumed : bytes_consumed + 5])
                search_instance_id = chans_unpacked[0]
                channame_string_len = chans_unpacked[1]
                bytes_consumed = bytes_consumed + 5

                ps_unpacked = unpack(
                    f"!{channame_string_len}s", msg_payload[bytes_consumed : bytes_consumed + channame_string_len]
                )
                channame_string = ps_unpacked[0].decode("ascii")
                bytes_consumed = bytes_consumed + channame_string_len

                self.channels.append(self.Channel(search_instance_id, channame_string))

        except Exception as e:
            raise BadPacketException from e
