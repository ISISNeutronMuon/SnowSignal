"""
Decode and understand PVAccess Protocol packets
Protocol specification is available here: https://docs.epics-controls.org/en/latest/pv-access/protocol.html
"""

import dataclasses
import logging
import socket
import struct
import traceback
from enum import Enum, IntEnum, unique
from struct import unpack

from .packet import BadPacketException, Packet

logger = logging.getLogger(__name__)


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


@unique
class Endianness(IntEnum):
    """Endianness of message"""

    LITTLEEND = 0
    BIGEND = 1

    def unpack_char(self) -> str:
        """Convert endianness to a Python struct format string, see
        https://docs.python.org/3/library/struct.html#format-strings"""
        match self.value:
            case self.LITTLEEND:
                return "<"
            case self.BIGEND:
                return ">"
            case _:
                raise IndexError("Unknown / Impossible Endianness")


@dataclasses.dataclass
class PVAccessMessageHeader:
    """PVAccess Message Header decoder

    https://docs.epics-controls.org/en/latest/pv-access/Protocol-Messages.html#message-header
    """

    @unique
    class MessageType(IntEnum):
        """Message header is type application or control"""

        APPLICATION = 0
        CONTROL = 1

    @unique
    class Segmentation(Enum):
        """Message is segmented, and what type of segment"""

        NOT_SEGMENTED = 0
        SEGMENT_START = 1
        SEGMENT_MIDDLE = 2
        SEGMENT_END = 3

    @unique
    class Role(IntEnum):
        """Message is from a client or server"""

        CLIENT = 0
        SERVER = 1

    raw: bytes  # The raw original bytes of the header

    magic: int  # Must be 0xCA for PVAccess
    version: int
    msgtype: MessageType
    segmented: Segmentation
    role: Role
    endian: Endianness
    message_command: PVAccessMessageType
    payload_size: int

    def __init__(self, raw: bytes) -> None:
        """Decode message header bytes"""

        self.raw = raw

        try:
            msg_header = self.raw[0:8]

            # Decode the first four bytes of the header
            # This also serves as a loose confirmation that this is a PVAccess protocol message
            # due to the magic bytes. Due to chance we'll only try to process mistakenly one
            # in 256 times. We decode only the first four bytes initially because we need to
            # know the endianness of the message
            pvh = unpack("BBBB", msg_header[0:4])
            if pvh[0] != 0xCA:
                logger.debug("Magic bytes were %s instead of 0xCA", hex(pvh[0]))
                raise BadPacketException(f"Magic bytes were {hex(pvh[0])} instead of 0xCA")

            self.magic = pvh[0]
            self.version = pvh[1]
            self.message_command = PVAccessMessageType(pvh[3])

            # Flags are packed in individual bits, or in one case a pair of bits, within a single byte
            # We need to know the endianness to decode the integer that follows
            flags = int(pvh[2])
            self.msgtype = self.MessageType(flags & 1)
            self.segmented = self.Segmentation((flags >> 4) & 0b11)
            self.role = self.Role((flags >> 6) & 1)
            self.endian = Endianness((flags >> 7) & 1)

            # Payload size, here we need to know the endianness
            pvhsize = unpack(f"{self.endian.unpack_char()}I", msg_header[4:8])
            self.payload_size = pvhsize[0]

        except Exception as e:
            raise BadPacketException from e


def decode_pvaccess_size(payload: bytes, endianness: Endianness, start_byte: int = 0) -> tuple[int, int]:
    """Decode a string or array size in the PVAccess Protocol format.

    https://docs.epics-controls.org/en/latest/pv-access/Protocol-Encoding.html#sizes

    We require a set of bytes to decode and optionally where in the bytes to start. This means that
    part of a message payload starting at the size or the entire payload with a pointer to the start
    of the size may be passed in. We then return a tuple of the size and a pointer to the byte after
    the decode."""

    endchar = endianness.unpack_char()

    # Calculate the length of the string or array. Usually this is encoded in a single byte, but
    # if the value of that byte is 254 then there is an integer which holds the size instead
    sizedecode_byte = unpack("B", payload[start_byte : start_byte + 1])
    bytes_for_decode = 1

    if sizedecode_byte[0] == 254:
        sizedecode_int = unpack(f"{endchar}I", payload[start_byte + 1 : start_byte + 5])

        pvasize = sizedecode_int[0]
        bytes_for_decode = 5
    elif sizedecode_byte[0] == 255:
        # I'm not sure why we're not using 0 to represent 0?
        pvasize = 0
    else:
        pvasize = sizedecode_byte[0]

    return (pvasize, start_byte + bytes_for_decode)


def decode_pvaccess_string(payload: bytes, endianness: Endianness, start_byte: int = 0) -> tuple[str, int]:
    """
    Decode a PVAccess Protocol string

    https://docs.epics-controls.org/en/latest/pv-access/Protocol-Encoding.html#strings

    This is basically an integer size specified in the usual PVAccess Protocol way
    (see decode_pvaccess_size()) and then an array of UTF-8 bytes
    """

    # First get the length of the string
    (pvastrlen, new_start_byte) = decode_pvaccess_size(payload, endianness, start_byte)

    # Then get the string
    pvastr_unpacked = unpack(f"!{pvastrlen}s", payload[new_start_byte : new_start_byte + pvastrlen])
    pvastr = pvastr_unpacked[0].decode("utf8")

    return (pvastr, new_start_byte + pvastrlen)


@dataclasses.dataclass
class PVAccessBeaconMessage:
    """
    PVAccess Beacon Message decode

    https://docs.epics-controls.org/en/latest/pv-access/Protocol-Messages.html#cmd-beacon-0x00
    """

    raw: bytes

    guid: str
    flags: bytes
    beacon_sequence_id: int
    change_count: int
    server_address: str  # IPv4Address | IPv6Address
    server_port: int
    protocol: str

    def __init__(self, raw: bytes, endianness: Endianness) -> None:
        """Decode beacon message payload"""

        self.raw = raw

        try:
            msg_payload = self.raw

            endchar = endianness.unpack_char()
            pbm = unpack(f"{endchar}12sBBH16sH", msg_payload[0:34])

            self.guid = pbm[0].hex()
            self.flags = pbm[1]
            self.beacon_sequence_id = pbm[2]
            self.change_count = pbm[3]
            self.server_address = pbm[4].hex()  # ip_address(pbm[4])
            self.server_port = pbm[5]

            (pvastr, _) = decode_pvaccess_string(msg_payload[34:], endianness)
            self.protocol = pvastr
        except Exception as e:
            raise BadPacketException from e


@dataclasses.dataclass
class PVAccessSearchMessage:
    """PVAccess Search Request Message decode

    https://docs.epics-controls.org/en/latest/pv-access/Protocol-Messages.html#cmd-search-0x03
    """

    raw: bytes

    search_sequence_id: int
    flags: bytes
    reponse_address: str  # IPv4Address | IPv6Address
    response_port: int
    protocols: list[str]

    @dataclasses.dataclass
    class Channel:
        search_instance_id: int
        channelname: str

        def __repr__(self) -> str:
            return f"{self.search_instance_id} / {self.channelname}"

    channels: list[Channel]

    def __repr__(self) -> str:
        return f"sid: {self.search_sequence_id} flags: {self.flags} raddr: {self.reponse_address} rport: {self.response_port} protos: {self.protocols}"

    def __init__(self, raw: bytes, endianness: Endianness) -> None:
        """Decode search message payload"""

        self.raw = raw

        try:
            msg_payload = self.raw

            endchar = endianness.unpack_char()
            psm = unpack(f"{endchar}IB3x16sH", msg_payload[0:26])

            self.search_sequence_id = psm[0]
            self.flags = psm[1]
            self.reponse_address = psm[2].hex()  # ip_address(pbm[4])
            self.response_port = psm[3]

            # Decode the array of protocol strings
            (protocol_strings_count, payload_pointer) = decode_pvaccess_size(msg_payload, endianness, 26)
            self.protocols: list[str] = []
            for x in range(protocol_strings_count):
                (protocol_string, payload_pointer) = decode_pvaccess_string(msg_payload, endianness, payload_pointer)
                self.protocols.append(protocol_string)

            # Decode the array of channel searches
            # Note that the spec uses a different size / count for this
            cc_unpacked = unpack(f"{endchar}H", msg_payload[payload_pointer : payload_pointer + 2])
            channels_count = cc_unpacked[0]
            payload_pointer = payload_pointer + 2

            # Get list of channels. This is an array of structs, where the structs are an integer identifier
            # and a channel name string. We catch struct unpack exceptions because an earlier version of SnowSignal
            # was rebroadcasting truncated strings
            self.channels: list[PVAccessSearchMessage.Channel] = []
            try:
                for x in range(channels_count):
                    # Get search instance ID
                    chans_unpacked = unpack(f"{endchar}I", msg_payload[payload_pointer : payload_pointer + 4])
                    search_instance_id = chans_unpacked[0]
                    payload_pointer = payload_pointer + 4

                    # Get channelname string
                    (channame_string, payload_pointer) = decode_pvaccess_string(
                        msg_payload, endianness, payload_pointer
                    )

                    self.channels.append(self.Channel(search_instance_id, channame_string))
            except struct.error as e:
                logger.debug(
                    "Unexpected termination of search channel array, possible truncated packet or malformed channel count"
                )
                logger.debug(
                    "%s, channels_count: %i no_channels_found: %i channels_found: %s",
                    self,
                    channels_count,
                    len(self.channels),
                    self.channels,
                )
                raise BadPacketException from e

        except Exception as e:
            raise BadPacketException from e


def log_pvaccess(payload: bytes, packet_src_ip: str | None, source: str = "Rebroadcasting") -> None:
    """Log details of a PVAccess message payload"""
    # We trap all BadPacketExceptions because
    try:
        # Decode the PVAcccess Protocol message header
        pvamgshdr = PVAccessMessageHeader(payload)

        # Construct a string describing the source for the later log messages
        if packet_src_ip:
            try:
                # Try to determine the name of the source machine, but such a thing may not exist
                srcname = socket.gethostbyaddr(packet_src_ip)[0] if packet_src_ip else "Unknown"
                srcstring = f"{packet_src_ip} --> {srcname}"
            except socket.herror:
                srcstring = f"{packet_src_ip}"
        else:
            srcstring = "Unspecified"

        messagehdr_str = (
            f"{source} {pvamgshdr.message_command.name} (v{pvamgshdr.version}) "
            f"[Flags: {pvamgshdr.msgtype.name},{pvamgshdr.segmented.name},{pvamgshdr.role.name},{pvamgshdr.endian.name}] "
            f"from {srcstring}"
        )

        pva_message = payload[8:]
        match pvamgshdr.message_command:
            case PVAccessMessageType.BEACON:
                pvabeaconmsg = PVAccessBeaconMessage(pva_message, pvamgshdr.endian)
                logger.info(
                    "%s: self-identifies as %s %s:%i;%s with update counters beacon:%i, PVs:%i",
                    messagehdr_str,
                    pvabeaconmsg.protocol,
                    pvabeaconmsg.server_address,
                    pvabeaconmsg.server_port,
                    pvabeaconmsg.guid,
                    pvabeaconmsg.beacon_sequence_id,
                    pvabeaconmsg.change_count,
                )
            case PVAccessMessageType.SEARCH_REQUEST:
                # Seems to work for pvxs and Phoebus sources
                pvasearchmsg = PVAccessSearchMessage(pva_message, pvamgshdr.endian)
                logger.info(
                    "%s: self-identifies as %s:%i (seq id %i) with protocols %s searching for %s",
                    messagehdr_str,
                    pvasearchmsg.reponse_address,
                    pvasearchmsg.response_port,
                    pvasearchmsg.search_sequence_id,
                    pvasearchmsg.protocols,
                    pvasearchmsg.channels,
                )
            case _:
                # Currently unsupported / unexpected
                logger.info("Decode of %s message is currently unsupported", pvamgshdr.message_command.name)

    except BadPacketException:
        # Ignore packets we can't decode
        logger.info("Packet not decoded; invalid or malformed PVAccess Protocol?")
        logger.info("Bad PVAccess packet from %s : %s", packet_src_ip, payload)
        logging.error(traceback.format_exc())


def log_pvaccess_packet(packet: Packet) -> None:
    """Details of a PVAccess message packet"""
    # Check packet is minimum length to support a PVAccess protocol header
    if packet.udp_length and packet.udp_length >= 8:
        payload = packet.get_udp_payload()
        packet_src_ip = packet.ip_src_addr
        log_pvaccess(payload, packet_src_ip, "Received")
    else:
        logger.debug("Received from %s payload that was not PVAccess Protocol message", packet.ip_src_addr)
