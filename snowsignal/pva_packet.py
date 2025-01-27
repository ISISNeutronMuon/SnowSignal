"""Decode and understand PVAccess Protocol packets"""

import dataclasses
import logging
import socket
import struct
import traceback
from enum import Enum, unique
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
                logger.debug("Magic bytes were %s instead of 0xCA", hex(pvh[0]))
                raise BadPacketException

            self.magic = pvh[0]
            self.version = pvh[1]
            self.flags = pvh[2]
            self.message_command = PVAccessMessageType(pvh[3])
            self.payload_size = pvh[4]

        except Exception as e:
            raise BadPacketException from e


def decode_pvaccess_size(payload: bytes, start_byte: int = 0) -> tuple[int, int]:
    """Decode a string or array size in the PVAccess Protocol format.
    We require a set of bytes to decode and optionally where in the bytes to start. This means that
    part of a message payload starting at the size or the entire payload with a pointer to the start
    of the size may be passed in. We then return a tuple of the size and a pointer to the byte after
    the decode."""

    # Calculate the length of the string or array. Usually this is encoded in a single byte, but
    # if the value of that byte is 254 then there is an integer which holds the size instead
    sizedecode_byte = unpack("!B", payload[start_byte : start_byte + 1])
    bytes_for_decode = 1

    if sizedecode_byte[0] == 254:
        sizedecode_int = unpack("!I", payload[start_byte + 1 : start_byte + 5])

        pvasize = sizedecode_int[0]
        bytes_for_decode = 5
    elif sizedecode_byte[0] == 255:
        # I'm not sure why we're not using 0 to represent 0?
        pvasize = 0
    else:
        pvasize = sizedecode_byte[0]

    return (pvasize, start_byte + bytes_for_decode)


def decode_pvaccess_string(payload: bytes, start_byte: int = 0) -> tuple[str, int]:
    """Decode a PVAccess Protocol string"""

    # First get the length of the string
    (pvastrlen, new_start_byte) = decode_pvaccess_size(payload, start_byte)

    # Then get the string
    pvastr_unpacked = unpack(f"!{pvastrlen}s", payload[new_start_byte : new_start_byte + pvastrlen])
    pvastr = pvastr_unpacked[0].decode("utf8")

    return (pvastr, new_start_byte + pvastrlen)


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

            pbm = unpack("!12sBBH16sH", msg_payload[0:34])

            self.guid = pbm[0].hex()
            self.flags = pbm[1]
            self.beacon_sequence_id = pbm[2]
            self.change_count = pbm[3]
            self.server_address = pbm[4].hex()  # ip_address(pbm[4])
            self.server_port = pbm[5]

            (pvastr, _) = decode_pvaccess_string(msg_payload[34:])
            self.protocol = pvastr
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

    @dataclasses.dataclass
    class Channel:
        search_instance_id: int
        channelname: str

        def __repr__(self) -> str:
            return f"{self.search_instance_id} / {self.channelname}"

    channels: list[Channel]

    def __repr__(self) -> str:
        return f"sid: {self.search_sequence_id} flags: {self.flags} raddr: {self.reponse_address} rport: {self.response_port} protos: {self.protocols}"

    def __init__(self, raw: bytes) -> None:
        """Decode search message payload"""

        self.raw = raw

        try:
            msg_payload = self.raw

            psm = unpack("!IB3x16sH", msg_payload[0:26])

            self.search_sequence_id = psm[0]
            self.flags = psm[1]
            self.reponse_address = psm[2].hex()  # ip_address(pbm[4])
            self.response_port = psm[3]

            # Decode the array of protocol strings
            (protocol_strings_count, payload_pointer) = decode_pvaccess_size(msg_payload, 26)
            self.protocols: list[str] = []
            for x in range(protocol_strings_count):
                (protocol_string, payload_pointer) = decode_pvaccess_string(msg_payload, payload_pointer)
                self.protocols.append(protocol_string)

            # Decode the array of channel searches
            # Note that the spec uses a different size / count for this
            cc_unpacked = unpack("!H", msg_payload[payload_pointer : payload_pointer + 2])
            channels_count = cc_unpacked[0]
            logger.debug(
                "channel count = %i,  bytes = %s %s",
                channels_count,
                msg_payload[payload_pointer : payload_pointer + 2],
                msg_payload[payload_pointer : payload_pointer + 2].hex(),
            )
            payload_pointer = payload_pointer + 2

            # Get list of channels. This is an array of structs, where the structs are an integers identifier
            # and a channel name string
            self.channels: list[self.Channel] = []
            # Some implementations get the channel count wrong by using local endianness instead of
            # network endianness. We have to handle there unexpectedly being no data. Note, we could still
            # undercount the amount of data. Do other implementations just ignore the count and use
            # a while loop, I wonder?
            try:
                for x in range(channels_count):
                    # Get search instance ID
                    chans_unpacked = unpack("!I", msg_payload[payload_pointer : payload_pointer + 4])
                    search_instance_id = chans_unpacked[0]
                    payload_pointer = payload_pointer + 4

                    # Get channelname string
                    (channame_string, payload_pointer) = decode_pvaccess_string(msg_payload, payload_pointer)

                    self.channels.append(self.Channel(search_instance_id, channame_string))
            except struct.error:
                logger.debug(
                    "Unexpected termination of search channel array, probable malformed channel count (endianess?)"
                )
                logger.debug(
                    "%s, channels_count: %i no_channels_found: %i channels_found: %s",
                    self,
                    channels_count,
                    len(self.channels),
                    self.channels,
                )

        except Exception as e:
            raise BadPacketException from e


def log_pvaccess(payload: bytes, packet_src_ip: str | None, source: str = "Rebroadcasting") -> None:
    try:
        pvamgshdr = PVAccessMessageHeader(payload)
        logger.info(
            "%s %s (v%i) from %s --> %s",
            source,
            pvamgshdr.message_command.name,
            pvamgshdr.version,
            packet_src_ip,
            socket.gethostbyaddr(packet_src_ip)[0] if packet_src_ip else "Unknown",
        )

        pva_message = payload[8:]
        match pvamgshdr.message_command:
            case PVAccessMessageType.BEACON:
                pvabeaconmsg = PVAccessBeaconMessage(pva_message)
                logger.info(
                    "%s BEACON source (%s) self-identifies as %s %s:%i;%s with update counters beacon:%i, PVs:%i",
                    source,
                    packet_src_ip,
                    pvabeaconmsg.protocol,
                    pvabeaconmsg.server_address,
                    pvabeaconmsg.server_port,
                    pvabeaconmsg.guid,
                    pvabeaconmsg.beacon_sequence_id,
                    pvabeaconmsg.change_count,
                )
            case PVAccessMessageType.SEARCH_REQUEST:
                # Seems to work for pvxs and Phoebus sources
                pvasearchmsg = PVAccessSearchMessage(pva_message)
                logger.info(
                    "%s SEARCH_REQUEST source (%s) self-identifies as %s:%i (seq id %i) with protocols %s searching for %s",
                    source,
                    packet_src_ip,
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
    # Check packet is minimum length to support a PVAccess protocol header
    if packet.udp_length and packet.udp_length >= 8:
        payload = packet.get_udp_payload()
        packet_src_ip = packet.ip_src_addr
        # payload_hdr = b"\xca\x02\x80\x03\x00\x00\x000"
        # payload = (
        #     payload_hdr
        #     + b"\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\xb0\xea\x01\x03tcp\x17\x00\x041 \x10\x1fTGT1:CRYO:CH4CBX:PV16M-C:STATUS 1 \x10 TGT1:CRYO:CH4GASPAN:PV36M:STATUS%1 \x10(TGT1:CRYO:CH4PLC:HEARTBEAT:PLC_HEARTBEAT&1 \x10#TGT1:CRYO:CH4PURGEPAN:PV310M:STATUS'1 \x10#TGT1:CRYO:CH4PURGEPAN:PV314M:STATUS(1 \x10#TGT1:CRYO:CH4PURGEPAN:PV315M:STATUS)1 \x10#TGT1:CRYO:CH4PURGEPAN:PV318M:STATUS+1 \x10-TGT1:CRYOCH4CRYOGENERATOR:CH4:PT170M:PRESSURE,1 \x10,TGT1:CRYOCH4CRYOGENERATOR:CH4:PT76M:PRESSURE-1 \x10%TGT1:CRYOGENERATOR:TS351M:TEMPERATURE.1 \x10$TGT1:GASPLATFORM:CH4:PT165M:PRESSURE/1 \x10$TGT1:GASPLATFORM:CH4:PT271M:PRESSURE01 \x10$TGT1:GASPLATFORM:CH4:PT297M:PRESSURE11 \x10$TGT1:GASPLATFORM:CH4:PT396M:PRESSURE21 \x10$TGT1:GASPLATFORM:CH4:PT397M:PRESSURE31 \x10$TGT1:GASPLATFORM:CH4:PT537M:PRESSURE41 \x10$TGT1:GASPLATFORM:CH4:PT558M:PRESSURE51 \x10 TGT1:R55ROOF:CH4:PT562M:PRESSURE61 \x10\x1eTGT1:WESTMEZZANINE:FM702M:FLOW71 \x10\x17TGT1:WTR:BEW:FM505:FLOW81 \x10\x18TGT1:WTR:BEW:LS501:LEVEL91 \x10\x1aTGT1:WTR:BEW:P502:PRESSURE:1 \x10\x1aTGT1:WTR:BEW:P504:PRESSURE"
        # )
        # packet_src_ip = "test"

        log_pvaccess(payload, packet_src_ip, "Received")
    else:
        logger.debug("Received from %s payload that was not PVAccess Protocol message", packet.ip_src_addr)
