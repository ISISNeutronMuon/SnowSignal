"""Tests of the PVAccess protocol packet decoding functions"""

import logging
import unittest
from struct import pack
from unittest.mock import patch

from snowsignal.packet import BadPacketException, Packet
from snowsignal.pva_packet import (
    Endianness,
    PVAccessMessageHeader,
    PVAccessMessageType,
    PVAccessSearchMessage,
    decode_pvaccess_size,
    decode_pvaccess_string,
    log_pvaccess_packet,
)


class TestPVAccessMessageHeader(unittest.TestCase):
    """Test the PVAccessMessageHeader class decodes the header correctly"""

    def test_pvaccess_message_header_beacon(self):
        """Test decoding a beacon message header"""

        raw_header = pack("BBBBI", 0xCA, 1, 0b00000000, PVAccessMessageType.BEACON.value, 100)
        header = PVAccessMessageHeader(raw_header)

        self.assertEqual(header.magic, 0xCA)
        self.assertEqual(header.version, 1)
        self.assertEqual(header.msgtype, PVAccessMessageHeader.MessageType.APPLICATION)
        self.assertEqual(header.segmented, PVAccessMessageHeader.Segmentation.NOT_SEGMENTED)
        self.assertEqual(header.role, PVAccessMessageHeader.Role.CLIENT)
        self.assertEqual(header.endian, Endianness.LITTLEEND)
        self.assertEqual(header.message_command, PVAccessMessageType.BEACON)
        self.assertEqual(header.payload_size, 100)

    def test_pvaccess_message_header_search(self):
        """Test decoding a search message header"""
        raw_header = pack(">BBBBI", 0xCA, 2, 0b11000000, PVAccessMessageType.SEARCH_REQUEST.value, 200)
        header = PVAccessMessageHeader(raw_header)

        self.assertEqual(header.magic, 0xCA)
        self.assertEqual(header.version, 2)
        self.assertEqual(header.msgtype, PVAccessMessageHeader.MessageType.APPLICATION)
        self.assertEqual(header.segmented, PVAccessMessageHeader.Segmentation.NOT_SEGMENTED)
        self.assertEqual(header.role, PVAccessMessageHeader.Role.SERVER)
        self.assertEqual(header.endian, Endianness.BIGEND)
        self.assertEqual(header.message_command, PVAccessMessageType.SEARCH_REQUEST)
        self.assertEqual(header.payload_size, 200)

    def test_pvaccess_message_header_invalid_magic(self):
        """Test decoding an invalid message header with magic bytes not equal to OxCA"""
        raw_header = pack("BBBBI", 0xCB, 1, 0b10000000, PVAccessMessageType.BEACON.value, 100)
        with self.assertRaises(BadPacketException):
            PVAccessMessageHeader(raw_header)


class TestPVAPacketFunctions(unittest.TestCase):
    """Decode the helper functions that deoce sizes and strings"""

    def test_decode_pvaccess_size_single_byte(self):
        """Decode size when a single byte"""
        payload = pack("B", 10)
        result = decode_pvaccess_size(payload, Endianness.LITTLEEND)
        self.assertEqual(result, (10, 1))

    def test_decode_pvaccess_size_integer(self):
        """Decode size when an integer of multiple bytes"""
        payload = pack("B", 254) + pack("<I", 1000)
        result = decode_pvaccess_size(payload, Endianness.LITTLEEND)
        self.assertEqual(result, (1000, 5))

    def test_decode_pvaccess_size_zero(self):
        """Decode the weird special case of 255 which is actually 0"""
        payload = pack("B", 255)
        result = decode_pvaccess_size(payload, Endianness.LITTLEEND)
        self.assertEqual(result, (0, 1))

    def test_decode_pvaccess_string(self):
        """Deocde a short string"""
        payload = pack("B", 5) + b"hello"
        result = decode_pvaccess_string(payload, Endianness.LITTLEEND)
        self.assertEqual(result, ("hello", 6))

    def test_decode_pvaccess_string_empty(self):
        """Decode an empty string"""
        payload = pack("B", 0)
        result = decode_pvaccess_string(payload, Endianness.LITTLEEND)
        self.assertEqual(result, ("", 1))

    def test_decode_pvaccess_string_with_integer_size(self):
        """??"""
        payload = pack("B", 254) + pack("<I", 5) + b"hello"
        result = decode_pvaccess_string(payload, Endianness.LITTLEEND)
        self.assertEqual(result, ("hello", 10))

    def test_decode_pvaccess_string_with_integer_size_bigendian(self):
        """Decode a string where the size is big endian"""
        payload = pack("B", 254) + pack(">I", 5) + b"hello"
        result = decode_pvaccess_string(payload, Endianness.BIGEND)
        self.assertEqual(result, ("hello", 10))


class TestPVAMessageSearch(unittest.TestCase):
    """Test decoding search message bodies"""

    def test_pvaccess_search_message(self):
        """Decode a simple search message"""
        raw_message = (
            pack("<IB3x16sH", 12345, 0, b"\x00" * 16, 5064)
            + pack("B", 1)  # One protocol string
            + pack("B", 3)
            + b"tcp"  # Protocol string "tcp"
            + pack("<H", 1)  # One channel
            + pack("<I", 67890)  # Search instance ID
            + pack("B", 4)
            + b"test"  # Channel name "test"
        )
        message = PVAccessSearchMessage(raw_message, Endianness.LITTLEEND)

        self.assertEqual(message.search_sequence_id, 12345)
        self.assertEqual(message.flags, 0)
        self.assertEqual(message.reponse_address, "00000000000000000000000000000000")
        self.assertEqual(message.response_port, 5064)
        self.assertEqual(message.protocols, ["tcp"])
        self.assertEqual(len(message.channels), 1)
        self.assertEqual(message.channels[0].search_instance_id, 67890)
        self.assertEqual(message.channels[0].channelname, "test")

    def test_pvaccess_search_message_multiple_protocols(self):
        """Decode a search message with multiple protocols specified"""
        raw_message = (
            pack("<IB3x16sH", 12345, 0, b"\x00" * 16, 5064)
            + pack("B", 2)  # Two protocol strings
            + pack("B", 3)
            + b"tcp"  # Protocol string "tcp"
            + pack("B", 3)
            + b"udp"  # Protocol string "udp"
            + pack("<H", 1)  # One channel
            + pack("<I", 67890)  # Search instance ID
            + pack("B", 4)
            + b"test"  # Channel name "test"
        )
        message = PVAccessSearchMessage(raw_message, Endianness.LITTLEEND)

        self.assertEqual(message.search_sequence_id, 12345)
        self.assertEqual(message.flags, 0)
        self.assertEqual(message.reponse_address, "00000000000000000000000000000000")
        self.assertEqual(message.response_port, 5064)
        self.assertEqual(message.protocols, ["tcp", "udp"])
        self.assertEqual(len(message.channels), 1)
        self.assertEqual(message.channels[0].search_instance_id, 67890)
        self.assertEqual(message.channels[0].channelname, "test")

    def test_pvaccess_search_message_invalid(self):
        """Decode a corrupt search message"""
        raw_message = pack("<IB3x16sH", 12345, 0, b"\x00" * 16, 5064)
        with self.assertRaises(BadPacketException):
            PVAccessSearchMessage(raw_message, Endianness.LITTLEEND)

    def test_pvaccess_bad_multiple_channels(self):
        """Decode a search message with multiple channels but fewer channels are searched for than specified"""
        raw_message = (
            pack("<IB3x16sH", 12345, 0, b"\x00" * 16, 5064)
            + pack("B", 1)  # One protocol string
            + pack("B", 3)
            + b"tcp"  # Protocol string "tcp"
            + pack("<H", 17)  # Seventeen channels, but only one provided
            + pack("<I", 67890)  # Search instance ID
            + pack("B", 4)
            + b"test"  # Channel name "test"
        )
        with self.assertRaises(BadPacketException):
            PVAccessSearchMessage(raw_message, Endianness.LITTLEEND)


class TestPVAPacketLog(unittest.TestCase):
    """Test the logging of bad or invalid packets"""

    def test_log_bad_packet(self):
        """Test a bad packet (no payload)"""
        # Too short packet
        beacon_packet = Packet(
            b"\xff\xff\xff\xff\xff\xff\xff\x02B\xac\x16\x00\x03\x08\x00E\x00\x00K3\x15@\x00@\x11\xaf^\xac\x16\x00\x02\xac\x16\xff\xff\xc5\xfb\x13\xd4"
        )

        with self.assertLogs(level=logging.DEBUG) as captured_logs:
            log_pvaccess_packet(beacon_packet)

        self.assertEqual(
            "Received from None payload that was not PVAccess Protocol message",
            captured_logs.records[0].getMessage(),
        )

    def test_log_packet_not_validpva(self):
        """Test a packet that is not a valid PVAccess packet"""
        # Valid packet with extra byte added at start to make it invalid
        beacon_packet = Packet(
            b"\xff\xff\xff\xff\xff\xff\xff\x02B\xac\x16\x00\x03\x08\x00E\x00\x00K3\x15@\x00@\x11\xaf^\xac\x16\x00\x02\xac\x16\xff\xff\xc5\xfb\x13\xd4\x007\xd6V\xca\x02\xc0\x00\x00\x00\x00')\x9bb\xff\xf3\xa5\x9a\x8b\xd7\xc1\x00\xb9\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x13\xd3\x03tcp\xff"
        )
        beacon_packet.decode_ethernet()
        beacon_packet.decode_ip()
        beacon_packet.decode_udp()

        with self.assertLogs(level=logging.DEBUG) as captured_logs:
            log_pvaccess_packet(beacon_packet)

        self.assertEqual(
            "Magic bytes were 0x40 instead of 0xCA",
            captured_logs.records[0].getMessage(),
        )

    @patch("socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_log_beacon_packet(self, _):
        """Test the logging of a valid beacon packet"""
        # Valid beacon packet
        beacon_packet = Packet(
            b"\xff\xff\xff\xff\xff\xff\x02B\xac\x16\x00\x03\x08\x00E\x00\x00K3\x15@\x00@\x11\xaf^\xac\x16\x00\x02\xac\x16\xff\xff\xc5\xfb\x13\xd4\x007\xd6V\xca\x02\xc0\x00\x00\x00\x00')\x9bb\xff\xf3\xa5\x9a\x8b\xd7\xc1\x00\xb9\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x13\xd3\x03tcp\xff"
        )
        beacon_packet.decode_ethernet()
        beacon_packet.decode_ip()
        beacon_packet.decode_udp()

        with self.assertLogs(level=logging.INFO) as captured_logs:
            log_pvaccess_packet(beacon_packet)

        self.assertEqual(
            "Received BEACON (v2) [Flags: APPLICATION,NOT_SEGMENTED,SERVER,BIGEND] from 172.22.0.2 --> example.com: self-identifies as tcp 00000000000000000000ffff00000000:5075;299b62fff3a59a8bd7c100b9 with update counters beacon:0, PVs:1",
            captured_logs.records[0].getMessage(),
        )

    @patch("socket.gethostbyaddr", return_value=("example.com", [], []))
    def test_log_search_packet(self, _):
        """Test the logging of a valid search packet"""
        # Valid search packet
        beacon_packet = Packet(
            b"\xff\xff\xff\xff\xff\xff\x02B\xac\x16\x00\x02\x08\x00E\x00\x00T\x17\x99@\x00@\x11\xca\xd1\xac\x16\x00\x02\xac\x16\xff\xff\xa0\x04\x13\xd4\x00@\xa7\x99\xca\x02\x80\x03\x00\x00\x000find\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\x04\x01\x03tcp\x00\x01\x124Vx\nmy:pv:name"
        )
        beacon_packet.decode_ethernet()
        beacon_packet.decode_ip()
        beacon_packet.decode_udp()

        with self.assertLogs(level=logging.INFO) as captured_logs:
            log_pvaccess_packet(beacon_packet)

        self.assertEqual(
            "Received SEARCH_REQUEST (v2) [Flags: APPLICATION,NOT_SEGMENTED,CLIENT,BIGEND] from 172.22.0.2 --> example.com: self-identifies as 00000000000000000000000000000000:40964 (seq id 1718185572) with protocols ['tcp'] searching for [305419896 / my:pv:name]",
            captured_logs.records[0].getMessage(),
        )


if __name__ == "__main__":
    unittest.main()
