"""Test packet.py file"""

import unittest
import unittest.mock
from unittest.mock import patch

import scapy.compat
import scapy.layers.inet
import scapy.layers.inet6
import scapy.layers.l2
import scapy.packet

from snowsignal import packet
from snowsignal.netutils import machine_readable_mac


class TestPacketMethods(unittest.TestCase):
    """Test functions for decoding raw packets"""

    def _create_ipv4_udp_frame(self) -> bytes:
        pack = (
            scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0a:1b:2c:3d:4e")
            / scapy.layers.inet.IP(dst="255.255.255.255", src="127.0.0.1")
            / scapy.layers.inet.UDP(sport=47892, dport=5076)
            / scapy.packet.Raw(load=b"testdata")
        )
        pack.show2(dump=True)

        return scapy.compat.raw(pack)

    def _create_ipv6_udp_frame(self) -> bytes:
        pack = (
            scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0a:1b:2c:3d:4e")
            / scapy.layers.inet6.IPv6(
                dst="2001:0db8:85a3:0000:0000:8a2e:0370:7334", src="3001:0da8:75a3:0000:0000:8a2e:0370:7334"
            )
            / scapy.layers.inet.UDP(sport=47892, dport=5076)
            / scapy.packet.Raw(load=b"testdata")
        )
        pack.show2(dump=True)

        return scapy.compat.raw(pack)

    ## This block of tests confirms that we correctly handle a well-formed Ethernet / IPv4 / UDP message
    #  Note the IPv4 above!
    def test_init_ip4udp_packet(self):
        """Test decoding a well-formed IPv4 packet with a valid UDP payload"""
        pack = packet.Packet(self._create_ipv4_udp_frame())

        self.assertEqual(pack.eth_protocol, packet.EthernetProtocol.IPv4)  # Only currently support Ethernet-II
        self.assertEqual(pack.eth_dst_mac, machine_readable_mac("ff:ff:ff:ff:ff:ff"))
        self.assertEqual(pack.eth_src_mac, machine_readable_mac("00:0a:1b:2c:3d:4e"))

    @patch("snowsignal.packet.Packet._decode_ipv4", side_effect=packet.Packet._decode_ipv4, autospec=True)
    def test_decodeip_ip4udp_packet(self, decode_ipv4_mock: unittest.mock.MagicMock):
        """Test decoding a valid IPv4 packet"""
        # def test_decodeip_ip4udp_packet(self):
        pack = packet.Packet(self._create_ipv4_udp_frame())
        pack.decode_ip()

        # Check the correct decode is called
        decode_ipv4_mock.assert_called_once()
        # and then check the results
        self.assertEqual(pack.ip_protocol, 17)
        self.assertEqual(pack.ip_dst_addr, "255.255.255.255")
        self.assertEqual(pack.ip_src_addr, "127.0.0.1")

    def test_decodeudp_ip4udp_packet(self):
        """Test decoding a valid IPv4 packet with a valid UDP payload"""
        pack = packet.Packet(self._create_ipv4_udp_frame())
        pack.decode_ip()
        pack.decode_udp()

        self.assertEqual(pack.udp_src_port, 47892)
        self.assertEqual(pack.udp_dst_port, 5076)
        self.assertEqual(pack.get_udp_payload(), b"testdata")

    ## This block of tests confirms that we correctly handle a well-formed Ethernet / IPv6 / UDP message
    #  Note the IPv6 above!
    def test_init_ip6udp_packet(self):
        """Test decoding Ethernet part of a valid IPv6 packet"""
        pack = packet.Packet(self._create_ipv6_udp_frame())

        self.assertEqual(pack.eth_protocol, packet.EthernetProtocol.IPv6)  # Only currently support Ethernet-II
        self.assertEqual(pack.eth_dst_mac, machine_readable_mac("ff:ff:ff:ff:ff:ff"))
        self.assertEqual(pack.eth_src_mac, machine_readable_mac("00:0a:1b:2c:3d:4e"))

    @patch("snowsignal.packet.Packet._decode_ipv6", side_effect=packet.Packet._decode_ipv6, autospec=True)
    def test_decodeip_ip6udp_packet(self, decode_ipv6_mock: unittest.mock.MagicMock):
        """Test decoding IPv6 part of a valid IPv6 packet with a valid UDP payload"""
        pack = packet.Packet(self._create_ipv6_udp_frame())
        pack.decode_ip()

        # Check the correct decode is called
        decode_ipv6_mock.assert_called_once()
        # and then check the results.
        self.assertEqual(pack.ip_protocol, 17)
        # A slight abuse of machine_readable_mac to convert an IPv6 address...
        self.assertEqual(pack.ip_dst_addr, machine_readable_mac("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertEqual(pack.ip_src_addr, machine_readable_mac("3001:0da8:75a3:0000:0000:8a2e:0370:7334"))

    def test_decodeudp_ip6udp_packet(self):
        """Test decoding a valid IPv6 packet with a valid UDP payload"""
        pack = packet.Packet(self._create_ipv6_udp_frame())
        pack.decode_ip()
        pack.decode_udp()

        self.assertEqual(pack.udp_src_port, 47892)
        self.assertEqual(pack.udp_dst_port, 5076)
        self.assertEqual(pack.get_udp_payload(), b"testdata")

    # Handling bad, corrupt or malicious packets
    def test_bad_ethernet_frame(self):
        """Test handling of corrupt Ethernet frame"""
        good_packet = self._create_ipv4_udp_frame()
        truncated_packet = good_packet[0:3]

        self.assertRaises(packet.BadPacketException, packet.Packet, truncated_packet)

    def test_bad_ip_headers(self):
        """Test handling of corrupt IPv4 and IPV6 packets"""
        good_ipv4_packet = self._create_ipv4_udp_frame()
        truncated_packet = packet.Packet(good_ipv4_packet[0:17])
        self.assertRaises(packet.BadPacketException, truncated_packet.decode_ip)

        good_ipv6_packet = self._create_ipv6_udp_frame()
        truncated_packet = packet.Packet(good_ipv6_packet[0:17])
        self.assertRaises(packet.BadPacketException, truncated_packet.decode_ip)

    def test_bad_udp_headers(self):
        """Test handling of corrupt UDP packets in IPv4 and IPv6"""
        good_ipv4_packet = self._create_ipv4_udp_frame()
        truncated_packet = packet.Packet(good_ipv4_packet[0:35])
        truncated_packet.decode_ip()
        self.assertRaises(packet.BadPacketException, truncated_packet.decode_udp)

        good_ipv6_packet = self._create_ipv6_udp_frame()
        truncated_packet = packet.Packet(good_ipv6_packet[0:55])
        truncated_packet.decode_ip()
        self.assertRaises(packet.BadPacketException, truncated_packet.decode_udp)

    def test_udp_packet_fragment(self):
        """Test handling of a last UDP fragment"""

        fragment_packet = packet.Packet(
            b"\xff\xff\xff\xff\xff\xff\x02B\n\x00\x03\xb5\x08\x00E\x00\x00'\x16\xde\x00\xb2@\x11G\x83\n\x00\x03\xb5\n\x00\x03\xff:LADA:MRE:DOUBLE:51"
        )
        fragment_packet.decode_ethernet()
        fragment_packet.decode_ip()

    def test_isfragment(self):
        """Test various packets to see if they trigger the correct behaviour of the is_ipv4_fragmented method"""

        pack = packet.Packet(self._create_ipv6_udp_frame())
        pack.decode_ip()
        pack.decode_udp()

        self.assertFalse(pack.is_ipv4_fragmented())

        pack = packet.Packet(self._create_ipv4_udp_frame())
        pack.decode_ip()
        pack.decode_udp()

        self.assertFalse(pack.is_ipv4_fragmented())

        pack.ipv4_more_fragments = True
        self.assertTrue(pack.is_ipv4_fragmented())

        pack.ipv4_more_fragments = False
        pack.ipv4_fragmented_offset = 1
        self.assertTrue(pack.is_ipv4_fragmented())

        fragment_packet = packet.Packet(
            b"\xff\xff\xff\xff\xff\xff\x02B\n\x00\x03\xb5\x08\x00E\x00\x00'\x16\xde\x00\xb2@\x11G\x83\n\x00\x03\xb5\n\x00\x03\xff:LADA:MRE:DOUBLE:51"
        )
        fragment_packet.decode_ethernet()
        fragment_packet.decode_ip()

        self.assertTrue(fragment_packet.is_ipv4_fragmented())
