""" Tests for the udp_relay_transmit file """

import ipaddress
import unittest
import unittest.mock
from unittest.mock import patch

import scapy.compat
import scapy.layers.l2
import scapy.layers.inet
import scapy.packet

from src import udp_relay_transmit

class TestUDPRelayTransmitMethods(unittest.TestCase):
    """ Test UDPRelayTransmit class """

    def setUp(self):
        self._test_payload = b'test_payload'

    def _create_broadcast_test_packet(self) -> scapy.packet.Packet:
        packet =  scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff", src='00:0a:1b:2c:3d:4e') \
                 /scapy.layers.inet.IP(dst='255.255.255.255', src='127.0.0.1') \
                 /scapy.layers.inet.UDP() \
                 /scapy.packet.Raw(load=self._test_payload)

        return packet


    def _create_unicast_test_packet(self, port = 5076) -> scapy.packet.Packet:
        packet =  scapy.layers.l2.Ether(dst="00:0a:1b:2c:3d:4e", src='00:0a:1b:2c:3d:4e') \
                 /scapy.layers.inet.IP(dst='255.255.255.255', src='127.0.0.1') \
                 /scapy.layers.inet.UDP(sport=port, dport=port) \
                 /scapy.packet.Raw(load=self._test_payload)

        return packet

    def test_is_broadcast_true(self):
        """ Test identifying a broadcast packet """

        test_packet = self._create_broadcast_test_packet()

        self.assertTrue( udp_relay_transmit.UDPRelayTransmit._is_broadcast(test_packet) ) # pylint: disable=protected-access

    def test_is_broadcast_false(self):
        """ Test identifying a non-broadcast packet """

        test_packet = self._create_broadcast_test_packet()
        test_packet[scapy.layers.l2.Ether].dst = '6f:70:8a:9b:0c:1d'
        test_packet[scapy.layers.inet.IP].dst = '127.0.0.2'

        self.assertFalse( udp_relay_transmit.UDPRelayTransmit._is_broadcast(test_packet) ) # pylint: disable=protected-access

    def test__setup_rebroadcast_packet(self):
        """ Test setup of filters and callback for rebroadcasting packets """

        transmitter = udp_relay_transmit.UDPRelayTransmit(local_port=9999)
        with patch('src.udp_relay_transmit.get_localhost_macs',
            return_value = ['00:1a:2b:3c:4d:5e', '6f:70:8a:9b:0c:1d']
            ):
            scapy_filter, prn, lfilter = transmitter._UDPRelayTransmit__setup_rebroadcast_packet() # pylint: disable=protected-access

        self.assertEqual(scapy_filter, "udp port 9999 and not (ether src 00:1a:2b:3c:4d:5e "
                                       "or 6f:70:8a:9b:0c:1d)")
        self.assertEqual(prn, transmitter._send_to_relays_packet) # pylint: disable=protected-access
        self.assertEqual(lfilter, transmitter._is_broadcast) # pylint: disable=protected-access


    def test__setup_rebroadcast_payload(self):
        """ Test setup of filters and callback for rebroadcasting payloads """

        transmitter = udp_relay_transmit.UDPRelayTransmit(local_port=9999)
        with patch('src.udp_relay_transmit.get_localhost_ips',
            return_value = ['127.0.0.1', '19.168.0.1']
            ):
            scapy_filter, prn, lfilter = transmitter._UDPRelayTransmit__setup_rebroadcast_payload() # pylint: disable=protected-access

        self.assertEqual(scapy_filter, "udp port 9999 and not (src 127.0.0.1 or 19.168.0.1)")
        self.assertEqual(prn, transmitter._send_to_relays_payload) # pylint: disable=protected-access
        self.assertEqual(lfilter, None) # pylint: disable=protected-access

    @patch('socket.socket.sendto')
    def test_send_to_relays_packet(self, socket_sendto_mock : unittest.mock.Mock):
        """ Test sending rebroadcast packets to remote relays """

        remote_relays = [ipaddress.IPv4Address('127.0.0.1'),
                         ipaddress.IPv6Address('fe80::e910:b9ea:1399:5300%27')]

        transmitter = udp_relay_transmit.UDPRelayTransmit(remote_port=9999, remote_relays=remote_relays)

        test_packet = self._create_unicast_test_packet()
        transmitter._send_to_relays_packet(test_packet) # pylint: disable=protected-access

        self.assertEqual(socket_sendto_mock.call_count, len(remote_relays),
                         "Expected socket.socket.sendto calls to equal number of remote relays")
        
        # We only need to test the last call
        sendto_pkt_raw       = socket_sendto_mock.call_args[0][0]
        sendto_pkt_ipaddress = socket_sendto_mock.call_args[0][1][0]
        sentto_pkt_port      = socket_sendto_mock.call_args[0][1][1]

        self.assertEqual(sendto_pkt_raw, scapy.compat.raw(test_packet))
        self.assertEqual(sendto_pkt_ipaddress, str(remote_relays[-1]))
        self.assertEqual(sentto_pkt_port, 9999)

    @patch('socket.socket.sendto')
    def test_send_to_relays_payload(self, socket_sendto_mock : unittest.mock.Mock):
        """ Test sending rebroadcast packets to remote relays """

        remote_relays = [ipaddress.IPv4Address('127.0.0.1'),
                         ipaddress.IPv6Address('fe80::e910:b9ea:1399:5300%27')]
        remote_port = 9999

        transmitter = udp_relay_transmit.UDPRelayTransmit(remote_port=remote_port,
                                                          remote_relays=remote_relays)

        test_packet = self._create_unicast_test_packet(remote_port)
        transmitter._send_to_relays_payload(test_packet) # pylint: disable=protected-access

        self.assertEqual(socket_sendto_mock.call_count, len(remote_relays),
                         "Expected socket.socket.sendto calls to equal number of remote relays")
        
        # We only need to test the last call
        sendto_pkt_raw       = socket_sendto_mock.call_args[0][0]
        sendto_pkt_ipaddress = socket_sendto_mock.call_args[0][1][0]
        sentto_pkt_port      = socket_sendto_mock.call_args[0][1][1]

        expected_payload = (b'SS' + int(remote_port).to_bytes(2, 'big') +
                            int(remote_port).to_bytes(2, 'big') +
                            self._test_payload)
        self.assertEqual(sendto_pkt_raw, expected_payload)
        self.assertEqual(sendto_pkt_ipaddress, str(remote_relays[-1]))
        self.assertEqual(sentto_pkt_port, 9999)


    def test_set_remote_relays(self):
        """ Test setting up and changing list of remote relays """

        remote_relays = [ipaddress.IPv4Address('127.0.0.1'),
                         ipaddress.IPv6Address('fe80::e910:b9ea:1399:5300%27')]

        transmitter = udp_relay_transmit.UDPRelayTransmit(remote_relays=remote_relays)
        self.assertEqual(transmitter.remote_relays, remote_relays)

        # Change the remote relays
        remote_relays.append(ipaddress.IPv4Address('9.9.9.9'))
        transmitter.set_remote_relays(remote_relays)
        self.assertEqual(transmitter.remote_relays, remote_relays)

