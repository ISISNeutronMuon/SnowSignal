""" Tests for the udp_relay_receive file """

import sys
import unittest
from unittest.mock import patch
import unittest.mock

import scapy.compat
import scapy.layers.l2
import scapy.layers.inet
import scapy.packet

from src import udp_relay_receive

class TestUDPRelayReceiveMethods(unittest.TestCase):
    """ Test the udp_relay_receive class method functions """

    # These tests doesn't work on Windows because in scapy.utils.mac2str
    # the line should be
    #     return b"".join(chb(int(x, 16)) for x in re.split(':|-', plain_str(mac)))

    def setUp(self):
        self._test_payload = b'testdata'

    def _create_receiver(self) -> udp_relay_receive.UDPRelayReceive:
        class Config:
            """ Very partial mock of argparser / snowsignal's config interface"""
            def __init__(self):
                self.target_interface = 'eth0'

        config = Config()
        if sys.platform == 'win32':
            config.target_interface = 'Ethernet'

        return udp_relay_receive.UDPRelayReceive(('localhost', 7124), 5076, config)

    def _create_test_packet(self) -> scapy.packet.Packet:
        packet =  scapy.layers.l2.Ether(dst="00:0a:1b:2c:3d:4e", src='00:0a:1b:2c:3d:4e') \
                 /scapy.layers.inet.IP(dst='255.255.255.255', src='127.0.0.1') \
                 /scapy.layers.inet.UDP() \
                 /scapy.packet.Raw(load=self._test_payload)

        return packet

    @patch('socket.socket.send')
    def test_datagram_received_badpacket(self, socket_send_mock : unittest.mock.Mock):
        """ Check that an obviously malformed packet doesn't trigger sending a packet. 
        This is supposed to fail silently expect for a log message.
        """
        data = b'badbytes'
        receiver = self._create_receiver()
        receiver.datagram_received(data, ('192.168.0.1', 7124))
        socket_send_mock.assert_not_called()

    @patch('socket.socket.sendto')
    def test_datagram_received_goodpacket(self, socket_sendto_mock : unittest.mock.Mock):
        """ Simulate receiving a well-formed packet """

        packet = self._create_test_packet()
        receiver = self._create_receiver()
        receiver.datagram_received(b'SS'+scapy.compat.raw(packet), ('192.168.0.1', 7124))
        socket_sendto_mock.assert_called_once()

        # Make some basic checks on the packet we've pretended to send
        raw_bytes : bytes = socket_sendto_mock.call_args[0][0]
        modified_packet = scapy.layers.inet.IP(raw_bytes)
        pkt_payload = scapy.compat.raw(modified_packet[scapy.layers.inet.UDP].payload)

        self.assertEqual(pkt_payload, self._test_payload)
