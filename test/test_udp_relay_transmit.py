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

class TestUDPRelayTransmitMethods(unittest.IsolatedAsyncioTestCase):
    """ Test UDPRelayTransmit class """

    def setUp(self):
        self._test_payload = b'test_payload'

    def _create_broadcast_test_packet(self) -> udp_relay_transmit.Packet:
        packet =  scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff", src='00:0a:1b:2c:3d:4e') \
                 /scapy.layers.inet.IP(dst='255.255.255.255', src='127.0.0.1') \
                 /scapy.layers.inet.UDP(dport=5076) \
                 /scapy.packet.Raw(load=self._test_payload)

        return udp_relay_transmit.Packet(scapy.compat.raw(packet))


    def _create_unicast_test_packet(self, port = 5076) -> udp_relay_transmit.Packet:
        packet =  scapy.layers.l2.Ether(dst="00:0a:1b:2c:3d:4e", src='00:0a:1b:2c:3d:4e') \
                 /scapy.layers.inet.IP(dst='255.255.255.255', src='127.0.0.1') \
                 /scapy.layers.inet.UDP(sport=port, dport=port) \
                 /scapy.packet.Raw(load=self._test_payload)

        return udp_relay_transmit.Packet(scapy.compat.raw(packet))

    @patch('asyncio.SelectorEventLoop.sock_sendto')
    async def test_send_to_relays_packet(self, socket_sendto_mock : unittest.mock.AsyncMock):
        """ Test sending rebroadcast packets to remote relays """

        remote_relays = [ipaddress.IPv4Address('127.0.0.1'),
                         ipaddress.IPv6Address('fe80::e910:b9ea:1399:5300%27')]

        transmitter = udp_relay_transmit.UDPRelayTransmit(remote_port=9999,
                                                          remote_relays=remote_relays)

        test_packet = self._create_unicast_test_packet()
        await transmitter._send_to_relays_packet(test_packet) # pylint: disable=protected-access

        self.assertEqual(socket_sendto_mock.call_count, len(remote_relays),
                         "Expected socket.socket.sendto calls to equal number of remote relays")

        # We only need to test the last call
        sendto_pkt_raw       = socket_sendto_mock.call_args[0][1]
        sendto_pkt_ipaddress = socket_sendto_mock.call_args[0][2][0]
        sentto_pkt_port      = socket_sendto_mock.call_args[0][2][1]

        self.assertEqual(sendto_pkt_raw, b'SS' + test_packet.raw)
        self.assertEqual(sendto_pkt_ipaddress, str(remote_relays[-1]))
        self.assertEqual(sentto_pkt_port, 9999)

    # @patch('asyncio.SelectorEventLoop.sock_sendto')
    # async def test_send_to_relays_payload(self, socket_sendto_mock : unittest.mock.AsyncMock):
    #     """ Test sending rebroadcast packets to remote relays """

    #     remote_relays = [ipaddress.IPv4Address('127.0.0.1'),
    #                      ipaddress.IPv6Address('fe80::e910:b9ea:1399:5300%27')]
    #     remote_port = 9999

    #     transmitter = udp_relay_transmit.UDPRelayTransmit(remote_port=remote_port,
    #                                                       remote_relays=remote_relays)

    #     test_packet = self._create_unicast_test_packet(remote_port)
    #     test_packet.decode_ip()
    #     test_packet.decode_udp()
    #     await transmitter._send_to_relays_payload(test_packet) # pylint: disable=protected-access

    #     self.assertEqual(socket_sendto_mock.call_count, len(remote_relays),
    #                      "Expected sock_sendto calls to equal number of remote relays")

    #     # We only need to test the last call
    #     sendto_pkt_raw       = socket_sendto_mock.call_args[0][1]
    #     sendto_pkt_ipaddress = socket_sendto_mock.call_args[0][2][0]
    #     sentto_pkt_port      = socket_sendto_mock.call_args[0][2][1]

    #     expected_payload = (b'SS' + int(remote_port).to_bytes(2, 'big') +
    #                         int(remote_port).to_bytes(2, 'big') +
    #                         self._test_payload)
    #     self.assertEqual(sendto_pkt_raw, expected_payload)
    #     self.assertEqual(sendto_pkt_ipaddress, str(remote_relays[-1]))
    #     self.assertEqual(sentto_pkt_port, 9999)


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


    async def test_valid_packet_sent(self): #, socket_mock : unittest.mock.AsyncMock):
        """ 
        This test took a lot of work to get right! It checks a valid packet passes
        all filters and gets dispatched to the relays. The code under test needed
        restructuring with the _continue_while_loop() in order to stop if a 
        filter failed. 
        """
        transmitter = udp_relay_transmit.UDPRelayTransmit(remote_relays=['0.0.0.0'])

        # Create valid packet to pass all filters
        test_packet = (self._create_broadcast_test_packet().raw, ('eth0', 2048, 0, 772, b'\x00\x00\x00\x00\x00\x00'))
        with (
            patch('asyncio.SelectorEventLoop.sock_recvfrom', return_value=test_packet),
            patch('src.udp_relay_transmit.UDPRelayTransmit._continue_while_loop', return_value=False),
            patch.object(transmitter, 'l1filter', wraps=transmitter.l1filter) as l1filter_mock,
            patch.object(transmitter, 'l2filter', wraps=transmitter.l2filter) as l2filter_mock,
            patch.object(transmitter, 'l3filter', wraps=transmitter.l3filter) as l3filter_mock,
            patch.object(transmitter, 'l4filter', wraps=transmitter.l4filter) as l4filter_mock,
            patch('src.udp_relay_transmit.UDPRelayTransmit._send_to_relays_bytes') as sendtorelays_mock,
        ):
            await transmitter.start()

        l1filter_mock.assert_called_once()
        l2filter_mock.assert_called_once()
        l3filter_mock.assert_called_once()
        l4filter_mock.assert_called_once()
        sendtorelays_mock.assert_called_once()
