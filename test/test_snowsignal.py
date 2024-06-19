""" Tests for the snowsignal file """
import asyncio
import os
import unittest
from unittest.mock import patch
import unittest.mock

import scapy.compat
import scapy.layers.l2
import scapy.layers.inet
import scapy.packet
import scapy.sendrecv

from src import snowsignal, udp_relay_receive, udp_relay_transmit
from src.packet import Packet

class TestSnowSignalAsynch(unittest.IsolatedAsyncioTestCase):
    """ Test the asynch functions in snowsignal.py """

    def setUp(self):
        self._test_payload = b'test_payload'

    def _create_broadcast_test_packet(self) -> scapy.packet.Packet:
        packet =  scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff", src='00:0a:1b:2c:3d:4e') \
                 /scapy.layers.inet.IP(dst='255.255.255.255', src='127.0.0.1') \
                 /scapy.layers.inet.UDP(dport=5076) \
                 /scapy.packet.Raw(load=self._test_payload)

        return packet

    async def test_main_runs(self):
        """ See if main executes without any problems! """

        await snowsignal.main('--log-level=error', loop_forever=False)

    @patch.object(snowsignal.UDPRelayReceive, 'datagram_received')
    async def test_integration(self,
                               receive_datagram_mock : unittest.mock.AsyncMock, 
                               ):
        """ Simple integration test """

        main_task = asyncio.create_task( snowsignal.main('--log-level=debug', loop_forever=True) )

        # Give time for setup to happen
        await asyncio.sleep(0.5)

        # Send a broadcast packet and check if it is sent to this relay
        # and correctly rejected
        test_packet = self._create_broadcast_test_packet()
        scapy.sendrecv.sendp(test_packet, 'eth0')

        # And some time for packets to fly around
        await asyncio.sleep(0.25)

        # Then test if it all worked!
        #transmit_to_relays_mock._send_to_relays_bytes.assert_called_once()
        raw_packet = scapy.compat.raw(test_packet)
        receive_datagram_mock.assert_called_once()
        print(f"Send    {len(b'SS'+raw_packet)} bytes   {b'SS'+raw_packet}")
        print(f"Receive {len(receive_datagram_mock.call_args[0][0])} bytes   {receive_datagram_mock.call_args[0][0]}")
        packet = Packet(b'SS'+raw_packet)
        print(f"Send    {len(packet.raw)} bytes   {packet.raw}")
        self.assertEqual(receive_datagram_mock.call_args[0][0], b'SS'+raw_packet)

        main_task.cancel()

class TestSnowSignalSynch(unittest.TestCase):
    """ Test the non-asynch functions in snowsignal"""

    def test_is_swarmmode(self):
        """ Test swarmmode detection """
        with patch.dict(os.environ):
            os.environ.pop('SERVICENAME', None)
            self.assertFalse(snowsignal.is_swarmmode())

        with patch.dict(os.environ, {"SERVICENAME": "something"}):
            self.assertTrue(snowsignal.is_swarmmode())

    # Setup a list of local IPs and a list of relays. At least one entry should overlap
    @patch('src.snowsignal.get_localhost_ips', return_value = ['127.0.0.1'])
    @patch('src.snowsignal.get_ips_from_name', return_value = ['127.0.0.1', '8.8.8.8'])
    def test_discover_relays(self, *_):
        """ Test relay discovery """

        with patch.dict(os.environ, {"SERVICENAME": "something"}):
            valid_ips = snowsignal.discover_relays()
            self.assertEqual(valid_ips, ['8.8.8.8'])