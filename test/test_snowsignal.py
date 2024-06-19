""" Tests for the snowsignal file """
import asyncio
import logging
import os
import unittest
from unittest.mock import patch
import unittest.mock

import scapy.compat
import scapy.layers.l2
import scapy.layers.inet
import scapy.packet
import scapy.sendrecv

from src import snowsignal

# Scapy a bit chatty so quiet it a bit
scapy.config.conf.use_pcap = False
scapy.config.conf.use_npcap = False
scapy.config.conf.verb = 0
scapy.config.conf.logLevel = logging.ERROR

class TestSnowSignalAsynch(unittest.IsolatedAsyncioTestCase):
    """ Test the asynch functions in snowsignal.py """

    def setUp(self):
        self._test_payload = b'test_payload'

    def _create_broadcast_test_packet(self, src) -> scapy.packet.Packet:
        packet =  scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff", src='00:0a:1b:2c:3d:4e') \
                 /scapy.layers.inet.IP(dst='255.255.255.255', src=src, ihl=5, flags='DF') \
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
        send_packet = self._create_broadcast_test_packet('172.21.0.1')
        send_packet.show2(dump=True)
        scapy.sendrecv.sendp(send_packet, 'eth0')

        # And some time for packets to fly around
        await asyncio.sleep(0.75)

        # Then test if it all worked!
        #transmit_to_relays_mock._send_to_relays_bytes.assert_called_once()
        receive_datagram_mock.assert_called_once()

        received_packet = scapy.layers.l2.Ether(receive_datagram_mock.call_args[0][0][2:])
        self.assertEqual(send_packet.show2(dump=True), received_packet.show2(dump=True))

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