"""Tests for the snowsignal file"""

import asyncio
import logging
import os
import unittest
import unittest.mock
from unittest.mock import patch

import scapy.compat
import scapy.config
import scapy.layers.inet
import scapy.layers.l2
import scapy.packet
import scapy.sendrecv

from snowsignal import netutils, snowsignal

# Scapy a bit chatty so quiet it a bit
scapy.config.conf.use_pcap = False
scapy.config.conf.use_npcap = False
scapy.config.conf.verb = 0
scapy.config.conf.logLevel = logging.ERROR


class TestSnowSignalAsynch(unittest.IsolatedAsyncioTestCase):
    """Test the asynch functions in snowsignal.py"""

    def setUp(self):
        self._test_payload = b"test_payload"

    def _create_broadcast_test_packet(self, src) -> scapy.packet.Packet:
        packet = (
            scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0a:1b:2c:3d:4e")
            / scapy.layers.inet.IP(dst="255.255.255.255", src=src, ihl=5, flags="DF")
            / scapy.layers.inet.UDP(dport=5076)
            / scapy.packet.Raw(load=self._test_payload)
        )

        return packet

    async def test_main_runs(self):
        """See if main executes without any problems!"""

        await snowsignal.main("--log-level=error", loop_forever=False)

    @patch.object(snowsignal.UDPRelayReceive, "datagram_received")
    async def test_integration(
        self,
        receive_datagram_mock: unittest.mock.AsyncMock,
    ):
        """Simple integration test"""
        # Start main, note that we are using the loopback interface. This is
        # important for CI/CD testing (and handy for keeping our test packets
        # local).
        main_task = asyncio.create_task(snowsignal.main("--target-interface=lo --log-level=error", loop_forever=True))

        # Give time for setup to happen
        await asyncio.sleep(0.5)

        # Send a test broadcast packet to the loopback interface
        local_addr = netutils.get_localipv4_from_iface("lo")
        send_packet = self._create_broadcast_test_packet(local_addr)
        send_packet.show2(dump=True)
        scapy.sendrecv.sendp(send_packet, "lo")

        # And some time for packets to fly around
        await asyncio.sleep(0.25)

        # Then test if it all worked!
        # First test that we received a packet from ourself
        receive_datagram_mock.assert_called_once()

        # Slightly complicated test that the packet received is correct
        received_packet = scapy.layers.l2.Ether(receive_datagram_mock.call_args[0][0][2:])
        self.assertEqual(send_packet.show2(dump=True), received_packet.show2(dump=True))

        # Quit main, though it probably quits anyway
        main_task.cancel()


class TestSnowSignalSynch(unittest.TestCase):
    """Test the non-asynch functions in snowsignal"""

    def test_is_swarmmode(self):
        """Test swarmmode detection"""
        with patch.dict(os.environ):
            os.environ.pop("SERVICENAME", None)
            self.assertFalse(snowsignal.is_swarmmode())

        with patch.dict(os.environ, {"SERVICENAME": "something"}):
            self.assertTrue(snowsignal.is_swarmmode())

    # Setup a list of local IPs and a list of relays. At least one entry should overlap
    @patch("snowsignal.snowsignal.get_localhost_ips", return_value=["127.0.0.1"])
    @patch("snowsignal.snowsignal.get_ips_from_name", return_value=["127.0.0.1", "8.8.8.8"])
    def test_discover_relays(self, *_):
        """Test relay discovery"""

        with patch.dict(os.environ, {"SERVICENAME": "something"}):
            valid_ips = snowsignal.discover_relays()
            self.assertEqual(valid_ips, ["8.8.8.8"])
