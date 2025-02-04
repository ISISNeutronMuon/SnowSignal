"""Tests for the snowsignal file"""

import asyncio
import logging
import os
import random
import string
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

logger = logging.getLogger(__name__)


class TestSnowSignalAsynch(unittest.IsolatedAsyncioTestCase):
    """Test the asynch functions in snowsignal.py"""

    def setUp(self):
        # Observed PVAccess behavious shows that searches for multiple channels top out at just under 1500 bytes
        self._test_payload = b"test_payload" + "".join(random.choices(string.ascii_lowercase, k=1450)).encode("utf8")

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


class TestSnowSignalFragmented(unittest.IsolatedAsyncioTestCase):
    """Test sending a valid fragmented UDP packet"""

    maxDiff = None

    def _create_broadcast_test_packet_frag1(self) -> scapy.packet.Packet:
        packet = scapy.layers.l2.Ether(
            b"\xff\xff\xff\xff\xff\xff\x02B\n\x00\x03\xb5\x08\x00E\x00\x05\xa4\xd4Y \x00@\x11e<\n\x00\x03\xb5\n\x00\x03\xff\xa5\xa8\x13\xd4\x05\xa3?:\xca\x02\x00\x03\x93\x05\x00\x00\\b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\xa8\xa5\x01\x03tcp4\x00m1 \x10\x15DEV:LADA:MRE:DOUBLE:0n1 \x10\x15DEV:LADA:MRE:DOUBLE:1o1 \x10\x15DEV:LADA:MRE:DOUBLE:2p1 \x10\x15DEV:LADA:MRE:DOUBLE:3q1 \x10\x15DEV:LADA:MRE:DOUBLE:4r1 \x10\x15DEV:LADA:MRE:DOUBLE:5s1 \x10\x15DEV:LADA:MRE:DOUBLE:6t1 \x10\x15DEV:LADA:MRE:DOUBLE:7u1 \x10\x15DEV:LADA:MRE:DOUBLE:8v1 \x10\x15DEV:LADA:MRE:DOUBLE:9w1 \x10\x16DEV:LADA:MRE:DOUBLE:10x1 \x10\x16DEV:LADA:MRE:DOUBLE:11y1 \x10\x16DEV:LADA:MRE:DOUBLE:12z1 \x10\x16DEV:LADA:MRE:DOUBLE:13{1 \x10\x16DEV:LADA:MRE:DOUBLE:14|1 \x10\x16DEV:LADA:MRE:DOUBLE:15}1 \x10\x16DEV:LADA:MRE:DOUBLE:16~1 \x10\x16DEV:LADA:MRE:DOUBLE:17\x7f1 \x10\x16DEV:LADA:MRE:DOUBLE:18\x801 \x10\x16DEV:LADA:MRE:DOUBLE:19\x811 \x10\x16DEV:LADA:MRE:DOUBLE:20\x821 \x10\x16DEV:LADA:MRE:DOUBLE:21\x831 \x10\x16DEV:LADA:MRE:DOUBLE:22\x841 \x10\x16DEV:LADA:MRE:DOUBLE:23\x851 \x10\x16DEV:LADA:MRE:DOUBLE:24\x861 \x10\x16DEV:LADA:MRE:DOUBLE:25\x871 \x10\x16DEV:LADA:MRE:DOUBLE:26\x881 \x10\x16DEV:LADA:MRE:DOUBLE:27\x891 \x10\x16DEV:LADA:MRE:DOUBLE:28\x8a1 \x10\x16DEV:LADA:MRE:DOUBLE:29\x8b1 \x10\x16DEV:LADA:MRE:DOUBLE:30\x8c1 \x10\x16DEV:LADA:MRE:DOUBLE:31\x8d1 \x10\x16DEV:LADA:MRE:DOUBLE:32\x8e1 \x10\x16DEV:LADA:MRE:DOUBLE:33\x8f1 \x10\x16DEV:LADA:MRE:DOUBLE:34\x901 \x10\x16DEV:LADA:MRE:DOUBLE:35\x911 \x10\x16DEV:LADA:MRE:DOUBLE:36\x921 \x10\x16DEV:LADA:MRE:DOUBLE:37\x931 \x10\x16DEV:LADA:MRE:DOUBLE:38\x941 \x10\x16DEV:LADA:MRE:DOUBLE:39\x951 \x10\x16DEV:LADA:MRE:DOUBLE:40\x961 \x10\x16DEV:LADA:MRE:DOUBLE:41\x971 \x10\x16DEV:LADA:MRE:DOUBLE:42\x981 \x10\x16DEV:LADA:MRE:DOUBLE:43\x991 \x10\x16DEV:LADA:MRE:DOUBLE:44\x9a1 \x10\x16DEV:LADA:MRE:DOUBLE:45\x9b1 \x10\x16DEV:LADA:MRE:DOUBLE:46\x9c1 \x10\x16DEV:LADA:MRE:DOUBLE:47\x9d1 \x10\x16DEV:LADA:MRE:DOUBLE:48\x9e1 \x10\x16DEV:LADA:MRE:DOUBLE:49\x9f1 \x10\x16DEV:LADA:MRE:DOUBLE:50\xa01 \x10\x16DEV"
        )

        return packet

    def _create_broadcast_test_packet_frag2(self) -> scapy.packet.Packet:
        packet = scapy.layers.l2.Ether(
            b"\xff\xff\xff\xff\xff\xff\x02B\n\x00\x03\xb5\x08\x00E\x00\x00'\xd4Y\x00\xb2@\x11\x8a\x07\n\x00\x03\xb5\n\x00\x03\xff:LADA:MRE:DOUBLE:51"
        )

        return packet

    async def test_main_runs(self):
        """See if main executes without any problems!"""

        await snowsignal.main("--log-level=error", loop_forever=False)

    @patch.object(snowsignal.UDPRelayTransmit, "_send_to_relays_packet")
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

        # Send the broadcast fragments to the loopback interface
        send_packet_frag1 = self._create_broadcast_test_packet_frag1()
        scapy.sendrecv.sendp(send_packet_frag1, "lo")

        send_packet_frag2 = self._create_broadcast_test_packet_frag2()
        scapy.sendrecv.sendp(send_packet_frag2, "lo")

        # And some time for packets to fly around
        await asyncio.sleep(0.25)

        # Then test if it all worked!
        self.assertEqual(receive_datagram_mock.call_count, 2)

        # Quit main, though it probably quits anyway
        main_task.cancel()
