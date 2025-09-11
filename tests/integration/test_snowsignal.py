"""Tests for the snowsignal file"""

import asyncio
import logging
import os
import random
import socket
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
    async def test_integration(self, receive_datagram_mock: unittest.mock.AsyncMock):
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

    ## This is often needed to understand what the hell is going on in this complex integration test
    # logging.basicConfig(
    #     format="%(asctime)s - %(levelname)s - %(name)s.%(funcName)s: %(message)s",
    #     encoding="utf-8",
    #     level=logging.DEBUG,
    # )

    def send_udp_broadcast(self, message: bytes, broadcast_address="255.255.255.255", port: int = 5076):
        """Send a UDP broadcast message"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(message, (broadcast_address, port))
        logger.debug(f"Sent UDP broadcast message to {broadcast_address}:{port}")
        sock.close()

    class UDPReceiveOnceProtocol(asyncio.DatagramProtocol):
        """Listen for a single UDP message"""

        def __init__(self):
            self.message = None

        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            self.message = data
            self.transport.close()

    async def test_fragmentation_sendreceive(self):
        """Simple test that we are sending and receiving"""
        broadcast_address = netutils.get_broadcast_from_iface("eth0")

        # Start loop listening for UDP messages on port 5076
        loop = asyncio.get_running_loop()
        _, protocol = await loop.create_datagram_endpoint(
            self.UDPReceiveOnceProtocol, local_addr=(broadcast_address, 5076)
        )

        # Give it a little time to fully setup
        await asyncio.sleep(0.1)

        # Send a fragmented UDP message. We ensure fragmentation by making the message payload long
        toolong_msg = b"abcdefghij" * 100
        self.send_udp_broadcast(toolong_msg, broadcast_address)

        # Give them time to arrive
        await asyncio.sleep(2)

        self.assertEqual(protocol.message, toolong_msg)

    # Because this test is using UDP broadcast messages sourced from the same container, and thus
    # the same MAC address, we need to switch off the UDPRelayTransmit l2filter
    # Mocking out the UDPRelayReceive has a primary purpose of letting us test that the fragments
    # are transmitted as expected, but it also serves to disable rebroadcasts and thus mitigate
    # the risk of a mini packet storm
    @unittest.skipIf(os.environ.get("GITHUB_ACTION", False), "GitHub Actions not supported")
    @patch("snowsignal.udp_relay_transmit.UDPRelayTransmit._packet_filter", 0x0003)
    @patch("snowsignal.udp_relay_transmit.UDPRelayTransmit.l2filter", return_value=True)
    @patch("snowsignal.udp_relay_receive.UDPRelayReceive.datagram_received")
    async def test_fragments_rebroadcast(self, mock_datagram_received: unittest.mock.AsyncMock, _):
        """Integration test to check what happens when we send a packet with a payload so
        large that it will become fragmented in an IPv4 environment
        """
        broadcast_address = netutils.get_broadcast_from_iface("eth0")
        logger.debug(
            "iface = %s, local_addr = %s, broadcast_addr = %s",
            "eth0",
            netutils.get_localipv4_from_iface("eth0"),
            broadcast_address,
        )

        # Start main. But first we need to determine if we're in the GitLab CI/CD environment. If we are then
        # for reasons that aren't clear to me we see only PACKET_OUTGOING and no PACKET_BROADCAST as we'd expect.
        # Outside of the GitLab CI/CD environment we can just use the usual default behaviour. In this case that's
        # to filter so we only see IP packets
        if os.environ.get("GITLAB_CI", False):
            packet_filter = 0x0003  # ETH_P_ALL, i.e. all packets
        else:
            packet_filter = 0x0800  # ETH_P_IP, i.e. IP packets

        with patch("snowsignal.udp_relay_transmit.UDPRelayTransmit._packet_filter", packet_filter):
            main_task = asyncio.create_task(snowsignal.main("--target-interface=eth0 -ll=debug", loop_forever=True))

            # Give time for setup to happen
            await asyncio.sleep(0.1)

            # Send a fragmented UDP message. We ensure fragmentation by making the message payload long
            toolong_msg = b""
            for i in range(500):
                toolong_msg += f"test{i:03d}".encode()
            self.send_udp_broadcast(toolong_msg, broadcast_address)

            # And some time for packets to fly around
            await asyncio.sleep(0.25)

            # Then test if it all worked! We attempt to reassemble the packet payload from the fragments
            # by looping throuhg the calls to datagram_received and examining the data argument
            received_packet_payloads = b""
            logger.debug("call_args_list = %s", mock_datagram_received.call_args_list)
            for call in mock_datagram_received.call_args_list:
                data = call[0][0]

                if data[0:2] == b"SS":
                    data = data[2:]
                else:
                    self.fail("Unexpected data format received; did not start with magic bytes 'SS'")

                # First fragment is UDP but later ones are not
                packet = scapy.layers.l2.Ether(data)
                try:
                    received_packet_payloads += bytes(packet[scapy.layers.inet.UDP].payload)
                except IndexError:
                    received_packet_payloads += bytes(packet[scapy.layers.inet.IP].payload)

            self.assertEqual(received_packet_payloads, toolong_msg)

            # Quit main, though it probably quits anyway
            main_task.cancel()
