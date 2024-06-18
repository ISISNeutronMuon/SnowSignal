""" Listen for UDP broadcasts on a port and transmit packet information to other relays """

import asyncio
import ipaddress
import logging
import struct

import scapy.compat
import scapy.config
import scapy.layers
import scapy.layers.inet
import scapy.packet
import scapy.sendrecv

from src.packet import Packet
from .netutils import get_macaddress_from_iface, machine_readable_mac

# Logging and configuration of Scapy
logger = logging.getLogger(__name__)

scapy.config.conf.use_pcap = False
scapy.config.conf.use_npcap = False
scapy.config.conf.verb = 0
scapy.config.conf.logLevel = logger.getEffectiveLevel()

class UDPRelayReceiveProtocol(asyncio.DatagramProtocol):
    """Listen to UDP messages from remote relays and forward them as broadcasts on the local net"""

    def __init__(self, broadcast_port: int, config = None) -> None:
        super().__init__()

        self.broadcast_port = broadcast_port
        self.transport = None  # Hasn't been initialised yet

        if config:
            self.iface = config.target_interface
        else:
            self.iface = 'eth0'

        # Assume the MAC address is immutable
        self.mac = get_macaddress_from_iface(self.iface)

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Handle a connection being established"""
        self.transport = transport

    def connection_lost(self, exc : Exception | None) -> None:
        """Handle a connection being lost"""
        # What does connection lost even mean for UDP?
        # Seems only necessary to stop some spurious errors on server shutdown

    def datagram_received(self, data: bytes, addr : tuple[any, int]) -> None:
        """Receive a UDP message and forward it to the remote relays"""
        logger.debug(
            "Received from %s for rebroadcast on port %i message: %r",
            addr,
            self.broadcast_port,
            data,
        )

        # Decode the received payload
        if data[0:2] == b'SS':
            data = data[2:]
        else:
            logger.debug("Malformed packet received")
            return

        # Alter the source mac address of the received packet so it originates from the local iface
        packet = Packet(data)
        packet.eth_src_mac = machine_readable_mac(self.mac) # TODO: Fix this!
        packet = packet.raw

        # Reconstitute the raw data back into a scapy packet. Note that we start
        # at the bottommost layer and the higher layers ought to be build
        # automatically. In testing in Docker Swarm some weird anomalies were
        # discovered but these are mitigated by packet.show2() further down.
        # The exception is that on Swarm the src was not created until that point.
        # But since we need to set the src we include it in the packet build here
        # even though it doesn't seem to be correctly set
        # TODO: What happens if we receive data that can't be turned
        # into a scapy packet?
        try:
            packet = scapy.layers.l2.Ether(data)
        except struct.error as err:
            logger.debug("Received anomalous data from %s which could not be ingested, "
                            "triggered exception %s", addr, err)
            return

        packet[scapy.layers.l2.Ether].src = self.mac

        # Force a recalculation of the ethernet checksum
        del packet.chksum
        del packet[scapy.layers.inet.UDP].chksum

        # TODO: Logic to validate what we're receiving as a PVAccess message
        # Note that although doing the validation on receipt means we're doing
        # it for every relay (instead of once if we did it on send), it's much
        # safer to do it on receipt since it means we don't have to trust the
        # sender as much

        # Note that very weirdly the next line is what actually does the
        # UDP checksum recalculation. It's not just for debugging info!
        # Perhaps only needed in the packet mode above?
        debugmsg = packet.show2(dump=True)
        logger.debug("Broadcasting packet\n%s", debugmsg)

        # Finally broadcast the new packet
        scapy.sendrecv.sendp(packet, iface=self.iface)


async def run_relay_receiver(
    local_addr: tuple[ipaddress.ip_address, int],
    broadcast_port: int,
    config = None
) -> None:
    """Start the UDP server that listens for messages from other relays and broadcasts them"""

    logger.info(
        "Starting UDP server listening on %s; will rebroadcast on port %i",
        local_addr,
        broadcast_port,
    )

    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    # One protocol instance will be created to serve all
    # client requests.
    transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPRelayReceiveProtocol(broadcast_port, config=config),
        local_addr=local_addr
    )

    try:
        while True:
            # Basically sleep forever!
            await asyncio.sleep(3600)
    finally:
        transport.close()
