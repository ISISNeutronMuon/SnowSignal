""" Listen for UDP broadcasts on a port and transmit packet information to other relays """

import asyncio
import ipaddress
import logging
import random
import struct

import scapy.compat
import scapy.config
import scapy.layers
import scapy.layers.inet
import scapy.packet
import scapy.sendrecv
from .netutils import get_macaddress_from_iface, get_localipv4_from_iface, get_broadcast_from_iface

# Logging and configuration of Scapy
logger = logging.getLogger(__name__)

scapy.config.conf.use_pcap = False
scapy.config.conf.use_npcap = False
scapy.config.conf.verb = 0
scapy.config.conf.logLevel = logger.getEffectiveLevel()

class UDPRelayReceiveProtocol(asyncio.DatagramProtocol):
    """Listen to UDP messages from remote relays and forward them as broadcasts on the local net"""

    def __init__(self, broadcast_port: int, config = None):
        self.broadcast_port = broadcast_port
        self.transport = None  # Hasn't been initialised yet

        if config:
            self.rebroadcast_mode = config.rebroadcast_mode
            self.iface = config.target_interface
        else:
            self.rebroadcast_mode = 'payload'
            self.iface = 'eth0'

        # Assume the MAC address is immutable
        self.mac = get_macaddress_from_iface(self.iface)

    def connection_made(self, transport: asyncio.DatagramTransport):
        """Handle a connection being established"""
        self.transport = transport

    def connection_lost(self, exc):
        """Handle a connection being lost"""
        # What does connection lost even mean for UDP?
        # Seems only necessary to stop some spurious errors on server shutdown

    def datagram_received(self, data: bytes, addr):
        """Receive a UDP message and forward it to the remote relays"""
        logger.debug(
            "Received from %s for rebroadcast on port %i message: %r",
            addr,
            self.broadcast_port,
            data,
        )

        # Create a packet based on a whole scapy-encoded packet we received from
        # another relay, or simply the payload of another packet
        if self.rebroadcast_mode == 'packet':
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
                packet = scapy.layers.l2.Ether(data, src=self.mac)
            except struct.error as err:
                logger.debug("Received anomalous data from %s which could not be ingested, "
                             "triggerred exception %s", addr, err)
                return

            # Change the packet ethernet source to be the mac address of this
            # network interface. In this way we can ignore these broadcasts 
            # using the rules in the PVAccessSniffer and prevent UDP storms
            packet[scapy.layers.l2.Ether].src = self.mac

            # Force a recalculation of the ethernet checksum
            del packet.chksum
            del packet[scapy.layers.inet.UDP].chksum
        elif self.rebroadcast_mode == 'payload':
            # In testing this did not work as expected for PVAccess
            # The reason seems to be that most implementations ignore the IP address
            # encoded in the search message payload and instead use the UDP src 
            # address. Since in this implementation that points back to this relay
            # the client can't connect to the server.

            # Decode the received payload
            if data[0:2] != b'SS':
                logger.debug("Malformed packet received")
                return

            # IPv4 packet structure: https://en.wikipedia.org/wiki/IPv4#Packet_structure
            # UDP datagram structure: https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure
            pkt_id = random.randint(0, 65535)
            pkt_flags = 'DF' # This is how it's set in the PVAccess packets I've inspected
            udp_sport = int.from_bytes(data[2:4], byteorder='big')
            udp_dport = int.from_bytes(data[4:6], byteorder='big')
            payload = data[6:]

            packet =  scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff") \
                     /scapy.layers.inet.IP(dst=get_broadcast_from_iface(self.iface), id=pkt_id, flags=pkt_flags) \
                     /scapy.layers.inet.UDP(sport=udp_sport, dport=udp_dport) \
                     /scapy.packet.Raw(load=payload)

            # For some reason in swarm testing src isn't being set
            if packet[scapy.layers.l2.Ether].src == '00:00:00:00:00:00':
                packet[scapy.layers.l2.Ether].src = get_macaddress_from_iface(self.iface)

            if packet[scapy.layers.inet.IP].src == '0.0.0.0':
                packet[scapy.layers.inet.IP].src = get_localipv4_from_iface(self.iface)

        else:
            logger.error('Unknown rebroadcast mode %s', self.rebroadcast_mode)
            raise SyntaxError(f'Unknown rebroadcast mode {self.rebroadcast_mode}')

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
):
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
