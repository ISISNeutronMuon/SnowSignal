""" Listen for UDP broadcasts on a port and transmit packet information to other relays 

This uses the standard asyncio.DatagramProtocol base class so most of the initial
management of the UDP packet is already done for us.
"""

import array
import asyncio
from copy import deepcopy
import ipaddress
import logging
import socket
import struct

from typing import Any
from .netutils import get_broadcast_from_iface, get_macaddress_from_iface

logger = logging.getLogger(__name__)

class UDPRelayReceive(asyncio.DatagramProtocol):
    """Listen to UDP messages from remote relays and forward them as broadcasts on the local net"""

    def __init__(self,
                 local_addr: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | str, int],
                 broadcast_port: int,
                 config = None
                ) -> None:
        super().__init__()

        self.local_addr = local_addr
        self.broadcast_port = broadcast_port
        self.transport = None  # Hasn't been initialised yet

        if config:
            self._iface = config.target_interface
        else:
            self._iface = 'eth0'

        # Assume the MAC address is immutable
        self._mac = get_macaddress_from_iface(self._iface)

        # Also assume the broadcast address associated with the
        # interface is immutable
        self._broadcast_addr = get_broadcast_from_iface(self._iface)

        self._loop_forever = True

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Handle a connection being established"""
        self.transport = transport

    def connection_lost(self, exc : Exception | None) -> None:
        """Handle a connection being lost"""
        # What does connection lost even mean for UDP?
        # Seems only necessary to stop some spurious errors on server shutdown

    def recalculate_udp_checksum(self, ip_packet):
        """ Calculate UDP checksum, using the IP and UDP parts of the packet, 
        and change the existing packet UDP checksum with the newly calculcated
        checksum"""

        # The UDP checksum algorithm is defined in RFC768
        # https://www.rfc-editor.org/rfc/rfc768.txt
        # "Checksum is the 16-bit one's complement of the one's complement sum of a
        #  pseudo header of information from the IP header, the UDP header, and the
        #  data, padded with zero octets at the end (if necessary) to make a
        #  multiple of two octets"

        # Extract the data needed to form the pseudo packet and header
        # Got this from https://dev.to/cwprogram/python-networking-tcp-and-udp-4i3l

        # Make a deepcopy of the UDP portion of the whole ip_packet so that we don't
        # accidentally modify it. Then zero the part that contains the UDP checksum.
        # A zero checksum is valid but we'll calculate the correct value
        pseudo_packet = bytearray(deepcopy(ip_packet[20:]))
        pseudo_packet[6] = 0x0
        pseudo_packet[7] = 0x0

        # We need information from the IP header to construct the pseudo-header
        # needed in turn to calculate the UDP checksum. Specifically we need the
        # source and destination IP addresses
        ip_header = struct.unpack('!BBHHHBBH4s4s', ip_packet[0:20])
        pseudo_header = struct.pack('!4s4sHH', ip_header[8], ip_header[9],
                                               socket.IPPROTO_UDP, len(pseudo_packet))

        # Combine the pseudo header and pseudo packet to form a complete pseudo packet
        # that we'll perform the checksum calculations on
        checksum_packet = pseudo_header + pseudo_packet

        # If there is an odd number of bytes in the checksum packet we need to
        # pad it to an even number of bytes
        if len(checksum_packet) % 2 == 1:
            checksum_packet += b"\0"

        # The checksum calculation proceeds by summing the one’s complement where
        # all binary 0s become 1s, of all 16-bit words in these components.
        onecompsum  = sum(array.array("H", checksum_packet))
        onecompsum  = (onecompsum >> 16) + (onecompsum & 0xffff)
        onecompsum += onecompsum >> 16
        onecompsum  = ~onecompsum   # Finally invert the bits

        # Test endianness and do some magic if we're on a little endian system
        if struct.pack("H", 1) != b"\x00\x01":
            onecompsum = ((onecompsum >> 8) & 0xff) | onecompsum << 8

        # If checksum is 0 change it to 0xFFFF to signal it has been calculated
        udp_checksum = onecompsum & 0xffff

        # Insert the calculated checksum into the IP + UDP packet
        ip_packet = ip_packet[:26] + udp_checksum.to_bytes(2,'big') + ip_packet[28:]

        return ip_packet

    def datagram_received(self, data: bytes, addr : tuple[str | Any, int]) -> None:
        """Receive a UDP message and forward it to the remote relays"""
        logger.debug(
            "Received from %s for rebroadcast on port %i message: %r",
            addr,
            self.broadcast_port,
            data,
        )

        # Simple verification of the received payload
        if data[0:2] == b'SS':
            data = data[2:]
        else:
            logger.debug("Malformed packet received")
            return

        # TODO: Apply any filters

        # Alter the source mac address of the received packet so it originates from the local iface
        #data = data[0:6] + machine_readable_mac(self.mac) + data[12:]

        # We can't use the data as is for some reason but need to recalculate the
        # ethernet checksum
        # Recalculate UDP checksum; we don't pass in the ethernet frame
        data = data[:14] + self.recalculate_udp_checksum(data[14:])

        # TODO: The code above does not change the IP source address
        # If we're on a different network segment then we should switch the
        # broadcast IP address to use get_broadcast_from_iface(). This will
        # then require recomputing checksums

        # TODO: Logic to validate what we're receiving as a PVAccess message
        # Note that although doing the validation on receipt means we're doing
        # it for every relay (instead of once if we did it on send), it's much
        # safer to do it on receipt since it means we don't have to trust the
        # sender as much

        # Finally broadcast the new packet
        # It doesn't feel much simpler but we're not using fully raw sockets here
        # but instead letting Python do the work of handling the Ethernet frames
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, True)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
            sendbytes = s.sendto(data[14:], (self._broadcast_addr, self.broadcast_port))
            logger.debug("Broadcast UDP packet of length %d on iface %s: %s",
                         sendbytes, self._iface, data[14:])


    async def start(self) -> None:
        """Start the UDP server that listens for messages from other relays and broadcasts them"""

        logger.info(
            "Starting UDP server listening on %s; will rebroadcast on port %i",
            self.local_addr,
            self.broadcast_port,
        )

        # Get a reference to the event loop as we plan to use
        # low-level APIs.
        loop = asyncio.get_running_loop()

        # One protocol instance will be created to serve all
        # client requests.
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self, #UDPRelayReceiveProtocol(broadcast_port, config=config),
            local_addr=self.local_addr,
            allow_broadcast=True
        )

        try:
            while self._loop_forever:
                # Basically sleep forever!
                await asyncio.sleep(1)
        finally:
            transport.close()
