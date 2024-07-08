""" Listen for UDP broadcasts on a port and transmit packet information to other relays 

This uses the standard asyncio.DatagramProtocol base class so most of the initial
management of the UDP packet is already done for us.
"""

import asyncio
import ipaddress
import logging
import socket

import scapy
import scapy.layers
import scapy.layers.l2
import scapy.layers.inet
import scapy.sendrecv

from .netutils import get_macaddress_from_iface, machine_readable_mac

logger = logging.getLogger(__name__)

class UDPRelayReceive(asyncio.DatagramProtocol):
    """Listen to UDP messages from remote relays and forward them as broadcasts on the local net"""

    def __init__(self, 
                 local_addr: tuple[ipaddress.ip_address, int], 
                 broadcast_port: int,
                 config = None
                ) -> None:
        super().__init__()

        self.local_addr = local_addr
        self.broadcast_port = broadcast_port
        self.transport = None  # Hasn't been initialised yet

        if config:
            self.iface = config.target_interface
        else:
            self.iface = 'eth0'

        # Assume the MAC address is immutable
        self.mac = get_macaddress_from_iface(self.iface)

        self._loop_forever = True

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

        # Simple verification of the received payload
        if data[0:2] == b'SS':
            data = data[2:]
        else:
            logger.debug("Malformed packet received")
            return

        # TODO: Apply any filters

        # Alter the source mac address of the received packet so it originates from the local iface
        # logger.debug('Datagram MAC: %s / %s', self.mac, machine_readable_mac(self.mac))
        # logger.debug('Packet unaltered: %r', data)
        print(20*'-' + ' 1 ' + 20*'-')
        spacket = scapy.layers.l2.Ether(data)
        spacket.show()
        data = data[0:6] + machine_readable_mac(self.mac) + data[12:]
        # logger.debug('Packet altered:   %r', data)
        spacket = scapy.layers.l2.Ether(data)
        print(20*'-' + ' 2 ' + 20*'-')
        spacket.show()
        print(20*'-' + ' 3 ' + 20*'-')
        spacket.show2()
        data=scapy.compat.raw(spacket)

        # TODO: Logic to validate what we're receiving as a PVAccess message
        # Note that although doing the validation on receipt means we're doing
        # it for every relay (instead of once if we did it on send), it's much
        # safer to do it on receipt since it means we don't have to trust the
        # sender as much

        # Finally broadcast the new packet
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
            s.bind((self.iface,0))
            logger.debug("Broadcasting packet on iface %s: %s", self.iface, data)
            s.send(data)

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
            local_addr=self.local_addr
        )

        try:
            while self._loop_forever:
                # Basically sleep forever!
                await asyncio.sleep(1)
        finally:
            transport.close()
