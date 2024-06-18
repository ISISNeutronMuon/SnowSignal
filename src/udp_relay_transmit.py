""" The PVASniffer class is """

import asyncio
import ipaddress
import logging
import socket

from .packet import BadPacketException, EthernetProtocol, Packet
from .netutils import get_localhost_macs, human_readable_mac, machine_readable_mac

logger = logging.getLogger(__name__)


class UDPRelayTransmit():
    """Listen for PVAccess UDP broadcasts and transmit to the other relays"""

    def __init__(
        self,
        local_port: int = 5076,
        remote_relays: list[ipaddress.ip_address] = None,
        remote_port=7124,
        config = None
    ):
        self._loop_forever = True

        logger.info("Initialising UDPRelayTransmit listening for UDP broadcasts "
                    "on port %i for relay to remote relays %s on port %i",
                    local_port, remote_relays, remote_port)

        self.local_port = local_port
        self.remote_port = remote_port
        self.remote_relays = remote_relays

        # If there's a config provided then use the setting from it,
        # otherwise use some sensible defaults
        if config:
            self._iface = config.target_interface
        else:
            self._iface = 'eth0'

        self._macs = get_localhost_macs()
        self._macs = [machine_readable_mac(x) for x in self._macs]
        self.ip_whitelist = [] # NotImplemented


    async def _send_to_relays_packet(self, packet: Packet):
        """
        Callback to send whole packet to other relays 
        if packet passes sniffer filters
        """
        logger.debug("Transmitting to relays UDP broadcast message:\n%s", packet)

        pkt_raw = b'SS' + packet.raw

        await self._send_to_relays_bytes(pkt_raw)


    async def _send_to_relays_bytes(self, msgbytes : bytes):
        """  Send bytes to the remote relays """

        for remote_relay in self.remote_relays:
            logger.debug(
                "Send to (%s, %i) message: %r",
                remote_relay, self.remote_port, msgbytes,
            )
            sock_family = socket.AF_INET
            if isinstance(remote_relay, ipaddress.IPv6Address):
                sock_family = socket.AF_INET6

            with socket.socket(sock_family, socket.SOCK_DGRAM) as s:
                s.setblocking(False)
                loop = asyncio.get_running_loop()
                await loop.sock_sendto(s, msgbytes, (str(remote_relay), self.remote_port))


    def l1filter(self, rawpacket : tuple) -> bool:
        """ Check the network interface is as expected"""
        packet_iface = rawpacket[1][0]
        if packet_iface != self._iface:
            logger.debug('Identified as using wrong iface %s', packet_iface)
            return False

        return True

    def l2filter(self, packet : Packet) -> bool:
        """ Tests to perform on Level2 of packet, i.e. Ethernet  """
        # Make sure this is a broadcast and that its payload is an IP protocol message
        if packet.eth_dst_mac != b'\xff\xff\xff\xff\xff\xff' or packet.eth_protocol == EthernetProtocol.UNKNOWN:
            logger.debug('Not broadcast or not known ethernet protocol, packet %r', packet)
            return False

        # Do not process packets sourced from this machine
        # TODO: Ban all MAC addresses from the machine
        if packet.eth_src_mac in self._macs:
            logger.debug('Source is a local MAC')
            return False

        logger.debug('l2filter - eth src MAC is %s', human_readable_mac(packet.eth_src_mac))

        return True

    def l3filter(self, packet : Packet) -> bool:
        """ Tests to perform on Level3 of packet, i.e IP Protocol"""

        # Make sure this contains a UDP payload
        if packet.ip_protocol != 17: # 17 is UDP
            return False

        # If we have a whitelist of source addresses then check it claims to come
        # from one of them
        if self.ip_whitelist:
            if packet.ip_src_addr not in self.ip_whitelist:
                return False

        return True

    def l4filter(self, packet : Packet) -> bool:
        """ Tests to perform on Level4 of packet, i.e. UDP Protocol """
        if packet.udp_dst_port != self.local_port:
            logger.debug('Wrong UDP destination port: %i', packet.udp_dst_port)
            return False

        return True


    async def start(self) -> None:
        """ Monitor for UDP broadcasts on the specified port """
        #create a AF_PACKET type raw socket (thats basically packet level)
        #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
        #define ETH_P_IP     0x0800          IP packets only
        with socket.socket( socket.AF_PACKET, # pylint: disable=no-member
                            socket.SOCK_RAW , 
                            socket.ntohs(0x0800)
                          ) as sock:
            sock.setblocking(False)

            while self._loop_forever:
                loop = asyncio.get_running_loop()
                packet = await loop.sock_recvfrom(sock, 1024)
                logger.debug('Received packet %r with data %r', packet[1], packet[0])

                try:
                    # Check Level 1 physical layer, i.e. network interface
                    if not self.l1filter(packet):
                        logger.debug('Failed l1filter')
                        self._loop_forever = self._continue_while_loop()
                        continue

                    # Check Level 2 data link layer, i.e. ethernet header
                    packet = Packet(packet[0])
                    if not self.l2filter(packet):
                        logger.debug('Failed l2filter')
                        self._loop_forever = self._continue_while_loop()
                        continue

                    # Check Level 3 network layer, i.e. IP protocol
                    packet.decode_ip()
                    if not self.l3filter(packet):
                        logger.debug('Failed l3filter')
                        self._loop_forever = self._continue_while_loop()
                        continue

                    # Check Level 4 transport protocol, i.e. UDP
                    packet.decode_udp()
                    if not self.l4filter(packet):
                        logger.debug('Failed l4filter')
                        self._loop_forever = self._continue_while_loop()
                        continue
                except BadPacketException as bpe:
                    logger.debug("Malformed packet %r", bpe)
                    self._loop_forever = self._continue_while_loop()
                    continue

                # Send to other relays
                await self._send_to_relays_packet(packet)
                self._loop_forever = self._continue_while_loop()

    def _continue_while_loop(self) -> bool:
        """ This function exists purely to allow unit testing of the start() function below """
        return self._loop_forever

    def stop(self):
        """ Stop the main event loop in the start function """
        self._loop_forever = False

    def set_remote_relays(self, remote_relays: list[ipaddress.ip_address]):
        """Update the list of remote relays"""
        # We check if there's a change because although it shouldn't much
        # matter if there's a race condition from making a change we might
        # as well minimise the risk anyway
        if remote_relays != self.remote_relays:
            logger.info('Updating remote relays, will use %s', remote_relays)
            self.remote_relays = remote_relays
