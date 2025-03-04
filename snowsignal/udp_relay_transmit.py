"""
The UDPRelayTransmit class is confusingly named. It transmits packets
into the relay mesh network. That means that it is also the class that
listens for UDP broadcasts on the specified network interface and port.

It applies a number of defined filters (level 1 to level 4) to verify
that the received packet was received on the specified network interface,
port, that it is a broadcast packet, and that it is a well-formed UDP packet.
Importantly it filters out any packets that were received from this network
interfaces MAC address.

If these criteria are met then it sends the packet to the rest of the mesh
network relays.
"""

import asyncio
import ipaddress
import logging
import socket
from collections.abc import Sequence
from dataclasses import dataclass

import cachetools

from .configure import ConfigArgs
from .netutils import get_localhost_macs, human_readable_mac, identify_pkttype, machine_readable_mac
from .packet import BadPacketException, EthernetProtocol, Packet
from .pva_packet import log_pvaccess_packet

logger = logging.getLogger(__name__)


@dataclass(init=True, repr=True, eq=True, frozen=True)
class FragID:
    """Enough details about an IPv4 fragment to identify its later parts"""

    fragid: int
    src: str
    dst: str


class UDPRelayTransmit:
    """Listen for UDP broadcasts and transmit to the other relays"""

    # We need a cache to store potential UDP fragments
    _fragcache = cachetools.TTLCache(maxsize=1024, ttl=1)

    # This next bit is supplied only so that the testing may override it
    # define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    # define ETH_P_IP     0x0800          IP packets only; I believe this is IPv4
    _packet_filter = 0x0800

    def __init__(
        self,
        remote_relays: Sequence[ipaddress.IPv4Address | ipaddress.IPv6Address | str],
        local_port: int = 5076,
        remote_port: int = 7124,
        config: ConfigArgs | None = None,
    ) -> None:
        self._loop_forever = True

        logger.info(
            "Initialising UDPRelayTransmit listening for UDP broadcasts "
            "on port %i for relay to remote relays %s on port %i",
            local_port,
            remote_relays,
            remote_port,
        )

        self.local_port = local_port
        self.remote_port = remote_port
        self.remote_relays = remote_relays

        # If there's a config provided then use the setting from it,
        # otherwise use some sensible defaults
        if config:
            self._iface = config.target_interface
            self._decode_pvaccess = config.decode_pvaccess
        else:
            self._iface = "eth0"
            self._decode_pvaccess = False

        self._macs = get_localhost_macs()
        self._macs = [machine_readable_mac(x) for x in self._macs]
        self.ip_whitelist = []  # NotImplemented

    async def _send_to_relays_packet(self, packet: Packet) -> None:
        """
        Callback to send whole packet to other relays
        if packet passes sniffer filters
        """
        logger.debug("Transmitting to relays UDP broadcast message:\n%s", packet)

        pkt_raw = b"SS" + packet.raw

        await self._send_to_relays_bytes(pkt_raw)

    async def _send_to_relays_bytes(self, msgbytes: bytes) -> None:
        """Send bytes to the remote relays"""

        for remote_relay in self.remote_relays:
            logger.debug(
                "Send to (%s, %i) message: %r",
                remote_relay,
                self.remote_port,
                msgbytes,
            )
            sock_family = socket.AF_INET
            if isinstance(remote_relay, ipaddress.IPv6Address):
                sock_family = socket.AF_INET6

            with socket.socket(sock_family, socket.SOCK_DGRAM) as s:
                s.setblocking(False)
                loop = asyncio.get_running_loop()
                bytessent = await loop.sock_sendto(s, msgbytes, (str(remote_relay), self.remote_port))
                if bytessent < len(msgbytes):
                    logger.warning(
                        "Sent truncated message to other SnowSignal nodes; was %i, should be %i",
                        bytessent,
                        len(msgbytes),
                    )

    def l1filter(self, ifname: str) -> bool:
        """Check the network interface is as expected"""
        if ifname != self._iface:
            logger.debug("Identified as using wrong iface %s", ifname)
            return False

        return True

    def l2filter(self, packet: Packet) -> bool:
        """Tests to perform on Level2 of packet, i.e. Ethernet"""
        # Make sure this is a broadcast and that its payload is an IP protocol message
        if packet.eth_dst_mac != b"\xff\xff\xff\xff\xff\xff":
            logger.debug("Not broadcast packet %r", packet)
            return False
        if packet.eth_protocol == EthernetProtocol.UNKNOWN:
            logger.debug("Not known ethernet protocol packet %r", packet)
            return False

        # Do not process packets sourced from this machine
        if packet.eth_src_mac in self._macs:
            logger.debug("Source is a local MAC")
            return False

        return True

    def l3filter(self, packet: Packet) -> bool:
        """Tests to perform on Level3 of packet, i.e IP Protocol"""

        # Make sure this contains a UDP payload
        if packet.ip_protocol != 17:  # 17 is UDP
            return False

        # If we have a whitelist of source addresses then check it claims to come
        # from one of them
        if self.ip_whitelist:
            if packet.ip_src_addr not in self.ip_whitelist:
                return False

        return True

    def l4filter(self, packet: Packet) -> bool:
        """Tests to perform on Level4 of packet, i.e. UDP Protocol"""
        if packet.udp_dst_port != self.local_port:
            logger.debug("Wrong UDP destination port: %i on packet %s", packet.udp_dst_port, packet)
            return False

        return True

    def filter_fragment(self, packet: Packet) -> bool:
        """
        We have identified this as a UDP packet fragment. If it the first fragment we apply the
        l4filter and then cache an identifier so that we may apply the result of that filter to
        the subsequent fragments.
        """

        # If this is the first packet then if will have a fragment offset of 0. Importantly,
        # we should still be able to evaluate it as a UDP packet and thus see if it satisfies
        # our filters. If it doesn't then neither will subsequent fragments. However, if it
        # does satisfy the filter then so will subsequent fragments which won't have UDP
        # headers for us to evaluate
        fragid = FragID(packet.ipv4_identification, packet.ip_src_addr, packet.ip_dst_addr)  # type: ignore

        # If the Fragment Offset is zero then this is the first fragment
        if packet.ipv4_fragmented_offset == 0:
            # The first fragment should be a valid UDP packet
            packet.decode_udp()
            # If it passes the l4filter then we cache its identifier so that subsequent fragments may be passed
            if self.l4filter(packet):
                logger.debug(
                    "Fragment (%i/%i), a first fragment, passed l4filter",
                    packet.ipv4_identification,
                    packet.ipv4_fragmented_offset,
                )
                self._fragcache[fragid] = packet
            else:
                logger.debug(
                    "Fragment (%i/%i) failed l4filter",
                    packet.ipv4_identification,
                    packet.ipv4_fragmented_offset,
                )
                return False
        else:
            # This is a fragment but not the first one. It will therefore not have a valid UDP header to decode.
            # Instead we check if its identifier is in the cache from an inspection of the first fragement. If it is
            # then the first fragment passed the l4filter and therefore this one does too.
            if not self._fragcache[fragid]:
                logger.debug(
                    "Fragment (%i/%i) not recognised as continuation of l4filter approved packet",
                    packet.ipv4_identification,
                    packet.ipv4_fragmented_offset,
                )
                return False

            # If this is the final fragment, indicated by the More Fragments flag being False but the Fragment Offset
            # being >0, then we need to remove its identifier from the fragment cache
            if not packet.ipv4_more_fragments:
                self._fragcache.pop(fragid)

        return True

    async def start(self) -> None:
        """Monitor for UDP broadcasts on the specified port"""

        logger.debug("UDPRelayTransmit starting to listen for raw packets")

        # create a AF_PACKET type raw socket (thats basically packet level)
        # define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
        # define ETH_P_IP     0x0800          IP packets only; I believe this is IPv4
        with socket.socket(
            socket.AF_PACKET,  # type: ignore - not available on Windows
            socket.SOCK_RAW,
            socket.ntohs(self._packet_filter),
        ) as sock:
            sock.setblocking(False)

            while self._loop_forever:
                loop = asyncio.get_running_loop()

                raw_packet = await loop.sock_recvfrom(sock, 65536)
                (ifname, proto, pkttype, hatype, addr) = raw_packet[1]
                raw_packet = raw_packet[0]
                logger.debug(
                    "Received on iface %s (proto %r, pktytype %r, hatype %r, addr %r) data %r",
                    ifname,
                    socket.ntohs(proto),
                    identify_pkttype(pkttype),
                    socket.ntohs(hatype),
                    human_readable_mac(addr),
                    raw_packet,
                )

                try:
                    # Check Level 1 physical layer, i.e. network interface
                    if not self.l1filter(ifname):
                        logger.debug("Failed l1filter")
                        self._loop_forever = self._continue_while_loop()
                        continue

                    # Check Level 2 data link layer, i.e. ethernet header
                    packet = Packet(raw_packet)
                    if not self.l2filter(packet):
                        logger.debug("Failed l2filter")
                        self._loop_forever = self._continue_while_loop()
                        continue

                    # Check Level 3 network layer, i.e. IP protocol
                    packet.decode_ip()
                    if not self.l3filter(packet):
                        logger.debug("Failed l3filter")
                        self._loop_forever = self._continue_while_loop()
                        continue

                    # Check for IP packet fragmentation, only IPv4 packets can be fragmented
                    # https://en.wikipedia.org/wiki/IPv4#Fragmentation_and_reassembly
                    if not packet.is_ipv4_fragmented():
                        # This is an ordinary unfragmented IP packet
                        # Check Level 4 transport protocol, i.e. UDP
                        packet.decode_udp()
                        if not self.l4filter(packet):
                            logger.debug("Failed l4filter")
                            self._loop_forever = self._continue_while_loop()
                            continue
                    else:
                        if not self.filter_fragment(packet):  # Note we may l4filter in this call
                            logger.debug("Failed l4filter of fragment")
                            self._loop_forever = self._continue_while_loop()
                            continue

                except BadPacketException as bpe:
                    logger.debug("Malformed packet %r", bpe)
                    self._loop_forever = self._continue_while_loop()
                    continue

                # Use this unusual conditional in order to avoid expensive
                # decoding operations when we're not debugging
                if self._decode_pvaccess and logger.isEnabledFor(logging.INFO):
                    log_pvaccess_packet(packet)

                # Send to other relays
                await self._send_to_relays_packet(packet)
                self._loop_forever = self._continue_while_loop()

        logger.warning("UDPRelayTransmit no longer listening for raw packets")

    def _continue_while_loop(self) -> bool:
        """This function exists purely to allow unit testing of the start() function above"""
        return self._loop_forever

    def stop(self) -> None:
        """Stop the main event loop in the start function"""
        self._loop_forever = False

    def set_remote_relays(self, remote_relays: list[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> None:
        """Update the list of remote relays"""
        # We check if there's a change because although it shouldn't much
        # matter if there's a race condition from making a change we might
        # as well minimise the risk anyway
        if remote_relays != self.remote_relays:
            logger.info("Updating remote relays, will use %s", remote_relays)
            self.remote_relays = remote_relays
