""" The PVASniffer class is """

import ipaddress
import logging
import socket
from typing import Callable

import scapy.compat
import scapy.config
import scapy.layers
import scapy.layers.inet
import scapy.packet
import scapy.sendrecv

from scapy.all import AsyncSniffer

from netutils import get_localhost_macs, get_localhost_ips


logger = logging.getLogger(__name__)


class UDPRelayTransmit:
    """Listen for PVAccess UDP broadcasts and transmit to the other relays"""

    def __init__(
        self,
        local_port: int = 5076,
        remote_relays: list[ipaddress.ip_address] = None,
        remote_port=7124,
        config = None
    ):
        logger.info("Initialising PVASniffer listening for UDP broadcasts "
                    "on port %i for relay to remote relays %s on port %i",
                    local_port, remote_relays, remote_port)
        self.local_port = local_port
        self.remote_port = remote_port
        self.remote_relays = remote_relays

        # If there's a config provided then use the setting from it,
        # otherwise use some sensible defaults
        if config:
            iface = config.target_interface
            mode = config.rebroadcast_mode

            # NOTE: Scapy filter syntax uses Berkeley Packet Filter (BPF)
            #       syntax, the same as used by tcpdump
            #       See https://biot.com/capstats/bpf.html
            if config.rebroadcast_mode == 'packet':
                (scapy_filter, prn, lfilter) = self.__setup_rebroadcast_packet()
            elif config.rebroadcast_mode == 'payload':
                (scapy_filter, prn, lfilter) = self.__setup_rebroadcast_payload()
        else:
            mode = 'packet'
            iface = 'eth0'
            (scapy_filter, prn, lfilter) = self.__setup_rebroadcast_packet()

        logger.debug("Setting up scapy sniffer in %s mode with filter '%s'",
                     mode, scapy_filter)

        # scapy expects iface as a list so format it that way
        if isinstance(iface, str):
            iface = [iface]

        # AsyncSniffer runs in its own thread
        self.sniffer = AsyncSniffer(
            iface   = iface,
            filter  = scapy_filter,
            prn     = prn,
            lfilter = lfilter,
            count   = 0,
            store   = False,
            quiet   = True,
        )

    def __setup_rebroadcast_packet(self) -> tuple[str, Callable[[scapy.packet.Packet], None], str]:
        """ Settings to use UDP rebroadcast of whole packet """
        local_macs = get_localhost_macs()
        filter_string = ' or '.join(local_macs)

        scapy_filter = f"udp port {self.local_port} and not (ether src {filter_string})"
        prn = self._send_to_relays_packet
        lfilter = self._is_broadcast

        return (scapy_filter, prn, lfilter)

    def __setup_rebroadcast_payload(self) -> tuple[str, Callable[[scapy.packet.Packet], None], str]:
        """ Settings to use UDP rebroadcast of just the payload """
        # We don't want to listen to our own UDP broadcasts
        local_ips = get_localhost_ips()
        local_ips_strings = [str(x) for x in local_ips]
        filter_string = ' or '.join(local_ips_strings)

        scapy_filter = f"udp port {self.local_port} and not (src {filter_string})"
        prn = self._send_to_relays_payload
        lfilter = None # self._is_broadcast

        return (scapy_filter, prn, lfilter)


    def _send_to_relays_payload(self, packet: scapy.packet.Packet):
        """
        Callback to send whole packet to other relays 
        if packet passes sniffer filters
        """
        logger.debug("Received UDP broadcast message:\n%s", packet.show(dump=True))
        logger.debug("scapy packet summary: %s", packet.summary())

        magic_id = b'SS'
        sport = int(packet[scapy.layers.inet.UDP].sport)
        dport = int(packet[scapy.layers.inet.UDP].dport)
        pkt_payload = bytes(packet.payload[scapy.layers.inet.UDP]["Raw"])

        relay_payload = magic_id + sport.to_bytes(2, 'big') + dport.to_bytes(2, 'big') + pkt_payload

        for remote_relay in self.remote_relays:
            logger.debug(
                "Send to (%s, %i) message: %r",
                remote_relay, self.remote_port, relay_payload,
            )
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(relay_payload, (str(remote_relay), self.remote_port))

    def _send_to_relays_packet(self, packet: scapy.packet.Packet):
        """
        Callback to send whole packet to other relays 
        if packet passes sniffer filters
        """

        logger.debug("Received UDP broadcast message:\n%s", packet.show(dump=True))
        logger.debug("scapy packet summary: %s", packet.summary())

        pkt_raw = scapy.compat.raw(packet)
        for remote_relay in self.remote_relays:
            logger.debug(
                "Send to (%s, %i) message: %r",
                remote_relay, self.remote_port, pkt_raw,
            )
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(pkt_raw, (str(remote_relay), self.remote_port))

        # # Check the packet source. If broadcast a packet with this source in the last
        # # second then we shouldn't do so again
        # pkt_raw = scapy.compat.raw(packet)
        # packet_hash = packet[scapy.layers.inet.IP].chksum
        # if not packet_hash in recent_packets:
        #     logger.debug("Received UDP broadcast message:\n%s", packet.show(dump=True))
        #     logger.debug("scapy packet summary: %s", packet.summary())

        #     for remote_relay in self.remote_relays:
        #         logger.debug(
        #             "Send to (%s, %i) message: %r",
        #             remote_relay, self.remote_port, pkt_raw,
        #         )
        #         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #         s.sendto(pkt_raw, (str(remote_relay), self.remote_port))
        # else:
        #     logger.debug(
        #         "Received message with banned hash %s from address %s; "
        #         "banned to prevent loops / packet storms",
        #         packet_hash, packet[scapy.layers.inet.IP].src,
        #     )

    def _is_broadcast(self, packet: scapy.packet.Packet):
        """Check if this is a broadcast packet"""

        return (
            packet.haslayer(scapy.layers.inet.UDP) # excessive since the filter only allows UDP?
            and packet.dst == scapy.layers.l2.Ether(scapy.data.ETHER_BROADCAST).dst
            and packet[scapy.layers.inet.IP].dst.endswith(".255")
        )

    def start(self):
        """Start sniffer"""
        logger.info("Starting to sniff for UDP broadcasts on port %i", self.local_port)
        self.sniffer.start()

    def stop(self):
        """Stop sniffer"""
        self.sniffer.stop()

    def set_remote_relays(self, remote_relays: list[ipaddress.ip_address]):
        """Update the list of remote relays"""
        # We check if there's a change because although it shouldn't much
        # matter if there's a race condition from making a change we might
        # as well minimise the risk anyway
        if remote_relays != self.remote_relays:
            logger.info('Updating remote relays, will use %s', remote_relays)
            self.remote_relays = remote_relays
