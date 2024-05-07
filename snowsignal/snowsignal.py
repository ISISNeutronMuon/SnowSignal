""" Experimental UDP Broadcast Relay for PVAccess """

import asyncio
import ipaddress
import logging
import os
import socket

import cachetools
import psutil
import scapy.compat
import scapy.config
import scapy.layers
import scapy.layers.inet
import scapy.packet
import scapy.sendrecv
from scapy.all import AsyncSniffer

# Logging and configuration of Scapy 
LOGLEVEL = logging.DEBUG

scapy.config.conf.use_pcap = False
scapy.config.conf.use_npcap = False
scapy.config.conf.verb = 0
scapy.config.conf.logLevel = LOGLEVEL

logger = logging.getLogger(__name__)
logging.basicConfig(encoding="utf-8", level=LOGLEVEL)

# This is a Time-to-Live cache to prevent loops and packet storms
# The maxsize was originally set when I thought I'd be storing IP addresses
# Now that it's IP checksums I'm not sure what a sensible maxsize is
recent_packets = cachetools.TTLCache(maxsize=256 * 256, ttl=1)


def is_swarmmode() -> bool:
    ''' Crude check to see if we're running in docker swarm'''

    swarmmode = False
    try:
        if os.environ['SERVICENAME']:
            swarmmode = True
    except KeyError:
        logger.warning("SERVICENAME not set - if this is not a test then something is wrong!")
    return swarmmode


def get_ips_from_name(name: str) -> list[ipaddress.ip_address]:
    """Given a hostname return its IP addresses as a list"""
    local_ips_details = socket.getaddrinfo(f"{name}", 80)

    ips = []
    for local_ip_detail in local_ips_details:
        addfamily = local_ip_detail[0]
        if addfamily in (socket.AddressFamily.AF_INET6, socket.AddressFamily.AF_INET):
            ip = ipaddress.ip_address(local_ip_detail[4][0])
            ips.append(ip)
        else:
            raise RuntimeError(f"Unknown AddressFamily {addfamily}")

    # Remove duplicates and return
    ips = list(set(ips))

    return ips


def get_localhost_ips() -> list[ipaddress.ip_address]:
    """Establish the IP address(es) of this container"""
    # Note that in a Docker Swarm environment we expect the container to
    # have at least two IP addresses, it's traditional IP address associated
    # with eth0 but also a Virtual IP (VIP) shared with all of the
    # other containers in the same task. We could also have other IP
    # addresses associated with other networks. So there could be many
    # IP addresses for this one container!

    # This is a bit of a hack but is apparently the most portable way
    local_ips = get_ips_from_name(socket.gethostname())
    logging.debug("\tThis system has IP address(es) %s:", local_ips)

    return local_ips


# Discover the other UDP Broadcast relays in the stack
def discover_relays() -> list[ipaddress.ip_address]:
    """Discover the other UDP Broadcast Relays in the stack"""

    logger.info("Beginning relay discovery")
    # Establish the IP address(es) of this container
    # This is a bit of a hack but is apparently the most portable way
    local_ips = get_localhost_ips()
    logging.debug("\tThis system has IP address(es) %s:", local_ips)

    # Get the list of IP addresses in this stack
    # First get the environment variable we're using to identify our stack
    try:
        stack_and_task = os.environ["SERVICENAME"]
    except KeyError:
        logger.critical(
            "Environment variable SERVICENAME must be set as {{.Service.Name}} in compose file"
        )
        raise

    # The important bit here is to query tasks. This will work however the
    # endpoint_mode is set and will only list the other containers and not
    # include the Virtual IP (VIP)
    task_ips = get_ips_from_name(f"tasks.{stack_and_task}")
    logger.debug("\tTasks in %s have IP address(es) %s:", stack_and_task, task_ips)

    # We don't want to communicate with ourself
    valid_ips = list(set(task_ips) - set(local_ips))
    logger.info("\tDiscovered relays: %s", valid_ips)

    return valid_ips


class UDPBroadcastRelayServerProtocol:
    """Listen to UDP messages from remote relays and forward them as broadcasts on the local net"""

    def __init__(self, broadcast_port: int):
        self.broadcast_port = broadcast_port
        self.transport = None  # Hasn't been initialised yet

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
        # TODO: Logic to validate what we're receiving as a PVAccess message
        # Note that although doing the validation on receipt means we're doing
        # it for every relay (instead of once if we did it on send), it's much
        # safer to do it on receipt since it means we don't have to trust the
        # sender as much

        # Reconstitute the raw data back into a scapy packet. Note that we start
        # at the bottommost layer and the higher layers ought to be build
        # automatically
        # TODO: URGENT! What happens if we receive data that can't be turned 
        # into a scapy packet?
        try:
            packet = scapy.layers.l2.Ether(data)
        except Exception as err:
            logger.debug("Received anomalous data from %s which could not be ingested, triggerred exception %s", addr, err)
            return

        # There's some difficult considerations with using the checksums
        # The UDP checksum is identical for identical search requests, so
        # if we use it we limit repeated rapid searches. The IP checksum
        # is different but more likely to collide
        recent_packets[packet[scapy.layers.inet.IP].chksum] = True

        # Force a recalculation of the ethernet checksum
        del packet.chksum 
        del packet[scapy.layers.inet.UDP].chksum
        # Note that very weirdly the next line is what actually does the 
        # recalculation. It's not just for debugging info!
        debugmsg = packet.show2(dump=True)
        logger.debug("Broadcasting packet\n%s", debugmsg)
        # TODO: Check if we're sending these broadcasts twice?
        scapy.sendrecv.sendp(packet, iface='eth0')


async def run_relay_server(
    local_addr: tuple[ipaddress.ip_address, int], broadcast_port: int
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
        lambda: UDPBroadcastRelayServerProtocol(broadcast_port), local_addr=local_addr
    )

    try:
        while True:
            # Basically sleep forever!
            await asyncio.sleep(3600)
    finally:
        transport.close()


class PVAccessSniffer:
    """Listen for PVAccess UDP broadcasts"""

    def __init__(
        self,
        local_port: int = 5076,
        remote_relays: list[ipaddress.ip_address] = None,
        remote_port=8888,
    ):
        self.local_port = local_port
        self.remote_port = remote_port
        self.remote_relays = remote_relays

        # AsyncSniffer runs in its own thread
        self.sniffer = AsyncSniffer(
            filter=f"udp port {self.local_port}",
            prn=self._send_to_relays,
            lfilter=self._is_broadcast,
            count=0,
            store=False,
            quiet = True,
        )

    def _send_to_relays(self, packet: scapy.packet.Packet):
        """Callback if packet passes sniffer filters"""

        # Check the packet source. If broadcast a packet with this source in the last
        # second then we shouldn't do so again
        pkt_raw = scapy.compat.raw(packet)
        packet_hash = packet[scapy.layers.inet.IP].chksum
        if not packet_hash in recent_packets:
            logger.debug("Received UDP broadcast message:\n%s", packet.show(dump=True))
            logger.debug("scapy packet summary: %s", packet.summary())

            for remote_relay in self.remote_relays:
                logger.debug(
                    "Send to (%s, %i) message: %r",
                    remote_relay, self.remote_port, pkt_raw,
                )
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(pkt_raw, (remote_relay, self.remote_port))
        else:
            logger.debug(
                "Received message with banned hash from address %s; "
                "banned to prevent loops / packet storms",
                packet[scapy.layers.inet.IP].src,
            )

    def _is_broadcast(self, packet: scapy.packet.Packet):
        """Check if this is a broadcast packet"""

        return (
            packet.haslayer(scapy.layers.inet.UDP)
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


async def main():
    ''' Main function
    Start PVAccessSniffer (in its own thread)
    and relay'''
    swarmmode = is_swarmmode()

    local_addr = psutil.net_if_addrs()['eth0'][0].address

    if swarmmode:
        pvasniffer = PVAccessSniffer(remote_relays=discover_relays())
    else:
        pvasniffer = PVAccessSniffer(remote_relays=[local_addr])
    pvasniffer.start()

    await run_relay_server((local_addr, 8888), 5076)

    try:
        while True:
            # Every 10 seconds change if the configuration of the remote relays has changed
            await asyncio.sleep(10)
            logger.info('Checking if relays need updating')
            if swarmmode:
                pvasniffer.set_remote_relays(discover_relays())
    finally:
        pvasniffer.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("Stopped by KeyboardInterrupt")
