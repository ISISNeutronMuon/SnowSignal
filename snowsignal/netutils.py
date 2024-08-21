"""Network related utility functions for SnowSignal"""

import ipaddress
import logging
import socket
import sys

import psutil

logger = logging.getLogger(__name__)

# Explanation for repeated use of `pyl1nt: disable=no-member` in
# this file: a "bug" in PyLint means that it incorrectly diagnoses
# socket.AddressFamily as an error, since it believes that socket
# has no attribute AddressFamily. So we suppress this incorrect error


def get_ips_from_name(name: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Given a hostname return its IP addresses as a list"""
    local_ips_details = socket.getaddrinfo(f"{name}", 80)

    ips = []
    for local_ip_detail in local_ips_details:
        addfamily = local_ip_detail[0]
        if addfamily in (socket.AddressFamily.AF_INET6, socket.AddressFamily.AF_INET):  # pylint: disable=no-member
            ip = ipaddress.ip_address(local_ip_detail[4][0])
            ips.append(ip)
        else:
            raise RuntimeError(f"Unknown AddressFamily {addfamily}")

    # Remove duplicates and return
    ips = list(set(ips))

    return ips


def get_localhost_ips() -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Establish the IP address(es) of this container"""
    # Note that in a Docker Swarm environment we expect the container to
    # have at least two IP addresses, it's traditional IP address associated
    # with eth0 but also a Virtual IP (VIP) shared with all of the
    # other containers in the same task. We could also have other IP
    # addresses associated with other networks. So there could be many
    # IP addresses for this one container!

    # This is a bit of a hack but is apparently the most portable way
    local_ips = get_ips_from_name(socket.gethostname())
    logger.debug("\tThis system has IP address(es) %s:", local_ips)

    return local_ips


class ResourceNotFoundException(OSError):
    """Indicate an expected hardware resource could not be found"""


def get_from_iface(
    iface: str,
    family: socket.AddressFamily | int,
    attribute: str = "address",  # pylint: disable=no-member
):
    """Get the IP address associated with a network interface"""
    snicaddrs = psutil.net_if_addrs()[iface]
    for snicaddr in snicaddrs:
        if snicaddr.family == family:
            return getattr(snicaddr, attribute)

    raise ResourceNotFoundException(
        f"Could not identify the {family}, " "{attribute} associated with interface {iface}"
    )


def get_localipv4_from_iface(iface: str) -> str:
    """Get the IPv4 address associated with a network interface"""
    return get_from_iface(iface, socket.AddressFamily.AF_INET)  # pylint: disable=no-member


def get_macaddress_from_iface(iface: str) -> str:
    """Get the MAC address associated with a network interface"""
    if sys.platform != "win32":
        return get_from_iface(iface, socket.AddressFamily.AF_PACKET)  # pylint: disable=no-member
    else:
        return get_from_iface(iface, psutil.AF_LINK)


def get_localhost_macs() -> list[str]:
    """Get all the MAC addresses of local network interfaces"""
    macs = []

    ifaces = psutil.net_if_addrs()
    for iface in ifaces:
        try:
            macs.append(get_macaddress_from_iface(iface))
        except ResourceNotFoundException:
            pass

    return macs


def get_broadcast_from_iface(iface: str) -> str:
    """Get the MAC address associated with a network interface"""
    broadcast_address = get_from_iface(iface, socket.AddressFamily.AF_INET, attribute="broadcast")  # pylint: disable=no-member

    # If we don't get a valid broadcast address then attempt to substitute one
    if not broadcast_address:
        return "255.255.255.255"

    return broadcast_address


def human_readable_mac(macbytes: bytes, separator: str = ":") -> str:
    """Convert MAC in bytes into human-readable string with separators"""
    unseparated_mac_str = macbytes.hex()
    return separator.join([i + j for i, j in zip(unseparated_mac_str[::2], unseparated_mac_str[1::2])])


def machine_readable_mac(macstr: str) -> bytes:
    """Convert MAC with ':' or '-' separators into bytes without seperators"""
    hexstring = macstr.translate({45: "", 58: ""})
    return bytes.fromhex(hexstring)


def identify_pkttype(pkttype: int) -> str:
    """Decode packet type from socket.recvfrom"""
    match pkttype:
        case socket.PACKET_HOST:
            return "PACKET_HOST"
        case socket.PACKET_BROADCAST:
            return "PACKET_BROADCAST"
        case socket.PACKET_MULTICAST:
            return "PACKET_MULTICAST"
        case socket.PACKET_OTHERHOST:
            return "PACKET_OTHERHOST"
        case socket.PACKET_OUTGOING:
            return "PACKET_OUTGOING"
        case _:
            return "UNKNOWN PACKET TYPE"
