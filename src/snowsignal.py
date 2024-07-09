""" Experimental UDP Broadcast Relay for PVAccess """

import asyncio
import ipaddress
import logging
import os
import sys
from typing import NamedTuple, Optional, Sequence

import configargparse
from .netutils import get_localhost_ips, get_ips_from_name, get_localipv4_from_iface
from .udp_relay_receive import UDPRelayReceive
from .udp_relay_transmit import UDPRelayTransmit

# Logging and configuration of Scapy
logger = logging.getLogger()

def is_swarmmode() -> bool:
    """ Crude check to see if we're running in docker swarm """

    swarmmode = False
    try:
        if os.environ['SERVICENAME']:
            swarmmode = True
    except KeyError:
        pass # Docker Swarm related environment variable not set
    return swarmmode


def setup_remote_relays(config,
                        local_addr : str | ipaddress.IPv4Address | ipaddress.IPv6Address,
                        swarmmode
                        ) -> list[str | ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """ Initial setup of the remote relays. If we're not in a Docker Swarm then
    this is largely immutable."""

    if swarmmode and not config.other_relays:
        # Use swarm DNS magic to identify the other nodes
        logger.debug('Using swarm DNS to identify other relays')
        remote_relays = discover_relays()
    elif not swarmmode and config.other_relays:
        logger.debug('Using user configuration of other relays')
        remote_relays = config.other_relays
    else:
        # Assume we're in testing mode and loopback to ourselves
        logger.debug('Using debug mode for other relays, will relay to self')
        remote_relays = [local_addr]
    return remote_relays


def discover_relays() -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Discover the other UDP Broadcast Relays in the stack"""

    logger.debug("Beginning relay discovery")
    # Establish the IP address(es) of this container
    # This is a bit of a hack but is apparently the most portable way
    local_ips = get_localhost_ips()

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


class Args(NamedTuple):
    """ This bit of weirdness allows us to use strong type hinting with Argparse
    or equivalent tools. See https://dev.to/xowap/the-ultimate-python-main-18kn """
    target_interface : str
    broadcast_port : int
    mesh_port : int
    other_relays : list[str]
    log_level : str

def configure(argv: Optional[Sequence[str]] = None):
    """ Setup configuration for the SnowSignal service """

    p = configargparse.ArgParser()
    p.add_argument('-t', '--target-interface', env_var='TARGET_INTERFACE',
                    default='eth0', type=str,
                    help='Target network interface')
    p.add_argument('-b', '--broadcast-port', env_var='BDCAST_PORT',
                    default=5076, type=int,
                    help='Port on which to receive and transmit UDP broadcasts')
    p.add_argument('-m', '--mesh-port', env_var='MESH_PORT',
                    default=7124, type=int,
                    help='Port on which this instance will communicate with others via UDP unicast')
    p.add_argument('--other-relays', nargs='+', type=str, default=[],
                    help='Manually select other relays to transmit received UDP broadcasts to')
    p.add_argument('-l', '--log-level', env_var='LOGLEVEL',
                    choices=['debug', 'info', 'warning', 'error', 'critical'],
                    default='info',
                    help='Logging level')
    # Remember to add new arguments to the Args class above!

    # config = p.parse_args(argv)
    config = Args(**p.parse_args(argv).__dict__)

    match config.log_level:
        case 'critical':
            loglevel = logging.CRITICAL
        case 'error':
            loglevel = logging.ERROR
        case 'warning':
            loglevel = logging.WARNING
        case 'info':
            loglevel = logging.INFO
        case 'debug':
            loglevel = logging.DEBUG

    if loglevel < logging.INFO:
        logging.basicConfig(format = '%(asctime)s - %(levelname)s - %(name)s.%(funcName)s: %(message)s',
                            encoding="utf-8", level=loglevel)
    else:
        logging.basicConfig(format = '%(asctime)s - %(levelname)s: %(message)s',
                            encoding="utf-8", level=loglevel)

    if config.broadcast_port == config.mesh_port:
        # Can't use the same port for two different purposes
        # Later, if we allow the receive relay and transmit relay on different
        # ports we may need to revisit this error
        logger.error('Broadcast port (%i) and mesh port (%i) may not be the same',
                     config.broadcast_port, config.mesh_port)
        raise ValueError(f'Broadcast port ({config.broadcast_port}) and '
                         f'mesh port ({config.mesh_port}) may not be the same')

    return config

# Weird "arg_list" syntax required to support unittests
async def main(argv: Optional[Sequence[str]] = None, loop_forever : bool = True):
    """ Main function
    Load up the configuration and do some other setup. But mostly we're here
    to start two asyncio tasks. One listens for UDP broadcasts and sends them
    on to other relays. The other listens to the other relays and rebroadcasts
    as they instruct. Then we sit in an infinite loop to allow these things to
    happen!
    """

    # Configure this relay
    config = configure(argv)
    logger.info('Starting with configuration %s', config)

    # Get the local IP address
    # TODO: Properly support IPv6
    local_addr = get_localipv4_from_iface(config.target_interface)

    # Check if we're running in a Docker Swarm
    swarmmode = is_swarmmode()

    # Identify the remote relays to send UDP broadcasts messages to
    remote_relays = setup_remote_relays(config, local_addr, swarmmode)

    # Start listening for UDP broadcasts to transmit to the other relays
    udp_relay_transmit = UDPRelayTransmit(remote_relays=remote_relays,
                                          local_port=config.broadcast_port,
                                          remote_port=config.mesh_port,
                                          config=config
                                         )
    asyncio.create_task( udp_relay_transmit.start() )

    # Listen for messages from the other relays to UDP broadcast
    udp_relay_receive = UDPRelayReceive(local_addr=(local_addr, config.mesh_port),
                                        broadcast_port=config.broadcast_port,
                                        config=config)
    asyncio.create_task( udp_relay_receive.start() )

    # Loop forever, but if in swarm mode periodically recheck the relays
    while loop_forever:
        await asyncio.sleep(10)
        if swarmmode:
            # Check to see if remote relays have changed
            # e.g. containers have restarted
            udp_relay_transmit.set_remote_relays(discover_relays())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("Stopped by KeyboardInterrupt")
        sys.exit(1)
