""" Experimental UDP Broadcast Relay for PVAccess """

import asyncio
import ipaddress
import logging
import os

import configargparse
from netutils import get_localhost_ips, get_ips_from_name, get_localipv4_from_iface
from udp_relay_receive import run_relay_receiver
from udp_relay_transmit import UDPRelayTransmit

# Logging and configuration of Scapy
logger = logging.getLogger()

def is_swarmmode() -> bool:
    ''' Crude check to see if we're running in docker swarm'''

    swarmmode = False
    try:
        if os.environ['SERVICENAME']:
            swarmmode = True
    except KeyError:
        pass # Docker Swarm related environment variable not set
    return swarmmode


# Discover the other UDP Broadcast relays in the stack
def discover_relays() -> list[ipaddress.ip_address]:
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


def configure():
    """ Setup configuration for the SnowSignal service """

    p = configargparse.ArgParser()
    p.add('-t', '--target-interface', default='eth0', type=str,
          help='Target network interface')
    p.add('-b', '--broadcast-port', default=5076, type=int,
          help='Port on which to receive and transmit UDP broadcasts')
    p.add('-m', '--mesh-port', default=7124, type=int,
          help='Port on which this instance will communicate with others via UDP unicast')
    p.add('--rebroadcast-mode', choices=['packet', 'payload'], default='packet',
          help='Transfer the whole packet or just the payload on the mesh network')
    p.add('--other-relays', nargs='+', type=str, default=[],
          help='Manually select other relays to transmit received UDP broadcasts to')
    p.add('-l', '--log-level', choices=['debug', 'info', 'warning', 'error', 'critical'],
          default='info',
          help='Logging level')

    config = p.parse_args()

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
        logging.basicConfig(format = '%(asctime)s - %(name)s - %(levelname)s: %(message)s',
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
        raise ValueError(f'Broadcast port ({config.broadcast_port}) and mesh port ({config.mesh_port}) may not be the same')

    return config

async def main():
    ''' Main function
    Start PVAccessSniffer (in its own thread)
    and relay'''

    # Configure 
    config = configure()
    logger.info('Starting with configuration %s', config)

    local_addr = get_localipv4_from_iface(config.target_interface)

    # Check if we're running in a Docker Swarm
    swarmmode = is_swarmmode()
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

    pvasniffer = UDPRelayTransmit(local_port=config.broadcast_port,
                                  remote_relays=remote_relays,
                                  remote_port=config.mesh_port,
                                  config=config
                                 )
    pvasniffer.start()

    asyncio.create_task( run_relay_receiver( (local_addr, config.mesh_port),
                                             config.broadcast_port,
                                             config=config
                                           )
                        )

    while True:
        await asyncio.sleep(10)
        if swarmmode:
            # Check to see if remote relays have changed 
            # e.g. containers have restarted
            pvasniffer.set_remote_relays(discover_relays())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("Stopped by KeyboardInterrupt")
