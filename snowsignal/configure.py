""" Configuration for SnowSignal
uses configargparse https://pypi.org/project/ConfigArgParse/
"""

import logging
from typing import NamedTuple, Sequence

import configargparse

logger = logging.getLogger(__name__)


class ConfigArgs(NamedTuple):
    """This bit of weirdness allows us to use strong type hinting with Argparse
    or equivalent tools. See https://dev.to/xowap/the-ultimate-python-main-18kn"""

    target_interface: str
    broadcast_port: int
    mesh_port: int
    other_relays: list[str]
    log_level: str


def configure(argv: Sequence[str] | None = None) -> ConfigArgs:
    """Setup configuration for the SnowSignal service"""

    p = configargparse.ArgParser()
    # Remember to add new arguments to the Args class above!
    p.add_argument(
        "-t",
        "--target-interface",
        env_var="TARGET_INTERFACE",
        default="eth0",
        type=str,
        help="Target network interface",
    )
    p.add_argument(
        "-b",
        "--broadcast-port",
        env_var="BDCAST_PORT",
        default=5076,
        type=int,
        help="Port on which to receive and transmit UDP broadcasts",
    )
    p.add_argument(
        "-m",
        "--mesh-port",
        env_var="MESH_PORT",
        default=7124,
        type=int,
        help="Port on which this instance will communicate with others via UDP unicast",
    )
    p.add_argument(
        "--other-relays",
        nargs="+",
        type=str,
        default=[],
        help="Manually select other relays to transmit received UDP broadcasts to",
    )
    p.add_argument(
        "-ll",
        "--log-level",
        env_var="LOGLEVEL",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="Logging level",
    )
    # Remember to add new arguments to the Args class above!

    # config = p.parse_args(argv)
    config = ConfigArgs(**p.parse_args(argv).__dict__)

    if config.log_level == "critical":
        loglevel = logging.CRITICAL
    elif config.log_level == "error":
        loglevel = logging.ERROR
    elif config.log_level == "warning":
        loglevel = logging.WARNING
    elif config.log_level == "info":
        loglevel = logging.INFO
    elif config.log_level == "debug":
        loglevel = logging.DEBUG

    if loglevel < logging.INFO:
        logging.basicConfig(
            format="%(asctime)s - %(levelname)s - " "%(name)s.%(funcName)s: %(message)s",
            encoding="utf-8",
            level=loglevel,
        )
    else:
        logging.basicConfig(format="%(asctime)s - %(levelname)s: %(message)s", encoding="utf-8", level=loglevel)

    if config.broadcast_port == config.mesh_port:
        # Can't use the same port for two different purposes
        # Later, if we allow the receive relay and transmit relay on different
        # ports we may need to revisit this error
        logger.error(
            "Broadcast port (%i) and mesh port (%i) may not be the same", config.broadcast_port, config.mesh_port
        )
        raise ValueError(
            f"Broadcast port ({config.broadcast_port}) and " f"mesh port ({config.mesh_port}) may not be the same"
        )

    return config
