import asyncio
from asyncio.log import logger
import sys

from .snowsignal import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("Stopped by KeyboardInterrupt")
        sys.exit(1)
