""" Tests for the snowsignal file """

import unittest
from unittest.mock import  patch
import unittest.mock

from src import snowsignal

class TestSnowSignal(unittest.IsolatedAsyncioTestCase):

    @patch('asyncio.sleep')
    async def test_main(self, mock_asyncio_sleep, ):
        """ See if main executes without any problems! """

        await snowsignal.main('--log-level=error', loop_forever=False)
