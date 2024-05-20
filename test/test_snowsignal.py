""" Tests for the snowsignal file """
import os
import unittest
from unittest.mock import patch
import unittest.mock

from src import snowsignal

class TestSnowSignal(unittest.IsolatedAsyncioTestCase):
    """ Test the functions in snowsignal.py """

    async def test_main(self):
        """ See if main executes without any problems! """

        await snowsignal.main('--log-level=error', loop_forever=False)

    def test_is_swarmmode(self):
        """ Test swarmmode detection """

        self.assertFalse(snowsignal.is_swarmmode())

        with patch.dict(os.environ, {"SERVICENAME": "something"}, clear=True):
            self.assertTrue(snowsignal.is_swarmmode())