""" Tests for the snowsignal file """
import os
import unittest
from unittest.mock import patch
import unittest.mock

from src import snowsignal

class TestSnowSignalAsynch(unittest.IsolatedAsyncioTestCase):
    """ Test the asynch functions in snowsignal.py """

    async def test_main(self):
        """ See if main executes without any problems! """

        await snowsignal.main('--log-level=error', loop_forever=False)


class TestSnowSignalSynch(unittest.TestCase):
    """ Test the non-asynch functions in snowsignal"""

    def test_is_swarmmode(self):
        """ Test swarmmode detection """
        with patch.dict(os.environ):
            os.environ.pop('SERVICENAME', None)
            self.assertFalse(snowsignal.is_swarmmode())

        with patch.dict(os.environ, {"SERVICENAME": "something"}):
            self.assertTrue(snowsignal.is_swarmmode())

    # Setup a list of local IPs and a list of relays. At least one entry should overlap
    @patch('src.snowsignal.get_localhost_ips', return_value = ['127.0.0.1'])
    @patch('src.snowsignal.get_ips_from_name', return_value = ['127.0.0.1', '8.8.8.8'])
    def test_discover_relays(self, *_):
        """ Test relay discovery """

        with patch.dict(os.environ, {"SERVICENAME": "something"}):
            valid_ips = snowsignal.discover_relays()
            self.assertEqual(valid_ips, ['8.8.8.8'])