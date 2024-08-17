import unittest
import ipaddress
import sys

import psutil

from src import netutils

class TestNetUtilsFunctions(unittest.TestCase):

    def test_get_ips_from_name(self):
        # Check that the function returns one or more IP addresses
        ips = netutils.get_ips_from_name('example.com')

        self.assertIsInstance(ips, list)
        self.assertTrue(len(ips))
        self.assertTrue(ipaddress.IPv4Address('93.184.215.14') in ips)
        for ip in ips:
            self.assertIsInstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))

    def test_get_localhost_ips(self):
        ips = netutils.get_localhost_ips()

        self.assertIsInstance(ips, list)
        self.assertTrue(len(ips), "Expected one or more local IP addresses")
        for ip in ips:
            self.assertIsInstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))

    def test_get_local_macs(self):
        macs = netutils.get_localhost_macs()

        self.assertIsInstance(macs, list)
        self.assertTrue(len(macs), "Expected one or more network interface MAC addresses")
        for mac in macs:
            self.assertRegex(mac, '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', 
                             "Expected string to match simple MAC address regex")

    def test_get_broadcast_from_iface(self):
        # Loop through the interfaces till we find one with a broadcast address
        ifaces = psutil.net_if_addrs().keys()
        for iface in ifaces:
            broadcast_address = netutils.get_broadcast_from_iface(iface)

            if broadcast_address:
                break

        # There isn't a AssertNotRaises but any exception will fail the test anyway
        # I'm not sure how to really test on Windows since the broadcast always returns None??!
        # best to fail the test as a reminder to implement in future?
        ipaddress.ip_address(broadcast_address)

    def test_human_readable_mac(self):
        test_args = (
            {'input' : bytes.fromhex('0a1b2c3d4e5f'), 'output' : '0a:1b:2c:3d:4e:5f', 'separator' : ':' },
            {'input' : bytes.fromhex('0a1b2c3d4e5f'), 'output' : '0a-1b-2c-3d-4e-5f', 'separator' : '-' },
        )
        # We don't test to see if malformed MACs are caught, i.e.
        #              '0a1b'           # Too short
        #              '0a1b2c3d4e5f6a' # Too long
        #              'rtojojaiojdi'   # Invalid characters

        # Test default argument behaviour
        self.assertEqual( netutils.human_readable_mac(test_args[0]['input']), test_args[0]['output'] )

        for test_arg in test_args:
            with self.subTest():
                mac = netutils.human_readable_mac(
                    test_arg['input'],
                    test_arg['separator']
                )
                self.assertEqual(
                    mac,
                    test_arg['output']
                )

    def test_machine_readable_mac(self):
        test_args = (
            {'input' : '0a:1b:2c:3d:4e:5f', 'output' : bytes.fromhex('0a1b2c3d4e5f')},
            {'input' : '0a-1b-2c-3d-4e-5f', 'output' : bytes.fromhex('0a1b2c3d4e5f')},
        ) 


        for test_arg in test_args:
            with self.subTest():
                mac = netutils.machine_readable_mac(
                        test_arg['input']
                )
                self.assertEqual(
                    mac,
                    test_arg['output']
                )

if __name__ == '__main__':
    unittest.main()
