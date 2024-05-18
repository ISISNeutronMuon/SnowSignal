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


if __name__ == '__main__':
    unittest.main()
