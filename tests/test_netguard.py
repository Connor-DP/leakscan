"""Tests for the runtime egress guard.

These deliberately go through :mod:`leakscan.netguard` rather than importing
``socket`` directly — the source audit forbids ``socket`` outside that module,
and the tests should hold themselves to the rule they enforce.
"""

from __future__ import annotations

import unittest

from leakscan import netguard


class GuardLifecycleTests(unittest.TestCase):
    def tearDown(self) -> None:
        netguard.uninstall()

    def test_install_is_idempotent(self) -> None:
        netguard.install()
        first = netguard.socket.socket
        netguard.install()
        self.assertIs(first, netguard.socket.socket)
        self.assertTrue(netguard.is_installed())

    def test_uninstall_restores_the_real_api(self) -> None:
        netguard.install()
        self.assertIsNot(netguard.socket.socket, netguard._real_socket)
        netguard.uninstall()
        self.assertIs(netguard.socket.socket, netguard._real_socket)
        self.assertIs(netguard.socket.getaddrinfo, netguard._real_getaddrinfo)
        self.assertFalse(netguard.is_installed())


class SelfTestTests(unittest.TestCase):
    def tearDown(self) -> None:
        netguard.uninstall()

    def test_all_checks_pass_when_installed(self) -> None:
        netguard.install()
        results = netguard.self_test()
        failed = [(name, detail) for name, passed, detail in results if not passed]
        self.assertEqual(failed, [], f"guard self-test failed: {failed}")

    def test_reports_failure_when_not_installed(self) -> None:
        netguard.uninstall()
        results = netguard.self_test()
        self.assertFalse(results[0][1])


class HostClassificationTests(unittest.TestCase):
    def test_local_hosts(self) -> None:
        for host in [
            None,
            "",
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.5.5.5",
            "::1",
            "[::1]",
        ]:
            with self.subTest(host=host):
                self.assertTrue(netguard._host_is_local(host))

    def test_remote_hosts(self) -> None:
        for host in [
            "example.com",
            "8.8.8.8",
            "203.0.113.1",
            "2606:4700:4700::1111",
            "169.254.169.254",  # cloud metadata endpoint
        ]:
            with self.subTest(host=host):
                self.assertFalse(netguard._host_is_local(host))


class AddressCheckTests(unittest.TestCase):
    def test_unix_socket_paths_are_allowed(self) -> None:
        netguard._check("/var/run/some.sock")
        netguard._check(b"/var/run/some.sock")

    def test_loopback_tuple_allowed(self) -> None:
        netguard._check(("127.0.0.1", 8787))
        netguard._check(("::1", 8787, 0, 0))

    def test_remote_tuple_blocked(self) -> None:
        with self.assertRaises(netguard.EgressBlocked):
            netguard._check(("example.com", 443))

    def test_metadata_endpoint_blocked(self) -> None:
        with self.assertRaises(netguard.EgressBlocked):
            netguard._check(("169.254.169.254", 80))


if __name__ == "__main__":
    unittest.main()
