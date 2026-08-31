"""Process-wide egress guard.

Everything this tool reads is sensitive, so the promise that content never
leaves the host has to be enforced rather than merely intended. Once
:func:`install` has run, any attempt to open an outbound connection or to
resolve a non-local hostname raises :class:`EgressBlocked`.

Loopback is allowed, so the local dashboard and the test suite can talk to
themselves. Nothing else is. DNS is guarded too: resolving an attacker- or
bug-chosen hostname is itself an exfiltration channel, since the name being
looked up can carry data.

This is the only module in the package permitted to import :mod:`socket`;
:mod:`leakscan.audit` enforces that, which keeps the surface a reviewer has to
read down to this one file.

Limitation, stated plainly: the guard rebinds attributes on the ``socket``
module, so it covers code that calls ``socket.socket(...)`` — which includes
the standard library's own HTTP machinery. Code that captured a reference
before :func:`install` ran, or that reaches the syscall another way, is not
covered. The static audit closes that gap from the other side by refusing to
let such code into the package at all.
"""

from __future__ import annotations

import ipaddress
import socket

__all__ = ["EgressBlocked", "install", "uninstall", "is_installed", "self_test"]


class EgressBlocked(RuntimeError):
    """Raised when code attempts to reach the network."""


_LOCAL_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)

_real_socket = socket.socket
_real_create_connection = socket.create_connection
_real_getaddrinfo = socket.getaddrinfo

_installed = False


def _host_is_local(host: object) -> bool:
    """True if *host* is loopback, unspecified, or a local hostname."""
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("utf-8", "replace")
    if not isinstance(host, str):
        return False

    name = host.strip().strip("[]").lower()
    if name in ("", "*"):
        # An unspecified bind address; binding is inbound, not egress.
        return True
    if name in _LOCAL_HOSTNAMES:
        return True

    # Strip an IPv6 zone index (fe80::1%en0) before parsing.
    candidate = name.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _check(address: object) -> None:
    """Raise :class:`EgressBlocked` unless *address* is local."""
    # AF_UNIX addresses are filesystem paths: local IPC, not egress.
    if isinstance(address, (str, bytes)):
        return
    if isinstance(address, tuple) and address:
        if _host_is_local(address[0]):
            return
        raise EgressBlocked(
            f"outbound connection to {address[0]!r} blocked: transcript content "
            f"must never leave this host"
        )
    raise EgressBlocked(f"outbound connection to {address!r} blocked")


class _GuardedSocket(_real_socket):
    """A socket that refuses to connect anywhere but loopback."""

    __slots__ = ()

    def connect(self, address):  # noqa: D102 - inherits socket's docstring
        _check(address)
        return super().connect(address)

    def connect_ex(self, address):  # noqa: D102
        _check(address)
        return super().connect_ex(address)

    def sendto(self, data, *args):  # noqa: D102
        # Signature is sendto(data, address) or sendto(data, flags, address).
        if args:
            _check(args[-1])
        return super().sendto(data, *args)


def _guarded_create_connection(address, *args, **kwargs):
    _check(address)
    return _real_create_connection(address, *args, **kwargs)


def _guarded_getaddrinfo(host, port, *args, **kwargs):
    if not _host_is_local(host):
        raise EgressBlocked(
            f"DNS resolution of {host!r} blocked: a hostname lookup can itself "
            f"carry data off the host"
        )
    return _real_getaddrinfo(host, port, *args, **kwargs)


def install() -> None:
    """Block outbound networking for this process. Idempotent."""
    global _installed
    if _installed:
        return
    socket.socket = _GuardedSocket  # type: ignore[misc,assignment]
    socket.create_connection = _guarded_create_connection  # type: ignore[assignment]
    socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore[assignment]
    _installed = True


def uninstall() -> None:
    """Restore the real socket API. Exists for the test suite only."""
    global _installed
    socket.socket = _real_socket  # type: ignore[misc,assignment]
    socket.create_connection = _real_create_connection  # type: ignore[assignment]
    socket.getaddrinfo = _real_getaddrinfo  # type: ignore[assignment]
    _installed = False


def is_installed() -> bool:
    """True if the guard is currently active."""
    return _installed


# Documentation-only addresses (RFC 5737 / RFC 2606): probing them can never
# reach a real host even if the guard were broken.
_PROBE_IP = "203.0.113.1"
_PROBE_HOST = "example.invalid"


def self_test() -> list[tuple[str, bool, str]]:
    """Exercise the guard. Returns ``(name, passed, detail)`` per check."""
    results: list[tuple[str, bool, str]] = []

    if not _installed:
        results.append(("guard installed", False, "install() has not been called"))
        return results
    results.append(("guard installed", True, "socket API is patched"))

    # 1. Outbound TCP must be refused by the guard, not merely fail to connect.
    name = "outbound TCP blocked"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(0.2)
            sock.connect((_PROBE_IP, 80))
        finally:
            sock.close()
    except EgressBlocked:
        results.append((name, True, f"connect to {_PROBE_IP}:80 refused"))
    except OSError as exc:
        results.append(
            (name, False, f"connect failed with OSError, not EgressBlocked: {exc}")
        )
    else:
        results.append((name, False, "connect was NOT blocked"))

    # 2. DNS for a non-local name must be refused.
    name = "outbound DNS blocked"
    try:
        socket.getaddrinfo(_PROBE_HOST, 80)
    except EgressBlocked:
        results.append((name, True, f"resolution of {_PROBE_HOST} refused"))
    except OSError as exc:
        results.append(
            (name, False, f"resolution failed on its own, guard did not fire: {exc}")
        )
    else:
        results.append((name, False, "resolution was NOT blocked"))

    # 3. Loopback must still work, or the dashboard cannot run.
    name = "loopback permitted"
    try:
        socket.getaddrinfo("127.0.0.1", 0)
    except EgressBlocked as exc:
        results.append((name, False, f"loopback wrongly blocked: {exc}"))
    except OSError as exc:
        results.append((name, False, f"loopback lookup failed: {exc}"))
    else:
        results.append((name, True, "127.0.0.1 resolves"))

    return results
