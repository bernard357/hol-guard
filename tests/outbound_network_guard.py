"""Refuse and record outbound network use from Python while a block runs.

Loopback and Unix sockets stay open: the daemon and the native resident talk
over them. Anything else is refused before it leaves the host and recorded, so
a test can assert the block never tried. Subprocesses, the native runtime
among them, are outside this guard.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
from collections.abc import Iterator

import pytest

_INET = (socket.AF_INET, socket.AF_INET6)


def _local(host: object) -> bool:
    if host is None:
        return True
    name = host.decode("ascii", "replace") if isinstance(host, bytes) else str(host)
    if name in {"", "localhost"}:
        return True
    try:
        return ipaddress.ip_address(name.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


@contextlib.contextmanager
def outbound_network_attempts() -> Iterator[list[str]]:
    attempts: list[str] = []
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def refuse(what: str) -> None:
        attempts.append(what)
        raise ConnectionRefusedError(f"outbound network refused in test: {what}")

    def connect(self: socket.socket, address: object) -> None:
        if self.family in _INET and isinstance(address, tuple) and not _local(address[0]):
            refuse(f"connect {address[0]}:{address[1]}")
        real_connect(self, address)

    def connect_ex(self: socket.socket, address: object) -> int:
        if self.family in _INET and isinstance(address, tuple) and not _local(address[0]):
            refuse(f"connect {address[0]}:{address[1]}")
        return real_connect_ex(self, address)

    def getaddrinfo(host: object, *args: object, **kwargs: object) -> object:
        if not _local(host):
            refuse(f"resolve {host}")
        return real_getaddrinfo(host, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket.socket, "connect", connect)
        patch.setattr(socket.socket, "connect_ex", connect_ex)
        patch.setattr(socket, "getaddrinfo", getaddrinfo)
        yield attempts
