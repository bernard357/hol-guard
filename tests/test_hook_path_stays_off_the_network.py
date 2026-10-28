"""The hook path carries no network client, model SDK or background assessment code.

Hooks answer from local state. Loading the daemon hook worker must not pull in
an HTTP client or model SDK, and must not load the background workspace
assessment worker, whose scheduling happens in the daemon, never in a hook.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys

import pytest

from tests.outbound_network_guard import outbound_network_attempts

_FORBIDDEN = (
    "aiohttp",
    "anthropic",
    "http.client",
    "httpx",
    "openai",
    "requests",
    "urllib.request",
    "urllib3",
    "codex_plugin_scanner.guard.runtime.runner",
    "codex_plugin_scanner.guard.workspace_assessment_admissions",
    "codex_plugin_scanner.guard.workspace_assessment_runner",
    "codex_plugin_scanner.guard.workspace_assessment_worker",
)

_PROBE = """
import json, sys
import codex_plugin_scanner.guard.daemon.hook_worker
print(json.dumps(sorted(sys.modules)))
"""


def _forbidden(module: str) -> bool:
    return any(module == name or module.startswith(f"{name}.") for name in _FORBIDDEN)


def test_loading_the_hook_worker_loads_no_network_client_or_assessment_worker() -> None:
    # A fresh interpreter, so modules other tests imported do not count.
    completed = subprocess.run([sys.executable, "-c", _PROBE], capture_output=True, text=True, check=True, timeout=120)
    loaded = set(json.loads(completed.stdout))
    assert "codex_plugin_scanner.guard.daemon.hook_worker" in loaded
    reached = sorted(name for name in loaded if _forbidden(name))
    assert not reached, f"the hook path loads network or background assessment code: {reached}"


def test_the_outbound_guard_refuses_remote_hosts_and_allows_loopback() -> None:
    with outbound_network_attempts() as attempts:
        with pytest.raises(ConnectionRefusedError):
            socket.getaddrinfo("example.com", 443)
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(ConnectionRefusedError):
                remote.connect(("93.184.216.34", 443))
        finally:
            remote.close()
        socket.getaddrinfo("127.0.0.1", 0)
    assert attempts == ["resolve example.com", "connect 93.184.216.34:443"]
