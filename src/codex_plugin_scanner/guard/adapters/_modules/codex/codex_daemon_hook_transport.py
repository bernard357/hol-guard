"""Authenticated daemon approval request transport for the Codex hook resume path."""

from __future__ import annotations

import http.client
import json
import re
import time
from collections.abc import Mapping
from pathlib import Path

from .codex_daemon_hook_auth import (
    _assert_loopback_http_url,
    _authenticated_state,
    _daemon_auth_token,
    _daemon_url,
    _DaemonResponseError,
    _http_json_response,
    _remaining_seconds,
)

_MINIMUM_OPERATION_SECONDS = 0.01


def _daemon_json_get(
    *,
    state_path: str | Path,
    path: str,
    timeout_seconds: float,
) -> dict[str, object] | None:
    if not path.startswith("/v1/requests/"):
        raise ValueError("daemon GET path is not an approval request")
    if timeout_seconds < _MINIMUM_OPERATION_SECONDS:
        return None
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    state, _discovery_key = _authenticated_state(state_path)
    host = str(state["host"])
    port_value = state["port"]
    if not isinstance(port_value, int):
        raise ValueError("daemon state port is invalid")
    endpoint = f"{_daemon_url(state_path)}{path}"
    _assert_loopback_http_url(endpoint)
    auth_token = _daemon_auth_token(state_path, state)
    connection = http.client.HTTPConnection(host, port_value, timeout=timeout_seconds)
    try:
        remaining = _remaining_seconds(deadline)
        if remaining < _MINIMUM_OPERATION_SECONDS:
            return None
        connection.timeout = remaining
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        connection.request(
            "GET",
            path,
            headers={
                "Connection": "close",
                "X-Guard-Token": auth_token,
            },
        )
        return _http_json_response(
            connection.getresponse(),
            label="daemon request",
            connection=connection,
            deadline=deadline,
            authenticated=True,
        )
    except _DaemonResponseError as error:
        if error.status == 404:
            return None
        raise
    finally:
        connection.close()


def _daemon_json_post(
    *,
    state_path: str | Path,
    path: str,
    payload: Mapping[str, object],
    timeout_seconds: float,
) -> dict[str, object] | None:
    if not re.fullmatch(r"/v1/requests/[A-Za-z0-9_-]{8,128}/live-decision", path):
        raise ValueError("daemon POST path is not a live approval decision")
    if timeout_seconds < _MINIMUM_OPERATION_SECONDS:
        return None
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    state, _discovery_key = _authenticated_state(state_path)
    host = str(state["host"])
    port_value = state["port"]
    if not isinstance(port_value, int):
        raise ValueError("daemon state port is invalid")
    endpoint = f"{_daemon_url(state_path)}{path}"
    _assert_loopback_http_url(endpoint)
    auth_token = _daemon_auth_token(state_path, state)
    body = json.dumps(dict(payload), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    connection = http.client.HTTPConnection(host, port_value, timeout=timeout_seconds)
    try:
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Connection": "close",
                "Content-Type": "application/json",
                "X-Guard-Token": auth_token,
            },
        )
        return _http_json_response(
            connection.getresponse(),
            label="daemon live approval decision",
            connection=connection,
            deadline=deadline,
            authenticated=True,
        )
    finally:
        connection.close()
