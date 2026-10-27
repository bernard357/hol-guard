"""Installed-wheel hook client used by native runtime probes."""

from __future__ import annotations

import importlib.util
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer

# Probes run this file with ``python -I`` against an installed wheel, so the
# repository root is not importable; load the shared hook client by path.
_DAEMON_HOOK_CLIENT_SPEC = importlib.util.spec_from_file_location(
    "hol_guard_daemon_hook_client",
    Path(__file__).resolve().parents[2] / "scripts" / "daemon_hook_client.py",
)
if _DAEMON_HOOK_CLIENT_SPEC is None or _DAEMON_HOOK_CLIENT_SPEC.loader is None:
    raise RuntimeError("installed hook client could not load the daemon hook client")
_DAEMON_HOOK_CLIENT = importlib.util.module_from_spec(_DAEMON_HOOK_CLIENT_SPEC)
_DAEMON_HOOK_CLIENT_SPEC.loader.exec_module(_DAEMON_HOOK_CLIENT)
authenticated_claude_hook_response = _DAEMON_HOOK_CLIENT.authenticated_claude_hook_response
_daemon_response_once = _DAEMON_HOOK_CLIENT._daemon_response_once

_SAFE_REASON_CODE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_DECISIONS = frozenset({"allow", "deny", "ask", "block", "review", "continue"})


def hook_failure_detail(harness: str, event: str, response: Mapping[str, object]) -> dict[str, object]:
    """Report a bounded category without response text or request payloads."""
    specific = response.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, Mapping) else None
    decision = response.get("decision")
    reason = response.get("reason_code")
    return {
        "harness": harness,
        "event": event,
        "decision": decision if isinstance(decision, str) and decision in _DECISIONS else None,
        "permission_decision": permission if isinstance(permission, str) and permission in _DECISIONS else None,
        "reason_code": reason if isinstance(reason, str) and _SAFE_REASON_CODE.fullmatch(reason) else None,
    }


def installed_hook_request(
    daemon: GuardDaemonServer,
    guard_home: Path,
    workspace: Path,
    harness: str,
    event: str,
    payload: dict[str, object],
) -> dict[str, object] | None:
    """Send a probe request through the harness's production authentication path."""

    query = urllib.parse.urlencode({"home": str(guard_home), "workspace": str(workspace)})
    encoded = json.dumps(payload, separators=(",", ":"))
    if harness == "codex":
        return _daemon_response_once(
            state_path=guard_home / "daemon-state.json",
            query=query,
            data=encoded,
            timeout_seconds=5,
        )
    if harness == "claude-code":
        decoded = json.loads(
            authenticated_claude_hook_response(
                state_path=guard_home / "daemon-state.json",
                query=query,
                data=encoded,
                timeout_seconds=10,
            )
        )
        return decoded if isinstance(decoded, dict) else None
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/hooks/{harness}?{query}",
        data=encoded.encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            decoded = json.loads(response.read().decode("utf-8"))
            return decoded if isinstance(decoded, dict) else None
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:512]
        raise RuntimeError(
            f"installed hook corpus request failed: harness={harness} event={event} status={error.code} body={detail}"
        ) from error
    except urllib.error.URLError as error:
        if isinstance(error.reason, TimeoutError):
            raise TimeoutError("installed hook transport timed out") from error
        raise
