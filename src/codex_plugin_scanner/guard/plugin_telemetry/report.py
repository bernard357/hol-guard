"""Build and send the weekly plugin install report.

Guard downloads the public HOL listing index, and the native
``plugin-telemetry`` command matches the plugins installed under each agent
runtime's home against it on the device. Only listed plugins are reported:
slug, runtime, plugin version and a weekly counting key.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen
from .state import TelemetryState, ensure_secret, read_secret, read_state, write_state

PLUGIN_TELEMETRY_COMMAND = "plugin-telemetry"
PLUGIN_TELEMETRY_FEATURE = "plugin-telemetry-v1"
INDEX_URL = "https://hol.org/api/guard/plugins/install-telemetry/index"
REPORT_URL = "https://hol.org/api/guard/plugins/install-telemetry"
PRIVACY_URL = "https://hol.org/privacy#guard-plugin-install-telemetry"
_TIMEOUT_SECONDS = 20.0
_NATIVE_TIMEOUT_SECONDS = 60.0
_INDEX_LIMIT_BYTES = 8 * 1024 * 1024
_OUTPUT_LIMIT_BYTES = 1024 * 1024
_INDEX_FIELDS = ("slug", "repository", "manifestName", "pluginRoot")


class PluginTelemetryError(RuntimeError):
    """The report could not be built or sent; the message is safe to print."""


def current_week(now: datetime | None = None) -> str:
    year, week, _weekday = (now or datetime.now(timezone.utc)).isocalendar()
    return f"{year}-W{week:02d}"


def runtime_homes(user_home: Path | None = None) -> dict[str, str]:
    """The agent runtime homes that exist on this machine."""

    home = user_home or Path.home()
    candidates = {
        "claude": os.environ.get("CLAUDE_CONFIG_DIR") or str(home / ".claude"),
        "codex": os.environ.get("CODEX_HOME") or str(home / ".codex"),
        "gemini": str(home / ".gemini"),
        "cursor": str(home / ".cursor"),
    }
    return {name: path for name, path in candidates.items() if Path(path).is_dir()}


def _request(url: str, *, body: bytes | None = None) -> urllib.request.Request:
    headers = {"User-Agent": f"hol-guard/{__version__}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")


def fetch_index() -> list[dict[str, object]]:
    try:
        with managed_urlopen(_request(INDEX_URL), timeout=_TIMEOUT_SECONDS) as response:
            raw = response.read(_INDEX_LIMIT_BYTES + 1)
    except (ManagedNetworkError, urllib.error.URLError, OSError) as error:
        raise PluginTelemetryError("The HOL plugin index could not be downloaded.") from error
    if len(raw) > _INDEX_LIMIT_BYTES:
        raise PluginTelemetryError("The HOL plugin index is larger than expected.")
    try:
        payload = json.loads(raw)
    except ValueError as error:
        raise PluginTelemetryError("The HOL plugin index was not valid JSON.") from error
    entries = payload.get("entries") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        raise PluginTelemetryError("The HOL plugin index was not in the expected shape.")
    return [
        {field: entry[field] for field in _INDEX_FIELDS if isinstance(entry.get(field), str)}
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("slug"), str)
    ]


def _native_request(request: Mapping[str, object]) -> dict[str, Any]:
    from ..codex_hook_launch_runtime import run_isolated_hook_process
    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or PLUGIN_TELEMETRY_FEATURE not in status.capabilities.features
    ):
        raise PluginTelemetryError("Plugin install counts need the Guard native runtime. Run: pip install -U hol-guard")
    runtime = status.identity.path
    completed = run_isolated_hook_process(
        (str(runtime), PLUGIN_TELEMETRY_COMMAND, "--stdin"),
        input_text=json.dumps(dict(request), sort_keys=True, separators=(",", ":")),
        cwd=runtime.parent,
        environment=dict(os.environ),
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise PluginTelemetryError("The Guard native runtime could not build the report.")
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise PluginTelemetryError("The Guard native runtime could not build the report.") from error
    if not isinstance(response, dict) or response.get("ok") is not True or not isinstance(response.get("result"), dict):
        code = response.get("error") if isinstance(response, dict) else None
        raise PluginTelemetryError(f"The Guard native runtime refused the report ({code or 'no result'}).")
    return response["result"]


def build_report(secret: str, *, week: str, index: list[dict[str, object]] | None = None) -> dict[str, Any]:
    """``{"installed": n, "report": {...}}`` for this machine and week."""

    return _native_request(
        {
            "command": "report",
            "homes": runtime_homes(),
            "index": fetch_index() if index is None else index,
            "secret": secret,
            "week": week,
            "guardVersion": __version__,
        }
    )


def post_report(report: Mapping[str, object]) -> int:
    body = json.dumps(dict(report), sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        with managed_urlopen(_request(REPORT_URL, body=body), timeout=_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read(64 * 1024) or b"{}")
    except urllib.error.HTTPError as error:
        raise PluginTelemetryError(f"HOL did not accept the report (HTTP {error.code}).") from error
    except (ManagedNetworkError, urllib.error.URLError, OSError, ValueError) as error:
        raise PluginTelemetryError("The report could not be sent.") from error
    accepted = payload.get("accepted") if isinstance(payload, dict) else None
    return accepted if isinstance(accepted, int) else 0


def dry_run(guard_home: Path) -> dict[str, Any]:
    """The report Guard would send this week, built without sending it.

    Before opt-in there is no device secret, so the keys use a throwaway one.
    """

    secret = read_secret(guard_home) or os.urandom(32).hex()
    return build_report(secret, week=current_week())


def send_now(guard_home: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Send this week's report. Requires opt-in; records the week on success."""

    state = read_state(guard_home)
    if not state.enabled:
        raise PluginTelemetryError("Plugin install counts are off. Run: hol-guard telemetry plugins on")
    week = current_week(now)
    built = build_report(ensure_secret(guard_home), week=week)
    report = built["report"]
    entries = report.get("entries") if isinstance(report, dict) else None
    accepted = post_report(report) if entries else 0
    write_state(guard_home, TelemetryState(enabled=True, last_week=week))
    return {"week": week, "installed": built.get("installed", 0), "listed": len(entries or []), "accepted": accepted}


def send_if_due(guard_home: Path, *, now: datetime | None = None) -> dict[str, Any] | None:
    """Send at most one report per ISO week, and only after opt-in."""

    state = read_state(guard_home)
    if not state.enabled or state.last_week == current_week(now):
        return None
    return send_now(guard_home, now=now)
