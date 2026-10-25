"""Facts the generic hook transport hands the resident decision op.

The resident owns every decision (see ``native_hook_decision``). This module
only gathers inputs: payload fields as given, and the classifier verdicts the
resident asks for by name. A classifier runs only when the resident needs its
verdict, and its boolean is a fact, not a decision.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Mapping
from pathlib import Path

_EVENT_KEYS = ("event", "hook_event_name", "hookEventName", "hook_name")
# The resident refuses a tool input above 64 KiB, and the hook-decision envelope
# is capped at 256 KiB; an oversized request is omitted rather than sent.
_MAX_TOOL_INPUT_BYTES = 64 * 1024
_MAX_NATIVE_REQUEST_BYTES = 128 * 1024


def _native_request(
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """The raw tool call and host facts the resident classifies itself.

    Nothing here is a verdict. When the host cannot be observed the request is
    omitted and the resident treats every dependent verdict as not benign.
    """

    from .. import native_git_execution_safety as git_safety
    from ..native_codex_tool_output import _environment_snapshot

    try:
        host: dict[str, object] = {
            "process_cwd": os.getcwd(),
            "home": str(Path.home()),
            "account_home": git_safety._account_home_directory(),
            "groups": git_safety._process_groups(),
            "environment": _environment_snapshot(),
            "git_executable": shutil.which("git"),
        }
    except (OSError, RuntimeError):
        return None
    tool_input = payload.get("tool_input", payload.get("arguments"))
    if _encoded_size(tool_input) > _MAX_TOOL_INPUT_BYTES:
        return None
    request: dict[str, object] = {
        "tool_name": payload.get("tool_name"),
        "tool_input": tool_input,
        "cwd": None if runtime_workspace is None else str(runtime_workspace),
        "home_dir": None if home_dir is None else str(home_dir),
        "host": host,
    }
    control_snapshot = _control_snapshot()
    if control_snapshot is not None:
        request["control_snapshot"] = control_snapshot
    return request if _encoded_size(request) <= _MAX_NATIVE_REQUEST_BYTES else None


def _encoded_size(value: object) -> int:
    try:
        return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return _MAX_NATIVE_REQUEST_BYTES + 1


def _control_snapshot() -> dict[str, object] | None:
    """The active extension-control layers and health, as observed (not a verdict)."""

    from ..runtime.extension_control_runtime import _layer_payload, current_extension_control_snapshot

    snapshot = current_extension_control_snapshot()
    if snapshot is None:
        return None
    return {
        "health": snapshot.health.value,
        "layers": sorted((_layer_payload(layer) for layer in snapshot.layers), key=lambda layer: str(layer["kind"])),
    }


__all__ = []
