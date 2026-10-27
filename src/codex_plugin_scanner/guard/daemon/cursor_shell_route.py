"""Cursor's contained route: the silent ``preToolUse`` probe and its sink.

Cursor sends a shell call to two hooks. Its ``preToolUse`` hook for ``Shell``
may rewrite the call through ``updated_input``; ``beforeShellExecution``,
which runs next with the rewritten command, cannot rewrite anything. Guard
therefore treats ``preToolUse`` as a probe: it asks the native authority
whether the call would run in the contained sink and, when it would, answers
with the sink command. Every other probe answer is a plain allow, and the
probe records nothing, so ``beforeShellExecution`` stays the one check the
user sees.

``beforeShellExecution`` then admits the sink command the probe wrote: the
exact argv this daemon quotes, for this daemon's Guard home, a workspace that
matches the hook's, and a private snapshot the sink will read. The sink
re-authorizes the saved call before it runs anything, so admitting the
command never widens what runs.
"""

from __future__ import annotations

import logging
import shlex
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .hook_worker import HookWorker

_LOGGER = logging.getLogger(__name__)

_CURSOR = "cursor"
_PRE_TOOL_USE = "PreToolUse"
_SHELL_TOOL = "Shell"
_SOURCE_HOOK_FIELD = "cursor_source_hook_event"
_PROBE_FIELD = "cursor_route_probe"
_BEFORE_SHELL = "beforeShellExecution"
_RECEIPT_ONLY_FIELD = "guard_containment_receipt_only"
_ROUTED_REASON = "native_contained_execution_routed"
_SINK_ARGS = ("guard", "execute-contained-test")
_ALLOW: dict[str, object] = {"policy_action": "allow"}
# The sink rewrite reads a Claude-shaped receipt (policy fields beside
# ``hookSpecificOutput``). Cursor's own rendering has neither, so the probe
# renders the verdict in Z Code's shape; the hook copies only the rewritten
# input back to Cursor.
_RECEIPT_FORMAT = "zcode"


def cursor_shell_route_response(
    worker: HookWorker,
    *,
    payload: Mapping[str, object],
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None,
) -> dict[str, object] | None:
    """The daemon's answer to a Cursor probe or sink call, or ``None`` to review it as usual."""

    if sys.platform == "win32" or payload.get(_RECEIPT_ONLY_FIELD) is not None:
        return None
    if is_cursor_shell_probe(payload):
        try:
            return _probe_response(
                worker,
                payload=payload,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                deadline=deadline,
            )
        except Exception:
            # beforeShellExecution still reviews the call that runs.
            _LOGGER.warning("Cursor shell route probe failed", exc_info=True)
            return dict(_ALLOW)
    if payload.get(_SOURCE_HOOK_FIELD) == _BEFORE_SHELL and _admitted_sink(
        payload, home_dir=home_dir, guard_home=guard_home, workspace=workspace
    ):
        return {"policy_action": "allow", "reason_code": _ROUTED_REASON}
    return None


def is_cursor_shell_probe(payload: Mapping[str, object]) -> bool:
    """Cursor's own ``preToolUse`` for ``Shell``, which names no source hook.

    Guard's Cursor hook names its probe with ``cursor_route_probe``. Any other
    caller that sends a ``Shell`` call for Cursor gets the ordinary review.
    """

    return (
        payload.get("hook_event_name") == _PRE_TOOL_USE
        and payload.get("tool_name") == _SHELL_TOOL
        and _SOURCE_HOOK_FIELD not in payload
        and payload.get(_PROBE_FIELD) is True
    )


def _command(payload: Mapping[str, object]) -> tuple[dict[str, object], str] | None:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    return (tool_input, command) if isinstance(command, str) else None


def _same_directory(value: object, workspace: Path) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return Path(value).expanduser().resolve(strict=True) == workspace.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False


def _probe_response(
    worker: HookWorker,
    *,
    payload: Mapping[str, object],
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None,
) -> dict[str, object]:
    from ..adapters.zcode_contained_tests import route_zcode_containment
    from ..native_hook_containment_route import edge_containment_route, native_containment_sink
    from ..native_policy_snapshot_harness_postures import recording_only_for_binding
    from .hook_fail_closed import render_pre_tool

    call = _command(payload)
    if workspace is None or call is None:
        return dict(_ALLOW)
    # The sink runs in the workspace, so only a call that runs there moves.
    # Cursor names the directory at the top level and may repeat it in the call.
    directories = (payload.get("cwd"), call[0].get("cwd"), call[0].get("working_directory"))
    if any(value not in (None, "") and not _same_directory(value, workspace) for value in directories):
        return dict(_ALLOW)
    snapshot = worker._native_policy_snapshot(workspace, deadline=deadline)
    if snapshot is None or recording_only_for_binding(snapshot, _CURSOR):
        return dict(_ALLOW)
    edge = worker._review_raw_hook_native(
        payload=dict(payload),
        harness=_CURSOR,
        event=_PRE_TOOL_USE,
        guard_home=guard_home,
        home_dir=home_dir,
        cwd=workspace,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=deadline,
        policy_snapshot=snapshot,
    )
    if edge is None or edge.get("harness") != _CURSOR or edge.get("event_name") != _PRE_TOOL_USE:
        return dict(_ALLOW)
    result = edge.get("result")
    if not isinstance(result, Mapping):
        return dict(_ALLOW)
    route = edge_containment_route(
        edge, result, event_name=_PRE_TOOL_USE, recording_only=False, guard_home=guard_home, deadline=deadline
    )
    if route != "sink":
        return dict(_ALLOW)
    receipt = render_pre_tool(_RECEIPT_FORMAT, result, guard_home=guard_home, deadline=deadline)
    sink = native_containment_sink(
        receipt, harness=_CURSOR, bridge=True, payload=payload, guard_home=guard_home, deadline=deadline
    )
    if sink.profile is None:
        return dict(_ALLOW)
    routed = route_zcode_containment(
        receipt,
        harness=_CURSOR,
        payload=payload,
        guard_home=guard_home,
        home_dir=home_dir,
        workspace=workspace,
        deadline=deadline,
    )
    if routed.get("policy_action") != "allow" or routed.get("reason_code") != _ROUTED_REASON:
        return dict(_ALLOW)
    return routed


def _admitted_sink(
    payload: Mapping[str, object],
    *,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
) -> bool:
    """Whether a ``beforeShellExecution`` call has the shape of the sink command a probe wrote.

    The hook checks only the argv shape. The sink itself opens the request
    owner-only, checks its digest and re-authorizes the command, so a request
    that fails those checks is refused there.
    """

    from ..adapters.zcode_contained_tests import contained_sink_command_prefix

    call = _command(payload)
    if workspace is None or call is None or "execute-contained-test" not in call[1]:
        return False
    try:
        argv = shlex.split(call[1])
        prefix = contained_sink_command_prefix()
        expected_head = (*prefix, *_SINK_ARGS, "--harness", _CURSOR, "--guard-home", str(guard_home))
        tail = argv[len(expected_head) :]
        if tuple(argv[: len(expected_head)]) != expected_head or len(tail) != 8:
            return False
        flags, values = tail[0::2], tail[1::2]
        if flags != ["--workspace", "--request-file", "--request-sha256", "--home"]:
            return False
        sink_workspace, request_file, request_sha256, sink_home = values
        if len(request_sha256) != 64 or not set(request_sha256) <= set("0123456789abcdef"):
            return False
        if sink_home != str(home_dir) or not _same_directory(sink_workspace, workspace):
            return False
        request = Path(request_file)
        if not request.is_absolute() or request.parent.parent.resolve() != Path(tempfile.gettempdir()).resolve():
            return False
    except Exception:
        return False
    return True


__all__ = ["cursor_shell_route_response", "is_cursor_shell_probe"]
