"""Revalidate one modeled shell segment through the resident."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.native_request_context import (
    _DEFAULT_BUDGET_MS,
    NativeRequestContextFailure,
    _call,
)
from codex_plugin_scanner.guard.runtime.shell_execution_context import (
    SHELL_CWD_NATIVE_UNAVAILABLE,
    SHELL_CWD_PATH_CHANGED,
    ShellExecutionContext,
    ShellExecutionSegment,
    _context_wire,
)


def validate_shell_execution_segment(
    context: ShellExecutionContext,
    segment: ShellExecutionSegment,
) -> tuple[Path | None, str | None]:
    """Revalidate a modeled cwd immediately before a filesystem-sensitive use."""

    if not segment.complete or segment.effective_cwd is None or segment.cwd_identity is None:
        return None, segment.reason_code or context.reason_code or SHELL_CWD_PATH_CHANGED
    if context.workspace_root is None or context.workspace_identity is None:
        return None, context.reason_code or SHELL_CWD_PATH_CHANGED
    wire = _single_segment_wire(context, segment)
    result = native_shell_validate_segment(wire, 0)
    if isinstance(result, NativeRequestContextFailure):
        return None, SHELL_CWD_NATIVE_UNAVAILABLE
    cwd, reason = result
    return (Path(cwd) if cwd is not None else None), reason


def _single_segment_wire(context: ShellExecutionContext, segment: ShellExecutionSegment) -> dict[str, Any]:
    """Segment checks and hashes depend only on the workspace and the segment."""

    return _context_wire(context, (segment,))


def native_shell_validate_segment(
    context: Mapping[str, Any],
    segment_index: int,
    *,
    guard_home: Path | None = None,
    budget_ms: int = _DEFAULT_BUDGET_MS,
) -> tuple[str | None, str | None] | NativeRequestContextFailure:
    """Re-read the filesystem for one modeled segment: ``(cwd, reason_code)``."""

    payload = _call(
        {"kind": "validate_segment", "body": {"context": dict(context), "segment_index": segment_index}},
        source="hook",
        guard_home=guard_home,
        budget_ms=budget_ms,
    )
    if isinstance(payload, NativeRequestContextFailure):
        return payload
    cwd, reason = payload.get("effective_cwd"), payload.get("reason_code")
    if (
        set(payload) != {"effective_cwd", "reason_code", "context_hash", "segment_hash"}
        or not (cwd is None or isinstance(cwd, str))
        or not (reason is None or isinstance(reason, str))
        or (cwd is None) == (reason is None)
    ):
        return NativeRequestContextFailure("native_request_context_payload_invalid")
    return cwd, reason
