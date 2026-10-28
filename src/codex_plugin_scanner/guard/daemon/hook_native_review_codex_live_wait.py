"""Attach a waiting Codex hook to the review it queued.

The native Codex hook bridge holds the tool call open while the user decides,
then asks the daemon to complete the live decision. That completion only
releases the action when the request carries a live wait: an operation linked
to the request that names the waiting bridge process and its deadline, and a
frozen ``suspended-response`` snapshot that tells Cloud Review the original
hook is still attached. Without both, an approval is finalized as a manual
retry and the waiting hook is denied.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..approval_wait_limits import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
from ..codex_resume import seed_request_resume_record
from ..continuation_runtime import continuation_offer_payload
from ..continuation_snapshot import validated_continuation_snapshot
from ..live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    process_identity_matches,
)

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)


def codex_live_wait_metadata(
    *,
    payload: Mapping[str, object],
    guard_home: Path,
    workspace: Path | None,
    now: datetime,
) -> dict[str, object] | None:
    """Describe the bridge's wait when it is a live process with a bounded budget."""

    process = payload.get(CODEX_BROWSER_WAIT_PROCESS_KEY)
    outer = payload.get(CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY)
    if not isinstance(outer, int) or isinstance(outer, bool) or not 1 <= outer <= MAX_APPROVAL_WAIT_TIMEOUT_SECONDS:
        return None
    if not process_identity_matches(process):
        return None
    from ..config import load_guard_config

    try:
        configured = int(load_guard_config(guard_home, workspace=workspace).approval_wait_timeout_seconds)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    wait_seconds = min(max(configured, 0), MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, outer)
    if wait_seconds <= 0:
        return None
    started_at = now.astimezone(timezone.utc)
    metadata: dict[str, object] = {
        "codex_hook_waits_for_browser_approval": True,
        "codex_browser_wait_started_at": started_at.isoformat(),
        "codex_browser_wait_deadline_at": (started_at + timedelta(seconds=wait_seconds)).isoformat(),
        "codex_browser_wait_timeout_seconds": wait_seconds,
        "codex_browser_wait_process": dict(cast("Mapping[str, object]", process)),
        "hook_event_name": "PreToolUse",
    }
    if workspace is not None:
        metadata["workspace"] = str(workspace)
    return metadata


def codex_live_wait_snapshot(
    store: object,
    *,
    request_id: str,
    metadata: Mapping[str, object],
    now: datetime,
) -> dict[str, object] | None:
    """Freeze the suspended-response capability the same offer rules would grant."""

    timestamp = now.astimezone(timezone.utc).isoformat()
    try:
        offer = continuation_offer_payload(
            cast("GuardStore", store),
            request_row={"request_id": request_id, "harness": "codex"},
            now=timestamp,
            headless=False,
            operation=_waiting_operation(metadata, timestamp),
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    snapshot = validated_continuation_snapshot(offer)
    if snapshot is None or snapshot.get("capability") != "suspended-response":
        return None
    return snapshot


def link_codex_live_wait(
    store: object,
    *,
    request_id: str,
    metadata: Mapping[str, object],
    workspace: Path | None,
    now: datetime,
) -> bool:
    """Record the operation for the waiting hook before its request is queued.

    The operation is written first so the request is never approvable without
    it: an approval that lands as soon as the request is stored still finds the
    waiting hook. When this fails the caller queues the request retry-only.
    """

    upsert_session = getattr(store, "upsert_guard_session", None)
    upsert_operation = getattr(store, "upsert_guard_operation", None)
    if not callable(upsert_session) or not callable(upsert_operation):
        return False
    timestamp = now.astimezone(timezone.utc).isoformat()
    try:
        session = upsert_session(
            session_id=f"codex-hook-{request_id}",
            harness="codex",
            surface="harness-adapter",
            status="waiting_on_approval",
            client_name="codex-hook",
            client_title="Codex hook",
            client_version=None,
            workspace=None if workspace is None else str(workspace),
            capabilities=["approval-resolution"],
            now=timestamp,
        )
        upsert_operation(
            operation_id=f"codex-hook-{request_id}",
            session_id=str(cast("Mapping[str, object]", session)["session_id"]),
            harness="codex",
            operation_type="tool_call",
            status="waiting_on_approval",
            approval_request_ids=[request_id],
            resume_token=None,
            metadata=dict(metadata),
            now=timestamp,
        )
    except (KeyError, OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Codex live wait was not linked to %s (%s)", request_id, type(error).__name__)
        return False
    return True


def seed_codex_live_wait(store: object, *, request_id: str, now: datetime) -> None:
    """Seed the resume record once the waiting hook's request is stored."""

    try:
        seed_request_resume_record(
            cast("GuardStore", store), request_id=request_id, now=now.astimezone(timezone.utc).isoformat()
        )
    except (KeyError, OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Codex live wait resume was not seeded for %s (%s)", request_id, type(error).__name__)


def _waiting_operation(metadata: Mapping[str, object], timestamp: str) -> dict[str, object]:
    return {
        "created_at": timestamp,
        "harness": "codex",
        "metadata": dict(metadata),
        "status": "waiting_on_approval",
        "updated_at": timestamp,
    }


__all__ = ["codex_live_wait_metadata", "codex_live_wait_snapshot", "link_codex_live_wait", "seed_codex_live_wait"]
