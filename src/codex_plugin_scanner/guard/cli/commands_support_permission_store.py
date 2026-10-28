"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._commands_shared import _now
    from .commands_support_runtime_artifacts import _optional_string


from ..native_hook_authority_state import (
    HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE,
    hook_authority_state,
)
from ._commands_shared import *
from .commands_parser_helpers import *


def _write_claude_native_permission_plan(
    *,
    store: GuardStore,
    plan: Mapping[str, Any],
    artifact_id: str,
    reason: str,
    source: str,
    now: str,
) -> bool:
    """Write the policy row and the events the plan names, in its order."""

    try:
        for event in plan["events"]:
            if event["before_policy"]:
                store.add_event(event["name"], event["payload"], now)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action=plan["policy_action"],
                artifact_id=artifact_id,
                artifact_hash=plan["stored_artifact_hash"],
                reason=reason,
                source=source,
            ),
            now,
        )
        for event in plan["events"]:
            if not event["before_policy"]:
                store.add_event(event["name"], event["payload"], now)
    except (ApprovalGateError, OSError, sqlite3.Error):
        return False
    return True


def _discard_claude_pending_permissions(store: GuardStore, payload: dict[str, object]) -> int:
    session_id = _optional_string(payload.get("session_id"))
    if session_id is None:
        return 0
    reply = hook_authority_state(
        store,
        "claude_discard_session",
        now=_now(),
        required_feature=HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE,
        session_id=session_id,
    )
    discarded = reply.get("discarded") if reply is not None else None
    return discarded if isinstance(discarded, int) and not isinstance(discarded, bool) else 0


__all__ = [
    "_discard_claude_pending_permissions",
    "_write_claude_native_permission_plan",
]
