"""Dashboard routes for background workspace assessments.

The routes live under ``/v1/supply-chain/`` so they inherit that family's
header-token and dashboard-session policy; scoped claim sessions cannot reach
them. Reads return digests, counts and package-coordinate findings. Writes
only admit, pause, queue or cancel; a run itself happens on the worker thread.
"""

from __future__ import annotations

from typing import Any, Final, Protocol

from .. import workspace_assessment_store as assessments
from ..workspace_assessment_worker import WorkspaceAdmissionError, admit_workspace, queue_manual_run

ASSESSMENTS_PATH: Final = "/v1/supply-chain/workspace-assessments"
FINDINGS_PATH: Final = "/v1/supply-chain/workspace-findings"
_ACTIONS: Final = frozenset({"run", "cancel", "pause", "resume"})


class WorkspaceAssessmentHandler(Protocol):
    server: Any

    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None: ...


def handle_workspace_assessment_get(handler: WorkspaceAssessmentHandler, path: str) -> bool:
    store = handler.server.store
    if path == ASSESSMENTS_PATH:
        handler._write_json(
            {
                "worktrees": assessments.list_worktrees(store),
                "runs": assessments.recent_runs(store, limit=50),
            }
        )
        return True
    if path == FINDINGS_PATH:
        handler._write_json(
            {
                "worktrees": assessments.list_worktrees(store),
                "assessments": assessments.latest_assessed_runs(store),
            }
        )
        return True
    return False


def handle_workspace_assessment_post(
    handler: WorkspaceAssessmentHandler,
    path: str,
    payload: dict[str, object],
) -> bool:
    if path == ASSESSMENTS_PATH:
        _admit(handler, payload)
        return True
    prefix = ASSESSMENTS_PATH + "/"
    if not path.startswith(prefix) or path[len(prefix) :] not in _ACTIONS:
        return False
    action = path[len(prefix) :]
    store = handler.server.store
    if action == "cancel":
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or not 0 < len(run_id) <= 64:
            handler._write_json({"error": "invalid_run_id"}, status=400)
            return True
        canceled = assessments.cancel(store, run_id, now_ms=_now_ms())
        handler._write_json({"canceled": canceled}, status=200 if canceled else 409)
        return True
    keys = _keys(payload)
    if keys is None:
        handler._write_json({"error": "invalid_worktree"}, status=400)
        return True
    if action in {"pause", "resume"}:
        changed = assessments.set_paused(store, keys, paused=action == "pause")
        handler._write_json({"paused": action == "pause"}, status=200 if changed else 404)
        return True
    run_id = queue_manual_run(store, keys)
    handler._write_json({"run_id": run_id}, status=202 if run_id else 404)
    return True


def _admit(handler: WorkspaceAssessmentHandler, payload: dict[str, object]) -> None:
    root = payload.get("root")
    if not isinstance(root, str) or not 0 < len(root) <= 4096:
        handler._write_json({"error": "invalid_root"}, status=400)
        return
    try:
        admitted = admit_workspace(handler.server.store, root)
    except WorkspaceAdmissionError as error:
        handler._write_json({"error": error.code}, status=422)
        return
    handler._write_json(admitted, status=202)


def _keys(payload: dict[str, object]) -> assessments.WorktreeKeys | None:
    codebase_key = payload.get("codebase_key")
    worktree_key = payload.get("worktree_key")
    if not (_is_key(codebase_key) and _is_key(worktree_key)):
        return None
    return assessments.WorktreeKeys(str(codebase_key), str(worktree_key))


def _is_key(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _now_ms() -> int:
    from ..workspace_assessment_runner import now_ms

    return now_ms()


__all__ = [
    "ASSESSMENTS_PATH",
    "FINDINGS_PATH",
    "handle_workspace_assessment_get",
    "handle_workspace_assessment_post",
]
