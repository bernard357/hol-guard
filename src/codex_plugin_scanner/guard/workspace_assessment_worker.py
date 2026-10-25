"""Background loop for workspace assessments.

Only worktrees a user admitted (from the dashboard or the CLI) or registered a
harness install for (``install --workspace``) are watched. Guard never takes a
root from repository text or from a hook's working directory.
Each poll takes a cheap stat snapshot of every admitted worktree and a digest
of the cached advisory bundles; a change queues an assessment, and the
coordinator's debounce and interval decide when it runs. Nothing here runs in
a hook path, and the Cloud audit is never used.
"""

from __future__ import annotations

import hashlib
import os
import threading
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from . import workspace_assessment_store as assessments
from .native_workspace_snapshot import WorkspaceSnapshotError, workspace_snapshot
from .workspace_assessment_admissions import admit_and_queue, end_unregistered_install_admissions, watched_roots
from .workspace_assessment_runner import DETECTOR_SET_DIGEST, feed_context_digest, now_ms, run_next

POLL_INTERVAL_SECONDS: Final = 30.0
# Recorded when an admitted root is missing, unreadable or now names another
# worktree. Losing the root is itself a change: it queues one run, which fails
# with the reason, and staying lost queues nothing more.
UNAVAILABLE_STAT_DIGEST: Final = hashlib.sha256(b"guard.workspace-stat.unavailable.v1").hexdigest()
# How long a root that could not be admitted waits before it is tried again;
# a native runtime that was unavailable may have come back.
ADMISSION_RETRY_MS: Final = 10 * 60_000
# Runs per poll; the rest wait for the next poll so shutdown stays prompt.
_MAX_RUNS_PER_POLL: Final = 4


class WorkspaceAdmissionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def admit_workspace(
    store: Any, root: str, *, clock: Callable[[], int] = now_ms, automatic: bool = False
) -> dict[str, object]:
    """Admit a worktree for background assessment and queue its first run.

    An ``automatic`` admission leaves a worktree that is already admitted alone,
    paused or not, and raises ``workspace_already_admitted``.
    """

    path = Path(root)
    if not path.is_absolute():
        raise WorkspaceAdmissionError("workspace_root_not_absolute")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise WorkspaceAdmissionError("workspace_root_missing") from error
    if not resolved.is_dir():
        raise WorkspaceAdmissionError("workspace_root_not_directory")
    try:
        snapshot = workspace_snapshot(resolved, mode="stat")
    except WorkspaceSnapshotError as error:
        raise WorkspaceAdmissionError(error.code) from error
    keys = assessments.WorktreeKeys(snapshot.codebase_key, snapshot.worktree_key)
    run_id = admit_and_queue(
        store,
        keys,
        root=str(resolved),
        now_ms=clock(),
        automatic=automatic,
        stat_digest=snapshot.snapshot_digest,
        feed_digest=feed_context_digest(store),
        detector_set_digest=DETECTOR_SET_DIGEST,
    )
    if run_id is None and automatic:
        raise WorkspaceAdmissionError("workspace_already_admitted")
    return {"codebase_key": keys.codebase_key, "worktree_key": keys.worktree_key, "run_id": run_id}


def admit_registered_workspaces(
    store: Any, *, attempted: dict[str, int] | None = None, clock: Callable[[], int] = now_ms
) -> int:
    """Admit the workspaces active harness installs were registered for.

    Registering an install for a workspace is the authorization, and removing
    the install withdraws it: an admission made here ends once no active install
    registers its root. A root whose admitted worktree is still there is skipped
    without a snapshot; one last observed unavailable is admitted again, since
    the path may now name another worktree. ``attempted`` holds roots that could
    not be admitted until they may be tried again, so a rejected root is not
    walked on every poll; a root that is missing is retried once it exists.
    """

    registered = [
        workspace
        for install in store.list_managed_installs()
        if install.get("active")
        and isinstance(workspace := install.get("workspace"), str)
        and Path(workspace).is_absolute()
    ]
    end_unregistered_install_admissions(store, {os.path.realpath(workspace) for workspace in registered})
    known = watched_roots(store, unavailable_digest=UNAVAILABLE_STAT_DIGEST)
    admitted = 0
    for workspace in registered:
        try:
            root = str(Path(workspace).resolve(strict=True))
        except (OSError, RuntimeError):
            continue
        current = clock()
        if root in known or (attempted is not None and attempted.get(root, 0) > current):
            continue
        try:
            admit_workspace(store, root, clock=clock, automatic=True)
        except WorkspaceAdmissionError:
            if attempted is not None:
                attempted[root] = current + ADMISSION_RETRY_MS
            continue
        if attempted is not None:
            attempted.pop(root, None)
        known.add(root)
        admitted += 1
    return admitted


def queue_manual_run(
    store: Any,
    keys: assessments.WorktreeKeys,
    *,
    trigger_kind: str = "manual",
    clock: Callable[[], int] = now_ms,
) -> str | None:
    return assessments.enqueue(
        store, keys, trigger_kind=trigger_kind, detector_set_digest=DETECTOR_SET_DIGEST, now_ms=clock()
    )


def observe(store: Any, *, clock: Callable[[], int] = now_ms) -> int:
    """Queue assessments for admitted worktrees whose files or feed changed."""

    queued = 0
    feed_digest = feed_context_digest(store)
    for worktree in assessments.list_worktrees(store, include_paused=False):
        keys = assessments.WorktreeKeys(str(worktree["codebase_key"]), str(worktree["worktree_key"]))
        try:
            snapshot = workspace_snapshot(Path(str(worktree["root"])), mode="stat")
        except WorkspaceSnapshotError:
            snapshot = None
        available = snapshot is not None and snapshot.worktree_key == keys.worktree_key
        triggers = assessments.record_observation(
            store,
            keys,
            stat_digest=snapshot.snapshot_digest if snapshot is not None and available else UNAVAILABLE_STAT_DIGEST,
            feed_digest=feed_digest,
        )
        for trigger in triggers:
            if assessments.enqueue(
                store, keys, trigger_kind=trigger, detector_set_digest=DETECTOR_SET_DIGEST, now_ms=clock()
            ):
                queued += 1
    return queued


def poll_once(
    store: Any, *, owner: str, stop: threading.Event | None = None, attempted: dict[str, int] | None = None
) -> int:
    from .config import load_guard_config

    admit_registered_workspaces(store, attempted=attempted)
    observe(store)
    ran = 0
    config = None
    while ran < _MAX_RUNS_PER_POLL and not (stop is not None and stop.is_set()):
        if config is None:
            config = load_guard_config(store.guard_home)
        if not run_next(store, config, owner=owner):
            break
        ran += 1
    return ran


def start_workspace_assessment_worker(
    store: Any,
    *,
    stop: threading.Event,
    on_error: Callable[[str], object],
    interval: float = POLL_INTERVAL_SECONDS,
) -> threading.Thread:
    """Poll admitted worktrees on a daemon thread until ``stop`` is set."""

    owner = f"daemon:{os.getpid()}:{uuid.uuid4().hex[:12]}"
    attempted: dict[str, int] = {}

    def loop() -> None:
        while not stop.wait(interval):
            try:
                poll_once(store, owner=owner, stop=stop, attempted=attempted)
            except Exception:
                on_error("workspace_assessment_poll_failed")

    thread = threading.Thread(target=loop, name="guard-workspace-assessment", daemon=True)
    thread.start()
    return thread


__all__ = [
    "ADMISSION_RETRY_MS",
    "POLL_INTERVAL_SECONDS",
    "UNAVAILABLE_STAT_DIGEST",
    "WorkspaceAdmissionError",
    "admit_registered_workspaces",
    "admit_workspace",
    "observe",
    "poll_once",
    "queue_manual_run",
    "start_workspace_assessment_worker",
]
