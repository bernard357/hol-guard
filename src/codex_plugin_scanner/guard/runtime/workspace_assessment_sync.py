"""Workspace assessment summary for the receipts sync context.

Guard Cloud gets one bounded summary per admitted worktree: its status, the
latest assessed run's coverage, and package-coordinate findings. Local keys are
plain digests of absolute paths, so every identifier that leaves the machine is
re-keyed with the per-install secret; roots, commits and file names never do.
The summary is sent again only when it changes or a day has passed.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Final

from .fleet_posture_common import keyed_digest, load_hash_key

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

SCHEMA_VERSION: Final = "guard.workspace-assessment-sync.v1"
DELIVERY_STATE_KEY: Final = "workspace_assessment_sync_delivery"
MAX_WORKTREES: Final = 50
MAX_FINDINGS_PER_WORKTREE: Final = 100
# Receipts share the request; the whole body must stay under 256 KiB.
MAX_SUMMARY_BYTES: Final = 128 * 1024
RESEND_AFTER: Final = timedelta(hours=24)

_FINDING_FIELDS: Final = (
    ("source_kind", "sourceKind"),
    ("detector", "detector"),
    ("severity", "severity"),
    ("decision", "decision"),
    ("ecosystem", "ecosystem"),
    ("package_name", "packageName"),
    ("package_version", "packageVersion"),
    ("fix_version", "fixVersion"),
    ("validation_state", "validationState"),
    ("lifecycle_state", "lifecycleState"),
)


@dataclass(frozen=True)
class WorkspaceAssessmentSyncBuild:
    payload: dict[str, object]
    digest: str


def build_workspace_assessment_sync(store: GuardStore, *, now: str) -> WorkspaceAssessmentSyncBuild | None:
    """The summary to send, or ``None`` when nothing changed or nothing is admitted."""

    from .. import workspace_assessment_reads as reads
    from ..workspace_assessment_store import WorktreeKeys

    worktrees = reads.list_worktrees(store)[:MAX_WORKTREES]
    if not worktrees:
        return None
    hash_key = load_hash_key(store, now)
    assessed = {(str(run["codebase_key"]), str(run["worktree_key"])): run for run in reads.latest_assessed_runs(store)}
    entries = []
    for worktree in worktrees:
        keys = (str(worktree["codebase_key"]), str(worktree["worktree_key"]))
        latest = reads.recent_runs(store, WorktreeKeys(*keys), limit=1)
        entries.append(_worktree_entry(worktree, latest[0] if latest else None, assessed.get(keys), hash_key))
    _fit_budget(entries)
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if not _due(store, digest, now):
        return None
    return WorkspaceAssessmentSyncBuild(
        payload={"schemaVersion": SCHEMA_VERSION, "generatedAt": now, "worktrees": entries},
        digest=digest,
    )


def commit_workspace_assessment_sent(store: GuardStore, built: WorkspaceAssessmentSyncBuild, *, now: str) -> None:
    store.set_sync_payload(DELIVERY_STATE_KEY, {"digest": built.digest, "sent_at": now}, now)


def build_workspace_assessment_sync_safely(store: GuardStore) -> WorkspaceAssessmentSyncBuild | None:
    """Build for one sync request. Never raises: the summary is best-effort."""

    try:
        return build_workspace_assessment_sync(store, now=_utc_now())
    except Exception:
        _LOGGER.debug("Workspace assessment summary could not be built", exc_info=True)
        return None


def record_workspace_assessment_delivery(store: GuardStore, built: WorkspaceAssessmentSyncBuild | None) -> None:
    """Commit a delivered summary, stamped with the local clock that built it."""

    if built is None:
        return
    try:
        commit_workspace_assessment_sent(store, built, now=str(built.payload["generatedAt"]))
    except Exception:
        _LOGGER.debug("Workspace assessment delivery could not be recorded", exc_info=True)


def worktree_status(
    worktree: dict[str, object],
    latest_run: dict[str, object] | None,
    assessed_run: dict[str, object] | None,
) -> str:
    if worktree.get("paused"):
        return "paused"
    latest_state = latest_run.get("state") if latest_run else None
    if latest_state in {"running", "queued"}:
        return str(latest_state)
    if latest_state == "failed":
        return "failed"
    if assessed_run is None:
        return "pending"
    if worktree.get("stale"):
        return "stale"
    return "partial" if assessed_run.get("state") == "partial" else "fresh"


def _worktree_entry(
    worktree: dict[str, object],
    latest_run: dict[str, object] | None,
    assessed_run: dict[str, object] | None,
    hash_key: bytes,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "codebaseKey": keyed_digest(hash_key, "guard.workspace.codebase\0" + str(worktree["codebase_key"])),
        "worktreeKey": keyed_digest(hash_key, "guard.workspace.worktree\0" + str(worktree["worktree_key"])),
        "status": worktree_status(worktree, latest_run, assessed_run),
        "dirtyGeneration": _generation(worktree.get("dirty_generation")),
        "lastCompletedGeneration": _generation(worktree.get("last_completed_generation")),
        "assessment": None,
        "findings": [],
        "findingsTruncated": False,
    }
    if assessed_run is None:
        return entry
    coverage = assessed_run.get("coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    detectors = coverage.get("detectors")
    detector_items = detectors.items() if isinstance(detectors, dict) else ()
    entry["assessment"] = {
        "runKey": keyed_digest(hash_key, "guard.workspace.run\0" + str(assessed_run["run_id"])),
        "kind": assessed_run.get("kind"),
        "trigger": assessed_run.get("trigger_kind"),
        "state": assessed_run.get("state"),
        "snapshotDigest": assessed_run.get("snapshot_digest"),
        "coverage": {
            "status": "complete" if coverage.get("status") == "complete" else "partial",
            "reasons": [str(item)[:128] for item in _list(coverage.get("reasons"))][:32],
            "detectors": {str(name)[:64]: str(state)[:32] for name, state in detector_items},
        },
        "startedAt": _iso(assessed_run.get("started_at_ms")),
        "finishedAt": _iso(assessed_run.get("finished_at_ms")),
    }
    findings = [item for item in _list(assessed_run.get("findings")) if isinstance(item, dict)]
    entry["findings"] = [_finding(item, hash_key) for item in findings[:MAX_FINDINGS_PER_WORKTREE]]
    entry["findingsTruncated"] = len(findings) > MAX_FINDINGS_PER_WORKTREE or "finding_cap" in _list(
        coverage.get("reasons")
    )
    return entry


def _finding(item: dict[str, object], hash_key: bytes) -> dict[str, object]:
    finding: dict[str, object] = {
        "findingKey": keyed_digest(hash_key, "guard.workspace.finding\0" + str(item.get("finding_id"))),
    }
    for source, target in _FINDING_FIELDS:
        value = item.get(source)
        finding[target] = value[:256] if isinstance(value, str) else None
    finding["ruleIds"] = [str(value)[:128] for value in _list(item.get("rule_ids"))][:32]
    finding["advisoryIds"] = [str(value)[:256] for value in _list(item.get("advisory_ids"))][:32]
    return finding


def _fit_budget(entries: list[dict[str, object]]) -> None:
    """Drop the lowest-ranked findings until the summary fits its byte budget."""

    def size() -> int:
        return len(json.dumps(entries, separators=(",", ":")).encode("utf-8"))

    while size() > MAX_SUMMARY_BYTES:
        largest = max(entries, key=lambda entry: len(_findings(entry)))
        findings = _findings(largest)
        if not findings:
            break
        drop = max(1, len(findings) // 4)
        del findings[-drop:]
        largest["findingsTruncated"] = True


def _findings(entry: dict[str, object]) -> list[object]:
    findings = entry["findings"]
    return findings if isinstance(findings, list) else []


def _due(store: GuardStore, digest: str, now: str) -> bool:
    state = store.get_sync_payload(DELIVERY_STATE_KEY)
    if not isinstance(state, dict) or state.get("digest") != digest:
        return True
    sent_at = _parse(state.get("sent_at"))
    current = _parse(now)
    return sent_at is None or current is None or current - sent_at >= RESEND_AFTER


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: object) -> str | None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _generation(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, (list, tuple)) else []


__all__ = [
    "DELIVERY_STATE_KEY",
    "SCHEMA_VERSION",
    "WorkspaceAssessmentSyncBuild",
    "build_workspace_assessment_sync",
    "build_workspace_assessment_sync_safely",
    "commit_workspace_assessment_sent",
    "record_workspace_assessment_delivery",
    "worktree_status",
]
