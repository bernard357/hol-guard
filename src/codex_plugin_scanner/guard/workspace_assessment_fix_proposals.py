"""Reviewed dependency fix proposals for workspace assessment findings.

A proposal is one minimal ``package.json`` version-spec edit that moves a
directly declared npm dependency to a finding's fix version. It moves through
three separate steps and never runs on its own:

* prepare reads manifests under the admitted root and stores the edit, its
  diff, and the hashes of the manifest before and after;
* apply is the user's explicit approval. It refuses (and marks the proposal
  stale) unless the manifest still has the prepared hash, so a user's own
  edits are never overwritten, and it queues a ``fix_verification`` run;
* verification marks the proposal fixed only after a later, complete
  supply-chain run on a different snapshot no longer reports the finding.

Guard does not run a package manager or any project code, so the lockfile is
left for the user to update with their own tooling.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from pathlib import Path
from typing import Any, Final

from . import workspace_assessment_store as assessments
from .workspace_assessment_fix_files import (
    ManifestAccessError,
    discover_manifests,
    lockfiles_for,
    read_manifest,
    write_manifest,
)
from .workspace_assessment_fix_manifest import FixEdit, FixUnsupportedError, apply_edits, plan_edits, unified_diff
from .workspace_assessment_worker import queue_manual_run

MAX_LISTED_PROPOSALS: Final = 100
MAX_PROPOSALS_PER_PREPARE: Final = 20
# Errors that say the file, not the dependency, was the problem. A manifest that
# declares the package for real explains a refusal better, so these rank last.
_STRUCTURAL_REASONS: Final = frozenset({"manifest_invalid_json", "manifest_too_deep", "manifest_not_utf8"})
# Absence of a finding only means "fixed" if the supply-chain detector looked at
# everything. These coverage reasons say it did not; any snapshot_* reason says
# the snapshot behind the run was itself partial. A detector_not_run:* reason
# (today the not-yet-existing secrets detector) is deliberately not listed: the
# finding comes from the supply-chain detector, so another detector's gap cannot
# hide it. Unknown or missing coverage is treated as incomplete.
_BLOCKING_COVERAGE_REASONS: Final = frozenset({"finding_cap", "supply_chain_incomplete", "lockfile_warnings"})
_COLUMNS: Final = (
    "proposal_id",
    "codebase_key",
    "worktree_key",
    "finding_id",
    "source_run_id",
    "snapshot_digest",
    "manifest_path",
    "base_sha256",
    "new_sha256",
    "edits_json",
    "diff_text",
    "state",
    "created_at_ms",
    "updated_at_ms",
    "applied_at_ms",
    "verified_at_ms",
    "verification_run_id",
)
_SELECT: Final = ", ".join(_COLUMNS)
# One apply at a time, so two requests cannot both pass the hash check.
_APPLY_LOCK: Final = threading.Lock()


class FixProposalError(Exception):
    """A refused request; ``code`` and ``status`` become the API response."""

    def __init__(self, code: str, status: int, **detail: object) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.detail = detail


def prepare(store: Any, keys: assessments.WorktreeKeys, finding_id: str, *, now_ms: int) -> dict[str, object]:
    """Store a proposal for each direct declaration of the finding's package."""

    root = _worktree_root(store, keys)
    run = assessments.latest_assessed_run(store, keys)
    if run is None:
        raise FixProposalError("no_assessed_run", 409)
    findings = run["findings"] if isinstance(run["findings"], list) else []
    finding = next((item for item in findings if isinstance(item, dict) and item.get("finding_id") == finding_id), None)
    if finding is None:
        raise FixProposalError("finding_not_found", 404)
    package, fix_version = finding.get("package_name"), finding.get("fix_version")
    if finding.get("source_kind") != "supply_chain":
        raise FixProposalError("fix_unsupported", 422, reason="unsupported_source")
    if finding.get("ecosystem") != "npm":
        raise FixProposalError("fix_unsupported", 422, reason="unsupported_ecosystem")
    if not isinstance(fix_version, str) or not fix_version:
        raise FixProposalError("fix_unsupported", 422, reason="no_fix_version")
    if not isinstance(package, str) or not package:
        raise FixProposalError("fix_unsupported", 422, reason="finding_incomplete")
    manifests, truncated = discover_manifests(root)
    planned: list[dict[str, object]] = []
    declared_refusals: list[tuple[str, str]] = []
    other_refusals: list[tuple[str, str]] = []
    for relative in manifests:
        try:
            raw, _mode = read_manifest(root, relative)
            text = raw.decode("utf-8")
            edits = plan_edits(text, package, fix_version)
            updated = apply_edits(text, edits)
            diff = unified_diff(text, updated, relative)
        except UnicodeDecodeError:
            other_refusals.append((relative, "manifest_not_utf8"))
        except ManifestAccessError as error:
            other_refusals.append((relative, error.code))
        except FixUnsupportedError as error:
            if error.code in _STRUCTURAL_REASONS:
                other_refusals.append((relative, error.code))
            elif error.code != "not_declared":
                declared_refusals.append((relative, error.code))
        else:
            planned.append(
                {
                    "manifest_path": relative,
                    "base_sha256": hashlib.sha256(raw).hexdigest(),
                    "new_sha256": hashlib.sha256(updated.encode("utf-8")).hexdigest(),
                    "edits": edits,
                    "diff": diff,
                }
            )
    skipped = [*declared_refusals, *other_refusals]
    if not planned:
        reason = skipped[0][1] if skipped else ("manifest_scan_incomplete" if truncated else "transitive_dependency")
        raise FixProposalError("fix_unsupported", 422, reason=reason, skipped=_skipped_payload(skipped))
    skipped.extend((str(item["manifest_path"]), "too_many_manifests") for item in planned[MAX_PROPOSALS_PER_PREPARE:])
    stored = _store_prepared(store, keys, finding_id, run, planned[:MAX_PROPOSALS_PER_PREPARE], now_ms=now_ms)
    return {"proposals": stored, "skipped": _skipped_payload(skipped)}


def apply(store: Any, proposal_id: str, *, now_ms: int) -> dict[str, object]:
    """Write a prepared proposal if its manifest is unchanged, then queue verification."""

    with _APPLY_LOCK:
        row = _fetch(store, proposal_id)
        if row is None:
            raise FixProposalError("fix_proposal_not_found", 404)
        if row["state"] == "stale":
            raise FixProposalError("fix_proposal_stale", 409)
        if row["state"] != "prepared":
            raise FixProposalError("fix_proposal_not_prepared", 409, state=row["state"])
        keys = assessments.WorktreeKeys(str(row["codebase_key"]), str(row["worktree_key"]))
        root = _worktree_root(store, keys)
        relative = str(row["manifest_path"])
        try:
            current, mode = read_manifest(root, relative)
        except ManifestAccessError as error:
            _set_state(store, proposal_id, "stale", now_ms=now_ms)
            raise FixProposalError("fix_proposal_stale", 409, reason=error.code) from error
        updated: bytes | None = None
        if hashlib.sha256(current).hexdigest() == row["base_sha256"]:
            try:
                text = current.decode("utf-8")
                updated = apply_edits(text, _stored_edits(row)).encode("utf-8")
            except (UnicodeDecodeError, FixUnsupportedError):
                updated = None
        if updated is None or hashlib.sha256(updated).hexdigest() != row["new_sha256"]:
            # The file moved on since the review (or no longer matches what was
            # reviewed): nothing is written, so the user's own edits stay.
            _set_state(store, proposal_id, "stale", now_ms=now_ms)
            raise FixProposalError("fix_proposal_stale", 409)
        try:
            write_manifest(root, relative, updated, mode=mode)
        except OSError as error:
            raise FixProposalError("fix_apply_failed", 500) from error
        _set_state(store, proposal_id, "applied", now_ms=now_ms, applied=True)
    queued = queue_manual_run(store, keys, trigger_kind="fix_verification", clock=lambda: now_ms)
    applied = _payload(_fetch(store, proposal_id) or row)
    return {
        "proposal": applied,
        "lockfile_update_required": True,
        "lockfiles": lockfiles_for(root, relative),
        "verification_run_id": queued,
    }


def list_proposals(
    store: Any, keys: assessments.WorktreeKeys, *, limit: int = MAX_LISTED_PROPOSALS, now_ms: int
) -> list[dict[str, object]]:
    """Newest proposals of a worktree, after settling any that a later run decides."""

    verify_proposals(store, keys, now_ms=now_ms)
    with store._connect() as connection:
        rows = connection.execute(
            f"""
            select {_SELECT} from workspace_fix_proposals
            where codebase_key = ? and worktree_key = ?
            order by created_at_ms desc, proposal_id desc
            limit ?
            """,
            (keys.codebase_key, keys.worktree_key, max(1, min(limit, MAX_LISTED_PROPOSALS))),
        ).fetchall()
    return [_payload(dict(zip(_COLUMNS, row, strict=True))) for row in rows]


def verify_proposals(store: Any, keys: assessments.WorktreeKeys, *, now_ms: int) -> None:
    """Settle applied proposals against the worktree's newest assessed run.

    Only the newest run is consulted, so the outcome is deterministic: a run
    that cannot vouch for the whole supply-chain input leaves a proposal as it
    is, and nothing but such a run can mark one fixed.
    """

    run = assessments.latest_assessed_run(store, keys)
    if run is None or not _supply_chain_verifiable(run["coverage"]):
        return
    findings = run["findings"] if isinstance(run["findings"], list) else []
    present = {item.get("finding_id") for item in findings if isinstance(item, dict)}
    started = run["started_at_ms"]
    with store._connect() as connection:
        connection.execute("begin immediate")
        rows = connection.execute(
            """
            select proposal_id, finding_id, snapshot_digest, applied_at_ms, state, verification_run_id
            from workspace_fix_proposals
            where codebase_key = ? and worktree_key = ? and state in ('applied', 'still_present')
            """,
            (keys.codebase_key, keys.worktree_key),
        ).fetchall()
        for proposal_id, finding_id, snapshot_digest, applied_at, state, verified_run in rows:
            # A run that started before the apply may have read the old manifest.
            if run["snapshot_digest"] == snapshot_digest or not isinstance(started, int) or started < applied_at:
                continue
            outcome = "still_present" if finding_id in present else "verified_fixed"
            if outcome == state and verified_run == run["run_id"]:
                continue
            connection.execute(
                """
                update workspace_fix_proposals set
                  state = ?, verified_at_ms = ?, verification_run_id = ?,
                  updated_at_ms = max(created_at_ms, ?)
                where proposal_id = ? and state in ('applied', 'still_present')
                """,
                (outcome, now_ms, run["run_id"], now_ms, proposal_id),
            )


def _supply_chain_verifiable(coverage: object) -> bool:
    if not isinstance(coverage, dict):
        return False
    detectors, reasons = coverage.get("detectors"), coverage.get("reasons")
    if not isinstance(detectors, dict) or detectors.get("supply_chain") != "complete":
        return False
    if not isinstance(reasons, list) or not all(isinstance(reason, str) for reason in reasons):
        return False
    return not any(reason in _BLOCKING_COVERAGE_REASONS or reason.startswith("snapshot_") for reason in reasons)


def _store_prepared(
    store: Any,
    keys: assessments.WorktreeKeys,
    finding_id: str,
    run: dict[str, object],
    planned: list[dict[str, object]],
    *,
    now_ms: int,
) -> list[dict[str, object]]:
    ids: list[str] = []
    with store._connect() as connection:
        connection.execute("begin immediate")
        for item in planned:
            existing = connection.execute(
                """
                select proposal_id, base_sha256, new_sha256, snapshot_digest from workspace_fix_proposals
                where codebase_key = ? and worktree_key = ? and finding_id = ? and manifest_path = ?
                  and state = 'prepared'
                """,
                (keys.codebase_key, keys.worktree_key, finding_id, item["manifest_path"]),
            ).fetchall()
            same = next(
                (
                    row[0]
                    for row in existing
                    if (row[1], row[2], row[3]) == (item["base_sha256"], item["new_sha256"], run["snapshot_digest"])
                ),
                None,
            )
            for row in existing:
                if row[0] != same:
                    connection.execute(
                        "update workspace_fix_proposals set state = 'stale', updated_at_ms = max(created_at_ms, ?)"
                        " where proposal_id = ?",
                        (now_ms, row[0]),
                    )
            if same is not None:
                ids.append(str(same))
                continue
            proposal_id = uuid.uuid4().hex
            edits = item["edits"]
            assert isinstance(edits, list)
            connection.execute(
                f"insert into workspace_fix_proposals ({_SELECT}) values ({', '.join('?' for _ in _COLUMNS)})",
                (
                    proposal_id,
                    keys.codebase_key,
                    keys.worktree_key,
                    finding_id,
                    run["run_id"],
                    run["snapshot_digest"],
                    item["manifest_path"],
                    item["base_sha256"],
                    item["new_sha256"],
                    json.dumps([_edit_record(edit) for edit in edits], separators=(",", ":")),
                    item["diff"],
                    "prepared",
                    now_ms,
                    now_ms,
                    None,
                    None,
                    None,
                ),
            )
            ids.append(proposal_id)
    return [_payload(row) for proposal_id in ids if (row := _fetch(store, proposal_id)) is not None]


def _worktree_root(store: Any, keys: assessments.WorktreeKeys) -> Path:
    with store._connect() as connection:
        row = connection.execute(
            "select private_root from workspace_assessment_state where codebase_key = ? and worktree_key = ?",
            (keys.codebase_key, keys.worktree_key),
        ).fetchone()
    if row is None:
        raise FixProposalError("worktree_not_found", 404)
    return Path(str(row[0]))


def _fetch(store: Any, proposal_id: str) -> dict[str, Any] | None:
    with store._connect() as connection:
        row = connection.execute(
            f"select {_SELECT} from workspace_fix_proposals where proposal_id = ?", (proposal_id,)
        ).fetchone()
    return dict(zip(_COLUMNS, row, strict=True)) if row is not None else None


def _set_state(store: Any, proposal_id: str, state: str, *, now_ms: int, applied: bool = False) -> None:
    with store._connect() as connection:
        connection.execute(
            """
            update workspace_fix_proposals set
              state = ?, updated_at_ms = max(created_at_ms, ?),
              applied_at_ms = case when ? then ? else applied_at_ms end
            where proposal_id = ? and state = 'prepared'
            """,
            (state, now_ms, 1 if applied else 0, now_ms, proposal_id),
        )


def _edit_record(edit: object) -> dict[str, object]:
    assert isinstance(edit, FixEdit)
    return {
        "section": edit.section,
        "start": edit.start,
        "end": edit.end,
        "from_spec": edit.from_spec,
        "to_spec": edit.to_spec,
    }


def _stored_edits(row: dict[str, Any]) -> list[FixEdit]:
    return [
        FixEdit(
            str(item["section"]), int(item["start"]), int(item["end"]), str(item["from_spec"]), str(item["to_spec"])
        )
        for item in json.loads(str(row["edits_json"]))
    ]


def _payload(row: dict[str, Any]) -> dict[str, object]:
    return {
        "proposal_id": row["proposal_id"],
        "codebase_key": row["codebase_key"],
        "worktree_key": row["worktree_key"],
        "finding_id": row["finding_id"],
        "source_run_id": row["source_run_id"],
        "snapshot_digest": row["snapshot_digest"],
        "manifest_path": row["manifest_path"],
        "base_sha256": row["base_sha256"],
        "new_sha256": row["new_sha256"],
        "edits": [
            {"section": item["section"], "from_spec": item["from_spec"], "to_spec": item["to_spec"]}
            for item in json.loads(str(row["edits_json"]))
        ],
        # Only a proposal still waiting for review needs its diff on the wire.
        "diff": row["diff_text"] if row["state"] == "prepared" else None,
        "state": row["state"],
        "created_at_ms": row["created_at_ms"],
        "updated_at_ms": row["updated_at_ms"],
        "applied_at_ms": row["applied_at_ms"],
        "verified_at_ms": row["verified_at_ms"],
        "verification_run_id": row["verification_run_id"],
    }


def _skipped_payload(skipped: list[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"manifest_path": path, "reason": reason} for path, reason in skipped[:MAX_PROPOSALS_PER_PREPARE]]


__all__ = [
    "MAX_LISTED_PROPOSALS",
    "FixProposalError",
    "apply",
    "list_proposals",
    "prepare",
    "verify_proposals",
]
