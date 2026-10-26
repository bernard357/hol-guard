"""Project the native CI workflow check into workspace findings and coverage.

The native snapshot reads every GitHub Actions workflow directly in the
worktree's ``.github/workflows`` directory and runs it through the shared
workflow rules: a privileged trigger that checks out pull request code, a
``write-all`` token and actions not pinned to a commit. It decides each
finding's stable ``finding_id``, the rule's severity and whether the check was
complete. A finding carries only the rule's fixed title and reason and the
workflow's root-relative path, never an action name, ref or command. This
module checks that shape and copies it into the stored finding; a finding that
does not match is dropped and leaves the detector incomplete instead of
silently complete.

Workflow findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

CI_WORKFLOW_DETECTOR: Final = "ci_workflow_v1"
CI_WORKFLOW_SOURCE_KIND: Final = "workspace_source"
WORKFLOWS_RESULT_SCHEMA: Final = "guard.workspace-workflows.v1"
MAX_CI_WORKFLOW_FINDINGS: Final = 200

_FINDING_ID = re.compile(r"[0-9a-f]{32}")
_RULE_IDS: Final = frozenset(
    {"ci.workflow.untrusted-checkout", "ci.workflow.write-all-permissions", "ci.workflow.unpinned-action"}
)
_REASON = re.compile(r"[a-z0-9_]{1,40}")
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})
_CONFIDENCES: Final = frozenset({"weak", "likely", "strong"})
_CATEGORY = re.compile(r"[a-z_]{1,32}")
# Any `.yml` or `.yaml` file directly in the root workflows directory, within
# the native snapshot's path bound.
_WORKFLOW_FILE = re.compile(r"\.github/workflows/[^/\0]*\.ya?ml")
_MAX_PATH_BYTES: Final = 4096
_MAX_TEXT_CHARS: Final = 1024
_SKIP_KINDS: Final = ("oversize", "not_text", "unread", "linked")


def project_ci_workflow_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native workflow result."""

    return _projection(result)[0]


def with_ci_workflow_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the CI workflow detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every workflow, or a malformed reply, leaves it incomplete.
    Both make the run partial. A worktree without workflows has no inputs.
    """

    reasons = list(_list(coverage.get("reasons")))
    summary: dict[str, object] = {}
    if result is None:
        status = "not_run"
        reasons.append(f"detector_not_run:{CI_WORKFLOW_DETECTOR}")
    else:
        status, summary, truncation = _status(result)
        if status != "complete":
            reasons.append("ci_workflow_incomplete")
        if "max_findings" in truncation and "finding_cap" not in reasons:
            reasons.append("finding_cap")
        if status == "complete" and summary.get("files_scanned") == 0:
            status = "no_inputs"
    detectors = coverage.get("detectors")
    return {
        **coverage,
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "detectors": {**(detectors if isinstance(detectors, Mapping) else {}), CI_WORKFLOW_DETECTOR: status},
        **({"ci_workflow": summary} if summary else {}),
    }


def _status(result: object) -> tuple[str, dict[str, object], list[str]]:
    if not isinstance(result, Mapping) or result.get("schema") != WORKFLOWS_RESULT_SCHEMA:
        return "error", {}, ["unreadable_result"]
    status = result.get("status")
    # A reply without its findings list or its scan counts cannot show that
    # nothing was found.
    files_scanned = result.get("files_scanned")
    if (
        not isinstance(status, str)
        or status not in {"complete", "incomplete"}
        or not isinstance(result.get("findings"), list)
        or not isinstance(files_scanned, int)
        or isinstance(files_scanned, bool)
        or files_scanned < 0
        or not isinstance(result.get("skipped"), Mapping)
        or not isinstance(result.get("truncation_reasons"), list)
    ):
        return "error", {}, ["unreadable_result"]
    reasons = _reasons(result.get("truncation_reasons"))
    if _projection(result)[1]:
        reasons = sorted({*reasons, "invalid_finding"})
    if status == "incomplete" and not reasons:
        reasons = ["incomplete"]
    skipped = result.get("skipped")
    summary: dict[str, object] = {
        "files_scanned": files_scanned,
        "skipped": {kind: _count(skipped.get(kind)) if isinstance(skipped, Mapping) else 0 for kind in _SKIP_KINDS},
        "truncation_reasons": reasons,
    }
    return ("incomplete" if reasons else "complete"), summary, reasons


def _projection(result: object) -> tuple[list[dict[str, object]], int]:
    raw = result.get("findings") if isinstance(result, Mapping) else None
    if not isinstance(raw, list):
        return [], 0
    kept = raw[:MAX_CI_WORKFLOW_FINDINGS]
    findings = [finding for item in kept if (finding := _finding(item)) is not None]
    return findings, len(kept) - len(findings) + max(0, len(raw) - MAX_CI_WORKFLOW_FINDINGS)


def _finding(item: object) -> dict[str, object] | None:
    if not isinstance(item, Mapping):
        return None
    finding_id = item.get("finding_id")
    rule_id = item.get("rule_id")
    path = item.get("path")
    category = item.get("category")
    severity = item.get("severity")
    confidence = item.get("confidence")
    title = _text(item.get("title"))
    reason = _text(item.get("reason"))
    hint = item.get("false_positive_hint")
    if (
        not isinstance(finding_id, str)
        or not _FINDING_ID.fullmatch(finding_id)
        or not isinstance(rule_id, str)
        or rule_id not in _RULE_IDS
        or not isinstance(path, str)
        or len(path.encode("utf-8", "surrogatepass")) > _MAX_PATH_BYTES
        or not _WORKFLOW_FILE.fullmatch(path)
        or not isinstance(category, str)
        or not _CATEGORY.fullmatch(category)
        or not isinstance(severity, str)
        or severity not in _SEVERITIES
        or not isinstance(confidence, str)
        or confidence not in _CONFIDENCES
        or title is None
        or reason is None
        or (hint is not None and _text(hint) is None)
    ):
        return None
    return {
        "finding_id": finding_id,
        "source_kind": CI_WORKFLOW_SOURCE_KIND,
        "detector": CI_WORKFLOW_DETECTOR,
        "severity": severity,
        "decision": "warn",
        "ecosystem": None,
        "package_name": None,
        "package_version": None,
        "fix_version": None,
        "rule_ids": [rule_id],
        "advisory_ids": [],
        "path": path,
        "line": None,
        "category": category,
        "confidence": confidence,
        "title": title,
        "reason": reason,
        "false_positive_hint": _text(hint),
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
    }


def _text(value: object) -> str | None:
    """Fixed rule text: one bounded printable line."""

    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_TEXT_CHARS:
        return None
    return value if value.isprintable() else None


def _reasons(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and _REASON.fullmatch(item)})


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, (list, tuple)) else []


__all__ = [
    "CI_WORKFLOW_DETECTOR",
    "CI_WORKFLOW_SOURCE_KIND",
    "MAX_CI_WORKFLOW_FINDINGS",
    "project_ci_workflow_findings",
    "with_ci_workflow_coverage",
]
