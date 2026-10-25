"""Project the native secret scan into workspace findings and coverage.

The native snapshot has already redacted every finding: it carries a rule id,
a root-relative path, a line and a keyed fingerprint, never the matched text.
This module only validates that shape and reshapes it. Anything that does not
match the expected shape is dropped rather than copied, so a malformed reply
cannot smuggle free text into stored findings.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Final

SECRET_DETECTOR: Final = "secrets"
SECRETS_RESULT_SCHEMA: Final = "guard.workspace-secrets.v1"
MAX_SECRET_FINDINGS: Final = 500

_RULE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_FINGERPRINT = re.compile(r"[0-9a-f]{32}")
_REASON = re.compile(r"[a-z0-9_]{1,40}")
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})
_MAX_PATH_CHARS: Final = 1024
_SKIP_KINDS: Final = ("credential_store", "not_text", "oversize")


def project_secret_findings(worktree_key: str, result: object) -> list[dict[str, object]]:
    """Return one finding per distinct secret location in the native result."""

    raw = result.get("findings") if isinstance(result, Mapping) else None
    if not isinstance(raw, list):
        return []
    findings: dict[str, dict[str, object]] = {}
    for item in raw[:MAX_SECRET_FINDINGS]:
        finding = _finding(worktree_key, item)
        if finding is not None:
            findings.setdefault(str(finding["finding_id"]), finding)
    return list(findings.values())


def secret_coverage(result: object) -> tuple[str, dict[str, object], list[str]]:
    """Return the detector status, a coverage summary and any truncation reasons.

    The status is ``complete`` only for a well-formed result that scanned every
    file it was given; a missing or malformed result is an ``error``.
    """

    if not isinstance(result, Mapping) or result.get("schema") != SECRETS_RESULT_SCHEMA:
        return "error", {}, ["unreadable_result"]
    reasons = _reasons(result.get("truncation_reasons"))
    status = result.get("status")
    if status not in {"complete", "incomplete"}:
        return "error", {}, ["unreadable_result"]
    if status == "incomplete" and not reasons:
        reasons = ["incomplete"]
    skipped = result.get("skipped")
    summary: dict[str, object] = {
        "files_scanned": _count(result.get("files_scanned")),
        "bytes_scanned": _count(result.get("bytes_scanned")),
        "skipped": {kind: _count(skipped.get(kind)) if isinstance(skipped, Mapping) else 0 for kind in _SKIP_KINDS},
        "truncation_reasons": reasons,
    }
    return ("complete" if status == "complete" and not reasons else "incomplete"), summary, reasons


def _finding(worktree_key: str, item: object) -> dict[str, object] | None:
    if not isinstance(item, Mapping):
        return None
    rule_id = item.get("rule_id")
    path = item.get("path")
    line = item.get("line")
    fingerprint = item.get("fingerprint")
    if (
        not isinstance(rule_id, str)
        or not _RULE_ID.fullmatch(rule_id)
        or not isinstance(path, str)
        or not path
        or len(path) > _MAX_PATH_CHARS
        or "\0" in path
        or isinstance(line, bool)
        or not isinstance(line, int)
        or line < 1
        or not isinstance(fingerprint, str)
        or not _FINGERPRINT.fullmatch(fingerprint)
    ):
        return None
    severity = str(item.get("severity") or "").lower()
    # The line is left out of the identity so the same secret keeps its
    # finding when surrounding lines move.
    finding_id = hashlib.sha256(
        "\0".join(("guard.workspace-finding.v1", worktree_key, "secret", rule_id, path, fingerprint)).encode("utf-8")
    ).hexdigest()[:32]
    return {
        "finding_id": finding_id,
        "source_kind": "secret",
        "detector": SECRET_DETECTOR,
        "severity": severity if severity in _SEVERITIES else "unknown",
        "decision": "warn",
        "ecosystem": None,
        "package_name": None,
        "package_version": None,
        "fix_version": None,
        "rule_ids": [rule_id],
        "advisory_ids": [],
        "path": path,
        "line": line,
        "fingerprint": fingerprint,
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
    }


def _reasons(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and _REASON.fullmatch(item)})


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


__all__ = [
    "MAX_SECRET_FINDINGS",
    "SECRET_DETECTOR",
    "project_secret_findings",
    "secret_coverage",
]
