"""Project the local supply chain audit into workspace findings.

Each package the audit asks about, blocks or warns on becomes one finding
named by its coordinate: ecosystem, scoped name and resolved version. New rule data,
a second lockfile listing the same package or another advisory adds evidence
to that finding instead of making a new one. A package whose lookup could not
be answered offline is a coverage gap, not a finding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Final

SUPPLY_CHAIN_DETECTOR: Final = "supply_chain_local_v1"
_MAX_LIST_ITEMS: Final = 8
_SEVERITY_ORDER: Final = ("critical", "high", "medium", "low", "info", "unknown")
_FINDING_DECISIONS: Final = frozenset({"block", "ask", "warn"})
# An automatic run never asks Cloud, so a package the cached bundle does not
# cover comes back with one of these codes. They mean the answer is unknown,
# which is a coverage gap rather than evidence that the package is risky.
_LOOKUP_UNAVAILABLE: Final = frozenset(
    {"cloud_auth_error", "cloud_http_error", "cloud_timeout", "cloud_validation_error"}
)
# With no advisory bundle cached, a package Guard only recorded was never
# compared with any intelligence: it is unknown, not clean.
_NO_CACHED_MATCH: Final = "no_cached_match"


def supply_chain_findings(worktree_key: str, payload: Mapping[str, object]) -> list[dict[str, object]]:
    """Project audit packages into workspace findings, most severe first.

    A finding carries package coordinates, reason codes and advisory
    identifiers. It never carries file content, commands or local paths.
    Its identity is the package coordinate alone: new rule data adds reasons
    to the same finding instead of replacing it with another one.
    """

    findings: dict[str, dict[str, object]] = {}
    for package in _packages(payload):
        decision = str(package.get("decision") or "")
        if decision not in _FINDING_DECISIONS or _lookup_unavailable(package):
            continue
        ecosystem = _text(package.get("ecosystem")) or "unknown"
        name = package_name(package)
        if name is None:
            continue
        version = _text(package.get("resolvedVersion")) or _text(package.get("requestedVersion"))
        raw_reasons = package.get("reasons")
        reasons = [item for item in raw_reasons if isinstance(item, Mapping)] if isinstance(raw_reasons, list) else []
        rule_ids = {value[:128] for item in reasons if (value := _text(item.get("code")))}
        if (rule_id := _text(package.get("ruleId"))) is not None:
            rule_ids.add(rule_id[:128])
        advisories = {value for item in reasons if (value := _text(item.get("advisoryId")))}
        advisories.update(_strings(package.get("relatedAdvisoryIds")))
        advisories.update(_strings(package.get("advisoryAliases")))
        finding_id = hashlib.sha256(
            "\0".join(
                ("guard.workspace-finding.v1", worktree_key, "supply_chain", ecosystem, name, version or "")
            ).encode("utf-8")
        ).hexdigest()[:32]
        severity = _max_severity(reasons)
        fix_version = _text(package.get("recommendedFixVersion"))
        if (earlier := findings.get(finding_id)) is not None:
            # The same package listed twice is more evidence for one finding.
            rule_ids.update(_strings(earlier["rule_ids"]))
            advisories.update(_strings(earlier["advisory_ids"]))
            severity = min(severity, earlier["severity"], key=_SEVERITY_ORDER.index)
            decision = min(decision, earlier["decision"], key=("block", "ask", "warn").index)
            fix_version = earlier["fix_version"] or fix_version
        findings[finding_id] = {
            "finding_id": finding_id,
            "source_kind": "supply_chain",
            "detector": SUPPLY_CHAIN_DETECTOR,
            "severity": severity,
            "decision": decision,
            "ecosystem": ecosystem,
            "package_name": name,
            "package_version": version,
            "fix_version": fix_version,
            "rule_ids": sorted(rule_ids)[:_MAX_LIST_ITEMS],
            "advisory_ids": sorted(advisories)[:_MAX_LIST_ITEMS],
            "validation_state": "confirmed",
            "lifecycle_state": "open",
        }
    return sorted(
        findings.values(),
        key=lambda item: (_SEVERITY_ORDER.index(str(item["severity"])), str(item["package_name"])),
    )


def package_name(package: Mapping[str, object]) -> str | None:
    """The package name with its namespace, such as `@scope/pkg` for npm.

    The audit reports a scoped package's namespace apart from its name, and
    `@a/pkg` is a different package from `pkg`.
    """

    name = _text(package.get("name"))
    namespace = _text(package.get("namespace"))
    if name is None or namespace is None or name.startswith(f"{namespace}/"):
        return name
    return f"{namespace}/{name}"[:256]


def _packages(payload: Mapping[str, object]) -> list[Mapping[str, object]]:
    evaluation = payload.get("evaluation")
    packages = evaluation.get("packages") if isinstance(evaluation, Mapping) else None
    return [item for item in packages if isinstance(item, Mapping)] if isinstance(packages, list) else []


def _lookup_unavailable(package: Mapping[str, object]) -> bool:
    if package.get("decision") == "block":
        return False
    codes = _reason_codes(package)
    return bool(codes) and codes <= _LOOKUP_UNAVAILABLE


def _reason_codes(package: Mapping[str, object]) -> set[object]:
    reasons = package.get("reasons")
    codes = {item.get("code") for item in reasons if isinstance(item, Mapping)} if isinstance(reasons, list) else set()
    codes.add(package.get("ruleId"))
    codes.discard(None)
    return codes


def unresolved_packages(payload: Mapping[str, object]) -> int:
    return sum(1 for package in _packages(payload) if _lookup_unavailable(package))


def unchecked_packages(payload: Mapping[str, object]) -> int:
    """Packages that went unchecked because no advisory bundle is cached."""

    evaluation = payload.get("evaluation")
    if not isinstance(evaluation, Mapping) or evaluation.get("bundle_version") is not None:
        return 0
    # The evaluator can add review reasons (an unidentified package, a lockfile
    # drift) beside the miss; none of them means advisories were consulted.
    return sum(1 for package in _packages(payload) if _NO_CACHED_MATCH in _reason_codes(package))


def _max_severity(reasons: list[Mapping[str, object]]) -> str:
    found = {str(item.get("severity") or "").lower() for item in reasons}
    return next((level for level in _SEVERITY_ORDER if level in found), "unknown")


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped[:256] if stripped else None


def _strings(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item[:256] for item in value if isinstance(item, str) and item]


__all__ = [
    "SUPPLY_CHAIN_DETECTOR",
    "package_name",
    "supply_chain_findings",
    "unchecked_packages",
    "unresolved_packages",
]
