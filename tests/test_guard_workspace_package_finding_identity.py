"""A package finding keeps its identity while the evidence for it changes.

New rule data, another lockfile naming the same package or an older run's
finding identity add evidence to one finding. None of them makes the same
package a second finding, so the finding's history, its fix proposals and its
Cloud key stay attached to the package.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from tests.test_guard_workspace_assessment_carry import T0, admitted, assess, outcome, package_finding
from tests.test_guard_workspace_assessment_runner import AUDIT, BLOCKED_PACKAGE, KEYS

INSTALL_SCRIPT = {"code": "install_script", "message": "m", "severity": "medium"}


def _project(*packages: dict[str, object]) -> list[dict[str, object]]:
    findings, _ = runner.project_supply_chain_findings(KEYS.worktree_key, {"evaluation": {"packages": list(packages)}})
    return findings


def test_new_rule_data_keeps_the_package_finding_id() -> None:
    [before] = _project(BLOCKED_PACKAGE)
    [after] = _project({**BLOCKED_PACKAGE, "reasons": [*BLOCKED_PACKAGE["reasons"], INSTALL_SCRIPT]})

    assert after["finding_id"] == before["finding_id"]
    assert "install_script" in after["rule_ids"]
    assert set(before["rule_ids"]) < set(after["rule_ids"])


def test_another_version_of_the_package_is_a_separate_finding() -> None:
    first, second = _project(BLOCKED_PACKAGE, {**BLOCKED_PACKAGE, "resolvedVersion": "0.0.8"})

    assert first["finding_id"] != second["finding_id"]


def test_a_package_listed_twice_is_one_finding_with_the_evidence_of_both() -> None:
    advisory_only = {
        **BLOCKED_PACKAGE,
        "decision": "warn",
        "ruleId": None,
        "recommendedFixVersion": None,
        "reasons": [BLOCKED_PACKAGE["reasons"][0]],
    }
    script_only = {
        **BLOCKED_PACKAGE,
        "relatedAdvisoryIds": [],
        "advisoryAliases": [],
        "reasons": [INSTALL_SCRIPT],
    }

    [finding] = _project(advisory_only, script_only)

    assert finding["decision"] == "block"
    assert finding["severity"] == "high"
    assert finding["fix_version"] == "1.2.9"
    assert finding["rule_ids"] == ["advisory_match", "install_script", "known-malicious"]
    assert finding["advisory_ids"] == ["CVE-2021-44906", "GHSA-xvch-5gv4-984h"]
    # The merge is order independent.
    assert _project(script_only, advisory_only) == [finding]


def test_the_projected_audit_still_names_one_finding_per_package() -> None:
    findings, _ = runner.project_supply_chain_findings(KEYS.worktree_key, AUDIT)

    assert [(item["package_name"], item["package_version"]) for item in findings] == [("minimist", "1.2.8")]


def test_a_partial_run_keeps_the_earlier_identity_of_a_package_it_reports(tmp_path: Path) -> None:
    # The earlier run recorded the package under another finding id, as runs
    # did while reason codes were part of the identity.
    store = admitted(tmp_path)
    listed = frozenset({("npm", "minimist", "1.2.8")})
    assess(store, outcome("completed", [package_finding("a" * 32, "1.2.8")], listed, supply_chain="complete"), at=T0)

    run = assess(
        store,
        outcome("partial", [package_finding("b" * 32, "1.2.8")], listed, supply_chain="incomplete"),
        at=T0 + 10,
    )

    assert [item["finding_id"] for item in run["findings"]] == ["a" * 32]
    assert "carried_findings" not in run["coverage"]


def test_a_completed_run_keeps_the_earlier_identity_of_each_package(tmp_path: Path) -> None:
    store = admitted(tmp_path)
    listed = frozenset({("npm", "minimist", "1.2.8"), ("npm", "minimist", "0.0.8")})
    assess(store, outcome("completed", [package_finding("a" * 32, "1.2.8")], listed, supply_chain="complete"), at=T0)

    run = assess(
        store,
        outcome(
            "completed",
            [package_finding("b" * 32, "1.2.8"), package_finding("c" * 32, "0.0.8")],
            listed,
            supply_chain="complete",
        ),
        at=T0 + 10,
    )

    # The package the earlier run named keeps its id; another version is new.
    assert [item["finding_id"] for item in run["findings"]] == ["a" * 32, "c" * 32]
