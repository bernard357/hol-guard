"""Contracts for the Cargo supply-chain gate in Security Gates.

The gate is what keeps an advisory, an unexpected registry or a second copy of a
crate out of the binary that decides what a harness may do, so the parts that
make it a gate rather than a report are pinned here: the four checks it runs,
the digest it verifies the tool against, and the settings in `rust/deny.toml`
that turn a finding into a failure.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security-gates.yml"
DENY_PATH = ROOT / "rust" / "deny.toml"
REQUIRED_CHECKS = ("advisories", "bans", "licenses", "sources")


def _job() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    job = workflow["jobs"]["cargo-deny"]
    assert isinstance(job, dict)
    return job


def _steps() -> list[dict[str, Any]]:
    steps = _job()["steps"]
    assert isinstance(steps, list)
    return steps


def _deny() -> dict[str, Any]:
    return tomllib.loads(DENY_PATH.read_text(encoding="utf-8"))


def test_gate_runs_every_check_against_the_workspace() -> None:
    commands = [step.get("run", "") for step in _steps()]
    check = next(command for command in commands if "cargo deny" in command)

    assert "--workspace" in check
    assert "--locked" in check
    for name in REQUIRED_CHECKS:
        assert f" {name}" in check


def test_the_tool_is_a_digest_verified_pinned_release() -> None:
    install = next(step for step in _steps() if step.get("name") == "Install cargo-deny")
    env = install["env"]
    version = env["CARGO_DENY_VERSION"]

    assert len(env["CARGO_DENY_SHA256"]) == 64
    assert "sha256sum --check --strict" in install["run"]
    assert f"/download/${{CARGO_DENY_VERSION}}/" in install["run"]

    cache = next(step for step in _steps() if step.get("id") == "cargo-deny-cache")
    # A cache key that outlives a version bump would serve the old binary.
    assert cache["with"]["key"].endswith(f"-v{version}")


def test_the_gate_fails_rather_than_warns() -> None:
    deny = _deny()

    assert deny["advisories"]["yanked"] == "deny"
    assert deny["advisories"]["unmaintained"] == "all"
    assert deny["bans"]["multiple-versions"] == "deny"
    assert deny["bans"]["wildcards"] == "deny"
    assert deny["sources"]["unknown-registry"] == "deny"
    assert deny["sources"]["unknown-git"] == "deny"
    assert deny["sources"]["allow-git"] == []


def test_licenses_are_allow_listed_and_cover_what_ships() -> None:
    licenses = _deny()["licenses"]

    # Everything not named here is denied, so the workspace's own terms and the
    # build scripts that produce the shipped binary both have to be in scope.
    assert "Apache-2.0" in licenses["allow"]
    assert licenses["include-build"] is True
    assert all("GPL" not in entry for entry in licenses["allow"])


def test_every_duplicate_exception_carries_a_reason() -> None:
    bans = _deny()["bans"]

    for entry in bans["skip"]:
        assert "@" in entry["crate"], entry
        assert entry["reason"].strip(), entry
    for entry in bans["deny"]:
        assert entry["reason"].strip(), entry
