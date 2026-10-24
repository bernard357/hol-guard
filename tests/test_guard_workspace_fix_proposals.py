"""Prepare, apply and verify reviewed dependency fixes for workspace findings."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_connection_schema as connection_schema
from codex_plugin_scanner.guard import workspace_assessment_fix_proposals as fixes
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.workspace_assessment_fix_manifest import FixUnsupportedError, plan_edits
from tests.workspace_fix_support import (
    COMPLETE_SUPPLY_CHAIN,
    FINDING_ID,
    FIXED_MANIFEST,
    KEYS,
    MANIFEST,
    T0,
    assess,
    digest,
    finding,
    seeded_store,
    write_manifest,
)

NOW = T0 + 10_000


def _prepared(tmp_path: Path, *, spec: str | None = None, finding_overrides: dict[str, object] | None = None):
    root = tmp_path / "work"
    text = MANIFEST if spec is None else f'{{"dependencies": {{"minimist": "{spec}"}}}}'
    manifest = write_manifest(root, text)
    store = seeded_store(tmp_path, root)
    assess(store, snapshot="before", at=T0 + 100, findings=[finding(**(finding_overrides or {}))])
    return store, root, manifest


def _prepare(store, **kwargs):
    return fixes.prepare(store, KEYS, FINDING_ID, now_ms=NOW, **kwargs)


def test_prepare_edits_only_the_direct_version_specs_and_keeps_every_other_byte(tmp_path: Path) -> None:
    store, _root, manifest = _prepared(tmp_path)
    before = manifest.read_bytes()

    result = _prepare(store)

    [proposal] = result["proposals"]
    assert proposal["state"] == "prepared"
    assert proposal["manifest_path"] == "package.json"
    assert [(e["section"], e["from_spec"], e["to_spec"]) for e in proposal["edits"]] == [
        ("dependencies", "^1.2.0", "^1.2.9"),
        ("devDependencies", "~1.2.0", "~1.2.9"),
    ]
    assert proposal["base_sha256"] == hashlib.sha256(before).hexdigest()
    expected = FIXED_MANIFEST.replace("\n", "\r\n").encode()
    assert proposal["new_sha256"] == hashlib.sha256(expected).hexdigest()
    assert proposal["snapshot_digest"] == assessments.latest_assessed_run(store, KEYS)["snapshot_digest"]
    assert proposal["finding_id"] == FINDING_ID
    assert '-        "minimist": "^1.2.0"' in proposal["diff"]
    assert '+        "minimist": "^1.2.9"' in proposal["diff"]
    assert "other" not in "".join(line for line in proposal["diff"].splitlines() if line[:1] in "+-")
    assert manifest.read_bytes() == before, "prepare must not write"


def test_prepare_is_idempotent_and_supersedes_a_proposal_for_a_changed_manifest(tmp_path: Path) -> None:
    store, _root, manifest = _prepared(tmp_path)
    [first] = _prepare(store)["proposals"]
    [again] = _prepare(store)["proposals"]
    assert again["proposal_id"] == first["proposal_id"]

    manifest.write_bytes(manifest.read_bytes() + b"\n")
    [second] = _prepare(store)["proposals"]

    assert second["proposal_id"] != first["proposal_id"]
    states = {p["proposal_id"]: p["state"] for p in fixes.list_proposals(store, KEYS, now_ms=NOW)}
    assert states == {first["proposal_id"]: "stale", second["proposal_id"]: "prepared"}


def test_transitive_only_dependency_is_refused_with_a_reason(tmp_path: Path) -> None:
    store, _root, _manifest = _prepared(tmp_path, finding_overrides={"package_name": "left-pad"})
    with pytest.raises(fixes.FixProposalError) as caught:
        _prepare(store)
    assert (caught.value.code, caught.value.status) == ("fix_unsupported", 422)
    assert caught.value.detail["reason"] == "transitive_dependency"


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        ("git+https://example.test/minimist.git", "spec_git_or_url"),
        ("https://example.test/minimist.tgz", "spec_git_or_url"),
        ("file:../minimist", "spec_local_path"),
        ("workspace:*", "spec_workspace_protocol"),
        ("npm:other@^1.2.0", "spec_npm_alias"),
        ("latest", "spec_dist_tag"),
        (">=1.2.0 <2", "spec_not_plain_semver"),
        ("1.x", "spec_not_plain_semver"),
    ],
)
def test_specs_that_are_not_plain_semver_are_refused(tmp_path: Path, spec: str, reason: str) -> None:
    store, _root, manifest = _prepared(tmp_path, spec=spec)
    before = manifest.read_bytes()
    with pytest.raises(fixes.FixProposalError) as caught:
        _prepare(store)
    assert caught.value.status == 422
    assert caught.value.detail["reason"] == reason
    assert manifest.read_bytes() == before


def test_a_declared_range_that_already_allows_the_fix_is_not_rewritten(tmp_path: Path) -> None:
    store, _root, _manifest = _prepared(tmp_path, spec="^1.4.0")
    with pytest.raises(fixes.FixProposalError) as caught:
        _prepare(store)
    assert caught.value.detail["reason"] == "declared_range_already_covers_fix"


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"source_kind": "secret"}, "unsupported_source"),
        ({"ecosystem": "pypi"}, "unsupported_ecosystem"),
        ({"fix_version": None}, "no_fix_version"),
    ],
)
def test_only_supply_chain_npm_findings_with_a_fix_version_are_eligible(
    tmp_path: Path, overrides: dict[str, object], reason: str
) -> None:
    store, _root, _manifest = _prepared(tmp_path, finding_overrides=overrides)
    with pytest.raises(fixes.FixProposalError) as caught:
        _prepare(store)
    assert caught.value.detail["reason"] == reason


def test_a_finding_from_an_older_run_is_not_eligible(tmp_path: Path) -> None:
    store, _root, _manifest = _prepared(tmp_path)
    assess(store, snapshot="later", at=T0 + 300, findings=[])
    with pytest.raises(fixes.FixProposalError) as caught:
        _prepare(store)
    assert (caught.value.code, caught.value.status) == ("finding_not_found", 404)


def test_unknown_worktree_has_no_proposals(tmp_path: Path) -> None:
    store = seeded_store(tmp_path, tmp_path)
    other = assessments.WorktreeKeys("a" * 64, "b" * 64)
    with pytest.raises(fixes.FixProposalError) as caught:
        fixes.prepare(store, other, FINDING_ID, now_ms=NOW)
    assert caught.value.status == 404


def test_a_symlinked_manifest_is_refused_and_never_followed(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"dependencies": {"minimist": "^1.2.0"}}', encoding="utf-8")
    (root / "package.json").symlink_to(outside)
    store = seeded_store(tmp_path, root)
    assess(store, snapshot="before", at=T0 + 100)

    with pytest.raises(fixes.FixProposalError) as caught:
        _prepare(store)

    assert caught.value.detail["reason"] == "manifest_is_symlink"
    assert outside.read_text(encoding="utf-8") == '{"dependencies": {"minimist": "^1.2.0"}}'


def test_a_symlinked_directory_is_not_entered(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    real = tmp_path / "elsewhere"
    write_manifest(real)
    (root / "linked").symlink_to(real, target_is_directory=True)
    store = seeded_store(tmp_path, root)
    assess(store, snapshot="before", at=T0 + 100)

    with pytest.raises(fixes.FixProposalError) as caught:
        _prepare(store)

    assert caught.value.detail["reason"] == "transitive_dependency"


def test_dependency_directories_are_skipped_and_nested_manifests_are_found(tmp_path: Path) -> None:
    root = tmp_path / "work"
    write_manifest(root / "node_modules" / "dep")
    write_manifest(root / "packages" / "app")
    store = seeded_store(tmp_path, root)
    assess(store, snapshot="before", at=T0 + 100)

    [proposal] = _prepare(store)["proposals"]

    assert proposal["manifest_path"] == "packages/app/package.json"


def test_apply_replaces_the_manifest_atomically_keeps_its_mode_and_queues_verification(tmp_path: Path) -> None:
    store, root, manifest = _prepared(tmp_path)
    manifest.chmod(0o640)
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n", encoding="utf-8")
    [proposal] = _prepare(store)["proposals"]
    inode_before = manifest.stat().st_ino
    replaced: list[str] = []
    real_replace = os.replace

    def spy(source, destination, *args, **kwargs):
        # The shared writer swaps by name inside the manifest's own directory.
        replaced.append((os.fspath(source), os.fspath(destination), kwargs.get("src_dir_fd") is not None))
        assert os.path.dirname(os.fspath(source)) == os.path.dirname(os.fspath(destination))
        return real_replace(source, destination, *args, **kwargs)

    os.replace = spy
    try:
        result = fixes.apply(store, proposal["proposal_id"], now_ms=NOW + 5)
    finally:
        os.replace = real_replace

    assert manifest.read_bytes() == FIXED_MANIFEST.replace("\n", "\r\n").encode()
    assert len(replaced) == 1
    assert replaced[0][1] == "package.json" and replaced[0][0] != "package.json"
    assert manifest.stat().st_ino != inode_before
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o640
    assert [p.name for p in root.iterdir() if p.name.startswith(".")] == []
    assert result["lockfile_update_required"] is True
    assert result["lockfiles"] == ["pnpm-lock.yaml"]
    assert result["proposal"]["state"] == "applied"
    assert result["proposal"]["applied_at_ms"] == NOW + 5
    run_id = result["verification_run_id"]
    assert run_id
    with store._connect() as connection:
        row = connection.execute(
            "select trigger_kind, state from workspace_assessment_runs where run_id = ?", (run_id,)
        ).fetchone()
    assert tuple(row) == ("fix_verification", "queued")


def test_stale_apply_is_a_conflict_and_writes_nothing(tmp_path: Path) -> None:
    store, _root, manifest = _prepared(tmp_path)
    [proposal] = _prepare(store)["proposals"]
    edited = manifest.read_bytes().replace(b"1.0.0", b"1.0.1")
    manifest.write_bytes(edited)

    with pytest.raises(fixes.FixProposalError) as caught:
        fixes.apply(store, proposal["proposal_id"], now_ms=NOW + 5)

    assert (caught.value.code, caught.value.status) == ("fix_proposal_stale", 409)
    assert manifest.read_bytes() == edited
    [listed] = fixes.list_proposals(store, KEYS, now_ms=NOW + 6)
    assert listed["state"] == "stale"
    with pytest.raises(fixes.FixProposalError) as again:
        fixes.apply(store, proposal["proposal_id"], now_ms=NOW + 7)
    assert again.value.code == "fix_proposal_stale"
    assert manifest.read_bytes() == edited


def test_apply_refuses_a_manifest_replaced_by_a_symlink(tmp_path: Path) -> None:
    store, _root, manifest = _prepared(tmp_path)
    [proposal] = _prepare(store)["proposals"]
    target = tmp_path / "elsewhere.json"
    target.write_bytes(manifest.read_bytes())
    manifest.unlink()
    manifest.symlink_to(target)

    with pytest.raises(fixes.FixProposalError) as caught:
        fixes.apply(store, proposal["proposal_id"], now_ms=NOW + 5)

    assert caught.value.status == 409
    assert target.read_bytes() == MANIFEST.replace("\n", "\r\n").encode()


def test_apply_runs_once_and_unknown_ids_are_not_found(tmp_path: Path) -> None:
    store, _root, _manifest = _prepared(tmp_path)
    [proposal] = _prepare(store)["proposals"]
    fixes.apply(store, proposal["proposal_id"], now_ms=NOW + 5)
    with pytest.raises(fixes.FixProposalError) as twice:
        fixes.apply(store, proposal["proposal_id"], now_ms=NOW + 6)
    assert (twice.value.code, twice.value.status) == ("fix_proposal_not_prepared", 409)
    with pytest.raises(fixes.FixProposalError) as missing:
        fixes.apply(store, "0" * 32, now_ms=NOW + 6)
    assert missing.value.status == 404


def _applied(tmp_path: Path):
    store, _root, _manifest = _prepared(tmp_path)
    [proposal] = _prepare(store)["proposals"]
    fixes.apply(store, proposal["proposal_id"], now_ms=NOW)
    # The queued fix_verification run is the one a worker would pick up next.
    return store, proposal["proposal_id"]


def _state(store, proposal_id: str) -> str:
    [listed] = [p for p in fixes.list_proposals(store, KEYS, now_ms=NOW + 99_000) if p["proposal_id"] == proposal_id]
    return str(listed["state"])


def _verification_run(store, *, snapshot: str, findings, coverage=None) -> None:
    claimed = assessments.claim_next(store, owner="verify", now_ms=NOW + 1_000)
    assert claimed is not None and claimed.trigger_kind == "fix_verification"
    outcome = assessments.RunOutcome(
        state="partial",
        snapshot_digest=digest(snapshot),
        coverage=COMPLETE_SUPPLY_CHAIN if coverage is None else coverage,
        findings=findings,
    )
    assert assessments.finish(store, claimed, outcome, now_ms=NOW + 2_000)


def test_a_complete_supply_chain_run_without_the_finding_marks_it_fixed(tmp_path: Path) -> None:
    store, proposal_id = _applied(tmp_path)
    assert _state(store, proposal_id) == "applied"

    # detector_not_run:secrets is in COMPLETE_SUPPLY_CHAIN and must not block.
    _verification_run(store, snapshot="after", findings=[])

    assert _state(store, proposal_id) == "verified_fixed"
    [listed] = fixes.list_proposals(store, KEYS, now_ms=NOW + 99_000)
    assert listed["verification_run_id"] and listed["verified_at_ms"] == NOW + 99_000
    assert listed["diff"] is None


def test_a_complete_run_that_still_has_the_finding_marks_it_still_present(tmp_path: Path) -> None:
    store, proposal_id = _applied(tmp_path)
    _verification_run(store, snapshot="after", findings=[finding()])
    assert _state(store, proposal_id) == "still_present"


@pytest.mark.parametrize(
    "coverage",
    [
        {"reasons": ["supply_chain_incomplete"], "detectors": {"supply_chain": "incomplete"}},
        {"reasons": ["finding_cap"], "detectors": {"supply_chain": "complete"}},
        {"reasons": ["lockfile_warnings"], "detectors": {"supply_chain": "complete"}},
        {"reasons": ["snapshot_truncated"], "detectors": {"supply_chain": "complete"}},
        {"reasons": [], "detectors": {"supply_chain": "no_inputs"}},
        {"reasons": [], "detectors": {}},
        {},
    ],
)
def test_partial_coverage_never_marks_a_fix_verified(tmp_path: Path, coverage: dict[str, object]) -> None:
    store, proposal_id = _applied(tmp_path)
    _verification_run(store, snapshot="after", findings=[], coverage=coverage)
    assert _state(store, proposal_id) == "applied"


def test_a_run_on_the_same_snapshot_does_not_count(tmp_path: Path) -> None:
    store, proposal_id = _applied(tmp_path)
    _verification_run(store, snapshot="before", findings=[])
    assert _state(store, proposal_id) == "applied"


def test_a_run_that_started_before_the_apply_does_not_count(tmp_path: Path) -> None:
    store, _root, _manifest = _prepared(tmp_path)
    [proposal] = _prepare(store)["proposals"]
    assess(store, snapshot="raced", at=T0 + 500, findings=[])
    fixes.apply(store, proposal["proposal_id"], now_ms=T0 + 5_000)
    assert _state(store, proposal["proposal_id"]) == "applied"


def test_list_is_bounded(tmp_path: Path) -> None:
    store, _root, manifest = _prepared(tmp_path)
    for _ in range(3):
        manifest.write_bytes(manifest.read_bytes() + b" ")
        _prepare(store)
    assert len(fixes.list_proposals(store, KEYS, limit=2, now_ms=NOW)) == 2
    assert len(fixes.list_proposals(store, KEYS, limit=10_000, now_ms=NOW)) == 3


def test_migration_34_adds_the_proposal_table_without_touching_other_tables(tmp_path: Path) -> None:
    store, _root, _manifest = _prepared(tmp_path)
    assert 34 in connection_schema._REQUIRED_SCHEMA_MIGRATION_VERSIONS
    with store._connect() as connection:
        versions = {row[0] for row in connection.execute("select version from schema_migrations")}
        tables = {row[0] for row in connection.execute("select name from sqlite_master where type = 'table'")}
    assert 34 in versions
    assert {"workspace_fix_proposals", "workspace_assessment_runs", "workspace_assessment_state"} <= tables


def test_plan_edits_leaves_unmatched_and_malformed_manifests_alone() -> None:
    with pytest.raises(FixUnsupportedError) as invalid:
        plan_edits('{"dependencies": {"minimist": "^1.2.0",}}', "minimist", "1.2.9")
    assert invalid.value.code == "manifest_invalid_json"
    with pytest.raises(FixUnsupportedError) as duplicate:
        plan_edits('{"dependencies": {"minimist": "^1.0.0", "minimist": "^1.1.0"}}', "minimist", "1.2.9")
    assert duplicate.value.code == "manifest_duplicate_declaration"
    with pytest.raises(FixUnsupportedError) as odd:
        plan_edits('{"dependencies": {"minimist": "^1.2.0"}}', "minimist", "latest")
    assert odd.value.code == "fix_version_not_plain_semver"
    [edit] = plan_edits('{"optionalDependencies":{"minimist":"1.0.0"}}', "minimist", "1.2.9")
    assert (edit.section, edit.to_spec) == ("optionalDependencies", "1.2.9")
