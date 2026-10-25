"""The ``runtimes`` section of fleet posture: projection, privacy, caching and size priority."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime import fleet_posture as fp
from codex_plugin_scanner.guard.runtime import fleet_posture_runtimes as fpr
from codex_plugin_scanner.guard.runtime.fleet_posture_common import keyed_digest
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_fleet_posture_builder import NOW, FakeAdapter, _build, _config, _row, _set_inventory, _validate

KEY = b"k" * 32
EXE = "e" * 64
PATH = "/Users/ada/.nvm/versions/node/v22.11.0/bin/node"


def _posture(rows: list[dict[str, object]], **overrides: object) -> dict[str, object]:
    posture: dict[str, object] = {
        "status": "ok",
        "error": None,
        "coverage": {
            "mode": "observed_only",
            "advisories_available": False,
            "reason": "runtime_advisories_unavailable",
        },
        "candidate_limit_reached": False,
        "unresolved_launches": [{"harness": "codex", "server": "github", "command": "ghx", "lookup": "path"}],
        "runtimes": rows,
    }
    posture.update(overrides)
    return posture


def _runtime(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "location_id": "loc-1",
        "path": PATH,
        "location_state": "present",
        "reason": None,
        "launched_by": [
            {"harness": "codex", "server": "acme-internal-db", "role": "command"},
            {"harness": "claude-code", "server": "acme-internal-db", "role": "command"},
            {"harness": "codex", "server": "other", "role": "command"},
            {"harness": "not-a-harness", "server": "x", "role": "command"},
        ],
        "artifact_id": "art-1",
        "family": "node",
        "version": "22.11.0",
        "identity_assurance": "self_reported",
        "executable_sha256": EXE,
        "os": "macos",
        "arch": "arm64",
        "advisory_matches": [{"advisory_id": "GHSA-aaaa", "status": "affected", "reason": "version"}],
    }
    row.update(overrides)
    return row


@pytest.fixture
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


@pytest.fixture
def context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")


def test_projection_names_no_path_server_or_command() -> None:
    section = fpr.project_runtime_posture(_posture([_runtime()]), hash_key=KEY)

    assert section == {
        "status": "ok",
        "reason": None,
        "coverage": "observed_only",
        "scopeComplete": False,
        "advisoriesAvailable": False,
        "candidateLimitReached": False,
        "unresolvedLaunches": 1,
        "items": [
            {
                "family": "node",
                "version": "22.11.0",
                "identityAssurance": "self_reported",
                "executableHash": f"sha256:{EXE}",
                "os": "macos",
                "arch": "arm64",
                "locationState": "present",
                "reason": None,
                "locationHash": keyed_digest(KEY, PATH),
                "harnesses": ["claude-code", "codex"],
                "advisoryIds": ["GHSA-aaaa"],
            }
        ],
    }
    text = json.dumps(section)
    for private in ("/Users", "ada", "acme-internal-db", "ghx", "github", "loc-1", "art-1"):
        assert private not in text


def test_unexpected_values_fall_back_to_unknown() -> None:
    row = _runtime(
        path=None,
        family="Node JS",
        os=None,
        arch="x86-64",
        identity_assurance="vendor_signed",
        location_state="gone",
        reason="Not A Code",
        executable_sha256="E" * 64,
        version="9" * 80,
        advisory_matches=["GHSA-b", "GHSA-b", {"advisory_id": ""}, 7],
    )

    [item] = fpr.project_runtime_posture(_posture([row]), hash_key=KEY)["items"]  # type: ignore[misc]

    assert item["family"] == item["os"] == item["arch"] == "unknown"
    assert item["identityAssurance"] == item["locationState"] == item["reason"] == "unknown"
    assert item["executableHash"] is None and item["locationHash"] is None
    assert item["version"] == "9" * 64
    assert item["advisoryIds"] == ["GHSA-b"]


def test_more_than_the_limit_is_reported_partial() -> None:
    section = fpr.project_runtime_posture(_posture([_runtime()] * (fpr.MAX_RUNTIMES + 1)), hash_key=KEY)

    assert len(section["items"]) == fpr.MAX_RUNTIMES  # type: ignore[arg-type]
    assert (section["status"], section["reason"], section["candidateLimitReached"]) == (
        "partial",
        "runtime_candidate_limit_reached",
        True,
    )


def test_unavailable_native_probe_is_reported_not_hidden() -> None:
    posture = _posture([], status="unavailable", error="native_runtime_unavailable", unresolved_launches=[])

    section = fpr.project_runtime_posture(posture, hash_key=KEY)

    assert (section["status"], section["reason"], section["items"]) == ("unavailable", "native_runtime_unavailable", [])


def test_posture_carries_runtimes_and_matches_the_contract(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [_row("skill-a")])
    monkeypatch.setattr(fpr, "_observe", lambda _context, _now: _posture([_runtime()]))

    payload = _build(store, context, [FakeAdapter("claude-code")]).payload

    _validate(payload)
    runtimes = payload["runtimes"]
    assert runtimes["items"][0]["harnesses"] == ["claude-code", "codex"]  # type: ignore[index]


def test_minimal_reporting_leaves_runtimes_out(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    monkeypatch.setattr(fpr, "_observe", pytest.fail)

    payload = _build(store, context, [FakeAdapter("claude-code")], reporting_enabled=False).payload

    assert "runtimes" not in payload


def test_runtimes_are_observed_once_per_ttl(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])
    calls: list[object] = []

    def observe(_context: object, now: object) -> dict[str, object]:
        calls.append(now)
        return _posture([_runtime()])

    monkeypatch.setattr(fpr, "_observe", observe)
    adapters = [FakeAdapter("claude-code")]

    def build_at(minutes: int) -> dict[str, object]:
        settings = fp.FleetPostureSettings(
            context=context,
            guard_config=_config(),
            now=NOW + timedelta(minutes=minutes),  # type: ignore[arg-type]
        )
        return fp.build_fleet_posture_state(store, adapters, settings).payload

    first = build_at(0)
    second = build_at(59)
    assert len(calls) == 1
    assert second["runtimes"] == first["runtimes"]

    build_at(60)
    assert len(calls) == 2


def test_failed_observation_omits_the_section_and_is_retried(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_inventory(store, monkeypatch, [])

    def broken(_context: object, _now: object) -> dict[str, object]:
        raise OSError("boom")

    monkeypatch.setattr(fpr, "_observe", broken)
    adapters = [FakeAdapter("claude-code")]
    assert "runtimes" not in _build(store, context, adapters).payload

    monkeypatch.setattr(fpr, "_observe", lambda _context, _now: _posture([_runtime()]))
    assert "runtimes" in _build(store, context, adapters).payload


def test_runtimes_give_way_before_inventory_rows(
    store: GuardStore, context: HarnessContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_row(f"skill-{index}") for index in range(20)]
    _set_inventory(store, monkeypatch, rows)
    adapters = [FakeAdapter("claude-code")]
    monkeypatch.setattr(fpr, "_observe", lambda _context, _now: _posture([]))
    without = _build(store, context, adapters, runtimes_ttl_seconds=0).payload
    del without["runtimes"]
    budget = fp.json_size(without) + 16
    monkeypatch.setattr(fp, "MAX_PAYLOAD_BYTES", budget)
    monkeypatch.setattr(fpr, "_observe", lambda _context, _now: _posture([_runtime()] * fpr.MAX_RUNTIMES))

    payload = _build(store, context, adapters, runtimes_ttl_seconds=0).payload

    assert "runtimes" not in payload
    assert len(payload["inventory"]["items"]) == len(rows)  # type: ignore[index, arg-type]
