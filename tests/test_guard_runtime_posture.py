"""Read-only runtime posture: candidates, native probe, advisory coverage, CLI.

The posture is observation only. It must name the executables configured
servers would launch, never run them, report unknown as unknown, and say so
plainly when advisories or the native runtime are unavailable.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import runtime_posture
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime_identity_assessment import RuntimeIdentityError
from codex_plugin_scanner.guard.runtime_identity_probe import RUNTIME_PROBE_FEATURE, probe_runtime_paths
from codex_plugin_scanner.guard.runtime_posture import ADVISORIES_UNAVAILABLE, build_runtime_posture

NOW = "2026-01-01T00:00:00+00:00"


def _executable(path: Path, body: str = "binary-not-a-script\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _detection(command: str, name: str = "files") -> HarnessDetection:
    artifact = GuardArtifact(
        artifact_id=f"claude-code:{name}",
        name=name,
        harness="claude-code",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="config.json",
        command=command,
        args=("--serve",),
        transport="stdio",
        metadata={"env": {}},
    )
    return HarnessDetection("claude-code", True, True, ("config.json",), (artifact,))


def _nvm_node(home: Path, version: str = "20.11.1") -> Path:
    return _executable(home / ".nvm" / "versions" / "node" / f"v{version}" / "bin" / "node")


@pytest.fixture
def native_runtime(native_hook_force: Path) -> Path:
    return native_hook_force


def test_posture_reports_observed_runtime_from_the_launch_path(native_runtime: Path, tmp_path: Path) -> None:
    node = _nvm_node(tmp_path)
    decoy = _nvm_node(tmp_path / "elsewhere", "18.0.0")

    payload = build_runtime_posture(
        [_detection("node")],
        generated_at=NOW,
        environment={"PATH": str(node.parent)},
    )

    assert payload["status"] == "ok"
    assert payload["scope_complete"] is False
    assert payload["coverage"]["mode"] == "observed_only"
    assert payload["coverage"]["reason"] == ADVISORIES_UNAVAILABLE
    assert payload["coverage"]["instances_enumerated"] is False
    assert payload["advisories"] == []
    [row] = payload["runtimes"]
    assert row["path"] == str(node.resolve())
    assert row["path"] != str(decoy.resolve())
    assert (row["family"], row["version"]) == ("node", "20.11.1")
    assert row["identity_assurance"] == "self_reported"
    assert row["coverage"] == "observed_only"
    assert row["location_state"] == "present"
    assert len(row["executable_sha256"]) == 64
    assert row["launched_by"] == [{"harness": "claude-code", "server": "files", "role": "launch"}]
    assert row["advisory_matches"] == []


def test_unrecognised_runtime_stays_unknown(native_runtime: Path, tmp_path: Path) -> None:
    tool = _executable(tmp_path / "bin" / "custom-launcher")

    payload = build_runtime_posture(
        [_detection("custom-launcher")], generated_at=NOW, environment={"PATH": str(tool.parent)}
    )

    [row] = payload["runtimes"]
    assert row["family"] == "unknown"
    assert row["version"] is None
    assert row["identity_assurance"] == "unknown"
    assert "safe" not in json.dumps(payload).replace("no runtime is reported safe", "")


def test_json_carries_no_environment_values_or_file_contents(native_runtime: Path, tmp_path: Path) -> None:
    secret = "sk-test-not-a-real-secret"
    tool = _executable(tmp_path / "bin" / "node", f"#!/bin/sh\n# {secret}\n")
    artifact = _detection("node").artifacts[0]
    detection = HarnessDetection(
        "claude-code",
        True,
        True,
        ("config.json",),
        (replace(artifact, metadata={"env": {"PATH": str(tool.parent), "API_TOKEN": secret}}),),
    )

    payload = build_runtime_posture([detection], generated_at=NOW, environment={"PATH": "/nonexistent"})

    assert payload["runtimes"]
    assert secret not in json.dumps(payload)


def test_missing_launch_executable_is_reported_not_guessed(native_runtime: Path, tmp_path: Path) -> None:
    payload = build_runtime_posture(
        [_detection("no-such-runtime")], generated_at=NOW, environment={"PATH": str(tmp_path)}
    )

    assert payload["runtimes"] == []
    assert payload["unresolved_launches"] == [
        {"harness": "claude-code", "server": "files", "command": "no-such-runtime"}
    ]
    assert payload["status"] == "ok"


def test_no_servers_never_touches_the_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(paths: list[str]) -> None:
        raise AssertionError("native must not be called without candidates")

    monkeypatch.setattr(runtime_posture, "probe_runtime_paths", refuse)

    payload = build_runtime_posture([], generated_at=NOW, environment={"PATH": ""})

    assert payload["status"] == "ok"
    assert payload["runtimes"] == []
    assert payload["coverage"]["reason"] == ADVISORIES_UNAVAILABLE


def test_native_unavailable_is_reported_honestly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    node = _nvm_node(tmp_path)

    def unavailable(paths: list[str]) -> None:
        raise RuntimeIdentityError("runtime_identity_native_unavailable")

    monkeypatch.setattr(runtime_posture, "collect_runtime_candidates", _fixed_candidates(node))
    monkeypatch.setattr(runtime_posture, "probe_runtime_paths", unavailable)

    payload = build_runtime_posture([], generated_at=NOW)

    assert payload["status"] == "unavailable"
    assert payload["error"] == "runtime_identity_native_unavailable"
    assert payload["runtimes"] == []
    assert payload["scope_complete"] is False


def test_assessment_failure_keeps_observations_and_marks_partial(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, native_runtime: Path
) -> None:
    node = _nvm_node(tmp_path)

    def failed(request: dict[str, object]) -> None:
        raise RuntimeIdentityError("runtime_identity_failed")

    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", failed)

    payload = build_runtime_posture([_detection("node")], generated_at=NOW, environment={"PATH": str(node.parent)})

    assert payload["status"] == "partial"
    assert payload["error"] == "runtime_identity_failed"
    assert payload["coverage"]["reason"] == "runtime_assessment_failed"
    assert len(payload["runtimes"]) == 1


def test_assess_receives_an_empty_advisory_list_and_incomplete_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, native_runtime: Path
) -> None:
    node = _nvm_node(tmp_path)
    seen: list[dict[str, object]] = []
    real = runtime_posture.assess_runtime_identity

    def spy(request: dict[str, object]):
        seen.append(request)
        return real(request)

    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", spy)

    build_runtime_posture([_detection("node")], generated_at=NOW, environment={"PATH": str(node.parent)})

    [request] = seen
    assert request["advisories"] == []
    assert request["scope_complete"] is False
    assert "instances" not in request
    assert [artifact["identity_assurance"] for artifact in request["artifacts"]] == ["self_reported"]


def test_probe_output_is_usable_as_assess_input(native_runtime: Path, tmp_path: Path) -> None:
    node = _nvm_node(tmp_path)
    missing = tmp_path / "gone" / "node"

    probe = probe_runtime_paths([str(node), str(missing)])

    states = {row["location_id"]: row["state"] for row in probe.locations}
    assert sorted(states.values()) == ["missing", "present"]
    assert all(str(tmp_path) not in json.dumps(row) for row in (*probe.artifacts, *probe.locations))
    assert RUNTIME_PROBE_FEATURE == "runtime-identity-probe-v1"


def test_cli_json_shape(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, native_runtime: Path
) -> None:
    node = _nvm_node(tmp_path)
    _patch_detections(monkeypatch, [_detection("node")], path=str(node.parent))

    code = main(["guard", "runtime", "posture", "--json", *_guard_args(tmp_path)])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "guard.runtime-posture.v1"
    assert payload["scope_complete"] is False
    assert payload["coverage"]["reason"] == ADVISORIES_UNAVAILABLE
    assert {"status", "error", "runtimes", "advisories", "unresolved_launches", "candidate_limit_reached"} <= set(
        payload
    )
    assert payload["runtimes"][0]["family"] == "node"


def test_cli_human_output_is_honest_about_coverage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, native_runtime: Path
) -> None:
    node = _nvm_node(tmp_path)
    _patch_detections(monkeypatch, [_detection("node"), _detection("ghost-tool", "ghost")], path=str(node.parent))

    code = main(["guard", "runtime", "posture", *_guard_args(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "node 20.11.1, assurance self_reported" in out
    assert "not found on PATH: ghost-tool" in out
    assert "scope complete: no" in out
    assert ADVISORIES_UNAVAILABLE in out
    assert "No runtime is reported safe." in out


def test_cli_native_unavailable_exits_nonzero_without_a_crash(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    node = _nvm_node(tmp_path)

    def unavailable(paths: list[str]) -> None:
        raise RuntimeIdentityError("runtime_identity_native_unavailable")

    monkeypatch.setattr(runtime_posture, "collect_runtime_candidates", _fixed_candidates(node))
    monkeypatch.setattr(runtime_posture, "probe_runtime_paths", unavailable)
    _patch_detections(monkeypatch, [])

    code = main(["guard", "runtime", "posture", "--json", *_guard_args(tmp_path)])
    json_out = json.loads(capsys.readouterr().out)
    human_code = main(["guard", "runtime", "posture", *_guard_args(tmp_path)])
    human_out = capsys.readouterr().out

    assert code == 1 and human_code == 1
    assert json_out["status"] == "unavailable"
    assert json_out["error"] == "runtime_identity_native_unavailable"
    assert "Unavailable: runtime_identity_native_unavailable" in human_out


def _guard_args(tmp_path: Path) -> list[str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return ["--home", str(home), "--guard-home", str(home / "guard"), "--workspace", str(tmp_path)]


def _patch_detections(
    monkeypatch: pytest.MonkeyPatch,
    detections: list[HarnessDetection],
    *,
    path: str | None = None,
) -> None:
    from codex_plugin_scanner.guard.adapters import harness_mcp_discovery

    monkeypatch.setattr(harness_mcp_discovery, "configured_harness_detections", lambda *_a, **_k: detections)
    if path is not None:
        monkeypatch.setenv("PATH", path)


def _fixed_candidates(path: Path):
    from codex_plugin_scanner.guard.runtime_identity_candidates import RuntimeCandidate, RuntimeCandidates

    found = RuntimeCandidates(
        candidates=(RuntimeCandidate(str(path), (("claude-code", "files", "launch"),)),),
        unresolved=(),
        truncated=False,
    )
    return lambda *_a, **_k: found
