from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
from codex_plugin_scanner.guard.cli import doctor_native_runtime
from codex_plugin_scanner.guard.cli.doctor_native_runtime import NativeAvailabilityResult, doctor_native_availability
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus


@pytest.mark.parametrize(("runtime_sha256", "available"), [("b" * 64, True), (None, False)])
def test_passive_scope_answers_availability_without_probing_or_repairing(
    monkeypatch: pytest.MonkeyPatch, runtime_sha256: str | None, available: bool
) -> None:
    def unexpected_probe() -> NativeRuntimeStatus:
        pytest.fail("Passive diagnostics must not probe or change the native binary")

    monkeypatch.setattr(native_runtime, "native_runtime_status", unexpected_probe)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: runtime_sha256)
    monkeypatch.setattr(native_runtime, "native_mode", lambda: "auto")

    with without_command_probes():
        result = doctor_native_availability()

    assert result["mode"] == "auto"
    assert result["available"] is available
    assert result["compatible"] is None
    assert result["reason_code"] == "native_status_probe_skipped"
    assert result["evaluation_verified"] is False
    # The shared-install panel is for a busy owner only; nothing to say here.
    assert "message" not in result


@pytest.mark.parametrize(
    ("available", "compatible", "reason"),
    [
        (False, False, "native_binary_missing"),
        (True, False, "native_manifest_version_mismatch"),
        (True, True, "native_available"),
    ],
)
def test_availability_preserves_validation_result_without_claiming_evaluation(
    monkeypatch: pytest.MonkeyPatch, available: bool, compatible: bool, reason: str
) -> None:
    status = NativeRuntimeStatus(mode="auto", available=available, compatible=compatible, reason=reason)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    assert doctor_native_availability() == {
        "mode": "auto",
        "available": available,
        "compatible": compatible,
        "reason_code": reason,
        "evaluation_verified": False,
    }


def test_availability_does_not_serialize_binary_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = NativeRuntimeIdentity(path=Path("/private/user/native-secret"), size=123, mtime_ns=456, sha256="a" * 64)
    status = NativeRuntimeStatus(
        mode="auto", available=True, compatible=True, reason="native_available", identity=identity
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    encoded = json.dumps(doctor_native_availability())
    assert "private" not in encoded
    assert "sha256" not in encoded
    assert "mtime" not in encoded


@pytest.mark.parametrize("exception", [OSError, RuntimeError, ValueError])
def test_failed_probe_does_not_disclose_exception(monkeypatch: pytest.MonkeyPatch, exception: type[Exception]) -> None:
    def failed_probe() -> NativeRuntimeStatus:
        raise exception("/private/user/native-secret")

    monkeypatch.setattr(native_runtime, "native_runtime_status", failed_probe)
    result = doctor_native_availability()
    assert result["reason_code"] == "native_status_probe_failed"
    assert result["mode"] == "unknown"
    assert result["available"] is False
    assert result["evaluation_verified"] is False
    assert "private" not in json.dumps(result)


def test_invalid_reason_is_not_disclosed(monkeypatch: pytest.MonkeyPatch) -> None:
    status = NativeRuntimeStatus(mode="auto", available=False, compatible=False, reason="/private/user/native-secret")
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    assert doctor_native_availability()["reason_code"] == "native_status_reason_unavailable"


def _hold_owner_lock(state_base: Path):
    fcntl = pytest.importorskip("fcntl")
    state_base.mkdir(parents=True)
    handle = (state_base / "managed-resident-owner.v1.lock").open("w+b")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return handle


def _status_for(runtime_sha256: str) -> NativeRuntimeStatus:
    identity = NativeRuntimeIdentity(path=Path("hol-guard-runtime"), size=1, mtime_ns=1, sha256=runtime_sha256)
    return NativeRuntimeStatus(mode="auto", available=True, compatible=True, reason="native_ready", identity=identity)


def _availability_while_held(
    guard_home: Path, runtime_sha256: str, monkeypatch: pytest.MonkeyPatch
) -> NativeAvailabilityResult:
    # flock conflicts across separate open() calls, even inside one process.
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for(runtime_sha256))
    return doctor_native_availability(guard_home)


def test_a_resident_owned_by_another_install_is_explained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with _hold_owner_lock(tmp_path / "native-runtime"):
        result = _availability_while_held(tmp_path, "a" * 64, monkeypatch)

    assert result["reason_code"] == "native_resident_owner_busy"
    assert "Another Guard install" in result["message"]


def test_a_live_resident_of_this_runtime_is_not_called_another_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_base = tmp_path / "native-runtime"
    with _hold_owner_lock(state_base):
        resident = state_base / "resident-v3-aaaaaaaaaaaaaaaa"
        resident.mkdir()
        state = {"runtime_sha256": "a" * 64, "process_id": os.getpid()}
        (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
        result = _availability_while_held(tmp_path, "a" * 64, monkeypatch)

    assert result["reason_code"] == "native_ready"
    assert "message" not in result


def test_a_free_owner_lock_is_not_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for("a" * 64))

    result = doctor_native_availability(tmp_path)

    assert result["reason_code"] == "native_ready"
    assert "message" not in result


def test_the_default_doctor_explains_a_busy_owner_without_running_the_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
    from codex_plugin_scanner.guard.cli import doctor_native_runtime

    def _must_not_run() -> NativeRuntimeStatus:
        raise AssertionError("the runtime must not run while command probes are off")

    monkeypatch.setattr(native_runtime, "native_runtime_status", _must_not_run)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)
    with _hold_owner_lock(tmp_path / "native-runtime"), without_command_probes():
        result = doctor_native_availability(tmp_path)

    assert result["reason_code"] == "native_resident_owner_busy"
    # The binary validated without being run, so availability is a real answer.
    assert result["available"] is True
    assert "Another Guard install" in result["message"]


def test_resident_presence_sees_a_live_resident_for_this_runtime(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    state = {"runtime_sha256": "a" * 64, "process_id": os.getpid()}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")

    assert native_resident_presence(tmp_path, "a" * 64) == {
        "live": True,
        "owner_lock_held": False,
        "generations": 1,
    }


def test_resident_presence_ignores_another_runtime_build(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-bbbbbbbbbbbbbbbb"
    resident.mkdir(parents=True)
    state = {"runtime_sha256": "b" * 64, "process_id": os.getpid()}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")

    presence = native_resident_presence(tmp_path, "a" * 64)

    assert presence["live"] is False
    assert presence["generations"] == 0


def test_resident_presence_reports_a_held_owner_lock(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    with _hold_owner_lock(tmp_path / "native-runtime"):
        presence = native_resident_presence(tmp_path, "a" * 64)

    assert presence["owner_lock_held"] is True
    assert presence["live"] is False


def test_resident_presence_is_unknown_without_a_runtime_identity(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    assert native_resident_presence(tmp_path, None) == {
        "live": None,
        "owner_lock_held": None,
        "generations": 0,
    }


def test_resident_presence_survives_a_damaged_state_file(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    (resident / "generation-1.json").write_text("{not json", encoding="utf-8")
    (resident / "generation-2.json").write_text("[]", encoding="utf-8")

    presence = native_resident_presence(tmp_path, "a" * 64)

    assert presence["live"] is False
    assert presence["generations"] == 0


def test_the_section_carries_availability_resident_and_this_process_counters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.cli import doctor_native_runtime

    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for("a" * 64))
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)

    section = doctor_native_runtime.native_runtime_section(tmp_path)

    assert section["availability"]["reason_code"] == "native_ready"
    assert section["resident"] == {"live": False, "owner_lock_held": False, "generations": 0}
    assert isinstance(section["daemon_http"], dict)
    assert "repair" not in section


def test_the_section_does_not_serialize_the_binary_path_or_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.cli import doctor_native_runtime

    identity = NativeRuntimeIdentity(path=Path("/private/user/native-secret"), size=1, mtime_ns=1, sha256="c" * 64)
    status = NativeRuntimeStatus(mode="auto", available=True, compatible=True, reason="native_ready", identity=identity)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "c" * 64)

    encoded = json.dumps(doctor_native_runtime.native_runtime_section(tmp_path))

    assert "native-secret" not in encoded
    assert "c" * 64 not in encoded
    assert "sha256" not in encoded
    assert "mtime" not in encoded


@pytest.mark.parametrize("process_id", [0, -1, True, "4", None])
def test_resident_presence_treats_a_state_file_without_a_real_pid_as_dead(tmp_path: Path, process_id: object) -> None:
    """A zero, negative, boolean or non-numeric pid names no process."""

    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    state = {"runtime_sha256": "a" * 64, "process_id": process_id}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")

    presence = native_resident_presence(tmp_path, "a" * 64)

    # The generation is still counted; only its liveness claim is rejected.
    assert presence == {"live": False, "owner_lock_held": False, "generations": 1}


def test_resident_presence_rejects_a_reused_pid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A live pid counts only while it is still the process the state named."""

    from codex_plugin_scanner.guard import native_resident_watchdog
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    state = {
        "runtime_sha256": "a" * 64,
        "process_id": os.getpid(),
        "process_start_marker": "linux:111",
    }
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(native_resident_watchdog, "process_start_token", lambda pid: "linux:222")

    presence = native_resident_presence(tmp_path, "a" * 64)

    assert presence["live"] is False
    assert presence["generations"] == 1


def test_resident_presence_keeps_a_pid_that_still_matches_its_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_resident_watchdog
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    resident = tmp_path / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    marker = "linux:111"
    state = {"runtime_sha256": "a" * 64, "process_id": os.getpid(), "process_start_marker": marker}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(native_resident_watchdog, "process_start_token", lambda pid: marker)

    assert native_resident_presence(tmp_path, "a" * 64)["live"] is True


def test_a_busy_owner_is_not_claimed_when_a_reused_pid_is_the_only_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both resident scans apply one rule, so they cannot disagree about liveness."""

    from codex_plugin_scanner.guard import native_resident_watchdog
    from codex_plugin_scanner.guard.cli.doctor_native_runtime import native_resident_presence

    state_base = tmp_path / "native-runtime"
    monkeypatch.setattr(native_resident_watchdog, "process_start_token", lambda pid: "linux:222")
    with _hold_owner_lock(state_base):
        resident = state_base / "resident-v3-aaaaaaaaaaaaaaaa"
        resident.mkdir()
        state = {
            "runtime_sha256": "a" * 64,
            "process_id": os.getpid(),
            "process_start_marker": "linux:111",
        }
        (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
        result = _availability_while_held(tmp_path, "a" * 64, monkeypatch)
        presence = native_resident_presence(tmp_path, "a" * 64)

    assert result["reason_code"] == "native_resident_owner_busy"
    assert presence["live"] is False
