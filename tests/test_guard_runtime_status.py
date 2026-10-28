"""``hol-guard guard runtime status`` and ``guard doctor --native``.

Both surfaces are read only: they report what the native runtime looks like
from here without starting it, repairing it, or producing a verdict of their
own. The counters they print belong to the printing process, and the report
says so rather than passing them off as the hook's.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.cli import doctor_native_runtime
from codex_plugin_scanner.guard.cli.runtime_posture_command import render_runtime_status
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus


def _guard_args(tmp_path: Path) -> list[str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return ["--home", str(home), "--guard-home", str(home / "guard"), "--workspace", str(tmp_path)]


def _pin_runtime(monkeypatch: pytest.MonkeyPatch, *, available: bool, reason: str) -> None:
    identity = NativeRuntimeIdentity(path=Path("hol-guard-runtime"), size=1, mtime_ns=1, sha256="a" * 64)
    status = NativeRuntimeStatus(
        mode="auto", available=available, compatible=available, reason=reason, identity=identity
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)


def test_status_json_reports_availability_and_resident_presence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=True, reason="native_ready")

    code = main(["guard", "runtime", "status", "--json", *_guard_args(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    section = payload["native_runtime"]
    assert code == 0
    assert section["availability"]["reason_code"] == "native_ready"
    assert section["availability"]["evaluation_verified"] is False
    assert section["resident"]["live"] is False
    assert isinstance(section["daemon_http"], dict)
    assert "generated_at" in payload


def test_status_exits_nonzero_when_the_probe_says_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=False, reason="native_binary_missing")

    code = main(["guard", "runtime", "status", "--json", *_guard_args(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["native_runtime"]["availability"]["available"] is False


def test_status_sees_a_resident_this_process_never_started(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=True, reason="native_ready")
    args = _guard_args(tmp_path)
    guard_home = Path(args[args.index("--guard-home") + 1])
    resident = guard_home / "native-runtime" / "resident-v3-aaaaaaaaaaaaaaaa"
    resident.mkdir(parents=True)
    state = {"runtime_sha256": "a" * 64, "process_id": os.getpid()}
    (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")

    code = main(["guard", "runtime", "status", "--json", *args])

    resident_payload = json.loads(capsys.readouterr().out)["native_runtime"]["resident"]
    assert code == 0
    assert resident_payload["live"] is True
    assert resident_payload["generations"] == 1


def test_status_text_scopes_the_counters_to_this_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=True, reason="native_ready")

    code = main(["guard", "runtime", "status", *_guard_args(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "Native runtime status (read only)" in out
    assert "available: yes" in out
    assert "Resident on this account: not running" in out
    assert "The hook and the daemon keep their own." in out


def test_status_output_does_not_disclose_the_binary_path_or_hash(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    identity = NativeRuntimeIdentity(path=Path("/private/user/native-secret"), size=1, mtime_ns=1, sha256="d" * 64)
    status = NativeRuntimeStatus(
        mode="auto", available=True, compatible=True, reason="native_ready", identity=identity
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "d" * 64)

    main(["guard", "runtime", "status", "--json", *_guard_args(tmp_path)])

    out = capsys.readouterr().out
    assert "native-secret" not in out
    assert "d" * 64 not in out


def test_render_names_an_unknown_resident_without_inventing_one() -> None:
    section = {
        "availability": {"mode": "unknown", "available": None, "compatible": None, "reason_code": "probe_skipped"},
        "resident": {"live": None, "owner_lock_held": None, "generations": 0},
        "daemon_http": {},
    }

    rendered = render_runtime_status(section)

    assert "available: unknown" in rendered
    assert "Resident on this account: unknown" in rendered
    assert "no counters recorded" in rendered


def test_render_reports_a_held_owner_lock() -> None:
    section = {
        "availability": {"mode": "auto", "available": True, "compatible": True, "reason_code": "native_ready"},
        "resident": {"live": True, "owner_lock_held": True, "generations": 2},
        "daemon_http": {"accepted": 3, "rejected": 0},
    }

    rendered = render_runtime_status(section)

    assert "Resident on this account: running (owner lock held, 2 recorded generations)" in rendered
    assert "accepted 3, rejected 0" in rendered


def test_doctor_native_reports_the_section_without_the_rest_of_the_scan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=True, reason="native_ready")

    code = main(["guard", "doctor", "--native", "--json", *_guard_args(tmp_path)])

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["native_runtime"]["availability"]["reason_code"] == "native_ready"
    assert "approval_gate" not in payload
    assert "harnesses" not in payload


def test_doctor_native_text_uses_the_runtime_report_not_the_harness_panel(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _pin_runtime(monkeypatch, available=True, reason="native_ready")

    code = main(["guard", "doctor", "--native", *_guard_args(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "Native runtime status (read only)" in out
    assert "Guard doctor" not in out
