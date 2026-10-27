"""The Codex tool-output bridge refuses platforms whose path model it does not carry."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_codex_tool_output as bridge
from codex_plugin_scanner.guard import native_resident_decision as resident


def test_windows_is_refused_with_a_typed_code_before_any_native_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_platform_is_supported", lambda: False)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the resident must not be contacted on an unsupported platform")

    monkeypatch.setattr(resident, "native_runtime_status", forbidden)
    answer = bridge.codex_tool_output_native("read_only_inspection", command="cat src/a.py")
    assert answer.allowed is False
    assert answer.value is None
    assert answer.error_code == "native_codex_tool_output_unsupported_platform"


@pytest.mark.parametrize("value", ["\ud83d", float("nan")])
def test_unencodable_post_tool_body_is_a_typed_denial(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    features = {resident._RESIDENT_PROTOCOL_FEATURE, bridge._CALL.feature, bridge._POST_TOOL_COMMANDS_FEATURE}
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(sha256="sha256:test"),
        capabilities=SimpleNamespace(features=features),
    )
    monkeypatch.setattr(bridge, "_platform_is_supported", lambda: True)
    monkeypatch.setattr(resident, "native_runtime_status", lambda **_kwargs: status)
    monkeypatch.setattr(resident, "_resolve_digest_home", lambda _home: None)
    monkeypatch.setattr(resident, "native_runtime_health_snapshot", lambda *_args: SimpleNamespace(circuit_open=False))
    monkeypatch.setattr(resident, "ensure_resident_prerequisite", lambda _home: True)
    answer = bridge.codex_tool_output_native("post_tool_output", body={"tool_response": value})
    assert answer.allowed is False
    assert answer.error_code == "native_codex_tool_output_invalid"


def test_a_transport_failure_keeps_the_bridge_s_own_unavailable_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """Callers and the recorded health reason both name ``native_codex_tool_output_unavailable``."""

    features = {resident._RESIDENT_PROTOCOL_FEATURE, bridge._CALL.feature}
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(sha256="sha256:test", path="/nonexistent/hol-guard-runtime"),
        capabilities=SimpleNamespace(features=features),
    )
    recorded: list[str] = []
    monkeypatch.setattr(bridge, "_platform_is_supported", lambda: True)
    monkeypatch.setattr(resident, "native_runtime_status", lambda **_kwargs: status)
    monkeypatch.setattr(resident, "_resolve_digest_home", lambda _home: None)
    monkeypatch.setattr(resident, "native_runtime_health_snapshot", lambda *_args: SimpleNamespace(circuit_open=False))
    monkeypatch.setattr(resident, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(resident, "native_resident_client_ready", lambda *_a, **_k: True)
    monkeypatch.setattr(
        resident,
        "native_record_resident_failure",
        lambda *_a, reason, **_k: recorded.append(reason),
    )
    monkeypatch.setattr(resident, "native_resident_client_request", lambda **_kwargs: None)
    answer = bridge.codex_tool_output_native("read_only_inspection", command="cat src/a.py")
    assert answer.allowed is False
    assert answer.error_code == "native_codex_tool_output_unavailable"
    assert recorded == ["native_codex_tool_output_unavailable"]
