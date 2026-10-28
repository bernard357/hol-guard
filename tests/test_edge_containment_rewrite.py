"""The edge rewrites a call it routes to the contained sink in the same answer.

The rewrite itself is pinned by the Rust tests beside ``edge_containment``.
These cover the wire: the envelope asks for it only from a resident that
advertises it, the decoder accepts the mark only on a route the edge answers,
and the daemon skips its second resident call only when the edge says it
rewrote. A grant route is answered the same way (``edge_containment_grant``)
when the envelope also carries the daemon's local CLI rules.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import zcode_contained_tests
from codex_plugin_scanner.guard.daemon import hook_contained_grant, hook_worker_native
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError
from codex_plugin_scanner.guard.native_hook_edge import (
    CONTAINMENT_GRANT_FEATURE,
    CONTAINMENT_REWRITE_FEATURE,
    _decode_edge,
    review_raw_hook_native,
)
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)

_PAYLOAD = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "make build"},
    "session_id": "sess-1",
    "tool_call_id": "call-1",
}
_RESULT = {
    "decision": "deny",
    "minimum_action": "sandbox-required",
    "policy_action": "sandbox-required",
    "reason_code": "native_workspace_containment_required",
}
_RECEIPT_RESPONSE = {
    "decision": "deny",
    "policy_action": "sandbox-required",
    "reason_code": "native_workspace_containment_required",
    "required_execution_profile": "workspace-contained-v1",
    "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
}
_ROUTED_RESPONSE = {
    "policy_action": "allow",
    "reason_code": "native_contained_execution_routed",
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "updatedInput": {"command": "guard execute-contained-test"},
    },
}


def _edge(**fields: object) -> dict[str, object]:
    return {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "result": dict(_RESULT),
        "receipt": {"request_id": "req-1", "decision_id": "b" * 64},
        "harness_response": dict(_RECEIPT_RESPONSE),
        "containment_route": "sink",
        **fields,
    }


@pytest.mark.parametrize("rewrite", ("routed", "kept"))
def test_the_decoder_accepts_the_rewrite_mark_on_a_sink_route(rewrite: str) -> None:
    edge = _edge(containment_rewrite=rewrite)
    assert _decode_edge(edge) == edge


@pytest.mark.parametrize(
    "fields",
    (
        {"containment_rewrite": "allow"},
        {"containment_rewrite": True},
        {"containment_rewrite": ["routed"]},
        {"containment_rewrite": "declined"},
        {"containment_rewrite": "kept", "containment_route": "none"},
        {"containment_rewrite": "declined", "containment_route": "none"},
        {"containment_rewrite": "allow", "containment_route": "grant"},
    ),
)
def test_the_decoder_refuses_a_rewrite_mark_off_a_sink_route(fields: dict[str, object]) -> None:
    assert _decode_edge(_edge(**fields)) is None


@pytest.mark.parametrize("answer", ("routed", "kept", "declined"))
def test_the_decoder_accepts_a_grant_answer_on_a_grant_route(answer: str) -> None:
    edge = _edge(containment_route="grant", containment_rewrite=answer)
    assert _decode_edge(edge) == edge


def _status(tmp_path: Path, *, advertised: bool, extra: tuple[str, ...] = ()) -> NativeRuntimeStatus:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    identity = NativeRuntimeIdentity(
        path=runtime,
        size=runtime.stat().st_size,
        mtime_ns=runtime.stat().st_mtime_ns,
        sha256="a" * 64,
    )
    capabilities = NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="test",
        rule_digest="b" * 64,
        build_sha="c" * 40,
        target="test",
        features=(
            "hook-envelope-v2",
            "hook-harness-response-v1",
            "edge-self-check-v1",
            "native-resident-client-v1",
            "pre-tool-generic-authority-v1",
            "git-execution-context-v1",
            *([CONTAINMENT_REWRITE_FEATURE] if advertised else []),
            *extra,
        ),
    )
    return NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ready",
        identity=identity,
        capabilities=capabilities,
    )


@pytest.mark.parametrize(
    ("advertised", "asked", "workspace", "event", "sent"),
    (
        (True, True, True, "PreToolUse", True),
        (False, True, True, "PreToolUse", False),
        (True, False, True, "PreToolUse", False),
        (True, True, False, "PreToolUse", False),
        (True, True, True, "UserPromptSubmit", False),
    ),
)
def test_the_envelope_carries_the_sink_argv_only_for_a_tool_call_a_resident_can_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    advertised: bool,
    asked: bool,
    workspace: bool,
    event: str,
    sent: bool,
) -> None:
    captured: dict[str, object] = {}

    def fake_client(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return json.dumps(_edge(event_name=event), separators=(",", ":")).encode()

    monkeypatch.setattr("codex_plugin_scanner.guard.native_hook_edge.native_resident_client_request", fake_client)
    review_raw_hook_native(
        payload={**_PAYLOAD, "hook_event_name": event},
        harness="claude",
        event=event,
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path if workspace else None,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=None,
        policy_snapshot={"generation": 1},
        runtime_status=_status(tmp_path, advertised=advertised),
        containment_sink=asked,
    )
    encoded = captured["payload"]
    assert isinstance(encoded, bytes)
    sink = json.loads(encoded).get("containment_sink")
    if sent:
        assert sink == {"sink_command": list(zcode_contained_tests.contained_sink_command_prefix())}
    else:
        # An older resident would refuse the field, and without a workspace
        # there is no snapshot to write.
        assert sink is None


class _Metrics:
    def record_route(self, _route: str) -> None:
        return None


@dataclass
class _SinkRouteFixture(HookWorkerNativeMixin):
    """A daemon whose edge answers a sink-routed PreToolUse."""

    edge: dict[str, object]
    captured: list[dict[str, object]] = field(default_factory=list)
    activity_writer: object | None = None
    metrics: _Metrics = field(default_factory=_Metrics)

    def _review_raw_hook_native(self, **kwargs: object) -> dict[str, object]:
        self.captured.append(kwargs)
        return self.edge

    def _record_native_decision_receipt(self, receipt: object) -> object:
        return receipt

    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> object:
        raise AssertionError("a PreToolUse sink route reads no structured view")


def _review(
    fixture: _SinkRouteFixture, tmp_path: Path, *, deadline: float | None = None
) -> tuple[dict[str, object], bool]:
    return fixture._review_native_edge_with_snapshot(
        payload=dict(_PAYLOAD),
        harness="claude-code",
        event_name="PreToolUse",
        default_harness="claude-code",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=deadline,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )


@pytest.mark.parametrize(
    ("rewrite", "response"),
    (("routed", _ROUTED_RESPONSE), ("kept", _RECEIPT_RESPONSE)),
)
def test_the_daemon_answers_with_the_edge_rewrite_in_one_resident_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rewrite: str,
    response: dict[str, object],
) -> None:
    def second_call(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("the edge already rewrote the sink route")

    monkeypatch.setattr(zcode_contained_tests, "route_zcode_containment", second_call)
    fixture = _SinkRouteFixture(edge=_edge(harness_response=dict(response), containment_rewrite=rewrite))
    answer, native = _review(fixture, tmp_path)
    assert native is True
    assert answer == response
    assert [call["containment_sink"] for call in fixture.captured] == [True]


def test_an_edge_that_did_not_rewrite_is_asked_as_before(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[dict[str, object]] = []

    def route(response: dict[str, object], **kwargs: object) -> dict[str, object]:
        asked.append(kwargs)
        assert response == _RECEIPT_RESPONSE
        return dict(_ROUTED_RESPONSE)

    monkeypatch.setattr(zcode_contained_tests, "route_zcode_containment", route)
    answer, native = _review(_SinkRouteFixture(edge=_edge()), tmp_path)
    assert native is True
    assert answer == _ROUTED_RESPONSE
    assert [call["workspace"] for call in asked] == [tmp_path]


def test_an_unmarked_sink_route_without_a_resident_answer_is_the_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NativeHookDecisionError("native_containment_rewrite_unavailable")

    monkeypatch.setattr(zcode_contained_tests, "route_zcode_containment", unavailable)
    answer, native = _review(_SinkRouteFixture(edge=_edge()), tmp_path)
    # Never the receipt's rewrite picked here, and never an allow.
    assert native is False
    assert answer.get("reason_code") == "native_containment_rewrite_unavailable"
    assert answer.get("policy_action") != "allow"


@pytest.mark.parametrize(
    "routed",
    (
        # An allow that changes a field other than the command line.
        {
            **_ROUTED_RESPONSE,
            "hookSpecificOutput": {
                **_ROUTED_RESPONSE["hookSpecificOutput"],  # type: ignore[dict-item]
                "updatedInput": {"command": "guard execute-contained-test", "run_in_background": True},
            },
        },
        # An allow that is not the routed reason.
        {**_ROUTED_RESPONSE, "reason_code": "native_allow"},
        # The receipt, marked routed.
        _RECEIPT_RESPONSE,
    ),
)
def test_an_edge_routed_allow_off_the_routed_shape_is_the_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, routed: dict[str, object]
) -> None:
    def second_call(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("a refused edge rewrite is not asked again")

    monkeypatch.setattr(zcode_contained_tests, "route_zcode_containment", second_call)
    fixture = _SinkRouteFixture(edge=_edge(harness_response=dict(routed), containment_rewrite="routed"))
    answer, native = _review(fixture, tmp_path)
    assert native is False
    assert answer.get("reason_code") == "native_containment_rewrite_invalid"
    assert answer.get("policy_action") != "allow"


@pytest.mark.parametrize(
    ("advertised", "rules", "asked"),
    ((True, True, True), (False, True, False), (True, False, False)),
)
def test_the_sink_argv_asks_for_the_grant_only_from_a_resident_that_answers_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advertised: bool, rules: bool, asked: bool
) -> None:
    captured: dict[str, object] = {}

    def fake_client(**kwargs: object) -> bytes:
        captured.update(kwargs)
        return json.dumps(_edge(), separators=(",", ":")).encode()

    monkeypatch.setattr("codex_plugin_scanner.guard.native_hook_edge.native_resident_client_request", fake_client)
    features = ("edge-local-cli-rule-v1", *([CONTAINMENT_GRANT_FEATURE] if advertised else []))
    review_raw_hook_native(
        payload=dict(_PAYLOAD),
        harness="claude",
        event="PreToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=None,
        policy_snapshot={"generation": 1},
        runtime_status=_status(tmp_path, advertised=True, extra=features),
        local_cli_rules={"store_path": str(tmp_path / "guard.db"), "user_home": str(tmp_path), "env": {}}
        if rules
        else None,
        containment_sink=True,
    )
    encoded = captured["payload"]
    assert isinstance(encoded, bytes)
    sink = json.loads(encoded)["containment_sink"]
    assert sink["sink_command"] == list(zcode_contained_tests.contained_sink_command_prefix())
    # An older resident would refuse the field, and without the rules there
    # is no grant to read.
    assert sink.get("grant") is (True if asked else None)


_OUTSIDE_ROOTS = {
    "decision": "review",
    "minimum_action": "review",
    "policy_action": "review",
    "reason_code": "native_workspace_containment_executable_outside_roots",
}
_REVIEW_RESPONSE = {
    "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"},
}


def _grant_edge(**fields: object) -> dict[str, object]:
    return _edge(
        **{
            "result": dict(_OUTSIDE_ROOTS),
            "harness_response": dict(_REVIEW_RESPONSE),
            "containment_route": "grant",
            **fields,
        }
    )


@dataclass
class _GrantRouteFixture(_SinkRouteFixture):
    """A daemon whose edge answers a grant-routed PreToolUse."""

    store: object = field(default_factory=object)


def _no_second_call(monkeypatch: pytest.MonkeyPatch) -> None:
    def second_call(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("the edge already answered the grant route")

    monkeypatch.setattr(hook_contained_grant, "granted_containment_response", second_call)


@pytest.mark.parametrize(
    ("answer", "response"),
    (("routed", _ROUTED_RESPONSE), ("kept", _RECEIPT_RESPONSE)),
)
def test_the_daemon_answers_with_the_edge_grant_in_one_resident_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    answer: str,
    response: dict[str, object],
) -> None:
    _no_second_call(monkeypatch)
    fixture = _GrantRouteFixture(edge=_grant_edge(harness_response=dict(response), containment_rewrite=answer))
    reply, native = _review(fixture, tmp_path)
    assert native is True
    assert reply == response
    assert len(fixture.captured) == 1


def test_an_edge_granted_allow_off_the_routed_shape_is_the_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_second_call(monkeypatch)
    routed = {**_ROUTED_RESPONSE, "reason_code": "native_allow"}
    fixture = _GrantRouteFixture(edge=_grant_edge(harness_response=routed, containment_rewrite="routed"))
    reply, native = _review(fixture, tmp_path)
    assert native is False
    assert reply.get("reason_code") == "native_containment_rewrite_invalid"
    assert reply.get("policy_action") != "allow"


def test_a_declined_grant_goes_straight_to_the_review_pause(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _no_second_call(monkeypatch)
    paused: list[object] = []

    def pause(_store: object, **kwargs: object) -> dict[str, object]:
        paused.append(kwargs["native_result"])
        return {"paused": True}

    monkeypatch.setattr(hook_worker_native, "pause_native_pre_tool_for_approval", pause)
    fixture = _GrantRouteFixture(edge=_grant_edge(containment_rewrite="declined"))
    reply, native = _review(fixture, tmp_path)
    assert native is True
    assert reply == {"paused": True}
    assert paused == [_OUTSIDE_ROOTS]
    assert len(fixture.captured) == 1


def test_an_unmarked_grant_route_asks_for_the_grant_as_before(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[dict[str, object]] = []

    def granted(_store: object, result: dict[str, object], **kwargs: object) -> dict[str, object]:
        assert result == _OUTSIDE_ROOTS
        asked.append(kwargs)
        return dict(_ROUTED_RESPONSE)

    monkeypatch.setattr(hook_contained_grant, "granted_containment_response", granted)
    reply, native = _review(_GrantRouteFixture(edge=_grant_edge()), tmp_path)
    assert native is True
    assert reply == _ROUTED_RESPONSE
    assert [call["workspace"] for call in asked] == [tmp_path]


def test_an_unmarked_grant_route_past_the_deadline_keeps_the_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The edge's grant step may run past the review's budget; asking again
    # then would render with a spent deadline, and the call would get the
    # fixed deny instead of its review.
    _no_second_call(monkeypatch)
    paused: list[object] = []

    def pause(_store: object, **kwargs: object) -> dict[str, object]:
        paused.append(kwargs["native_result"])
        return {"paused": True}

    monkeypatch.setattr(hook_worker_native, "pause_native_pre_tool_for_approval", pause)
    reply, native = _review(_GrantRouteFixture(edge=_grant_edge()), tmp_path, deadline=time.monotonic() - 1.0)
    assert native is True
    assert reply == {"paused": True}
    assert paused == [_OUTSIDE_ROOTS]
