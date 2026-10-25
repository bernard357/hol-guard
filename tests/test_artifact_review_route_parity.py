"""The resident's artifact review route keeps the approval invariant.

``scripts/ci/record_artifact_review_route_vectors.py`` recorded the retired
Python branch ladder of ``review_native_artifact_hook``. The Rust suite replays
the route fields; this suite pins the approval invariant on the recorded
routes (a review-tier verdict keeps its approval choice unless the operator
chose not to be asked), checks the transport decodes a bound route and fails
closed on a malformed one, and that the resident answers the recorded routes.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_resident_decision as shared

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/artifact_review_route_vectors.json.gz"
REVIEW_TIER = {"review", "require-reapproval"}
SILENT = {"silent_review", "silent_block"}


def _vectors() -> list[dict[str, Any]]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


def test_review_tier_verdicts_keep_allow_once_and_always_allow() -> None:
    offered = 0
    for vector in _vectors():
        facts, route = vector["facts"], vector["route"]
        if facts["policy_action"] not in REVIEW_TIER or facts["observe_mode"]:
            continue
        assert route["terminalize"] == "none"
        if route["route"] in SILENT:
            assert facts["asks_for_approval"] is False, facts
            continue
        if route["route"] == "continue":
            assert facts["prompt_hard_block"] is True, facts
            continue
        offered += 1
    assert offered > 1_000


def test_terminal_verdicts_are_never_queued() -> None:
    for vector in _vectors():
        facts, route = vector["facts"], vector["route"]
        if facts["policy_action"] in {"block", "sandbox-required"}:
            assert route["route"] not in {"queue_approval", "silent_review"}, facts
        if route["route"] == "silent_review":
            assert facts["policy_action"] in REVIEW_TIER


_FACTS = {
    "harness": "cursor",
    "canonical_harness": "cursor",
    "event": "PreToolUse",
    "policy_action": "review",
    "artifact_type": "tool_action_request",
    "observe_mode": False,
    "asks_for_approval": True,
    "json": False,
    "output_stream_present": False,
    "prompt_hard_block": False,
    "prompt_secret_read": False,
}
_ROUTE = {
    "kind": "artifact_review_route",
    "route": "queue_approval",
    "terminalize": "none",
    "record_claude_notice": False,
    "attach_cursor_request_ids": True,
    "system_message": "none",
    "additional_context": "none",
    "silent_review": None,
}


def _resident_answering(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], asked: list[str]) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(
            features={"resident-protocol-v2", decision.HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE}
        ),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append(required_feature)
        assert request["query"] == {"kind": "artifact_review_route", "inputs": _FACTS}
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(decision, "_resident_request", transport)


def test_a_bound_route_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _ROUTE, asked)
    answer = decision.native_artifact_review_route(_FACTS)
    assert answer == {key: value for key, value in _ROUTE.items() if key != "kind"}
    assert asked == [decision.HOOK_DECISION_ARTIFACT_REVIEW_ROUTE_FEATURE]


@pytest.mark.parametrize(
    "overrides",
    [
        {"route": "queue_everything"},
        {"terminalize": "sometimes"},
        {"system_message": "codex_prompt"},
        {"additional_context": "claude_punctuated"},
        {"record_claude_notice": "yes"},
        {"attach_cursor_request_ids": None},
        {"silent_review": {"action": "review", "reason": "x"}},
        {"route": "silent_review"},
        {"route": "silent_review", "silent_review": {"action": "block", "reason": "x"}},
        {"route": "silent_block", "silent_review": {"action": "review", "reason": "x", "extra": 1}},
        {"extra": True},
    ],
)
def test_a_malformed_route_fails_closed(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_answering(monkeypatch, {**_ROUTE, **overrides}, [])
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_artifact_review_route(_FACTS)


def test_incomplete_inputs_are_refused_before_the_resident_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _ROUTE, asked)
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_artifact_review_route({key: value for key, value in _FACTS.items() if key != "json"})
    assert asked == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_routes() -> None:
    failures: list[str] = []
    for vector in _vectors()[::47]:
        answer = decision.native_artifact_review_route(vector["facts"])
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {expected!r}"
            for key, expected in vector["route"].items()
            if answer[key] != expected
        )
    assert failures == []
