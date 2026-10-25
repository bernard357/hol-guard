"""The resident's artifact directive is decoded behind its capability.

``scripts/ci/record_artifact_directive_vectors.py`` recorded the retired
Python routing of ``finalize_native_artifact_hook``. The Rust suite replays the
directive fields; this suite checks the transport decodes a bound directive,
fails closed on a malformed one and that the resident answers the recorded
directives.
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
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/artifact_directive_vectors.json.gz"


def _vectors() -> list[dict[str, Any]]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_directives() -> None:
    failures: list[str] = []
    for vector in _vectors()[::53]:
        answer = decision.native_artifact_directive(vector["facts"])
        assert answer["queue_observe_request"] is False
        assert answer["queue_approval_request"] is False
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {expected!r}"
            for key, expected in vector["directive"].items()
            if answer[key] != expected
        )
    assert failures == []


_FACTS = {
    "harness": "kimi",
    "canonical_harness": "kimi",
    "event": "PreToolUse",
    "policy_action": "block",
    "json": False,
    "output_stream_present": False,
    "replayed": False,
    "approval_context_present": False,
    "prompt_hard_block": False,
    "prompt_secret_read": False,
}
_DIRECTIVE = {
    "kind": "artifact_directive",
    "route": "exit_block",
    "queue_observe_request": False,
    "queue_approval_request": False,
    "emitter": "default",
    "exit_code": 2,
    "json_exit_code": 2,
    "stderr_only_on_nonzero_exit": False,
    "codex_native_reason": "never",
    "include_remediation": True,
    "terminal_notice": False,
    "system_message": "none",
    "try_json_document": False,
    "after_json": "native_response",
    "envelope_decision": "block",
    "exit_block_stderr": True,
    "json_reason": "harness",
}


def _resident_answering(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], asked: list[str]) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", decision.HOOK_DECISION_JSON_EXIT_CODE_FEATURE}),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append(required_feature)
        assert request["query"] == {"kind": "artifact_directive", "inputs": _FACTS}
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(decision, "_resident_request", transport)


def test_a_bound_directive_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _DIRECTIVE, asked)
    answer = decision.native_artifact_directive(_FACTS)
    assert answer == {key: value for key, value in _DIRECTIVE.items() if key != "kind"}
    assert asked == [decision.HOOK_DECISION_JSON_EXIT_CODE_FEATURE]


@pytest.mark.parametrize(
    "overrides",
    [
        {"route": "silent_exit"},
        {"emitter": "copilot"},
        {"codex_native_reason": "always"},
        {"system_message": "sometimes"},
        {"after_json": "other"},
        {"envelope_decision": "ask"},
        {"json_reason": "prompt"},
        {"queue_approval_request": True},
        {"exit_block_stderr": None},
        {"exit_code": "2"},
        {"json_exit_code": "1"},
        {"extra": True},
    ],
)
def test_a_malformed_directive_fails_closed(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_answering(monkeypatch, {**_DIRECTIVE, **overrides}, [])
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_artifact_directive(_FACTS)


def test_incomplete_inputs_are_refused_before_the_resident_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _DIRECTIVE, asked)
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_artifact_directive({key: value for key, value in _FACTS.items() if key != "replayed"})
    assert asked == []
