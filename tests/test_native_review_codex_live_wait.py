"""A Codex hook that waits for approval is released when the user allows it."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.codex_live_decision import complete_codex_live_decision
from codex_plugin_scanner.guard.continuation_snapshot import validated_continuation_snapshot
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.live_process_identity import (
    CODEX_BROWSER_WAIT_PROCESS_KEY,
    CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    current_process_identity,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_pretool_edge_fixtures import canonical_receipt_bytes
from tests.native_review_evidence_support import with_review_evidence
from tests.test_native_command_observations import _edge, _observations, _receipt

_HARNESS = "codex"


def _hook_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[HookWorker, GuardStore]:
    from codex_plugin_scanner.guard.config import update_guard_settings

    observations = _observations()
    result = _edge(observations)["result"]
    result.update(minimum_action="review", action={"action_type": "unknown"})
    receipt = _receipt(observations)
    receipt["harness"] = _HARNESS

    def review_raw_hook_native(*_args: object, **kwargs: object) -> dict[str, object]:
        bound_receipt = copy.deepcopy(receipt)
        bound_receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(bound_receipt)).hexdigest()
        edge = {
            "schema": "guard-hook-edge-result.v2",
            "authority": "rust",
            "harness": _HARNESS,
            "event_name": "PreToolUse",
            "payload_kind": "inline",
            "result": {
                "schema": "guard-pre-tool-result.v1",
                "version": 1,
                "authority": "rust",
                "reason": "HOL Guard requires review before this command can execute.",
                **copy.deepcopy(result),
            },
            "receipt": bound_receipt,
        }
        return with_review_evidence(edge, **kwargs)

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", review_raw_hook_native)
    store = GuardStore(tmp_path / "guard-home")
    update_guard_settings(store.guard_home, {"blocked_request_mode": "ask", "approval_wait_timeout_seconds": 300})
    store.upsert_runtime_state(
        session_id="native-review",
        daemon_host="127.0.0.1",
        daemon_port=4781,
        started_at="2026-09-05T00:00:00+00:00",
        last_heartbeat_at="2026-09-05T00:00:00+00:00",
    )
    return HookWorker(store=store), store


def _review(worker: HookWorker, tmp_path: Path, workspace: Path, wait: dict[str, object] | None) -> dict[str, object]:
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "session_id": "codex-session",
        "tool_use_id": "tool-1",
        "tool_name": "Bash",
        "tool_input": {"command": "cat package.json"},
        "cwd": str(workspace),
    }
    if wait is not None:
        payload.update(wait)
    return worker.review_http_payload(
        payload=payload,
        params={},
        default_harness=_HARNESS,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
    )


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"name": "fixture"}\n', encoding="utf-8")
    return workspace


def _snapshot(row: dict[str, Any]) -> dict[str, object] | None:
    for key in ("continuation_snapshot", "continuation_snapshot_json"):
        snapshot = validated_continuation_snapshot(row.get(key))
        if snapshot is not None:
            return snapshot
    return None


def _live_wait(timeout_seconds: int = 120) -> dict[str, object]:
    identity = current_process_identity()
    assert identity is not None
    return {CODEX_BROWSER_WAIT_PROCESS_KEY: identity, CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: timeout_seconds}


def _allow_once(store: GuardStore, request_id: str, workspace: Path) -> None:
    row = store.get_approval_request(request_id)
    assert row is not None
    contract = request_scope_contract(row)
    assert contract is not None
    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="allow once",
        persist_policy=None,
        scope_contract_version=str(row["scope_contract_version"]),
        scope_contract_digest=str(row["scope_contract_digest"]),
    )


def test_allowing_a_waiting_codex_review_releases_the_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)

    review = _review(worker, tmp_path, workspace, _live_wait())
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)
    row = store.get_approval_request(request_id)
    assert row is not None
    snapshot = _snapshot(row)
    assert snapshot is not None
    assert snapshot["capability"] == "suspended-response"
    assert snapshot["hookAttached"] is True
    operation = store.get_guard_operation_for_approval_request(request_id)
    assert operation is not None
    assert operation["status"] == "waiting_on_approval"

    _allow_once(store, request_id, workspace)
    resolved = store.get_approval_request(request_id)
    assert resolved is not None
    completed = complete_codex_live_decision(
        store,
        request_id=request_id,
        now=str(resolved["resolved_at"]),
        fresh_allow_authorized=True,
    )

    assert completed["completed"] is True, completed
    assert completed["action"] == "allow"
    continuation = completed["continuation"]
    assert isinstance(continuation, dict)
    assert continuation["continuationStatus"] == "resumed"


def test_wait_budget_is_bounded_by_the_bridge_and_the_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)

    review = _review(worker, tmp_path, workspace, _live_wait(timeout_seconds=30))
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)
    operation = store.get_guard_operation_for_approval_request(request_id)
    assert operation is not None
    metadata = operation["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["codex_browser_wait_timeout_seconds"] == 30


@pytest.mark.parametrize(
    "wait",
    [
        None,
        {CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120},
        {CODEX_BROWSER_WAIT_PROCESS_KEY: {"pid": 1, "startToken": "posix:not-this-process"}},
        {
            CODEX_BROWSER_WAIT_PROCESS_KEY: {"pid": 1, "startToken": "posix:not-this-process"},
            CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY: 120,
        },
    ],
    ids=["no-bridge", "no-process", "no-budget", "other-process"],
)
def test_a_review_without_a_live_waiting_bridge_stays_a_manual_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, wait: dict[str, object] | None
) -> None:
    workspace = _workspace(tmp_path)
    worker, store = _hook_worker(tmp_path, monkeypatch)

    review = _review(worker, tmp_path, workspace, wait)
    request_id = review["approval_request_id"]
    assert isinstance(request_id, str)
    row = store.get_approval_request(request_id)
    assert row is not None
    snapshot = _snapshot(row)
    assert snapshot is not None
    assert snapshot["capability"] == "retry-only"
    assert store.get_guard_operation_for_approval_request(request_id) is None
