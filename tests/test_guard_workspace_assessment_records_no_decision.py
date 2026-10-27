from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_workspace_assessment_runner import AUDIT, SCANNED, T0, queued_run, snapshots

# Every GuardStore write that records an enforcement outcome: receipts, decision
# receipts, approvals and the events the Cloud sync sends on.
RECORDING_METHODS = (
    "add_receipt",
    "record_tool_call_evidence",
    "record_native_decision_receipt",
    "record_local_once_approval",
    "add_approval_request",
    "add_event",
    "add_guard_event_v1",
)


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    for name in RECORDING_METHODS:
        assert callable(getattr(GuardStore, name))
        monkeypatch.setattr(GuardStore, name, lambda self, *args, _name=name, **kwargs: calls.append(_name))
    return calls


def test_a_blocking_finding_is_reported_without_recording_a_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorded: list[str]
) -> None:
    # A background assessment reports what it found. A package the audit would
    # block on install is a finding, not a blocked action: no receipt, approval
    # request or event comes out of the run.
    store, claimed = queued_run(tmp_path)
    snapshots(monkeypatch, runner, SCANNED)
    monkeypatch.setattr(runner, "_local_audit", lambda store, config, root: AUDIT)
    outcome = runner.execute(store, None, claimed, clock=lambda: T0)
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 1)
    [finding] = outcome.findings
    assert (finding["package_name"], finding["decision"]) == ("minimist", "block")
    assert recorded == []
