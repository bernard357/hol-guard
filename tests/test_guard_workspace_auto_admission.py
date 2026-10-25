from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard import native_workspace_snapshot as native
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_workspace_assessment_runner import KEYS, SNAPSHOT, T0, digest, snapshots

STAT = replace(SNAPSHOT, mode="stat")
NOW = "2026-10-25T00:00:00+00:00"


def register(store: GuardStore, harness: str, workspace: str | None, *, active: bool = True) -> None:
    store.set_managed_install(harness, active, workspace, {}, NOW)


def test_registered_workspace_is_admitted_once_with_a_workspace_open_run(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    modes = snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))
    register(store, "codex", str(tmp_path))

    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 1
    [worktree] = assessments.list_worktrees(store)
    assert (worktree["worktree_key"], worktree["root"]) == (KEYS.worktree_key, str(tmp_path.resolve()))
    [run] = assessments.recent_runs(store)
    assert run["trigger_kind"] == "workspace_open"
    # Already admitted: no second snapshot, no second run.
    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 0
    assert modes == ["stat"]
    assert len(assessments.recent_runs(store)) == 1


def test_installs_without_a_usable_workspace_admit_nothing(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    monkeypatch.setattr(worker, "workspace_snapshot", pytest.fail)
    register(store, "claude-code", None)
    register(store, "codex", "relative/project")
    register(store, "cursor", str(tmp_path / "missing"))
    register(store, "opencode", str(tmp_path), active=False)

    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 0
    assert assessments.list_worktrees(store) == []


def test_automatic_admission_never_resumes_a_paused_worktree(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    old_root = tmp_path / "old"
    old_root.mkdir()
    assessments.admit_worktree(store, KEYS, root=str(old_root), now_ms=T0)
    assert assessments.set_paused(store, KEYS, paused=True)
    # The same worktree, reached through a newly registered root.
    snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))

    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 0
    [worktree] = assessments.list_worktrees(store)
    assert worktree["paused"] is True
    assert worktree["root"] == str(old_root)
    assert assessments.recent_runs(store) == []


def test_rejected_root_is_not_walked_again(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    calls: list[Path] = []

    def unavailable(root: Path, **_: object) -> native.WorkspaceSnapshot:
        calls.append(root)
        raise native.WorkspaceSnapshotError("workspace_snapshot_unavailable")

    monkeypatch.setattr(worker, "workspace_snapshot", unavailable)
    register(store, "claude-code", str(tmp_path))
    attempted: set[str] = set()

    assert worker.admit_registered_workspaces(store, attempted=attempted, clock=lambda: T0) == 0
    assert worker.admit_registered_workspaces(store, attempted=attempted, clock=lambda: T0) == 0
    assert len(calls) == 1
    assert assessments.list_worktrees(store) == []


def test_poll_admits_registered_workspaces_before_observing(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, replace(STAT, snapshot_digest=digest("stat-1")))
    monkeypatch.setattr(guard_config, "load_guard_config", lambda home: object())
    monkeypatch.setattr(worker, "run_next", lambda store, config, owner: False)
    register(store, "claude-code", str(tmp_path))

    assert worker.poll_once(store, owner="test", stop=threading.Event(), attempted=set()) == 0
    [run] = assessments.recent_runs(store)
    assert run["trigger_kind"] == "workspace_open"


def test_manual_admission_still_resumes_a_paused_worktree(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    assert assessments.set_paused(store, KEYS, paused=True)

    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    assert assessments.list_worktrees(store)[0]["paused"] is False
