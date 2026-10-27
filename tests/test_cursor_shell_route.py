"""Cursor's silent ``preToolUse`` probe: the daemon answer and the hook copy."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_script_template_route import (
    HOOK_SCRIPT_TEMPLATE_ROUTE,
)
from codex_plugin_scanner.guard.daemon import cursor_shell_route as route

_SHELL = {"hook_event_name": "PreToolUse", "tool_name": "Shell", "tool_input": {"command": "pytest -q"}}
_PROBE = {**_SHELL, "cursor_route_probe": True}
_BEFORE_SHELL = {**_SHELL, "cursor_source_hook_event": "beforeShellExecution"}
_ROUTED = "native_contained_execution_routed"
_SINK = {"command": "guard execute-contained-test", "cwd": "/w"}

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="Cursor's contained route is macOS and Linux only")


class _FailingWorker:
    def __init__(self) -> None:
        self.asked = False

    def _native_policy_snapshot(self, *_args: object, **_kwargs: object) -> object:
        self.asked = True
        raise RuntimeError("snapshot unavailable")


def _respond(
    payload: dict[str, object], workspace: Path | None, worker: _FailingWorker | None = None
) -> dict[str, object] | None:
    return route.cursor_shell_route_response(
        worker or _FailingWorker(),  # type: ignore[arg-type]
        payload=payload,
        home_dir=Path("/home/tester"),
        guard_home=Path("/home/tester/.hol-guard"),
        workspace=workspace,
        deadline=None,
    )


def test_only_cursors_own_shell_pretooluse_is_a_probe() -> None:
    assert route.is_cursor_shell_probe(_PROBE)
    # A Shell call another hook sends for Cursor keeps its ordinary review.
    assert not route.is_cursor_shell_probe(_SHELL)
    assert not route.is_cursor_shell_probe({**_SHELL, "cursor_route_probe": "true"})
    assert not route.is_cursor_shell_probe({**_PROBE, "cursor_source_hook_event": "beforeShellExecution"})
    assert not route.is_cursor_shell_probe(_BEFORE_SHELL)
    assert not route.is_cursor_shell_probe({**_PROBE, "tool_name": "Write"})
    assert not route.is_cursor_shell_probe({**_PROBE, "hook_event_name": "PostToolUse"})


@posix_only
def test_a_failed_probe_is_a_plain_allow(tmp_path: Path) -> None:
    assert _respond(_PROBE, tmp_path) == {"policy_action": "allow"}
    assert _respond(_PROBE, None) == {"policy_action": "allow"}


@posix_only
@pytest.mark.parametrize(
    "placement",
    [
        lambda directory: {"cwd": directory},
        lambda directory: {"tool_input": {"command": "pytest -q", "cwd": directory}},
        lambda directory: {"tool_input": {"command": "pytest -q", "working_directory": directory}},
    ],
)
def test_a_probe_outside_the_workspace_is_never_reviewed(tmp_path: Path, placement: object) -> None:
    # The sink runs in the workspace, so a call Cursor runs elsewhere keeps its own directory.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    worker = _FailingWorker()
    assert _respond({**_PROBE, **placement(str(elsewhere))}, tmp_path, worker) == {"policy_action": "allow"}  # type: ignore[operator]
    assert not worker.asked
    inside = _FailingWorker()
    assert _respond({**_PROBE, **placement(str(tmp_path))}, tmp_path, inside) == {"policy_action": "allow"}  # type: ignore[operator]
    assert inside.asked


def test_the_sink_command_accepts_the_cursor_harness(tmp_path: Path) -> None:
    from codex_plugin_scanner.cli import _build_parser

    args = _build_parser("hol-guard", program_mode="hol-guard").parse_args(
        [
            "execute-contained-test",
            "--harness",
            "cursor",
            "--guard-home",
            str(tmp_path / "guard"),
            "--workspace",
            str(tmp_path),
            "--request-file",
            str(tmp_path / "request.json"),
            "--request-sha256",
            "0" * 64,
            "--home",
            str(tmp_path),
        ]
    )
    assert args.harness == "cursor"


@posix_only
def test_non_probe_calls_are_reviewed_as_usual(tmp_path: Path) -> None:
    assert _respond({**_PROBE, "tool_name": "Write"}, tmp_path) is None
    assert _respond(_SHELL, tmp_path) is None
    assert _respond(_BEFORE_SHELL, tmp_path) is None
    assert _respond({**_PROBE, "guard_containment_receipt_only": True}, tmp_path) is None


@posix_only
@pytest.mark.parametrize(
    "command",
    [
        "guard execute-contained-test --harness cursor",
        "rm -rf build; guard execute-contained-test --harness cursor",
        "guard execute-contained-test --harness cursor --guard-home /tmp/other",
    ],
)
def test_before_shell_admits_only_the_exact_sink_command(tmp_path: Path, command: str) -> None:
    payload = {**_BEFORE_SHELL, "tool_input": {"command": command}}
    assert _respond(payload, tmp_path) is None


def test_windows_is_never_routed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(route.sys, "platform", "win32")
    assert _respond(_PROBE, tmp_path) is None


def _hook_copy() -> dict[str, object]:
    namespace: dict[str, object] = {"json": json}
    exec(HOOK_SCRIPT_TEMPLATE_ROUTE, namespace)
    return namespace


def _routed_body(updated: object) -> str:
    return json.dumps(
        {"policy_action": "allow", "reason_code": _ROUTED, "hookSpecificOutput": {"updatedInput": updated}}
    )


def test_hook_copy_returns_the_sink_command_only_for_a_routed_answer() -> None:
    respond = _hook_copy()["_cursor_shell_route_response"]
    assert respond(_routed_body(_SINK) + "\n") == {"permission": "allow", "updated_input": _SINK}
    plain = {"permission": "allow"}
    for body in (
        "",
        "not json",
        "[]",
        json.dumps({"policy_action": "allow"}),
        json.dumps({"policy_action": "deny", "reason_code": _ROUTED}),
        _routed_body(None),
        _routed_body({"command": 1}),
        _routed_body(_SINK).replace('"/w"', "NaN"),
        _routed_body(_SINK).replace('"/w"', "1e400"),
        _routed_body(_SINK).replace('"/w"', '"\\ud800"'),
    ):
        assert respond(body) == plain, body


def test_hook_copy_probe_matches_the_daemon() -> None:
    # The hook detects its probe before it names it for the daemon.
    probe = _hook_copy()["_cursor_shell_route_probe"]
    for payload in (_SHELL, _BEFORE_SHELL, {**_SHELL, "tool_name": "Write"}):
        assert probe(payload) == route.is_cursor_shell_probe({**payload, "cursor_route_probe": True})


class _RoutingWorker:
    def _native_policy_snapshot(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def _review_raw_hook_native(self, **_kwargs: object) -> dict[str, object]:
        return {"harness": "cursor", "event_name": "PreToolUse", "result": {"decision": "deny"}}


@posix_only
def test_a_probe_the_sink_takes_answers_with_the_rewritten_call(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import native_hook_containment_route, native_policy_snapshot_harness_postures
    from codex_plugin_scanner.guard.adapters import zcode_contained_tests
    from codex_plugin_scanner.guard.daemon import hook_fail_closed

    routed = {"policy_action": "allow", "reason_code": _ROUTED, "hookSpecificOutput": {"updatedInput": _SINK}}
    asked: list[dict[str, object]] = []

    def rewrite(response: dict[str, object], **kwargs: object) -> native_hook_containment_route.ContainmentRewrite:
        asked.append(kwargs)
        return native_hook_containment_route.ContainmentRewrite("test", None, routed)

    monkeypatch.setattr(native_policy_snapshot_harness_postures, "recording_only_for_binding", lambda *_: False)
    monkeypatch.setattr(native_hook_containment_route, "edge_containment_route", lambda *_a, **_k: "sink")
    monkeypatch.setattr(hook_fail_closed, "render_pre_tool", lambda *_a, **_k: {"policy_action": "deny"})
    monkeypatch.setattr(zcode_contained_tests, "native_containment_rewrite", rewrite)
    assert _respond(_PROBE, tmp_path, _RoutingWorker()) == routed  # type: ignore[arg-type]
    # Cursor is routed only as a bridge harness: its own hook applies the rewrite.
    assert [call["bridge"] for call in asked] == [True]
