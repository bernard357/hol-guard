"""Tests for the Muse harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.muse import MuseHarnessAdapter
from codex_plugin_scanner.guard.adapters.muse_config import is_guard_managed_hook_command
from codex_plugin_scanner.guard.adapters.muse_hook_render import (
    apply_muse_pretool_approval_wait,
    muse_bridge_response,
)
from codex_plugin_scanner.guard.inventory_contract import _agent_type

FIXTURES = Path(__file__).parent / "fixtures" / "muse"


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _settings_path(ctx: HarnessContext) -> Path:
    return ctx.home_dir / ".config" / "muse" / "settings.json"


def _fixture_payload(name: str) -> dict[str, object]:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _managed_commands(payload: dict[str, object]) -> list[str]:
    commands: list[str] = []
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        for groups in hooks.values():
            if not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, dict):
                    continue
                for handler in group.get("hooks") or []:
                    if isinstance(handler, dict) and is_guard_managed_hook_command(handler.get("command")):
                        commands.append(str(handler["command"]))
    return commands


class TestMuseAdapterIdentity:
    def test_harness_identifier_is_muse(self) -> None:
        assert MuseHarnessAdapter.harness == "muse"

    def test_aliases_resolve(self) -> None:
        for alias in ("muse", "muse-code"):
            assert get_adapter(alias).harness == "muse"

    def test_get_adapter_returns_muse_instance(self) -> None:
        assert isinstance(get_adapter("muse"), MuseHarnessAdapter)

    def test_muse_is_registered_in_adapter_list(self) -> None:
        assert "muse" in {item.harness for item in list_adapters()}

    def test_contract_resolve(self) -> None:
        from codex_plugin_scanner.guard.adapters.contracts import contract_for, setup_contract_for

        contract = contract_for("muse")
        assert contract is not None
        assert contract.harness == "muse"
        assert contract.resume_support is True
        assert contract.native_approval is True
        assert contract.smoke_command == "hol-guard install muse --dry-run"
        setup = setup_contract_for("muse-code")
        assert setup is not None
        assert setup.harness == "muse"

    def test_agent_type_attributes_muse(self) -> None:
        assert _agent_type("muse") == "muse"

    def test_capability_rows_cover_muse_events(self) -> None:
        from codex_plugin_scanner.guard.adapters.contracts import contract_for

        contract = contract_for("muse")
        assert contract is not None
        events = {row.event for row in contract.capability_events}
        assert {"PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse", "SessionStart"} <= events

    def test_environment_attribution(self) -> None:
        from codex_plugin_scanner.guard.runtime.harness_attribution import resolve_environment_harness

        assert resolve_environment_harness({"MUSE_SESSION_ID": "session-1"}) == "muse"
        assert resolve_environment_harness({"MUSE_THREAD_ID": "thread-1"}) == "muse"


class TestMuseDetect:
    def test_detects_settings_hooks_and_mcp(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), _fixture_payload("settings.json"))
        result = MuseHarnessAdapter().detect(ctx)
        assert result.installed is True
        assert any(".config/muse/settings.json" in path for path in result.config_paths)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert any(a.command == "echo user-pretool" and a.metadata.get("event") == "PreToolUse" for a in hooks)
        assert any(a.command == "echo session-start" and a.metadata.get("event") == "SessionStart" for a in hooks)
        mcp = {a.name: a for a in result.artifacts if a.artifact_type == "mcp_server"}
        assert mcp["local-stdio"].command == "python3"
        assert mcp["local-stdio"].args == ("mcp/server.py",)
        assert mcp["local-stdio"].transport == "stdio"
        assert mcp["remote-http"].url == "https://mcp.example.com/sse"
        assert mcp["remote-http"].transport == "http"

    def test_detects_project_plugin_manifest(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write(ctx.workspace_dir / ".muse-plugin" / "plugin.json", _fixture_payload("plugin.json"))
        result = MuseHarnessAdapter().detect(ctx)
        hooks = [a for a in result.artifacts if a.artifact_type == "hook"]
        assert any(a.metadata.get("event") == "PreToolUse" for a in hooks)
        mcp = [a for a in result.artifacts if a.artifact_type == "mcp_server"]
        assert any(a.name == "workspace-index" for a in mcp)

    def test_guard_managed_hooks_excluded_from_artifacts(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        payload = _fixture_payload("settings.json")
        hooks = payload["hooks"]
        assert isinstance(hooks, dict)
        groups = hooks["PreToolUse"]
        assert isinstance(groups, list)
        groups.append(
            {"hooks": [{"type": "command", "command": "python3 guard hook --harness muse # HOL_GUARD_MANAGED_MUSE"}]}
        )
        _write(_settings_path(ctx), payload)
        result = MuseHarnessAdapter().detect(ctx)
        commands = [a.command for a in result.artifacts if a.artifact_type == "hook"]
        assert "echo user-pretool" in commands
        assert not any(command and "HOL_GUARD_MANAGED_MUSE" in command for command in commands)

    def test_unparseable_settings_warns_and_is_still_found(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        path = _settings_path(ctx)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        result = MuseHarnessAdapter().detect(ctx)
        assert any(".config/muse/settings.json" in found for found in result.config_paths)
        assert any("could not be parsed" in warning for warning in result.warnings)


class TestMuseInstallUninstall:
    def _patch_shims(self, monkeypatch: pytest.MonkeyPatch, ctx: HarnessContext) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.muse.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-muse"), "notes": []},
        )

    def test_install_writes_five_managed_event_groups(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        manifest = MuseHarnessAdapter().install(ctx)
        assert manifest["active"] is True
        payload = json.loads(_settings_path(ctx).read_text(encoding="utf-8"))
        assert payload["schema_version"] == 1
        hooks = payload["hooks"]
        assert set(hooks.keys()) == {
            "PreToolUse",
            "PermissionRequest",
            "UserPromptSubmit",
            "PostToolUse",
            "SessionStart",
        }
        # No matcher: Muse reads an omitted matcher as every tool.
        for groups in hooks.values():
            for group in groups:
                assert "matcher" not in group
                for handler in group.get("hooks", []):
                    if is_guard_managed_hook_command(handler.get("command")):
                        assert handler["type"] == "command"
                        assert isinstance(handler["timeout"], int)
        assert _managed_commands(payload)

        def _managed_timeout(event: str) -> int:
            return hooks[event][0]["hooks"][0]["timeout"]

        assert _managed_timeout("PreToolUse") == _managed_timeout("PostToolUse")
        assert _managed_timeout("PreToolUse") > 30
        assert _managed_timeout("PermissionRequest") == 30
        assert _managed_timeout("UserPromptSubmit") == 30

    def test_install_preserves_user_settings_and_hooks(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), _fixture_payload("settings.json"))
        self._patch_shims(monkeypatch, ctx)
        MuseHarnessAdapter().install(ctx)
        payload = json.loads(_settings_path(ctx).read_text(encoding="utf-8"))
        assert payload["provider"] == "meta"
        assert payload["model"] == "muse-wonder-1.0"
        assert payload["mcpServers"]["remote-http"]["url"] == "https://mcp.example.com/sse"
        pretool_commands = [
            handler["command"]
            for group in payload["hooks"]["PreToolUse"]
            for handler in group.get("hooks", [])
            if isinstance(handler, dict)
        ]
        assert "echo user-pretool" in pretool_commands

    def test_install_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        self._patch_shims(monkeypatch, ctx)
        adapter = MuseHarnessAdapter()
        adapter.install(ctx)
        first = _settings_path(ctx).read_text(encoding="utf-8")
        adapter.install(ctx)
        second = _settings_path(ctx).read_text(encoding="utf-8")
        assert json.loads(first) == json.loads(second)
        assert len(_managed_commands(json.loads(second))) == 5

    def test_install_creates_backup_and_state(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), _fixture_payload("settings.json"))
        self._patch_shims(monkeypatch, ctx)
        MuseHarnessAdapter().install(ctx)
        state_dir = ctx.guard_home / "managed" / "muse"
        assert (state_dir / "settings.json.backup").is_file()
        assert (state_dir / "install.state.json").is_file()

    def test_install_refuses_unparseable_settings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        path = _settings_path(ctx)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        self._patch_shims(monkeypatch, ctx)
        with pytest.raises(ValueError, match="could not be parsed"):
            MuseHarnessAdapter().install(ctx)

    def test_install_refuses_non_object_hooks_value(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), {"schema_version": 1, "hooks": []})
        self._patch_shims(monkeypatch, ctx)
        with pytest.raises(ValueError, match="non-object hooks"):
            MuseHarnessAdapter().install(ctx)

    def test_uninstall_removes_managed_hooks_and_keeps_user_ones(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = _ctx(tmp_path)
        _write(_settings_path(ctx), _fixture_payload("settings.json"))
        self._patch_shims(monkeypatch, ctx)
        adapter = MuseHarnessAdapter()
        adapter.install(ctx)
        manifest = adapter.uninstall(ctx)
        assert manifest["active"] is False
        payload = json.loads(_settings_path(ctx).read_text(encoding="utf-8"))
        assert _managed_commands(payload) == []
        pretool_commands = [
            handler["command"]
            for group in payload["hooks"]["PreToolUse"]
            for handler in group.get("hooks", [])
            if isinstance(handler, dict)
        ]
        assert "echo user-pretool" in pretool_commands
        assert payload["mcpServers"]["local-stdio"]["command"] == ["python3", "mcp/server.py"]
        assert not (ctx.guard_home / "managed" / "muse" / "install.state.json").exists()


class TestMuseHookRender:
    def test_allow_is_empty_stdout(self) -> None:
        # Muse rejects a bare permissionDecision allow; allow is silence.
        assert muse_bridge_response({"policy_action": "allow"}, event_name="PreToolUse") == ("", "", 0)

    def test_block_is_json_deny_on_exit_zero(self) -> None:
        stdout, _stderr, exit_code = muse_bridge_response(
            {"policy_action": "block", "reason": "nope"}, event_name="PreToolUse"
        )
        assert exit_code == 0
        payload = json.loads(stdout)
        assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert payload["hookSpecificOutput"]["permissionDecisionReason"] == "nope"

    def test_prompt_block_uses_decision_block(self) -> None:
        stdout, _stderr, exit_code = muse_bridge_response(
            {"policy_action": "review", "reason": "needs approval"}, event_name="UserPromptSubmit"
        )
        assert exit_code == 0
        assert json.loads(stdout) == {"decision": "block", "reason": "needs approval"}

    def test_permission_request_review_defers_to_muse_prompt(self) -> None:
        assert muse_bridge_response({"policy_action": "review"}, event_name="PermissionRequest") == ("", "", 0)

    def test_permission_request_block_denies(self) -> None:
        stdout, _stderr, _exit_code = muse_bridge_response(
            {"policy_action": "block", "reason": "never"}, event_name="PermissionRequest"
        )
        assert json.loads(stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_post_tool_use_adds_context_and_never_denies(self) -> None:
        stdout, _stderr, exit_code = muse_bridge_response(
            {"policy_action": "block", "reason": "output flagged"}, event_name="PostToolUse"
        )
        assert exit_code == 0
        assert json.loads(stdout)["hookSpecificOutput"]["additionalContext"] == "output flagged"

    def test_session_start_adds_guard_context(self) -> None:
        stdout, _stderr, _exit_code = muse_bridge_response({"policy_action": "allow"}, event_name="SessionStart")
        assert "HOL Guard" in json.loads(stdout)["hookSpecificOutput"]["additionalContext"]


class TestMuseApprovalResume:
    def test_approval_wait_allows_the_identical_call(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.approvals.wait_for_approval_requests",
            lambda **kwargs: {
                "resolved": True,
                "items": [{"status": "resolved", "resolution_action": "allow"}],
            },
        )
        response: dict[str, object] = {
            "policy_action": "review",
            "decision": "deny",
            "primary_approval_request_id": "req-1",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "review",
            },
        }
        updated = apply_muse_pretool_approval_wait(
            response,
            event_name="PreToolUse",
            store=object(),
            timeout_seconds=5,  # type: ignore[arg-type]
        )
        assert updated["policy_action"] == "allow"
        # The resumed answer renders as silence: Muse runs the original call.
        assert muse_bridge_response(updated, event_name="PreToolUse") == ("", "", 0)

    def test_approval_wait_denial_keeps_the_call_blocked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.approvals.wait_for_approval_requests",
            lambda **kwargs: {
                "resolved": True,
                "items": [{"status": "resolved", "resolution_action": "block"}],
            },
        )
        response: dict[str, object] = {
            "policy_action": "review",
            "primary_approval_request_id": "req-1",
        }
        updated = apply_muse_pretool_approval_wait(
            response,
            event_name="PreToolUse",
            store=object(),
            timeout_seconds=5,  # type: ignore[arg-type]
        )
        assert updated["policy_action"] == "block"
        stdout, _stderr, _exit_code = muse_bridge_response(updated, event_name="PreToolUse")
        assert json.loads(stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_approval_wait_pending_keeps_review(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.approvals.wait_for_approval_requests",
            lambda **kwargs: {"resolved": False, "items": []},
        )
        response: dict[str, object] = {
            "policy_action": "review",
            "primary_approval_request_id": "req-1",
        }
        updated = apply_muse_pretool_approval_wait(
            response,
            event_name="PreToolUse",
            store=object(),
            timeout_seconds=5,  # type: ignore[arg-type]
        )
        assert updated["policy_action"] == "review"

    def test_exit_code_uses_zero_envelope_for_pretool(self) -> None:
        from codex_plugin_scanner.guard.cli.native_hook_exit_code import native_hook_verdict_exit_code

        assert native_hook_verdict_exit_code("muse", "block", "PreToolUse") == 0
        assert native_hook_verdict_exit_code("muse", "block", "UserPromptSubmit") == 0
        assert native_hook_verdict_exit_code("muse", "block", "PostToolUse") == 1
        assert native_hook_verdict_exit_code("muse", "allow", "PreToolUse") == 0
