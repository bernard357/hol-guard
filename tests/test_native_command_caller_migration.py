from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_support_command_activity as activity
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlMutationRequiredError,
)


def test_activity_read_only_authority_upgrade_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SimpleNamespace(
        read_extension_control_authority_for_registry=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            NativeCommandControlMutationRequiredError()
        )
    )
    monkeypatch.setattr(
        activity,
        "evaluate_command_native",
        lambda *_args, **_kwargs: pytest.fail("native evaluation must not run without a read-only snapshot"),
    )

    with pytest.raises(NativeCommandControlMutationRequiredError):
        activity._evaluate_payload_command(
            {"tool_name": "Shell", "tool_input": {"command": "git push origin main"}},
            store=store,
            guard_home=tmp_path / "guard",
            cwd=tmp_path,
            home_dir=tmp_path,
        )


_WORKFLOW_ARTIFACT = GuardArtifact(
    artifact_id="codex:project:tool-action:github",
    name="GitHub workflow",
    harness="codex",
    artifact_type="tool_action_request",
    source_scope="project",
    config_path="redacted",
    command="gh run rerun 1",
)
