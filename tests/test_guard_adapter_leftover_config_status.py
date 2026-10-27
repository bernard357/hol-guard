"""Setup status for Guard configuration left behind by a tool that is no longer installed."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessAdapter, HarnessContext
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.fleet_posture_tools import derive_protection_state


class _StubAdapter(HarnessAdapter):
    harness = "stubtool"
    executable = "stubtool"

    def __init__(self, *, command_available: bool, warnings: tuple[str, ...] = ()) -> None:
        self._command_available = command_available
        self._warnings = warnings

    def detect(self, context: HarnessContext) -> HarnessDetection:
        config_path = context.home_dir / ".stubtool" / "config.json"
        return HarnessDetection(
            harness=self.harness,
            installed=True,
            command_available=self._command_available,
            config_paths=(str(config_path),),
            artifacts=(
                GuardArtifact(
                    artifact_id="stubtool:hook",
                    name="guard hook",
                    harness=self.harness,
                    artifact_type="hook",
                    source_scope="global",
                    config_path=str(config_path),
                    command="hol-guard",
                    args=("hook", "stubtool"),
                ),
            ),
            warnings=self._warnings,
        )


def _diagnostics(adapter: HarnessAdapter, tmp_path: Path) -> dict[str, object]:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    return adapter.diagnostics(context)


def _protection_state(diagnostics: dict[str, object]) -> str:
    now = datetime.now(timezone.utc)
    return derive_protection_state(
        setup_status=str(diagnostics["setup_status"]),
        has_config_paths=bool(diagnostics["config_paths"]),
        paused=False,
        last_activity_at=None,
        now=now,
    )


def test_guard_config_for_uninstalled_tool_is_not_reported_broken(tmp_path: Path) -> None:
    diagnostics = _diagnostics(_StubAdapter(command_available=False), tmp_path)

    assert diagnostics["setup_status"] == "not_found"
    assert _protection_state(diagnostics) == "needs_setup"
    warnings = [str(warning) for warning in diagnostics["warnings"]]  # type: ignore[union-attr]
    assert any("hol-guard uninstall stubtool" in warning for warning in warnings)


def test_guard_config_for_installed_tool_stays_active(tmp_path: Path) -> None:
    diagnostics = _diagnostics(_StubAdapter(command_available=True), tmp_path)

    assert diagnostics["setup_status"] == "active"
    assert diagnostics["warnings"] == []


@pytest.mark.parametrize(
    "failure",
    [
        "Guard native hooks are disabled for stubtool.",
        "Managed Codex hooks are missing from the stubtool config.",
    ],
)
def test_other_setup_failures_stay_broken_when_tool_is_missing(tmp_path: Path, failure: str) -> None:
    diagnostics = _diagnostics(_StubAdapter(command_available=False, warnings=(failure,)), tmp_path)

    assert diagnostics["setup_status"] == "broken"
    assert _protection_state(diagnostics) == "broken"


def test_other_setup_failures_stay_broken_when_tool_is_installed(tmp_path: Path) -> None:
    adapter = _StubAdapter(command_available=True, warnings=("Guard native hooks are disabled for stubtool.",))

    assert _diagnostics(adapter, tmp_path)["setup_status"] == "broken"
