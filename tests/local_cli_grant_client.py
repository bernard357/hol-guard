"""Drive the resident's local CLI hook the way the retired grant path did."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from codex_plugin_scanner.guard import local_cli_hook
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.models import GuardAction
    from codex_plugin_scanner.guard.store import GuardStore


def local_cli_grant_action(
    *,
    store: GuardStore,
    command: str | None,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
    grant_allowed: bool,
    reason_code: str | None = None,
    path: str | None = None,
) -> GuardAction:
    """Record the CLI the command launches and refine the action with its grant.

    The resident decides the refined action. No bound answer is a resident
    outage: this raises ``NativeHookDecisionError`` and the hook answers with
    the host outage response, as the direct hook path does, instead of an
    action picked here.
    """

    if command is None:
        return current_action
    action = local_cli_hook.native_local_cli_hook(
        store,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
        grant_allowed=grant_allowed,
        reason_code=reason_code,
        path=path,
    )
    if action is None:
        raise NativeHookDecisionError("native_local_cli_hook_unavailable")
    return action
