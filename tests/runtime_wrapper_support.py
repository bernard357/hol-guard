"""Test-only wrappers over native runtime answers.

Guard's runtime reaches these answers through other routes; the wrappers stay
here so the tests that pin each answer's shape keep a stable entry point.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard import local_cli_hook
from codex_plugin_scanner.guard.adapters.grok_config import (
    FOREIGN_HOOK_COMPAT_VENDORS,
    _compat_table_span,
    build_managed_config_block,
    force_compat_hooks_false,
    remove_managed_block,
)
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.native_cli_runtime_support import cli_runtime_support as _native_cli_support
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError
from codex_plugin_scanner.guard.runtime.mcp_protection import McpServerIdentity
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


def prepare_managed_config_text(
    existing_text: str,
    hook_command: str,
    *,
    saved_prior_hooks: Mapping[str, str | None] | None = None,
) -> tuple[str, dict[str, str | None]]:
    """Merge Guard's managed block without duplicating compat tables."""

    cleaned = remove_managed_block(existing_text)
    saved = dict(saved_prior_hooks or {})
    prior_hooks: dict[str, str | None] = {}
    emit_vendors: list[str] = []
    for vendor in FOREIGN_HOOK_COMPAT_VENDORS:
        if _compat_table_span(cleaned, vendor) is None:
            emit_vendors.append(vendor)
            prior_hooks[vendor] = saved.get(vendor)
            continue
        cleaned, previous = force_compat_hooks_false(cleaned, vendor)
        saved_value = saved.get(vendor)
        prior_hooks[vendor] = saved_value if saved_value is not None else previous
    managed_block = build_managed_config_block(hook_command, emit_compat_vendors=tuple(emit_vendors))
    merged = f"{cleaned.rstrip()}\n\n{managed_block}\n".lstrip()
    return merged, prior_hooks


@dataclass(frozen=True, slots=True)
class _CopilotMcpRuntimeServer:
    server_name: str
    source_scope: str
    config_path: str
    server_config: object


def _copilot_identity_dto(value: dict[str, Any]) -> McpServerIdentity:
    fields: dict[str, Any] = dict(value)
    fields["env_keys"] = tuple(fields["env_keys"])
    return McpServerIdentity(**fields)


def _copilot_runtime_server_identity(
    server: _CopilotMcpRuntimeServer,
    *,
    launch_cwd: Path,
) -> tuple[McpServerIdentity, dict[str, object], str]:
    environment = server.server_config.get("env") if isinstance(server.server_config, Mapping) else None
    result = _native_cli_support(
        "server_identity",
        {
            "server": {
                "server_name": server.server_name,
                "source_scope": server.source_scope,
                "config_path": server.config_path,
                "server_config": server.server_config,
                "environment_keys": list(environment) if isinstance(environment, Mapping) else [],
            },
            "launch_cwd": str(launch_cwd),
            "environment": dict(os.environ),
        },
    )
    identity = result["server_identity"]
    server_identity = _copilot_identity_dto(identity)
    return server_identity, result["fingerprint"], result["transport"]
