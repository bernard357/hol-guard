"""Grok managed-config block writer, kept for the merge tests."""

from __future__ import annotations

import json
from collections.abc import Mapping

from codex_plugin_scanner.guard.adapters.grok_config import (
    FOREIGN_HOOK_COMPAT_VENDORS,
    GROK_PRETOOL_HOOK_TIMEOUT_SECONDS,
    GUARD_MANAGED_BEGIN,
    GUARD_MANAGED_END,
    MANAGED_DENY_RULES,
    _compat_hooks_assignment,
    _compat_table_span,
    remove_managed_block,
)


def _toml_inline_command_hook(hook_command: str, *, timeout: int) -> str:
    return '{ type = "command", command = ' + json.dumps(hook_command) + f", timeout = {timeout} }}"


def foreign_hook_compat_toml(vendors: tuple[str, ...] = FOREIGN_HOOK_COMPAT_VENDORS) -> str:
    """Disable Grok's vendor hook-file import.

    Grok merges other products' hook settings by default. Those files often
    split the interpreter from its arguments. Grok runs only the interpreter
    and feeds the hook JSON on stdin, so Python treats the payload as source
    and exits 1 with a traceback on every prompt and tool event. Guard keeps
    Grok-native hooks in this managed block and the dedicated hook JSON files.
    """

    chunks: list[str] = []
    for vendor in vendors:
        if chunks:
            chunks.append("")
        chunks.extend([f"[compat.{vendor}]", "hooks = false"])
    return "\n".join(chunks)


def force_compat_hooks_false(text: str, vendor: str) -> tuple[str, str | None]:
    """Set hooks=false on an existing compat table. Return prior hooks value."""

    span = _compat_table_span(text, vendor)
    if span is None:
        return text, None
    start, end = span
    block = text[start:end]
    assignment = _compat_hooks_assignment(block)
    previous = assignment[2] if assignment is not None else ""
    if assignment is not None:
        line_start, line_end, _, newline = assignment
        block = block[:line_start] + "hooks = false" + newline + block[line_end:]
    else:
        header = f"[compat.{vendor}]"
        block = block.replace(header, header + "\nhooks = false", 1)
    return text[:start] + block + text[end:], previous


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


def build_managed_config_block(
    hook_command: str = "",
    *,
    emit_compat_vendors: tuple[str, ...] = FOREIGN_HOOK_COMPAT_VENDORS,
) -> str:
    deny_lines = ",\n".join(f'  "{rule}"' for rule in MANAGED_DENY_RULES)
    lines = [
        GUARD_MANAGED_BEGIN,
        "# Permission rules below are managed by HOL Guard. Do not edit manually.",
        "[permission]",
        "deny = [",
        deny_lines,
        "]",
    ]
    compat = foreign_hook_compat_toml(emit_compat_vendors)
    if compat:
        lines.extend(["", compat])
    if hook_command.strip():
        command_hook = _toml_inline_command_hook(hook_command, timeout=GROK_PRETOOL_HOOK_TIMEOUT_SECONDS)
        observe_hook = _toml_inline_command_hook(hook_command, timeout=15)
        lines.extend(
            [
                "",
                "[[hooks.PreToolUse]]",
                f"hooks = [{command_hook}]",
                "",
                "[[hooks.UserPromptSubmit]]",
                f"hooks = [{observe_hook}]",
                "",
                "[[hooks.SubagentStart]]",
                f"hooks = [{observe_hook}]",
                "",
                "[[hooks.SessionStart]]",
                f"hooks = [{observe_hook}]",
            ]
        )
    lines.append(GUARD_MANAGED_END)
    return "\n".join(lines)
