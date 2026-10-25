"""Proof-gated policy relaxation for routine Codex workspace patches."""

from __future__ import annotations

_AGENT_INSTRUCTION_FILE_NAMES = frozenset(
    {
        "agents.md",
        "claude.md",
        "copilot-instructions.md",
        ".clinerules",
        ".cursorrules",
        ".windsurfrules",
    }
)
_AGENT_INSTRUCTION_DIRECTORIES = frozenset({".agents", ".claude", ".codex", ".cursor"})
_PROTECTED_WORKSPACE_METADATA_DIRECTORIES = frozenset({".bzr", ".git", ".hg", ".jj", ".pijul", ".svn", "_darcs"})


__all__ = []
