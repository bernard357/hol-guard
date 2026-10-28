"""Test-side resident question for the Codex prompt-file credential scan.

The resident owns the scan. This wrapper asks it directly so tests can pin its
answer; no production path calls it.
"""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_codex_tool_output import codex_tool_output_native
from codex_plugin_scanner.guard.native_prompt import artifact_from_dict
from codex_plugin_scanner.guard.native_sensitive_request import NativeSensitiveRequestError


def codex_prompt_credential_file_artifact(
    *, prompt_text: str, cwd: Path | None, config_path: str
) -> GuardArtifact | None:
    """Review the prompt in the resident: the artifact it names, or ``None``."""

    answer = codex_tool_output_native(
        "prompt_credential_file",
        prompt_text=prompt_text,
        cwd=cwd,
        config_path=config_path,
        deadline_ms=8_000,
        timeout_seconds=9.0,
    )
    if not answer.allowed or answer.value is None or answer.error_code is not None:
        raise NativeSensitiveRequestError(answer.error_code or "native_codex_prompt_file_unavailable")
    return artifact_from_dict(json.loads(answer.value))
