"""Public carriers delegated to the existing native shell kernels."""

from __future__ import annotations

from pathlib import Path

from ...native_shell_request_authority import shell_request_authority
from ..github_capability_contract import GitHubCommandAssessment


def classify_github_shell_capabilities(command_text: str, *, home_dir: Path | None) -> GitHubCommandAssessment | None:
    value = shell_request_authority("classify_github_shell_capabilities", locals())
    return (
        None
        if value is None
        else GitHubCommandAssessment(
            value["capability"], value["reason_code"], value["detail"], tuple(value["capabilities"])
        )
    )


__all__ = ["classify_github_shell_capabilities"]
