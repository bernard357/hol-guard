"""Run a step Guard proved again directly on the host, outside the sandbox."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
from pathlib import Path

from .restricted_pytest_model import RestrictedPytestError


def run_on_host(
    command: str,
    *,
    cwd: Path,
    workspace: Path,
    timeout_seconds: int,
    merge_stderr: bool,
    label: str,
) -> int:
    """Run `command` with `/bin/sh` in `cwd` and return its exit status.

    `label` names the step in the timeout error. The search path drops every
    entry contained work in `workspace` could have written.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    process = subprocess.Popen(
        ["/bin/sh", "-c", command],
        cwd=cwd,
        env={**os.environ, "PATH": outside_search_path(os.environ.get("PATH", ""), workspace)},
        stdin=subprocess.DEVNULL,
        stderr=subprocess.STDOUT if merge_stderr else None,
        start_new_session=True,
    )
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise RestrictedPytestError(
            "pytest_restricted_timeout",
            f"{label} exceeded the {timeout_seconds}-second execution deadline.",
            exit_code=124,
        ) from error
    return return_code if return_code >= 0 else 128 + abs(return_code)


def outside_search_path(search_path: str, workspace: Path) -> str:
    """`search_path` without entries the contained checks could have written.

    The checks could plant a `git` or `gh` in a relative or workspace entry,
    which a host step would then run unsandboxed, as the sandbox's own PATH
    filter anticipates.
    """
    root = workspace.resolve()
    kept: list[str] = []
    for entry in search_path.split(os.pathsep):
        if not os.path.isabs(entry):
            continue
        resolved = Path(entry).resolve()
        if resolved != root and not resolved.is_relative_to(root):
            kept.append(entry)
    return os.pathsep.join(kept)
