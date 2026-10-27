"""Execution-owned containment for exact local test and lint commands.

The resident owns the whole launch: it parses the package intent from the
shim's manager and argv, applies the manager and workspace limits, runs the
single local execution under enforcement and returns the verdict. An allowed
Vitest handoff from Guard's installed package shims that cannot be contained
stops with ``SystemExit`` instead of falling through uncontained.
"""

from __future__ import annotations

from pathlib import Path

from . import native_execution as _native_execution
from .contained_runner_result import ContainedRunnerResult

ContainedNodeResult = ContainedRunnerResult


def try_execute_contained_node_command(
    manager: str,
    argv: tuple[str, ...],
    *,
    workspace: Path,
    guard_home: Path,
    shim_directory: Path,
    environment: dict[str, str],
    timeout_seconds: float = 120.0,
) -> ContainedNodeResult | None:
    """Run one exact local test or lint command, or return to Guard review."""

    return _native_execution.contained_node_execute_native(
        workspace,
        manager,
        argv,
        guard_home=guard_home,
        shim_directory=shim_directory,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )


__all__ = ("ContainedNodeResult", "try_execute_contained_node_command")
