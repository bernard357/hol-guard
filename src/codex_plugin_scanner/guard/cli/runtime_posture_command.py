"""``hol-guard runtime posture``: runtimes configured tools would launch, read only.

Prints the executables configured MCP servers launch with their inferred family,
version and identity assurance. Nothing is started, no running process is
enumerated, and no setting, approval or policy changes. Unknown stays unknown.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, TextIO

from ...argparse_utils import FriendlyArgumentParser
from .commands_parser_helpers import _add_guard_common_args

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext


def configure_runtime_parser(guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    runtime_parser = guard_subparsers.add_parser(
        "runtime",
        help="Inspect the runtimes configured tools launch with (read only)",
    )
    _add_guard_common_args(runtime_parser)
    runtime_parser.add_argument("--json", action="store_true")
    runtime_subparsers = runtime_parser.add_subparsers(dest="runtime_command", parser_class=FriendlyArgumentParser)
    posture_parser = runtime_subparsers.add_parser(
        "posture",
        help="Show observed runtime identities and advisory coverage without running them",
    )
    _add_guard_common_args(posture_parser, suppress_defaults=True)
    posture_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)


def run_runtime_posture_command(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    output_stream: TextIO | None = None,
) -> int:
    from ..adapters.harness_mcp_discovery import configured_harness_detections
    from ..runtime_posture import build_runtime_posture

    stream = output_stream if output_stream is not None else sys.stdout
    if getattr(args, "runtime_command", None) not in (None, "posture"):
        raise ValueError(f"unsupported runtime command: {args.runtime_command}")
    detections = configured_harness_detections(context.home_dir, context.guard_home, context.workspace_dir)
    payload = build_runtime_posture(
        detections,
        generated_at=datetime.now(timezone.utc).isoformat(),
        workspace_dir=context.workspace_dir,
    )
    if getattr(args, "json", False):
        stream.write(json.dumps(payload, indent=2, sort_keys=True))
        stream.write("\n")
    else:
        stream.write(render_runtime_posture(payload))
    return 1 if payload["status"] == "unavailable" else 0


def render_runtime_posture(payload: dict[str, object]) -> str:
    coverage = payload.get("coverage")
    reason = coverage.get("reason") if isinstance(coverage, dict) else None
    lines = ["Runtime posture (read only)"]
    if payload["status"] == "unavailable":
        lines.append(f"Unavailable: {payload.get('error')}. The native runtime could not inspect executables.")
    runtimes = payload.get("runtimes")
    rows = runtimes if isinstance(runtimes, list) else []
    if not rows and payload["status"] != "unavailable":
        lines.append("No configured MCP server launch executables were found.")
    for row in rows:
        lines.extend(_render_row(row))
    unresolved = payload.get("unresolved_launches")
    for item in unresolved if isinstance(unresolved, list) else []:
        lines.append(f"  not found on PATH: {item['command']} ({item['harness']} / {item['server']})")
    if payload.get("candidate_limit_reached"):
        lines.append("  Candidate limit reached; some launch executables were not inspected.")
    lines.append(f"Coverage: observed_only; scope complete: no; advisories: unavailable ({reason}).")
    lines.append("Unknown versions stay unknown. No runtime is reported safe.")
    return "\n".join(lines) + "\n"


def _render_row(row: object) -> list[str]:
    if not isinstance(row, dict):
        return []
    family = row.get("family") or "unknown"
    version = row.get("version") or "unknown version"
    detail = f"{family} {version}, assurance {row['identity_assurance']}"
    if row["location_state"] != "present":
        detail = f"{row['location_state']}" + (f" ({row['reason']})" if row.get("reason") else "")
    lines = [f"  {row['path']}", f"    {detail}"]
    launched = row.get("launched_by")
    users = sorted({f"{item['harness']}/{item['server']}" for item in launched}) if isinstance(launched, list) else []
    if users:
        lines.append(f"    launched by: {', '.join(users)}")
    return lines


__all__ = ["configure_runtime_parser", "render_runtime_posture", "run_runtime_posture_command"]
