"""Load the commands of a command-line tool Guard has only seen in use.

Tools Guard notices while it reviews agent commands are recorded by name and
identity, but their ``--help`` is never read, so they list no commands to
allow or block. This module reads that help on the operator's request, with
the same probe the Add custom extension flow uses, under tighter conditions:

* only a program found on ``PATH`` by its bare name, never a script launched
  through an interpreter, a package runner, or a file named like a personal
  script (``deploy.sh``), since a script is the likeliest thing to ignore
  ``--help`` and do its real work;
* only when the program ``PATH`` resolves to today is the same one Guard
  recorded: the same id and identity hash. A replaced binary is not probed;
* new commands are merged onto the stored ones, so a probe can never remove a
  command or the choice the operator already made for it, and a failed probe
  changes nothing.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Mapping
from pathlib import Path

from ..local_cli_errors import LocalCliCatalogLimitError
from ..local_cli_trust import utc_now
from ..runtime.local_cli_commands import MAX_LOCAL_CLI_COMMANDS, LocalCliCommand
from ..runtime.local_cli_identity import UnlistedCliIdentity, recognize_operator_cli
from .local_cli_api_contract import LocalCliApiError
from .local_cli_profiles_api import merge_profile_commands
from .mcp_discovery_jobs import DiscoveryStageError

DiscoverCommands = Callable[
    [str, UnlistedCliIdentity, Path, Path, Path],
    tuple[tuple[LocalCliCommand, ...], str, str | None],
]

_BARE_PROGRAM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_SCRIPT_SUFFIXES = frozenset(
    {
        ".bash",
        ".bat",
        ".cmd",
        ".fish",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".pl",
        ".ps1",
        ".py",
        ".rb",
        ".sh",
        ".zsh",
    }
)


def verified_cli_for_reload(item: Mapping[str, object], *, home_dir: Path) -> UnlistedCliIdentity:
    """Return the stored tool's identity, re-derived from ``PATH``, or refuse.

    No process starts here. Refusals carry a message the dashboard shows as is.
    """

    name = item.get("name")
    if (
        item.get("kind") != "executable"
        or not isinstance(name, str)
        or _BARE_PROGRAM_NAME.fullmatch(name) is None
        or Path(name).suffix.lower() in _SCRIPT_SUFFIXES
    ):
        label = name if isinstance(name, str) and name else "this tool"
        raise LocalCliApiError(
            400,
            "cli_reload_needs_path",
            f"Guard does not run {label} on its own because it looks like a script. "
            "If it prints help for --help, find it again in Add custom extension using its full path.",
        )
    identity, _, _ = recognize_operator_cli(name, cwd=home_dir, home_dir=home_dir)
    if (
        identity is None
        or identity.kind != "executable"
        or identity.runner is not None
        or identity.cli_id != item.get("cli_id")
        or identity.identity_hash != item.get("identity_hash")
    ):
        raise LocalCliApiError(
            409,
            "cli_identity_changed",
            f"The {name} on your PATH is not the program Guard recorded. "
            "Find it again in Add custom extension to review the new one.",
        )
    return identity


def load_cli_commands(
    store: object,
    identity: UnlistedCliIdentity,
    *,
    discover: DiscoverCommands,
    home_dir: Path,
    guard_home: Path,
    cancel: threading.Event,
) -> None:
    """Read ``identity``'s --help and add any new commands to its catalog."""

    # The probe re-resolves the name and only runs a program whose id still
    # matches, so a binary swapped after the check above is not run.
    commands, help_status, _ = discover(identity.name, identity, home_dir, home_dir, guard_home)
    if cancel.is_set():
        return
    if help_status == "failed":
        raise DiscoveryStageError("cli_help_unreadable")
    try:
        store.merge_local_cli_commands(  # type: ignore[attr-defined]
            identity.cli_id,
            merge_profile_commands(identity.name, commands),
            limit=MAX_LOCAL_CLI_COMMANDS,
        )
    except LocalCliCatalogLimitError:
        raise DiscoveryStageError("catalog_limit_reached") from None
    store.record_local_cli_observation(  # type: ignore[attr-defined]
        identity,
        seen_at=utc_now(),
        # The stored location class stays; a resolved path is not recorded.
        help_status=help_status,
        surface="cli",
    )
