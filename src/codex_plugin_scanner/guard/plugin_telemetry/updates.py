"""``hol-guard plugin updates``: newer checked releases of installed plugins.

Guard downloads two public indexes from HOL, the plugin listings and the
releases their authors recorded with the HOL Plugin Release workflow, and the
native runtime compares the installed versions with them on the device. The
check runs only when the user asks for it and sends nothing about the
installed plugins.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..config import resolve_guard_home
from ..mdm.network import ManagedNetworkError, managed_urlopen
from .report import (
    _INDEX_LIMIT_BYTES,
    _TIMEOUT_SECONDS,
    PluginTelemetryError,
    _native_request,
    _request,
    fetch_index,
    installed_index,
    runtime_homes,
)

PLUGIN_UPDATES_FEATURE = "plugin-updates-v1"
RELEASE_INDEX_URL = "https://hol.org/api/guard/plugins/releases/index"
DISMISSALS_FILE = "plugin-updates.json"
_MAX_DISMISSALS = 500
_RELEASE_FIELDS = ("version", "maxSeverity", "fixesSecurity")


def fetch_release_index() -> list[dict[str, object]]:
    try:
        with managed_urlopen(_request(RELEASE_INDEX_URL), timeout=_TIMEOUT_SECONDS) as response:
            raw = response.read(_INDEX_LIMIT_BYTES + 1)
    except (ManagedNetworkError, urllib.error.URLError, OSError) as error:
        raise PluginTelemetryError("The HOL release index could not be downloaded.") from error
    if len(raw) > _INDEX_LIMIT_BYTES:
        raise PluginTelemetryError("The HOL release index is larger than expected.")
    try:
        payload = json.loads(raw)
    except ValueError as error:
        raise PluginTelemetryError("The HOL release index was not valid JSON.") from error
    entries = payload.get("entries") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        raise PluginTelemetryError("The HOL release index was not in the expected shape.")
    cleaned: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        slug, url, releases = entry.get("slug"), entry.get("releasesUrl"), entry.get("releases")
        if not isinstance(slug, str) or not isinstance(url, str) or not isinstance(releases, list):
            continue
        cleaned.append(
            {
                "slug": slug,
                "releasesUrl": url,
                "releases": [
                    {field: release[field] for field in _RELEASE_FIELDS if field in release}
                    for release in releases
                    if isinstance(release, dict) and isinstance(release.get("version"), str)
                ],
            }
        )
    return cleaned


def read_dismissals(guard_home: Path) -> list[dict[str, str]]:
    try:
        payload = json.loads((guard_home / DISMISSALS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items = payload.get("dismissed") if isinstance(payload, dict) else None
    return [
        {"slug": item["slug"], "version": item["version"]}
        for item in (items if isinstance(items, list) else [])
        if isinstance(item, dict) and isinstance(item.get("slug"), str) and isinstance(item.get("version"), str)
    ][-_MAX_DISMISSALS:]


def write_dismissals(guard_home: Path, dismissals: list[dict[str, str]]) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    target = guard_home / DISMISSALS_FILE
    temporary = target.with_name(f"{DISMISSALS_FILE}.tmp")
    temporary.write_text(json.dumps({"dismissed": dismissals[-_MAX_DISMISSALS:]}, sort_keys=True), encoding="utf-8")
    os.replace(temporary, target)


def check_updates(guard_home: Path) -> dict[str, Any]:
    """``{"updates": [...], "dismissed": n}`` for the plugins installed on this machine."""

    index = installed_index(fetch_index())
    slugs = {entry["slug"] for entry in index}
    releases = [entry for entry in fetch_release_index() if entry["slug"] in slugs]
    return _native_request(
        {
            "command": "updates",
            "homes": runtime_homes(),
            "index": index,
            "releases": releases,
            "dismissed": read_dismissals(guard_home),
        },
        feature=PLUGIN_UPDATES_FEATURE,
    )


def build_parser(*, program_name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=program_name,
        description=(
            "Compare installed plugins with the releases their authors checked on HOL. "
            "Guard downloads the public indexes and compares versions on this machine; "
            "nothing about your plugins is sent."
        ),
    )
    parser.add_argument("--guard-home", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Print JSON.")
    actions = parser.add_subparsers(dest="action")
    dismiss = actions.add_parser("dismiss", help="Stop prompting for a listing until a newer release is checked.")
    dismiss.add_argument("slug", help="Listing slug, as the update prompt shows it.")
    dismiss.add_argument("--version", required=True, help="The latest version the prompt showed.")
    dismiss.add_argument("--json", action="store_true", help="Print JSON.")
    actions.add_parser("reset", help="Show dismissed prompts again.").add_argument(
        "--json", action="store_true", help="Print JSON."
    )
    return parser


def _describe(update: dict[str, Any]) -> str:
    line = (
        f"{update['slug']} ({update['runtime']}): {update['installedVersion']} -> {update['latestVersion']}\n"
        f"  {update['releasesUrl']}"
    )
    if update.get("reason") == "security_fix":
        return f"{line}\n  Urgent: a newer release fixes a high or critical finding."
    if update.get("reason") == "installed_high_severity":
        return f"{line}\n  Urgent: the installed release had a high or critical finding."
    return line


def main(argv: Sequence[str], *, program_name: str = "hol-guard plugin updates") -> int:
    args = build_parser(program_name=program_name).parse_args(list(argv))
    guard_home = resolve_guard_home(args.guard_home)
    if args.action == "dismiss":
        dismissals = [item for item in read_dismissals(guard_home) if item["slug"] != args.slug]
        dismissals.append({"slug": args.slug, "version": args.version})
        write_dismissals(guard_home, dismissals)
        payload = {"slug": args.slug, "version": args.version, "dismissed": True}
        print(json.dumps(payload, sort_keys=True) if args.json else f"Dismissed {args.slug} {args.version}.")
        return 0
    if args.action == "reset":
        write_dismissals(guard_home, [])
        print(json.dumps({"dismissed": 0}) if args.json else "Dismissed update prompts will show again.")
        return 0
    try:
        result = check_updates(guard_home)
    except PluginTelemetryError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    updates = result.get("updates") or []
    if not updates:
        print("No newer checked releases for the plugins installed here.")
    else:
        print("\n".join(_describe(update) for update in updates))
    hidden = result.get("dismissed") or 0
    if hidden:
        print(f"\n{hidden} dismissed. Run: {program_name} reset")
    return 0
