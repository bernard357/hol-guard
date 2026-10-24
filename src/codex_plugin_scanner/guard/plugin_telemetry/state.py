"""Consent and the device secret for plugin install counts.

Both live in the Guard home. Counts are off until the user runs
``hol-guard telemetry plugins on``. The device secret only keys the weekly
counting hashes and never leaves the machine; turning counts off deletes it,
so turning them on again starts a new, unlinkable series.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

SETTINGS_FILE = "plugin-telemetry.json"
SECRET_FILE = "plugin-telemetry.key"
_SECRET_BYTES = 32


@dataclass(frozen=True)
class TelemetryState:
    enabled: bool
    last_week: str | None


def read_state(guard_home: Path) -> TelemetryState:
    try:
        payload = json.loads((guard_home / SETTINGS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return TelemetryState(enabled=False, last_week=None)
    if not isinstance(payload, dict):
        return TelemetryState(enabled=False, last_week=None)
    last_week = payload.get("lastWeek")
    return TelemetryState(
        enabled=payload.get("enabled") is True,
        last_week=last_week if isinstance(last_week, str) else None,
    )


def write_state(guard_home: Path, state: TelemetryState) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    target = guard_home / SETTINGS_FILE
    temporary = target.with_name(f"{SETTINGS_FILE}.tmp")
    temporary.write_text(
        json.dumps({"enabled": state.enabled, "lastWeek": state.last_week}, sort_keys=True),
        encoding="utf-8",
    )
    os.replace(temporary, target)


def read_secret(guard_home: Path) -> str | None:
    """The hex device secret, or None when there is no valid one."""

    try:
        value = (guard_home / SECRET_FILE).read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        return None
    if len(value) != _SECRET_BYTES * 2 or any(character not in "0123456789abcdef" for character in value):
        return None
    return value


def ensure_secret(guard_home: Path) -> str:
    """The device secret, created with owner-only permissions when missing."""

    existing = read_secret(guard_home)
    if existing is not None:
        return existing
    guard_home.mkdir(parents=True, exist_ok=True)
    target = guard_home / SECRET_FILE
    target.unlink(missing_ok=True)
    value = secrets.token_hex(_SECRET_BYTES)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(value)
    return value


def delete_secret(guard_home: Path) -> None:
    (guard_home / SECRET_FILE).unlink(missing_ok=True)
