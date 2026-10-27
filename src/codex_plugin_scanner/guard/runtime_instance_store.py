"""Running runtime instances carried from one probe to the next.

Once the file at a runtime's path is replaced, nothing on disk says what an
older process started from. The native probe binds each process to its build
while the file still provably matches; this file keeps the running ones so the
next probe can pass them back as ``known_instances``. Losing or damaging it
only makes those processes unknown, which never clears an advisory; the native
probe rejects any stored artifact that claims more than it could observe.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from .runtime_identity_probe import RuntimeProbe

INSTANCE_STORE_NAME = "runtime-instances.json"
INSTANCE_STORE_SCHEMA = "guard.runtime-instances.v1"
MAX_KNOWN_INSTANCES = 1_024
_KEYS = frozenset({"boot_identity", "pid", "start_identity", "location_id", "artifact"})


def load_known_instances(guard_home: Path) -> list[dict[str, object]]:
    """The instances an earlier probe saw running, or none when the record is missing or unreadable."""

    try:
        data = json.loads((guard_home / INSTANCE_STORE_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict) or data.get("schema") != INSTANCE_STORE_SCHEMA:
        return []
    items = data.get("instances")
    if not isinstance(items, list):
        return []
    return [dict(item) for item in items if isinstance(item, dict) and set(item) == _KEYS][:MAX_KNOWN_INSTANCES]


def remember_instances(guard_home: Path, known: Sequence[Mapping[str, object]], probe: RuntimeProbe) -> None:
    """Keep what ``probe`` saw running, and earlier instances at locations it did not cover."""

    if probe.instances is None:
        return
    probed = {location.get("location_id") for location in probe.locations}
    artifacts = {artifact.get("artifact_id"): artifact for artifact in probe.artifacts}
    kept: list[dict[str, object]] = [
        {
            "boot_identity": row["boot_identity"],
            "pid": row["pid"],
            "start_identity": row["start_identity"],
            "location_id": row["location_id"],
            "artifact": artifacts[row["artifact_id"]],
        }
        for row in probe.instances
        if row.get("state") == "running" and row.get("location_id") is not None
    ]
    seen = {(item["boot_identity"], item["pid"], item["start_identity"]) for item in kept}
    for item in known:
        process = (item.get("boot_identity"), item.get("pid"), item.get("start_identity"))
        if item.get("location_id") not in probed and process not in seen:
            seen.add(process)
            kept.append(dict(item))
    payload = {"schema": INSTANCE_STORE_SCHEMA, "instances": kept[:MAX_KNOWN_INSTANCES]}
    try:
        _write(guard_home / INSTANCE_STORE_NAME, json.dumps(payload, separators=(",", ":"), sort_keys=True))
    except OSError:
        # The next probe then reports these processes as unknown, never as fixed.
        return


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


__all__ = [
    "INSTANCE_STORE_NAME",
    "MAX_KNOWN_INSTANCES",
    "load_known_instances",
    "remember_instances",
]
