"""Bridge to the native ``runtime-identity-probe`` command.

The native command inspects each candidate executable without starting it:
it resolves symlinks, hashes the file and infers family and version from the
install layout. This module only sends paths and checks the shape of the
reply. Its ``artifacts`` and ``locations`` are valid input for
``runtime-identity-assess``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .runtime_identity_assessment import RuntimeIdentityError, run_native_identity_command

RUNTIME_PROBE_FEATURE = "runtime-identity-probe-v1"
RUNTIME_PROBE_COMMAND = "runtime-identity-probe"
RUNTIME_PROBE_SCHEMA = "guard.runtime-identity-probe.v1"
RUNTIME_PROBE_MAX_PATHS = 128
# The probe hashes whole files, so it gets more time than a plain assessment.
_PROBE_TIMEOUT_SECONDS = 60.0

_LOCATION_STATES = frozenset({"present", "missing", "unknown"})
_ARTIFACT_TEXT_KEYS = ("artifact_id", "family", "os", "arch", "identity_assurance")


@dataclass(frozen=True)
class RuntimeProbe:
    artifacts: tuple[dict[str, object], ...]
    locations: tuple[dict[str, object], ...]
    observations: tuple[dict[str, object], ...]


def probe_runtime_paths(paths: Sequence[str]) -> RuntimeProbe:
    """Describe the executables at ``paths`` natively, never running them."""

    unique = tuple(dict.fromkeys(paths))
    if len(unique) > RUNTIME_PROBE_MAX_PATHS:
        raise RuntimeIdentityError("runtime_identity_probe_too_many_paths")
    if not unique:
        return RuntimeProbe(artifacts=(), locations=(), observations=())
    reply = run_native_identity_command(
        RUNTIME_PROBE_FEATURE,
        RUNTIME_PROBE_COMMAND,
        {"paths": list(unique)},
        timeout_seconds=_PROBE_TIMEOUT_SECONDS,
    )
    if reply.get("ok") is not True:
        error = reply.get("error")
        raise RuntimeIdentityError(error if isinstance(error, str) and error else "runtime_identity_probe_failed")
    return _parse_result(reply.get("result"))


def _parse_result(result: object) -> RuntimeProbe:
    if not isinstance(result, dict) or result.get("schema") != RUNTIME_PROBE_SCHEMA:
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    artifacts = result.get("artifacts")
    locations = result.get("locations")
    observations = result.get("observations")
    if not (isinstance(artifacts, list) and isinstance(locations, list) and isinstance(observations, list)):
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    artifact_ids: set[object] = {row.get("artifact_id") for row in artifacts if isinstance(row, dict)}
    if not (
        all(_artifact_ok(row) for row in artifacts)
        and all(_location_ok(row, artifact_ids) for row in locations)
        and all(_observation_ok(row) for row in observations)
    ):
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    return RuntimeProbe(
        artifacts=tuple(artifacts),
        locations=tuple(locations),
        observations=tuple(observations),
    )


def _artifact_ok(row: object) -> bool:
    if not isinstance(row, dict):
        return False
    assurance = row.get("identity_assurance")
    # The probe infers from paths, so it can never report a trusted identity.
    return (
        all(isinstance(row.get(key), str) for key in _ARTIFACT_TEXT_KEYS)
        and assurance in {"unknown", "self_reported"}
        and (row.get("version") is None or isinstance(row.get("version"), str))
        and isinstance(row.get("executable_sha256"), str)
    )


def _location_ok(row: object, artifact_ids: set[object]) -> bool:
    if not isinstance(row, dict) or not isinstance(row.get("location_id"), str):
        return False
    artifact_id = row.get("artifact_id")
    return row.get("state") in _LOCATION_STATES and (artifact_id is None or artifact_id in artifact_ids)


def _observation_ok(row: object) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("location_id"), str)
        and isinstance(row.get("requested_path"), str)
        and row.get("state") in _LOCATION_STATES
        and (row.get("resolved_path") is None or isinstance(row.get("resolved_path"), str))
        and (row.get("reason") is None or isinstance(row.get("reason"), str))
    )


__all__ = [
    "RUNTIME_PROBE_FEATURE",
    "RUNTIME_PROBE_MAX_PATHS",
    "RuntimeProbe",
    "probe_runtime_paths",
]
